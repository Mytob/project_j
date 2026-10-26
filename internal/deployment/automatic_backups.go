package deployment

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	defaultSystemdUnitDir = "/etc/systemd/system"
	backupServiceName     = "jellyfin-proxy-backup.service"
	backupTimerName       = "jellyfin-proxy-backup.timer"
)

var generatedBackupName = regexp.MustCompile(`^jellyfin-proxy-[A-Za-z0-9.+_-]+-[A-Za-z0-9._-]+-[0-9]{8}T[0-9]{6}\.[0-9]{9}Z\.bak$`)

const MaxManagedBackups = 10

// ConfigureAutomaticBackups installs only Jellyfin Proxy's own systemd units.
// Both units identify their owner so an unrelated host service is never replaced.
func ConfigureAutomaticBackups(ctx context.Context, root, version, schedule string, retentionDays int, unitDir, backupDir string, runner CommandRunner) error {
	if runner == nil {
		runner = ExecRunner{}
	}
	if root == "" || !filepath.IsAbs(root) || !releaseVersionPathSafe(version) {
		return errors.New("automatic backup release path is invalid")
	}
	if schedule != "daily" && schedule != "weekly" {
		return errors.New("automatic backup schedule must be daily or weekly")
	}
	if retentionDays != 7 && retentionDays != 14 && retentionDays != 30 {
		return errors.New("automatic backup retention must be 7, 14, or 30 days")
	}
	if unitDir == "" {
		unitDir = defaultSystemdUnitDir
	}
	if backupDir == "" {
		backupDir = DefaultBackupRoot
	}
	if !filepath.IsAbs(unitDir) {
		return errors.New("systemd unit directory must be absolute")
	}
	if !filepath.IsAbs(backupDir) {
		return errors.New("automatic backup directory must be absolute")
	}
	program := filepath.Join(root, "releases", version, "bin", "proxyctl-linux-amd64")
	info, err := os.Lstat(program)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("retained proxyctl executable is missing or unsafe")
	}
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return fmt.Errorf("create systemd unit directory: %w", err)
	}
	dirInfo, err := os.Lstat(unitDir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("systemd unit directory is not a real directory")
	}
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return fmt.Errorf("create automatic backup directory: %w", err)
	}
	backupDirInfo, err := os.Lstat(backupDir)
	if err != nil || !backupDirInfo.IsDir() || backupDirInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("automatic backup path is not a real directory")
	}
	if err := os.Chmod(backupDir, 0o700); err != nil {
		return fmt.Errorf("secure automatic backup directory: %w", err)
	}
	calendar := "*-*-* 03:20:00"
	if schedule == "weekly" {
		calendar = "Sun *-*-* 03:20:00"
	}
	service := fmt.Sprintf(`# Managed by Jellyfin Proxy v1.6; changes are replaced during application install or update.
[Unit]
Description=Create a verified Jellyfin Proxy backup
After=docker.service

[Service]
Type=oneshot
User=root
Group=root
ExecStart=%s backup
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectSystem=strict
ReadWritePaths=%s
`, escapeSystemdArg(program), escapeSystemdArg(backupDir))
	timer := fmt.Sprintf(`# Managed by Jellyfin Proxy v1.6; changes are replaced during application install or update.
[Unit]
Description=Scheduled Jellyfin Proxy backup

[Timer]
OnCalendar=%s
Persistent=true
RandomizedDelaySec=15m
Unit=jellyfin-proxy-backup.service

[Install]
WantedBy=timers.target
`, calendar)
	servicePath := filepath.Join(unitDir, backupServiceName)
	timerPath := filepath.Join(unitDir, backupTimerName)
	oldService, serviceExisted, err := readOwnedUnit(servicePath)
	if err != nil {
		return err
	}
	oldTimer, timerExisted, err := readOwnedUnit(timerPath)
	if err != nil {
		return err
	}
	wasEnabled := unitState(ctx, runner, backupTimerName, "is-enabled")
	wasActive := unitState(ctx, runner, backupTimerName, "is-active")
	rollback := func(cause error) error {
		_, _ = runner.Run(context.Background(), "systemctl", "disable", "--now", backupTimerName)
		var failures []error
		for _, item := range []struct {
			path   string
			data   []byte
			exists bool
		}{{servicePath, oldService, serviceExisted}, {timerPath, oldTimer, timerExisted}} {
			if item.exists {
				if restoreErr := atomicReplace(item.path, item.data, 0o644); restoreErr != nil {
					failures = append(failures, restoreErr)
				}
			} else if removeErr := os.Remove(item.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				failures = append(failures, removeErr)
			}
		}
		if _, reloadErr := runner.Run(context.Background(), "systemctl", "daemon-reload"); reloadErr != nil {
			failures = append(failures, reloadErr)
		}
		if wasEnabled {
			args := []string{"enable"}
			if wasActive {
				args = append(args, "--now")
			}
			args = append(args, backupTimerName)
			if _, stateErr := runner.Run(context.Background(), "systemctl", args...); stateErr != nil {
				failures = append(failures, stateErr)
			}
		}
		if len(failures) != 0 {
			return errors.Join(cause, fmt.Errorf("automatic backup unit rollback failed: %w", errors.Join(failures...)))
		}
		return cause
	}
	if err := atomicReplace(servicePath, []byte(service), 0o644); err != nil {
		return fmt.Errorf("write automatic backup service: %w", err)
	}
	if err := atomicReplace(timerPath, []byte(timer), 0o644); err != nil {
		return rollback(fmt.Errorf("write automatic backup timer: %w", err))
	}
	if _, err := runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return rollback(fmt.Errorf("reload systemd units: %w", err))
	}
	if _, err := runner.Run(ctx, "systemctl", "enable", "--now", backupTimerName); err != nil {
		return rollback(fmt.Errorf("enable automatic backup timer: %w", err))
	}
	return nil
}

func readOwnedUnit(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("refusing unsafe existing systemd unit %s", filepath.Base(path))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	if !strings.HasPrefix(string(data), "# Managed by Jellyfin Proxy v1.6;") {
		return nil, false, fmt.Errorf("refusing to replace unmanaged systemd unit %s", filepath.Base(path))
	}
	return data, true, nil
}

func unitState(ctx context.Context, runner CommandRunner, unit, query string) bool {
	output, err := runner.Run(ctx, "systemctl", query, unit)
	if err != nil {
		return false
	}
	value := strings.TrimSpace(output)
	return value == "enabled" || value == "active" || value == "ok"
}

func escapeSystemdArg(value string) string {
	value = strings.ReplaceAll(value, "%", "%%")
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, " ", `\s`)
	return value
}

func releaseVersionPathSafe(version string) bool {
	return version != "" && filepath.Base(version) == version && !strings.ContainsAny(version, "/\\\x00")
}

// ReadBackupSettings loads the retained automatic backup policy. Old v1.5
// installs did not store these values and continue with daily/30-day defaults.
func ReadBackupSettings(installRoot string) (string, int, error) {
	if installRoot == "" {
		installRoot = DefaultInstallRoot
	}
	data, err := os.ReadFile(filepath.Join(installRoot, ".env"))
	if err != nil {
		return "", 0, err
	}
	environment, err := readEnvironment(data)
	if err != nil {
		return "", 0, err
	}
	return environment.BackupSchedule, environment.BackupRetentionDays, nil
}

// CleanupBackups deletes expired or excess regular archives generated by this
// product. User-named archives, symlinks, directories, and unrelated files are
// deliberately left alone. An active update-recovery archive is always kept.
func CleanupBackups(directory string, retentionDays int, now time.Time) (int, error) {
	return cleanupBackups(directory, DefaultInstallRoot, retentionDays, now)
}

func cleanupBackups(directory, installRoot string, retentionDays int, now time.Time) (int, error) {
	if retentionDays != 7 && retentionDays != 14 && retentionDays != 30 {
		return 0, errors.New("backup retention must be 7, 14, or 30 days")
	}
	if directory == "" {
		directory = DefaultBackupRoot
	}
	dirInfo, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 || dirInfo.Mode().Perm()&0o077 != 0 {
		return 0, errors.New("backup cleanup requires a private, real directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, fmt.Errorf("list backup directory: %w", err)
	}
	if now.IsZero() {
		now = time.Now()
	}
	cutoff := now.Add(-time.Duration(retentionDays) * 24 * time.Hour)
	type candidate struct {
		name      string
		path      string
		modTime   time.Time
		protected bool
	}
	managed := make([]candidate, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !generatedBackupName.MatchString(name) {
			continue
		}
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		managed = append(managed, candidate{name: name, path: path, modTime: info.ModTime()})
	}
	sort.Slice(managed, func(i, j int) bool {
		if managed[i].modTime.Equal(managed[j].modTime) {
			return managed[i].name > managed[j].name
		}
		return managed[i].modTime.After(managed[j].modTime)
	})
	protectedCount := 0
	for index := range managed {
		protected, err := updateBackupProtected(installRoot, managed[index].path)
		if err != nil {
			return 0, fmt.Errorf("check active update recovery backup before cleanup: %w", err)
		}
		managed[index].protected = protected
		if protected {
			protectedCount++
		}
	}
	retainedLimit := MaxManagedBackups - protectedCount
	if retainedLimit < 0 {
		retainedLimit = 0
	}
	removed := 0
	retained := 0
	for _, item := range managed {
		if item.protected {
			continue
		}
		if item.modTime.After(cutoff) && retained < retainedLimit {
			retained++
			continue
		}
		if err := os.Remove(item.path); err != nil {
			return removed, fmt.Errorf("remove expired or excess backup %s: %w", item.name, err)
		}
		removed++
		sidecar := item.path + ".sha256"
		if sidecarInfo, err := os.Lstat(sidecar); err == nil && sidecarInfo.Mode().IsRegular() && sidecarInfo.Mode()&os.ModeSymlink == 0 {
			if err := os.Remove(sidecar); err != nil {
				return removed, fmt.Errorf("remove expired backup checksum %s: %w", filepath.Base(sidecar), err)
			}
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
	}
	return removed, nil
}

// DeleteStoredBackup removes one explicitly selected archive and its checksum
// sidecar from the private backup directory. Active update-recovery archives
// are protected even when an administrator requests deletion.
func DeleteStoredBackup(directory, installRoot, name string) error {
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) || filepath.Ext(name) != ".bak" {
		return errors.New("backup name is invalid")
	}
	dirInfo, err := os.Lstat(directory)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 || dirInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("backup deletion requires a private, real directory")
	}
	path := filepath.Join(directory, name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 {
		return errors.New("backup is unavailable")
	}
	protected, err := updateBackupProtected(installRoot, path)
	if err != nil {
		return fmt.Errorf("check active update recovery backup: %w", err)
	}
	if protected {
		return errors.New("backup is required for active update recovery")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete stored backup: %w", err)
	}
	sidecar := path + ".sha256"
	if sidecarInfo, err := os.Lstat(sidecar); err == nil && sidecarInfo.Mode().IsRegular() && sidecarInfo.Mode()&os.ModeSymlink == 0 {
		if err := os.Remove(sidecar); err != nil {
			return fmt.Errorf("delete backup checksum: %w", err)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect backup checksum: %w", err)
	}
	return nil
}

func updateBackupProtected(installRoot, backupPath string) (bool, error) {
	if installRoot == "" {
		installRoot = DefaultInstallRoot
	}
	rootInfo, err := os.Lstat(installRoot)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("active installation root is unsafe while checking recovery backups")
	}
	journal, err := readUpdateJournal(installRoot)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	activeBackup, err := filepath.Abs(journal.BackupPath)
	if err != nil {
		return false, err
	}
	candidate, err := filepath.Abs(backupPath)
	if err != nil {
		return false, err
	}
	return filepath.Clean(activeBackup) == filepath.Clean(candidate), nil
}
