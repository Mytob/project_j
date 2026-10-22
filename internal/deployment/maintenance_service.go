package deployment

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const maintenanceServiceName = "jellyfin-proxy-maintenance.service"

const defaultMaintenanceSocket = "/run/jellyfin-proxy-maintenance/maintenance.sock"

// ConfigureHostMaintenance installs the restricted host-side API used by the
// admin container for container observation and fixed maintenance workflows.
// It authorizes only the admin UID over Unix peer credentials; web-facing
// containers receive no Docker API socket.
func ConfigureHostMaintenance(ctx context.Context, root, version, unitDir string, runner CommandRunner) error {
	return configureHostMaintenance(ctx, root, version, unitDir, DefaultBackupRoot, runner)
}

func configureHostMaintenance(ctx context.Context, root, version, unitDir, backupDir string, runner CommandRunner) error {
	if runner == nil {
		runner = ExecRunner{}
	}
	if root == "" || !filepath.IsAbs(root) || !releaseVersionPathSafe(version) {
		return errors.New("maintenance release path is invalid")
	}
	if unitDir == "" {
		unitDir = defaultSystemdUnitDir
	}
	if !filepath.IsAbs(unitDir) {
		return errors.New("systemd unit directory must be absolute")
	}
	if backupDir == "" {
		backupDir = DefaultBackupRoot
	}
	if !filepath.IsAbs(backupDir) {
		return errors.New("maintenance backup directory must be absolute")
	}
	program := filepath.Join(root, "releases", version, "bin", "maintenance-linux-amd64")
	info, err := os.Lstat(program)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return errors.New("retained maintenance executable is missing or unsafe")
	}
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return fmt.Errorf("create systemd unit directory: %w", err)
	}
	dirInfo, err := os.Lstat(unitDir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("systemd unit directory is not a real directory")
	}
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return fmt.Errorf("prepare protected backup directory: %w", err)
	}
	backupInfo, err := os.Lstat(backupDir)
	if err != nil || !backupInfo.IsDir() || backupInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("protected backup directory must be a real directory")
	}
	if err := os.Chmod(backupDir, 0o700); err != nil {
		return fmt.Errorf("secure protected backup directory: %w", err)
	}
	// systemd requires every ReadWritePaths target to exist when it starts the
	// service. The helper needs only the product install tree, the proxyctl
	// executable/state locations, backup storage, and the unit directory for
	// the fixed update/restore workflows.
	for _, writable := range []struct {
		path string
		mode os.FileMode
	}{
		{root, 0},
		{defaultProxyctlDir, 0},
		{defaultProxyctlStateDir, 0o750},
		{unitDir, 0},
		{backupDir, 0},
	} {
		if err := ensureMaintenanceWritableDirectory(writable.path, writable.mode); err != nil {
			return fmt.Errorf("prepare restricted maintenance path %q: %w", writable.path, err)
		}
	}
	unit := fmt.Sprintf(`# Managed by Jellyfin Proxy v1.6; changes are replaced during application install or update.
[Unit]
Description=Jellyfin Proxy restricted host maintenance API
After=docker.service
Requires=docker.service

[Service]
Type=simple
User=root
Group=root
RuntimeDirectory=jellyfin-proxy-maintenance
RuntimeDirectoryMode=0750
StateDirectory=jellyfin-proxy-maintenance
StateDirectoryMode=0700
UMask=0007
ExecStart=%s --socket %s --docker-socket /var/run/docker.sock
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectProc=invisible
ProcSubset=pid
PrivateDevices=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
ReadOnlyPaths=/var/run/docker.sock
ReadWritePaths=%s %s %s %s %s

[Install]
WantedBy=multi-user.target
`, escapeSystemdArg(program), escapeSystemdArg(defaultMaintenanceSocket), escapeSystemdArg(root), escapeSystemdArg(defaultProxyctlDir), escapeSystemdArg(defaultProxyctlStateDir), escapeSystemdArg(unitDir), escapeSystemdArg(backupDir))
	path := filepath.Join(unitDir, maintenanceServiceName)
	old, existed, err := readOwnedUnit(path)
	if err != nil {
		return err
	}
	wasEnabled := unitState(ctx, runner, maintenanceServiceName, "is-enabled")
	wasActive := unitState(ctx, runner, maintenanceServiceName, "is-active")
	rollback := func(cause error) error {
		_, _ = runner.Run(context.Background(), "systemctl", "disable", "--now", maintenanceServiceName)
		if existed {
			if restoreErr := atomicReplace(path, old, 0o644); restoreErr != nil {
				return errors.Join(cause, fmt.Errorf("restore previous maintenance unit: %w", restoreErr))
			}
		} else if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return errors.Join(cause, fmt.Errorf("remove failed maintenance unit: %w", removeErr))
		}
		if _, reloadErr := runner.Run(context.Background(), "systemctl", "daemon-reload"); reloadErr != nil {
			return errors.Join(cause, fmt.Errorf("reload systemd after maintenance rollback: %w", reloadErr))
		}
		if wasEnabled {
			args := []string{"enable"}
			if wasActive {
				args = append(args, "--now")
			}
			args = append(args, maintenanceServiceName)
			if _, restoreErr := runner.Run(context.Background(), "systemctl", args...); restoreErr != nil {
				return errors.Join(cause, fmt.Errorf("restore prior maintenance service state: %w", restoreErr))
			}
		}
		return cause
	}
	if err := atomicReplace(path, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write restricted maintenance unit: %w", err)
	}
	if _, err := runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return rollback(fmt.Errorf("reload systemd maintenance unit: %w", err))
	}
	if _, err := runner.Run(ctx, "systemctl", "enable", "--now", maintenanceServiceName); err != nil {
		return rollback(fmt.Errorf("start restricted maintenance service: %w", err))
	}
	if wasActive {
		if _, err := runner.Run(ctx, "systemctl", "restart", maintenanceServiceName); err != nil {
			return rollback(fmt.Errorf("restart restricted maintenance service with its updated unit: %w", err))
		}
	}
	return nil
}

func ensureMaintenanceWritableDirectory(path string, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return errors.New("writable directory must be an absolute non-root path")
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("writable path is not a real directory")
	}
	if mode != 0 {
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
	}
	return nil
}

// RefreshHostServices reapplies the host units from the currently active
// release. The persistent proxyctl executable can be older than a newly
// installed release while it is performing an update, so update invokes the
// just-installed utility to reconcile unit templates after replacing it.
func RefreshHostServices(ctx context.Context, root, unitDir, backupDir string, runner CommandRunner) error {
	if root == "" {
		root = DefaultInstallRoot
	}
	if err := validateInstalledLayout(root); err != nil {
		return fmt.Errorf("validate installation before refreshing host services: %w", err)
	}
	manifest, err := readCurrentRelease(root)
	if err != nil {
		return fmt.Errorf("read active release before refreshing host services: %w", err)
	}
	schedule, retention, err := ReadBackupSettings(root)
	if err != nil {
		return fmt.Errorf("read backup policy before refreshing host services: %w", err)
	}
	if err := configureHostMaintenance(ctx, root, manifest.Version, unitDir, backupDir, runner); err != nil {
		return err
	}
	if err := ConfigureAutomaticBackups(ctx, root, manifest.Version, schedule, retention, unitDir, backupDir, runner); err != nil {
		return err
	}
	return nil
}

// RemoveHostMaintenance removes only the product-owned service unit. It is
// used when a fresh installation fails before its application is committed.
func RemoveHostMaintenance(ctx context.Context, unitDir string, runner CommandRunner) error {
	if runner == nil {
		runner = ExecRunner{}
	}
	if unitDir == "" {
		unitDir = defaultSystemdUnitDir
	}
	path := filepath.Join(unitDir, maintenanceServiceName)
	if _, _, err := readOwnedUnit(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if _, err := runner.Run(ctx, "systemctl", "disable", "--now", maintenanceServiceName); err != nil {
		return fmt.Errorf("stop restricted maintenance service: %w", err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove restricted maintenance unit: %w", err)
	}
	if _, err := runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("reload systemd after maintenance removal: %w", err)
	}
	return nil
}
