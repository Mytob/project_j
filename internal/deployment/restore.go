package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mytob/project_j/internal/backup"
	"github.com/Mytob/project_j/internal/monitoring"
)

var restorePaths = []string{"config", "data", "site", ".env", "compose.yaml"}

type restoreJournal struct {
	Version string `json:"version"`
	Stage   string `json:"stage"`
	State   string `json:"state"`
}

type RestoreOptions struct {
	InstallRoot           string
	BackupPath            string
	SafetyBackupPath      string
	Runner                CommandRunner
	WaitInterval          time.Duration
	WaitAttempts          int
	HTTPSCheck            func(context.Context, string) error
	ConfigureHostServices bool
	SystemdUnitDir        string
	BackupDirectory       string
	Progress              func(UpdateProgress)
}

// Restore applies a validated application backup after making a verified
// safety backup of the current installation. It never restores host SSH or
// firewall configuration and keeps a durable journal until health is proven.
func Restore(ctx context.Context, options RestoreOptions) (manifest backup.Manifest, resultErr error) {
	const restoreSteps = 7
	progress := func(step int, done bool, message string) {
		if options.Progress != nil {
			options.Progress(UpdateProgress{Step: step, Total: restoreSteps, Message: message, Done: done})
		}
	}
	progress(1, false, "Validating the backup")
	if options.InstallRoot == "" {
		options.InstallRoot = DefaultInstallRoot
	}
	if !filepath.IsAbs(options.InstallRoot) {
		return manifest, errors.New("installation root must be an absolute path")
	}
	if options.Runner == nil {
		options.Runner = ExecRunner{}
	}
	if options.WaitInterval <= 0 {
		options.WaitInterval = time.Second
	}
	if options.WaitAttempts <= 0 {
		options.WaitAttempts = 90
	}
	if err := validateInstalledLayout(options.InstallRoot); err != nil {
		return manifest, err
	}
	if _, err := RecoverInterruptedRestore(ctx, options.InstallRoot, options.Runner); err != nil {
		return manifest, fmt.Errorf("recover previous interrupted restore first: %w", err)
	}
	manifest, err := ValidateBackup(options.BackupPath)
	if err != nil {
		return manifest, err
	}
	progress(1, true, "Backup integrity and compatibility verified")
	if manifest.DatabaseSchema != monitoring.DatabaseSchemaVersion {
		return manifest, fmt.Errorf("backup database schema %d is incompatible with supported schema %d", manifest.DatabaseSchema, monitoring.DatabaseSchemaVersion)
	}
	backupRelease, err := readReleaseManifest(filepath.Join(options.InstallRoot, "releases", manifest.Version))
	if err != nil || backupRelease.BuildID != manifest.BuildID || backupRelease.DatabaseSchemaMinimum > manifest.DatabaseSchema || backupRelease.DatabaseSchemaMaximum < manifest.DatabaseSchema {
		return manifest, errors.New("backup release is not retained or its build/database schema is incompatible")
	}
	progress(2, false, "Staging restored files and validating Compose")
	stage, err := os.MkdirTemp(options.InstallRoot, ".restore-")
	if err != nil {
		return manifest, fmt.Errorf("create restore staging directory: %w", err)
	}
	defer func() {
		if resultErr == nil {
			_ = os.RemoveAll(stage)
			return
		}
		if _, recoverErr := RecoverInterruptedRestore(context.Background(), options.InstallRoot, options.Runner); recoverErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("automatic restore rollback failed: %w", recoverErr))
			return
		}
		_ = os.RemoveAll(stage)
	}()
	if err := os.Chmod(stage, 0o700); err != nil {
		return manifest, err
	}
	newRoot := filepath.Join(stage, "new")
	oldRoot := filepath.Join(stage, "old")
	if _, err := ExtractBackup(options.BackupPath, newRoot); err != nil {
		return manifest, fmt.Errorf("extract restore staging copy: %w", err)
	}
	environmentBytes, err := os.ReadFile(filepath.Join(newRoot, ".env"))
	if err != nil {
		return manifest, err
	}
	environment, err := readEnvironment(environmentBytes)
	if err != nil || environment.Version != manifest.Version {
		return manifest, errors.New("backup environment does not match its release metadata")
	}
	if _, err := options.Runner.Run(ctx, "docker", "compose", "--project-name", "jellyfin-proxy", "--project-directory", options.InstallRoot, "--file", filepath.Join(newRoot, "compose.yaml"), "--env-file", filepath.Join(newRoot, ".env"), "config", "--quiet"); err != nil {
		return manifest, fmt.Errorf("restored Compose configuration is invalid: %w", err)
	}
	progress(2, true, "Restored files and Compose configuration validated")
	progress(3, false, "Creating the mandatory safety backup")
	if _, _, err := CreateBackup(options.InstallRoot, options.SafetyBackupPath); err != nil {
		return manifest, fmt.Errorf("mandatory pre-restore backup failed; restore was not applied: %w", err)
	}
	progress(3, true, "Safety backup created and verified")
	if err := os.Mkdir(oldRoot, 0o700); err != nil {
		return manifest, err
	}
	journalPath := filepath.Join(options.InstallRoot, ".restore-transaction.json")
	if err := writeRestoreJournal(journalPath, restoreJournal{Version: manifest.Version, Stage: filepath.Base(stage), State: "prepared"}); err != nil {
		return manifest, err
	}
	if err := writeRestoreJournal(journalPath, restoreJournal{Version: manifest.Version, Stage: filepath.Base(stage), State: "stopping"}); err != nil {
		return manifest, err
	}
	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "down")...); err != nil {
		return manifest, fmt.Errorf("stop application stack for restore: %w", err)
	}
	progress(4, true, "Application stack stopped")
	if err := writeRestoreJournal(journalPath, restoreJournal{Version: manifest.Version, Stage: filepath.Base(stage), State: "replacing"}); err != nil {
		return manifest, err
	}
	progress(5, false, "Installing restored files and ownership")
	for _, relative := range restorePaths {
		if err := os.Rename(filepath.Join(options.InstallRoot, relative), filepath.Join(oldRoot, relative)); err != nil {
			return manifest, fmt.Errorf("stage current %s before restore: %w", relative, err)
		}
	}
	for _, relative := range restorePaths {
		if err := os.Rename(filepath.Join(newRoot, relative), filepath.Join(options.InstallRoot, relative)); err != nil {
			return manifest, fmt.Errorf("activate restored %s: %w", relative, err)
		}
	}
	if err := secureRestoredLayout(options.InstallRoot); err != nil {
		return manifest, err
	}
	if err := os.Chmod(filepath.Join(options.InstallRoot, ".env"), 0o640); err != nil {
		return manifest, err
	}
	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "config", "--quiet")...); err != nil {
		return manifest, fmt.Errorf("validate active restored Compose configuration: %w", err)
	}
	if options.ConfigureHostServices {
		if err := ConfigureHostMaintenance(ctx, options.InstallRoot, manifest.Version, options.SystemdUnitDir, options.Runner); err != nil {
			return manifest, fmt.Errorf("configure restricted maintenance service for restored release: %w", err)
		}
	}
	progress(5, true, "Restored files installed with restricted ownership")
	progress(6, false, "Starting the application and checking all containers")
	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "up", "--detach", "--pull", "never")...); err != nil {
		return manifest, fmt.Errorf("start restored application stack: %w", err)
	}
	if err := waitForReadiness(ctx, InstallOptions{InstallRoot: options.InstallRoot, Runner: options.Runner, WaitInterval: options.WaitInterval, WaitAttempts: options.WaitAttempts}); err != nil {
		return manifest, fmt.Errorf("restored services did not become healthy: %w", err)
	}
	progress(6, true, "All application containers are healthy")
	progress(7, false, "Checking HTTPS and restoring scheduled backups")
	if options.HTTPSCheck == nil {
		options.HTTPSCheck = checkPublicHTTPS
	}
	if err := waitForHTTPS(ctx, environment.Domain, options.WaitInterval, options.WaitAttempts, options.HTTPSCheck); err != nil {
		return manifest, fmt.Errorf("restored public HTTPS check failed: %w", err)
	}
	if options.ConfigureHostServices {
		if err := ConfigureAutomaticBackups(ctx, options.InstallRoot, manifest.Version, environment.BackupSchedule, environment.BackupRetentionDays, options.SystemdUnitDir, options.BackupDirectory, options.Runner); err != nil {
			return manifest, fmt.Errorf("restore automatic backup service settings: %w", err)
		}
	}
	if err := os.Remove(journalPath); err != nil {
		return manifest, fmt.Errorf("remove completed restore journal: %w", err)
	}
	progress(7, true, "Restore verified and committed")
	return manifest, nil
}

func secureRestoredLayout(root string) error {
	for _, item := range []struct {
		path string
		uid  int
		gid  int
		mode os.FileMode
	}{
		{path: "config", uid: 0, gid: adminContainerUID, mode: 0o750},
		{path: filepath.Join("config", "wireguard"), uid: 0, gid: adminContainerUID, mode: 0o750},
		{path: "data", uid: adminContainerUID, gid: adminContainerUID, mode: 0o700},
		{path: filepath.Join("config", "security-event-key"), uid: 0, gid: adminContainerUID, mode: 0o750},
		{path: "site", uid: 0, gid: 0, mode: 0o755},
	} {
		path := filepath.Join(root, item.path)
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			if strings.Contains(item.path, "wireguard") {
				continue
			}
			if err := os.MkdirAll(path, item.mode); err != nil {
				return fmt.Errorf("create restored directory %s: %w", item.path, err)
			}
		} else if err != nil {
			return err
		}
		if err := os.Chown(path, item.uid, item.gid); err != nil {
			return fmt.Errorf("set restored %s ownership: %w", item.path, err)
		}
		if err := os.Chmod(path, item.mode); err != nil {
			return fmt.Errorf("set restored %s permissions: %w", item.path, err)
		}
	}
	if err := secureRestoredConfig(filepath.Join(root, "config")); err != nil {
		return err
	}
	if err := secureRestoredData(filepath.Join(root, "data")); err != nil {
		return err
	}
	if err := secureRestoredRootFile(filepath.Join(root, ".env"), 0, 0, 0o640); err != nil {
		return err
	}
	return initializeWebContentStore(filepath.Join(root, "data", "site-content"), filepath.Join(root, "site"))
}

func secureRestoredConfig(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("restored configuration contains a symbolic link: %s", path)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		uid, gid, mode := 0, adminContainerUID, os.FileMode(0o750)
		if !entry.IsDir() {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("restored configuration contains a non-regular file: %s", path)
			}
			mode = 0o640
		}
		if filepath.ToSlash(strings.TrimPrefix(path, root+string(os.PathSeparator))) == "wireguard/server.conf" {
			gid, mode = 0, 0o600
		}
		if filepath.ToSlash(strings.TrimPrefix(path, root+string(os.PathSeparator))) == "security-event-key/event.key" {
			gid, mode = adminContainerUID, 0o440
		}
		if err := os.Chown(path, uid, gid); err != nil {
			return fmt.Errorf("set restored config ownership: %w", err)
		}
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("set restored config permissions: %w", err)
		}
		return nil
	})
}

func secureRestoredData(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "site-content" {
			return filepath.SkipDir
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("restored application data contains a symbolic link: %s", path)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !entry.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("restored application data contains a non-regular file: %s", path)
		}

		uid, gid, mode := adminContainerUID, adminContainerUID, os.FileMode(0o700)
		if !entry.IsDir() {
			mode = restrictedDataFileMode(info.Mode().Perm())
		}
		switch {
		case underPath(relative, "security-state"), underPath(relative, "fail2ban"):
			uid, gid = 0, 0
			if entry.IsDir() {
				mode = 0o700
			} else {
				mode = 0o600
			}
		case underPath(relative, "security-events"):
			if underPath(relative, "security-events/rejected") {
				uid, gid = 0, 0
				if entry.IsDir() {
					mode = 0o700
				} else {
					mode = 0o600
				}
			} else {
				uid, gid = adminContainerUID, 0
				if entry.IsDir() {
					mode = 0o2770
				} else {
					mode = 0o640
				}
			}
		case underPath(relative, "wireguard-client"):
			uid, gid = 0, adminContainerUID
			if entry.IsDir() {
				mode = 0o2770
			} else {
				mode = 0o640
			}
		}
		if err := os.Chown(path, uid, gid); err != nil {
			return fmt.Errorf("set restored data ownership for %s: %w", relative, err)
		}
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("set restored data permissions for %s: %w", relative, err)
		}
		return nil
	})
}

func underPath(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+"/")
}

func restrictedDataFileMode(mode os.FileMode) os.FileMode {
	mode &= 0o700
	if mode == 0 {
		return 0o600
	}
	return mode
}

func secureRestoredRootFile(path string, uid, gid int, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("restored environment file is missing or unsafe")
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("set restored root-file ownership: %w", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("set restored root-file permissions: %w", err)
	}
	return nil
}

// RecoverInterruptedRestore rolls back a restore transaction left before its
// health checks completed. It only uses paths from a strict, private journal.
func RecoverInterruptedRestore(ctx context.Context, root string, runner CommandRunner) (bool, error) {
	if root == "" {
		root = DefaultInstallRoot
	}
	path := filepath.Join(root, ".restore-transaction.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var journal restoreJournal
	if json.Unmarshal(data, &journal) != nil || journal.Version == "" || !strings.HasPrefix(journal.Stage, ".restore-") || filepath.Base(journal.Stage) != journal.Stage || (journal.State != "prepared" && journal.State != "stopping" && journal.State != "replacing") {
		return false, errors.New("restore transaction journal is invalid; do not remove it manually")
	}
	stage := filepath.Join(root, journal.Stage)
	if resolved, err := filepath.EvalSymlinks(stage); err == nil {
		rootResolved, rootErr := filepath.EvalSymlinks(root)
		if rootErr != nil || !strings.HasPrefix(resolved, rootResolved+string(os.PathSeparator)) {
			return false, errors.New("restore staging directory escapes the installation root")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	oldRoot := filepath.Join(stage, "old")
	for _, relative := range restorePaths {
		oldPath := filepath.Join(oldRoot, relative)
		if _, err := os.Lstat(oldPath); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return false, err
		}
		currentPath := filepath.Join(root, relative)
		if err := os.RemoveAll(currentPath); err != nil {
			return false, fmt.Errorf("remove interrupted restored %s: %w", relative, err)
		}
		if err := os.Rename(oldPath, currentPath); err != nil {
			return false, fmt.Errorf("restore previous %s: %w", relative, err)
		}
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	if journal.State != "prepared" {
		if _, err := runner.Run(ctx, "docker", composeArgs(root, "up", "--detach", "--pull", "never")...); err != nil {
			return true, fmt.Errorf("restart previous services after interrupted restore: %w", err)
		}
		if err := waitForReadiness(ctx, InstallOptions{InstallRoot: root, Runner: runner, WaitInterval: 2 * time.Second, WaitAttempts: 60}); err != nil {
			return true, fmt.Errorf("previous services did not recover after interrupted restore: %w", err)
		}
	}
	if err := os.Remove(path); err != nil {
		return true, err
	}
	if err := os.RemoveAll(stage); err != nil {
		return true, err
	}
	return true, nil
}

func writeRestoreJournal(path string, journal restoreJournal) error {
	data, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return atomicReplace(path, data, 0o600)
}
