package deployment

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Mytob/project_j/internal/monitoring"
	"github.com/Mytob/project_j/internal/release"
)

var ErrNoPreviousRelease = errors.New("no retained previous release is available for rollback")

type RollbackOptions struct {
	InstallRoot           string
	BackupPath            string
	Runner                CommandRunner
	WaitInterval          time.Duration
	WaitAttempts          int
	HTTPSCheck            func(context.Context, string) error
	ConfigureHostServices bool
	SystemdUnitDir        string
	BackupDirectory       string
	MaintenanceUpdated    func()
	Progress              func(UpdateProgress)
}

// RollbackPrevious activates the retained previous release while preserving
// the current application data, administrator credentials, and WireGuard
// identity. A verified pre-rollback backup and the same durable journal used by
// package updates make process and reboot interruption recoverable.
func RollbackPrevious(ctx context.Context, options RollbackOptions) (target release.Manifest, resultErr error) {
	const steps = 7
	progress := func(step int, done bool, message string) {
		if options.Progress != nil {
			options.Progress(UpdateProgress{Step: step, Total: steps, Message: message, Done: done})
		}
	}
	progress(1, false, "Checking the current installation")
	if options.InstallRoot == "" {
		options.InstallRoot = DefaultInstallRoot
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
		return target, err
	}
	if _, err := RecoverInterruptedUpdate(ctx, UpdateRecoveryOptions{
		InstallRoot: options.InstallRoot, Runner: options.Runner, WaitInterval: options.WaitInterval,
		WaitAttempts: options.WaitAttempts, ConfigureHostServices: options.ConfigureHostServices,
		SystemdUnitDir: options.SystemdUnitDir, BackupDirectory: options.BackupDirectory,
		MaintenanceUpdated: options.MaintenanceUpdated,
	}); err != nil {
		return target, fmt.Errorf("recover the pending update before rollback: %w", err)
	}
	current, err := readCurrentRelease(options.InstallRoot)
	if err != nil {
		return target, err
	}
	progress(1, true, "Current installation is valid")

	progress(2, false, "Verifying the retained previous release")
	target, err = PreviousReleaseForRollback(options.InstallRoot)
	if err != nil {
		return target, err
	}
	previousRoot := filepath.Join(options.InstallRoot, "releases", target.Version)
	composeStatus, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "ps", "--format", "json")...)
	if err != nil {
		return target, fmt.Errorf("inspect current deployment before rollback: %w", err)
	}
	if !composeServicesHealthy(composeStatus) {
		return target, errors.New("the existing Jellyfin Proxy deployment is not healthy; restore it before rollback")
	}
	databaseSchema, err := monitoring.HistoryDatabaseSchema(filepath.Join(options.InstallRoot, "data", "statistics", "statistics.db"))
	if err != nil {
		return target, fmt.Errorf("inspect the current statistics database before rollback: %w", err)
	}
	if databaseSchema < current.DatabaseSchemaMinimum || databaseSchema > current.DatabaseSchemaMaximum {
		return target, fmt.Errorf("current release %s does not support the installed database schema %d", current.Version, databaseSchema)
	}
	if databaseSchema < target.DatabaseSchemaMinimum || databaseSchema > target.DatabaseSchemaMaximum {
		return target, fmt.Errorf("retained release %s does not support database schema %d (supports %d-%d)", target.Version, databaseSchema, target.DatabaseSchemaMinimum, target.DatabaseSchemaMaximum)
	}
	progress(2, true, "Previous release files verified")

	progress(3, false, "Creating a verified pre-rollback backup")
	backupPath, _, err := CreateBackup(options.InstallRoot, options.BackupPath)
	if err != nil {
		return target, fmt.Errorf("mandatory pre-rollback backup failed; rollback was not applied: %w", err)
	}
	progress(3, true, "Pre-rollback backup created at "+backupPath)

	transactionID, stage, err := newUpdateStage(options.InstallRoot)
	if err != nil {
		return target, err
	}
	if err := snapshotUpdateFiles(options.InstallRoot, stage); err != nil {
		_ = os.RemoveAll(filepath.Join(options.InstallRoot, stage))
		return target, fmt.Errorf("snapshot current release before rollback: %w", err)
	}
	transaction := updateJournal{
		Format: 1, ID: transactionID, PreviousVersion: current.Version, TargetVersion: target.Version,
		Stage: stage, State: "prepared", BackupPath: backupPath,
	}
	if err := writeUpdateJournal(options.InstallRoot, transaction); err != nil {
		_ = os.RemoveAll(filepath.Join(options.InstallRoot, stage))
		return target, fmt.Errorf("persist rollback recovery journal: %w", err)
	}

	previousFiles := make(map[string][]byte, len(updateRecoveryFiles))
	for _, relative := range updateRecoveryFiles {
		previousFiles[relative], err = os.ReadFile(filepath.Join(options.InstallRoot, relative))
		if err != nil {
			_ = removeUpdateJournal(options.InstallRoot, transaction)
			return target, fmt.Errorf("read current %s before rollback: %w", relative, err)
		}
	}
	environment, err := readEnvironment(previousFiles[".env"])
	if err != nil {
		_ = removeUpdateJournal(options.InstallRoot, transaction)
		return target, err
	}
	if environment.Version != current.Version {
		_ = removeUpdateJournal(options.InstallRoot, transaction)
		return target, errors.New("active release metadata changed while rollback was being prepared")
	}
	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "config", "--quiet")...); err != nil {
		_ = removeUpdateJournal(options.InstallRoot, transaction)
		return target, fmt.Errorf("validate current Compose configuration before rollback: %w", err)
	}

	changed := false
	stackMayBeRunning := true
	journalActive := true
	defer func() {
		if !journalActive || resultErr == nil {
			return
		}
		if changed {
			transaction.State = "rolling-back"
			var recoveryErrors []error
			if err := writeUpdateJournal(options.InstallRoot, transaction); err != nil {
				recoveryErrors = append(recoveryErrors, err)
			}
			for _, relative := range updateRecoveryFiles {
				mode := os.FileMode(0o644)
				if relative == ".env" {
					mode = 0o640
				}
				if err := replaceUpdateFileDurable(filepath.Join(options.InstallRoot, relative), previousFiles[relative], mode); err != nil {
					recoveryErrors = append(recoveryErrors, fmt.Errorf("restore %s: %w", relative, err))
				}
			}
			if options.ConfigureHostServices {
				if err := configureHostMaintenanceForOperation(context.Background(), options.InstallRoot, current.Version, options.SystemdUnitDir, options.BackupDirectory, options.Runner, options.MaintenanceUpdated); err != nil {
					recoveryErrors = append(recoveryErrors, fmt.Errorf("restore maintenance service: %w", err))
				}
				if err := ConfigureAutomaticBackups(context.Background(), options.InstallRoot, current.Version, environment.BackupSchedule, environment.BackupRetentionDays, options.SystemdUnitDir, options.BackupDirectory, options.Runner); err != nil {
					recoveryErrors = append(recoveryErrors, fmt.Errorf("restore backup schedule: %w", err))
				}
			}
			if stackMayBeRunning {
				if _, err := options.Runner.Run(context.Background(), "docker", composeArgs(options.InstallRoot, "up", "--detach", "--force-recreate", "--pull", "never")...); err != nil {
					recoveryErrors = append(recoveryErrors, fmt.Errorf("restart current release: %w", err))
				} else if err := waitForReadiness(context.Background(), InstallOptions{InstallRoot: options.InstallRoot, Runner: options.Runner, WaitInterval: options.WaitInterval, WaitAttempts: options.WaitAttempts}); err != nil {
					recoveryErrors = append(recoveryErrors, fmt.Errorf("current release readiness: %w", err))
				}
			}
			if len(recoveryErrors) > 0 {
				resultErr = errors.Join(resultErr, fmt.Errorf("rollback failed and previous release recovery was incomplete; journal and backup were retained: %w", errors.Join(recoveryErrors...)))
				return
			}
		}
		if err := removeUpdateJournal(options.InstallRoot, transaction); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove rollback journal: %w", err))
			return
		}
		journalActive = false
	}()

	progress(4, false, "Checking retained Docker images")
	if err := verifyLoadedImages(ctx, options.Runner, target.Images); err != nil {
		return target, err
	}
	progress(4, true, "Previous release images verified")
	newEnvironment := fmt.Sprintf("BASE_DOMAIN=%s\nRELEASE_VERSION=%s\nWIREGUARD_PORT=%d\nSYSTEMD_JOURNAL_GID=%s\nBACKUP_SCHEDULE=%s\nBACKUP_RETENTION_DAYS=%d\n", environment.Domain, target.Version, environment.WireGuardPort, environment.JournalGID, environment.BackupSchedule, environment.BackupRetentionDays)
	progress(5, false, "Activating the retained release without restoring application data")
	transaction.State = "stopping"
	if err := writeUpdateJournal(options.InstallRoot, transaction); err != nil {
		return target, fmt.Errorf("record rollback stop stage: %w", err)
	}
	changed = true
	stackMayBeRunning = true
	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "stop")...); err != nil {
		return target, fmt.Errorf("stop application before rollback: %w", err)
	}
	transaction.State = "replacing"
	if err := writeUpdateJournal(options.InstallRoot, transaction); err != nil {
		changed = true
		return target, fmt.Errorf("record rollback activation stage: %w", err)
	}
	for _, file := range []struct {
		path    string
		content []byte
		mode    os.FileMode
	}{
		{path: ".env", content: []byte(newEnvironment), mode: 0o640},
		{path: "compose.yaml", content: mustRead(filepath.Join(previousRoot, "compose.yaml")), mode: 0o644},
		{path: filepath.Join("config", "Caddyfile"), content: mustRead(filepath.Join(previousRoot, "config", "Caddyfile")), mode: 0o644},
	} {
		if file.content == nil {
			return target, errors.New("verified previous release is missing a required activation file")
		}
		if err := replaceUpdateFileDurable(filepath.Join(options.InstallRoot, file.path), file.content, file.mode); err != nil {
			return target, fmt.Errorf("activate previous release file %s: %w", file.path, err)
		}
	}
	if options.ConfigureHostServices {
		if err := configureHostMaintenanceForOperation(ctx, options.InstallRoot, target.Version, options.SystemdUnitDir, options.BackupDirectory, options.Runner, options.MaintenanceUpdated); err != nil {
			return target, fmt.Errorf("configure maintenance service for previous release: %w", err)
		}
		if err := ConfigureAutomaticBackups(ctx, options.InstallRoot, target.Version, environment.BackupSchedule, environment.BackupRetentionDays, options.SystemdUnitDir, options.BackupDirectory, options.Runner); err != nil {
			return target, fmt.Errorf("configure backup schedule for previous release: %w", err)
		}
	}
	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "config", "--quiet")...); err != nil {
		return target, fmt.Errorf("previous release Compose configuration is invalid: %w", err)
	}
	progress(5, true, "Previous release configuration validated")
	progress(6, false, "Restarting the previous release and checking HTTPS")
	transaction.State = "starting"
	if err := writeUpdateJournal(options.InstallRoot, transaction); err != nil {
		return target, err
	}
	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "up", "--detach", "--force-recreate", "--pull", "never")...); err != nil {
		return target, fmt.Errorf("start previous release: %w", err)
	}
	transaction.State = "verifying"
	if err := writeUpdateJournal(options.InstallRoot, transaction); err != nil {
		return target, err
	}
	if err := waitForReadiness(ctx, InstallOptions{InstallRoot: options.InstallRoot, Runner: options.Runner, WaitInterval: options.WaitInterval, WaitAttempts: options.WaitAttempts}); err != nil {
		return target, fmt.Errorf("previous release did not become healthy: %w", err)
	}
	if options.HTTPSCheck == nil {
		options.HTTPSCheck = checkPublicHTTPS
	}
	if err := waitForHTTPS(ctx, environment.Domain, options.WaitInterval, options.WaitAttempts, options.HTTPSCheck); err != nil {
		return target, fmt.Errorf("previous release HTTPS check failed: %w", err)
	}
	progress(6, true, "Previous release services and HTTPS are healthy")
	progress(7, false, "Retaining the active and rollback releases")
	if err := retainActiveAndPrevious(options.InstallRoot, target.Version, current.Version); err != nil {
		return target, fmt.Errorf("rollback succeeded but release retention failed: %w", err)
	}
	transaction.State = "committing"
	if err := writeUpdateJournal(options.InstallRoot, transaction); err != nil {
		return target, fmt.Errorf("previous release is healthy but rollback commit was not persisted: %w", err)
	}
	if err := removeUpdateJournal(options.InstallRoot, transaction); err != nil {
		return target, fmt.Errorf("previous release is healthy but rollback journal cleanup failed: %w", err)
	}
	journalActive = false
	progress(7, true, "Rollback completed; current data and the newer release are retained")
	return target, nil
}

// PreviousReleaseForRollback returns the newest verified retained release
// older than the active version, if one is available.
func PreviousReleaseForRollback(installRoot string) (release.Manifest, error) {
	if installRoot == "" {
		installRoot = DefaultInstallRoot
	}
	if err := validateInstalledLayout(installRoot); err != nil {
		return release.Manifest{}, err
	}
	current, err := readCurrentRelease(installRoot)
	if err != nil {
		return release.Manifest{}, err
	}
	version, err := previousRetainedVersion(installRoot, current.Version)
	if err != nil {
		return release.Manifest{}, err
	}
	directory := filepath.Join(installRoot, "releases", version)
	manifest, err := readReleaseManifest(directory)
	if err != nil {
		return release.Manifest{}, err
	}
	if err := release.VerifyRetainedFiles(directory, manifest); err != nil {
		return release.Manifest{}, fmt.Errorf("verify previous release files: %w", err)
	}
	if manifest.Version != version || manifest.Platform != "linux/amd64" {
		return release.Manifest{}, errors.New("retained previous release is incompatible with this host")
	}
	if err := validatePackagePortAndVersion(manifest, 51820); err != nil {
		return release.Manifest{}, err
	}
	if err := validateProxyctlMinimum(manifest); err != nil {
		return release.Manifest{}, err
	}
	return manifest, nil
}

func previousRetainedVersion(root, current string) (string, error) {
	entries, err := os.ReadDir(filepath.Join(root, "releases"))
	if err != nil {
		return "", err
	}
	versions := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || entry.Name() == current || !release.ValidVersion(entry.Name()) {
			continue
		}
		manifest, err := readReleaseManifest(filepath.Join(root, "releases", entry.Name()))
		if err != nil || manifest.Version != entry.Name() {
			continue
		}
		comparison, err := release.CompareVersions(entry.Name(), current)
		if err != nil || comparison >= 0 {
			continue
		}
		versions = append(versions, entry.Name())
	}
	if len(versions) == 0 {
		return "", ErrNoPreviousRelease
	}
	sort.Slice(versions, func(i, j int) bool {
		comparison, err := release.CompareVersions(versions[i], versions[j])
		return err == nil && comparison > 0
	})
	return versions[0], nil
}
