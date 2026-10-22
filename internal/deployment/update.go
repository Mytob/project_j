package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Mytob/project_j/internal/auth"
	"github.com/Mytob/project_j/internal/monitoring"
	"github.com/Mytob/project_j/internal/release"
)

// UpdateOptions describe a package update and contain test seams for the host
// facts, command runner, and readiness checks.
type UpdateOptions struct {
	PackagePath            string
	PackageSHA256          string
	InstallRoot            string
	BackupPath             string
	Host                   HostFacts
	Runner                 CommandRunner
	WaitInterval           time.Duration
	WaitAttempts           int
	HTTPSCheck             func(context.Context, string) error
	ConfigureHostServices  bool
	SystemdUnitDir         string
	BackupDirectory        string
	ProxyctlDirectory      string
	ProxyctlStateDirectory string
	MaintenanceUpdated     func()
	Progress               func(UpdateProgress)
}

// UpdateProgress reports completion of an updater milestone. Percentage is
// derived from completed milestones; it is not a byte-level estimate for
// Docker or network operations.
type UpdateProgress struct {
	Step    int
	Total   int
	Message string
	Done    bool
}

// Update installs a verified release over an existing deployment while
// preserving operator-owned data and restoring the previous release if the
// new one fails its health or HTTPS checks.
func Update(ctx context.Context, options UpdateOptions) (manifest release.Manifest, resultErr error) {
	if options.PackageSHA256 == "" {
		return manifest, errors.New("an independently supplied package SHA-256 is required")
	}
	const updateSteps = 8
	progress := func(step int, done bool, message string) {
		if options.Progress != nil {
			options.Progress(UpdateProgress{Step: step, Total: updateSteps, Message: message, Done: done})
		}
	}
	progress(1, false, "Checking the current installation")
	if err := ValidateHost(options.Host); err != nil {
		return manifest, err
	}
	if options.InstallRoot == "" {
		options.InstallRoot = DefaultInstallRoot
	}
	if !filepath.IsAbs(options.InstallRoot) {
		return manifest, errors.New("installation root must be an absolute path")
	}
	if options.Runner == nil {
		options.Runner = ExecRunner{}
	}
	if err := validateUpdateRoot(options.InstallRoot); err != nil {
		return manifest, err
	}
	if _, err := RecoverInterruptedUpdate(ctx, UpdateRecoveryOptions{
		InstallRoot: options.InstallRoot, Runner: options.Runner, WaitInterval: options.WaitInterval,
		WaitAttempts: options.WaitAttempts, ConfigureHostServices: options.ConfigureHostServices,
		SystemdUnitDir: options.SystemdUnitDir, BackupDirectory: options.BackupDirectory,
		MaintenanceUpdated: options.MaintenanceUpdated,
	}); err != nil {
		return manifest, fmt.Errorf("recover interrupted update before proceeding: %w", err)
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
	current, err := readCurrentRelease(options.InstallRoot)
	if err != nil {
		return manifest, err
	}
	if _, err := auth.LoadCredential(filepath.Join(options.InstallRoot, "config", "admin.json")); err != nil {
		return manifest, fmt.Errorf("validate retained administrator credential: %w", err)
	}
	composeStatus, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "ps", "--format", "json")...)
	if err != nil || !composeServicesHealthy(composeStatus) {
		return manifest, errors.New("the existing Jellyfin Proxy deployment is not healthy; restore it before updating")
	}
	progress(1, true, "Current installation is healthy")

	progress(2, false, "Verifying the release package and version")
	stageRoot, err := os.MkdirTemp(filepath.Join(options.InstallRoot, "releases"), ".update-")
	if err != nil {
		return manifest, fmt.Errorf("create update staging directory: %w", err)
	}
	defer os.RemoveAll(stageRoot)
	packageDir := filepath.Join(stageRoot, "package")
	manifest, err = release.ExtractAndValidate(options.PackagePath, packageDir, options.PackageSHA256)
	if err != nil {
		return manifest, err
	}
	if err := validateProxyctlMinimum(manifest); err != nil {
		return manifest, err
	}
	if err := validatePackagePortAndVersion(manifest, 51820); err != nil {
		return manifest, err
	}
	versionOrder, err := release.CompareVersions(manifest.Version, current.Version)
	if err != nil {
		return manifest, fmt.Errorf("compare release versions: %w", err)
	}
	if versionOrder == 0 {
		return manifest, errors.New("release version is already active")
	}
	if versionOrder < 0 {
		return manifest, fmt.Errorf("refusing downgrade from %s to older release %s", current.Version, manifest.Version)
	}
	if !supportsUpgradeFrom(manifest, current.Version) {
		return manifest, fmt.Errorf("release %s does not support updating from %s", manifest.Version, current.Version)
	}
	databaseSchema, err := monitoring.HistoryDatabaseSchema(filepath.Join(options.InstallRoot, "data", "statistics", "statistics.db"))
	if err != nil {
		return manifest, fmt.Errorf("inspect the current statistics database before updating: %w", err)
	}
	if databaseSchema < current.DatabaseSchemaMinimum || databaseSchema > current.DatabaseSchemaMaximum {
		return manifest, fmt.Errorf("current release %s does not support the installed database schema %d", current.Version, databaseSchema)
	}
	if databaseSchema < manifest.DatabaseSchemaMinimum || databaseSchema > manifest.DatabaseSchemaMaximum {
		return manifest, fmt.Errorf("release %s does not support the installed database schema %d (supports %d-%d)", manifest.Version, databaseSchema, manifest.DatabaseSchemaMinimum, manifest.DatabaseSchemaMaximum)
	}
	if err := ensureTOTPStorage(options.InstallRoot); err != nil {
		return manifest, fmt.Errorf("validate or initialize persistent TOTP storage: %w", err)
	}
	if err := ensureWireGuardClientConfigDirectory(options.InstallRoot); err != nil {
		return manifest, fmt.Errorf("prepare one-time Windows configuration storage: %w", err)
	}
	if err := initializeWebContentStore(filepath.Join(options.InstallRoot, "data", "site-content"), filepath.Join(options.InstallRoot, "site")); err != nil {
		return manifest, fmt.Errorf("prepare persistent public website before update: %w", err)
	}
	backupPath, _, err := CreateBackup(options.InstallRoot, options.BackupPath)
	if err != nil {
		return manifest, fmt.Errorf("mandatory pre-update backup failed; update was not applied: %w", err)
	}
	progress(2, true, "Release verified and pre-update backup created at "+backupPath)
	id, transactionStage, err := newUpdateStage(options.InstallRoot)
	if err != nil {
		return manifest, err
	}
	if err := snapshotUpdateFiles(options.InstallRoot, transactionStage); err != nil {
		_ = os.RemoveAll(filepath.Join(options.InstallRoot, transactionStage))
		return manifest, err
	}
	transaction := updateJournal{
		Format: 1, ID: id, PreviousVersion: current.Version, TargetVersion: manifest.Version,
		Stage: transactionStage, State: "prepared", BackupPath: backupPath,
	}
	if err := writeUpdateJournal(options.InstallRoot, transaction); err != nil {
		_ = os.RemoveAll(filepath.Join(options.InstallRoot, transactionStage))
		return manifest, fmt.Errorf("persist update recovery journal: %w", err)
	}
	progress(3, false, "Retaining the verified release files")
	finalRelease := filepath.Join(options.InstallRoot, "releases", manifest.Version)
	createdRelease := false
	changed := false
	composeMayBeRunning := false
	transactionActive := true
	paths := updateRecoveryFiles
	previous := make(map[string][]byte, len(paths))
	var environment activeEnvironment
	if _, err := os.Lstat(finalRelease); err == nil {
		stored, readErr := readReleaseManifest(finalRelease)
		if readErr != nil || !sameManifest(stored, manifest) {
			return manifest, errors.New("a different package with this release version is already retained")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return manifest, fmt.Errorf("inspect retained release directory: %w", err)
	} else if err := os.Rename(packageDir, finalRelease); err != nil {
		return manifest, fmt.Errorf("retain verified update package: %w", err)
	} else {
		createdRelease = true
	}
	transaction.ReleaseCreated = createdRelease
	if err := writeUpdateJournal(options.InstallRoot, transaction); err != nil {
		return manifest, fmt.Errorf("record retained update release in recovery journal: %w", err)
	}
	progress(3, true, "Release files retained")
	defer func() {
		if !transactionActive {
			return
		}
		if resultErr == nil {
			return
		}
		if !changed && !composeMayBeRunning {
			if createdRelease {
				_ = os.RemoveAll(finalRelease)
			}
			if cleanupErr := removeUpdateJournal(options.InstallRoot, transaction); cleanupErr != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("remove unused update recovery journal: %w", cleanupErr))
			} else {
				transactionActive = false
			}
			return
		}
		progress(7, false, "Restoring the previous release after update failure")
		transaction.State = "rolling-back"
		var restoreErrors []string
		if err := writeUpdateJournal(options.InstallRoot, transaction); err != nil {
			restoreErrors = append(restoreErrors, fmt.Sprintf("persist rollback stage: %v", err))
		}
		for _, relative := range paths {
			mode := os.FileMode(0o644)
			if relative == ".env" {
				mode = 0o640
			}
			if err := replaceUpdateFileDurable(filepath.Join(options.InstallRoot, relative), previous[relative], mode); err != nil {
				restoreErrors = append(restoreErrors, fmt.Sprintf("restore %s: %v", relative, err))
			}
		}
		if options.ConfigureHostServices {
			if err := configureHostMaintenanceForOperation(context.Background(), options.InstallRoot, current.Version, options.SystemdUnitDir, options.BackupDirectory, options.Runner, options.MaintenanceUpdated); err != nil {
				restoreErrors = append(restoreErrors, fmt.Sprintf("restore previous maintenance service: %v", err))
			}
			if err := ConfigureAutomaticBackups(context.Background(), options.InstallRoot, current.Version, environment.BackupSchedule, environment.BackupRetentionDays, options.SystemdUnitDir, options.BackupDirectory, options.Runner); err != nil {
				restoreErrors = append(restoreErrors, fmt.Sprintf("restore previous automatic backup service: %v", err))
			}
		}
		if composeMayBeRunning {
			if _, err := options.Runner.Run(context.Background(), "docker", composeArgs(options.InstallRoot, "up", "--detach", "--force-recreate", "--pull", "never")...); err != nil {
				restoreErrors = append(restoreErrors, fmt.Sprintf("restart previous release: %v", err))
			} else if err := waitForReadiness(context.Background(), InstallOptions{InstallRoot: options.InstallRoot, Runner: options.Runner, WaitInterval: options.WaitInterval, WaitAttempts: options.WaitAttempts}); err != nil {
				restoreErrors = append(restoreErrors, fmt.Sprintf("previous release readiness: %v", err))
			}
		}
		if len(restoreErrors) > 0 {
			resultErr = fmt.Errorf("%w; automatic rollback encountered errors: %s; recovery journal and backup were retained", resultErr, strings.Join(restoreErrors, "; "))
			return
		}
		if createdRelease {
			if err := os.RemoveAll(finalRelease); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("remove failed update release; recovery journal retained: %w", err))
				return
			}
		}
		if err := removeUpdateJournal(options.InstallRoot, transaction); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("finish rollback cleanup; recovery journal retained: %w", err))
			return
		}
		transactionActive = false
	}()

	progress(4, false, "Loading the bundled Docker images; this can take a few minutes")
	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "config", "--quiet")...); err != nil {
		return manifest, fmt.Errorf("validate current Compose configuration: %w", err)
	}
	imagesPath := filepath.Join(finalRelease, "images.tar")
	if _, err := options.Runner.Run(ctx, "docker", "image", "load", "--input", imagesPath); err != nil {
		return manifest, fmt.Errorf("load bundled update images: %w", err)
	}
	if err := verifyLoadedImages(ctx, options.Runner, manifest.Images); err != nil {
		return manifest, fmt.Errorf("verify bundled update images (%s): %w", imageReferences(manifest.Images), err)
	}
	progress(4, true, "Bundled Docker images loaded")

	progress(5, false, "Preparing configuration while preserving deployment data")
	for _, relative := range paths {
		data, err := os.ReadFile(filepath.Join(options.InstallRoot, relative))
		if err != nil {
			return manifest, fmt.Errorf("read active %s: %w", relative, err)
		}
		previous[relative] = data
	}
	environment, err = readEnvironment(previous[".env"])
	if err != nil {
		return manifest, err
	}
	if environment.Version != current.Version {
		return manifest, errors.New("active release metadata changed while update was being prepared")
	}
	newEnvironment := fmt.Sprintf("BASE_DOMAIN=%s\nRELEASE_VERSION=%s\nWIREGUARD_PORT=%d\nSYSTEMD_JOURNAL_GID=%s\nBACKUP_SCHEDULE=%s\nBACKUP_RETENTION_DAYS=%d\n", environment.Domain, manifest.Version, environment.WireGuardPort, environment.JournalGID, environment.BackupSchedule, environment.BackupRetentionDays)
	progress(5, true, "Existing configuration captured")
	progress(6, false, "Activating the new release files")
	transaction.State = "stopping"
	if err := writeUpdateJournal(options.InstallRoot, transaction); err != nil {
		return manifest, fmt.Errorf("persist update stop stage: %w", err)
	}
	changed = true
	composeMayBeRunning = true
	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "stop")...); err != nil {
		return manifest, fmt.Errorf("stop application stack for update: %w", err)
	}
	transaction.State = "replacing"
	if err := writeUpdateJournal(options.InstallRoot, transaction); err != nil {
		return manifest, fmt.Errorf("persist update activation stage: %w", err)
	}
	for _, file := range []struct {
		relative string
		content  []byte
		mode     os.FileMode
	}{
		{relative: ".env", content: []byte(newEnvironment), mode: 0o640},
		{relative: "compose.yaml", content: mustRead(filepath.Join(finalRelease, "compose.yaml")), mode: 0o644},
		{relative: filepath.Join("config", "Caddyfile"), content: mustRead(filepath.Join(finalRelease, "config", "Caddyfile")), mode: 0o644},
	} {
		if file.content == nil {
			return manifest, errors.New("verified release template is unavailable")
		}
		if err := replaceUpdateFileDurable(filepath.Join(options.InstallRoot, file.relative), file.content, file.mode); err != nil {
			return manifest, fmt.Errorf("activate release file %s: %w", file.relative, err)
		}
		changed = true
	}
	if options.ConfigureHostServices {
		if err := configureHostMaintenanceForOperation(ctx, options.InstallRoot, manifest.Version, options.SystemdUnitDir, options.BackupDirectory, options.Runner, options.MaintenanceUpdated); err != nil {
			return manifest, fmt.Errorf("prepare restricted maintenance service for updated release: %w", err)
		}
	}
	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "config", "--quiet")...); err != nil {
		return manifest, fmt.Errorf("validate updated Compose configuration: %w", err)
	}
	progress(6, true, "Updated configuration validated")
	progress(7, false, "Restarting services and waiting for health checks")
	transaction.State = "starting"
	if err := writeUpdateJournal(options.InstallRoot, transaction); err != nil {
		return manifest, fmt.Errorf("persist update start stage: %w", err)
	}
	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "up", "--detach", "--force-recreate", "--pull", "never")...); err != nil {
		return manifest, fmt.Errorf("start updated Jellyfin Proxy services: %w", err)
	}
	transaction.State = "verifying"
	if err := writeUpdateJournal(options.InstallRoot, transaction); err != nil {
		return manifest, fmt.Errorf("persist update verification stage: %w", err)
	}
	if err := waitForReadiness(ctx, InstallOptions{InstallRoot: options.InstallRoot, Runner: options.Runner, WaitInterval: options.WaitInterval, WaitAttempts: options.WaitAttempts}); err != nil {
		return manifest, fmt.Errorf("updated services did not become healthy; the previous release was restored: %w", err)
	}
	progress(7, true, "Updated services are healthy")
	progress(8, false, "Checking public HTTPS and retaining the active release")
	if options.HTTPSCheck == nil {
		options.HTTPSCheck = checkPublicHTTPS
	}
	if err := waitForHTTPS(ctx, environment.Domain, options.WaitInterval, options.WaitAttempts, options.HTTPSCheck); err != nil {
		return manifest, fmt.Errorf("updated release public HTTPS check failed; the previous release was restored: %w", err)
	}
	if options.ConfigureHostServices {
		if err := configureHostMaintenanceForOperation(ctx, options.InstallRoot, manifest.Version, options.SystemdUnitDir, options.BackupDirectory, options.Runner, options.MaintenanceUpdated); err != nil {
			return manifest, fmt.Errorf("update restricted maintenance service: %w", err)
		}
		if err := ConfigureAutomaticBackups(ctx, options.InstallRoot, manifest.Version, environment.BackupSchedule, environment.BackupRetentionDays, options.SystemdUnitDir, options.BackupDirectory, options.Runner); err != nil {
			return manifest, fmt.Errorf("update automatic backup service: %w", err)
		}
		if err := InstallPersistentProxyctl(options.InstallRoot, manifest.Version, options.ProxyctlDirectory, options.ProxyctlStateDirectory); err != nil {
			return manifest, fmt.Errorf("update persistent proxyctl utility: %w", err)
		}
		proxyctlDirectory := options.ProxyctlDirectory
		if proxyctlDirectory == "" {
			proxyctlDirectory = defaultProxyctlDir
		}
		args := []string{"sync-host-services"}
		if options.MaintenanceUpdated != nil {
			args = append(args, "--defer-maintenance-restart")
		}
		if _, err := options.Runner.Run(ctx, filepath.Join(proxyctlDirectory, "proxyctl"), args...); err != nil {
			return manifest, fmt.Errorf("refresh host service units with the updated proxyctl utility: %w", err)
		}
	}
	if err := retainActiveAndPrevious(options.InstallRoot, manifest.Version, current.Version); err != nil {
		return manifest, fmt.Errorf("update succeeded, but release retention cleanup failed: %w", err)
	}
	transaction.State = "committing"
	if err := writeUpdateJournal(options.InstallRoot, transaction); err != nil {
		return manifest, fmt.Errorf("updated services are healthy, but the final transaction state could not be saved: %w", err)
	}
	changed = false
	composeMayBeRunning = false
	if err := removeUpdateJournal(options.InstallRoot, transaction); err != nil {
		transactionActive = false
		return manifest, fmt.Errorf("update is healthy, but recovery-journal cleanup failed; run proxyctl repair: %w", err)
	}
	transactionActive = false
	progress(8, true, "Update completed successfully")
	return manifest, nil
}

// ensureWireGuardClientConfigDirectory restores the ownership and permissions
// required for the unprivileged admin service to consume a downloaded config.
// Older deployments may have created this bind-mounted directory as root:root.
func ensureWireGuardClientConfigDirectory(installRoot string) error {
	path := filepath.Join(installRoot, "data", "wireguard-client")
	if err := os.MkdirAll(path, 0o2770); err != nil {
		return err
	}
	if err := os.Chown(path, 0, adminContainerUID); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o2770); err != nil {
		return err
	}
	return nil
}

// ResetPassword replaces the local administrator password and recreates only
// the admin container. Sessions are in-memory, so its restart invalidates all
// existing sessions without touching the other services or persistent data.
func ResetPassword(ctx context.Context, installRoot, password string, runner CommandRunner) error {
	if installRoot == "" {
		installRoot = DefaultInstallRoot
	}
	if !filepath.IsAbs(installRoot) {
		return errors.New("installation root must be an absolute path")
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	if err := validateInstalledLayout(installRoot); err != nil {
		return err
	}
	credentialPath, err := activeCredentialPath(installRoot)
	if err != nil {
		return err
	}
	old, err := os.ReadFile(credentialPath)
	if err != nil {
		return fmt.Errorf("read current administrator credential: %w", err)
	}
	if _, err := auth.LoadCredential(credentialPath); err != nil {
		return fmt.Errorf("validate current administrator credential: %w", err)
	}
	if _, err := runner.Run(ctx, "docker", composeArgs(installRoot, "ps", "--format", "json")...); err != nil {
		return fmt.Errorf("check admin deployment: %w", err)
	}
	if err := auth.SaveCredential(credentialPath, password); err != nil {
		return fmt.Errorf("save new administrator password: %w", err)
	}
	if err := os.Chown(credentialPath, 0, adminContainerUID); err != nil {
		_ = atomicReplace(credentialPath, old, 0o640)
		_ = os.Chown(credentialPath, 0, adminContainerUID)
		return fmt.Errorf("set administrator credential ownership: %w", err)
	}
	if err := os.Chmod(credentialPath, 0o640); err != nil {
		_ = atomicReplace(credentialPath, old, 0o640)
		_ = os.Chown(credentialPath, 0, adminContainerUID)
		return fmt.Errorf("set administrator credential permissions: %w", err)
	}
	if _, err := runner.Run(ctx, "docker", composeArgs(installRoot, "up", "--detach", "--no-deps", "--force-recreate", "--pull", "never", "admin")...); err != nil {
		rollbackCredential(credentialPath, old)
		_, _ = runner.Run(context.Background(), "docker", composeArgs(installRoot, "up", "--detach", "--no-deps", "--force-recreate", "--pull", "never", "admin")...)
		return fmt.Errorf("restart admin with the new credential: %w", err)
	}
	if err := waitForReadiness(ctx, InstallOptions{InstallRoot: installRoot, Runner: runner, WaitInterval: time.Second, WaitAttempts: 90}); err != nil {
		rollbackCredential(credentialPath, old)
		_, _ = runner.Run(context.Background(), "docker", composeArgs(installRoot, "up", "--detach", "--no-deps", "--force-recreate", "--pull", "never", "admin")...)
		return fmt.Errorf("admin did not become healthy after password reset; the previous credential was restored: %w", err)
	}
	return nil
}

// TOTPRecoveryAction identifies a local privileged TOTP state transition.
type TOTPRecoveryAction string

const (
	TOTPReset   TOTPRecoveryAction = "reset"
	TOTPDisable TOTPRecoveryAction = "disable"
	TOTPReplace TOTPRecoveryAction = "replace"
)

// RecoverTOTP changes the persistent authenticator state and recreates only
// the admin service. On any failure after the transition, it restores the
// original state file and restarts the previous admin service.
func RecoverTOTP(ctx context.Context, installRoot string, action TOTPRecoveryAction, runner CommandRunner) (resultErr error) {
	if installRoot == "" {
		installRoot = DefaultInstallRoot
	}
	if !filepath.IsAbs(installRoot) {
		return errors.New("installation root must be an absolute path")
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	if action != TOTPReset && action != TOTPDisable && action != TOTPReplace {
		return errors.New("unknown TOTP recovery action")
	}
	if err := validateInstalledLayout(installRoot); err != nil {
		return err
	}
	statePath := filepath.Join(installRoot, "data", "totp-state.json")
	stateInfo, err := os.Lstat(statePath)
	if err != nil || stateInfo.Mode()&os.ModeSymlink != 0 || !stateInfo.Mode().IsRegular() {
		return errors.New("TOTP state file is missing or unsafe")
	}
	previous, err := os.ReadFile(statePath)
	if err != nil {
		return fmt.Errorf("read current TOTP state: %w", err)
	}
	key, err := auth.LoadTOTPKey(filepath.Join(installRoot, "config", "totp.key"))
	if err != nil {
		return fmt.Errorf("validate TOTP storage key: %w", err)
	}
	defer clear(key)
	store, err := auth.NewTOTPStore(statePath, key)
	if err != nil {
		return fmt.Errorf("validate current TOTP state: %w", err)
	}
	if action == TOTPReplace && store.Status() != auth.TOTPEnabled {
		return errors.New("replace-totp requires an enabled authenticator; use reset-totp for recovery")
	}
	composeStatus, err := runner.Run(ctx, "docker", composeArgs(installRoot, "ps", "--format", "json")...)
	if err != nil || !composeServicesHealthy(composeStatus) {
		return errors.New("the existing Jellyfin Proxy deployment is not healthy; restore it before changing TOTP")
	}
	if _, err := runner.Run(ctx, "docker", composeArgs(installRoot, "stop", "admin")...); err != nil {
		if _, restartErr := runner.Run(context.Background(), "docker", composeArgs(installRoot, "up", "--detach", "--no-deps", "--force-recreate", "--pull", "never", "admin")...); restartErr != nil {
			return fmt.Errorf("stop admin before changing TOTP: %w; admin restart also failed: %v", err, restartErr)
		}
		return fmt.Errorf("stop admin before changing TOTP: %w", err)
	}
	changed := false
	rollback := func() error {
		var failures []string
		if changed {
			if err := atomicReplace(statePath, previous, 0o600); err != nil {
				failures = append(failures, "restore TOTP state: "+err.Error())
			} else if err := os.Chown(statePath, adminContainerUID, adminContainerUID); err != nil {
				failures = append(failures, "restore TOTP state ownership: "+err.Error())
			}
		}
		if _, err := runner.Run(context.Background(), "docker", composeArgs(installRoot, "up", "--detach", "--no-deps", "--force-recreate", "--pull", "never", "admin")...); err != nil {
			failures = append(failures, "restart admin: "+err.Error())
		} else if err := waitForReadiness(context.Background(), InstallOptions{InstallRoot: installRoot, Runner: runner, WaitInterval: time.Second, WaitAttempts: 90}); err != nil {
			failures = append(failures, "admin readiness: "+err.Error())
		}
		if len(failures) != 0 {
			return errors.New(strings.Join(failures, "; "))
		}
		return nil
	}
	defer func() {
		if resultErr == nil {
			return
		}
		if rollbackErr := rollback(); rollbackErr != nil {
			resultErr = fmt.Errorf("%w; recovery rollback failed: %v", resultErr, rollbackErr)
		}
	}()
	switch action {
	case TOTPReset, TOTPReplace:
		if err := store.RequireFreshEnrollment(); err != nil {
			return fmt.Errorf("require fresh authenticator enrollment: %w", err)
		}
	case TOTPDisable:
		if err := store.Disable(); err != nil {
			return fmt.Errorf("disable authenticator: %w", err)
		}
	}
	changed = true
	if err := os.Chown(statePath, adminContainerUID, adminContainerUID); err != nil {
		return fmt.Errorf("set TOTP state ownership: %w", err)
	}
	if err := os.Chmod(statePath, 0o600); err != nil {
		return fmt.Errorf("set TOTP state permissions: %w", err)
	}
	if _, err := runner.Run(ctx, "docker", composeArgs(installRoot, "up", "--detach", "--no-deps", "--force-recreate", "--pull", "never", "admin")...); err != nil {
		return fmt.Errorf("restart admin with the updated authenticator state: %w", err)
	}
	if err := waitForReadiness(ctx, InstallOptions{InstallRoot: installRoot, Runner: runner, WaitInterval: time.Second, WaitAttempts: 90}); err != nil {
		return fmt.Errorf("admin did not become healthy after TOTP recovery: %w", err)
	}
	return nil
}

type activeEnvironment struct {
	Domain              string
	Version             string
	WireGuardPort       uint16
	JournalGID          string
	BackupSchedule      string
	BackupRetentionDays int
}

func readEnvironment(data []byte) (activeEnvironment, error) {
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || (key != "BASE_DOMAIN" && key != "RELEASE_VERSION" && key != "WIREGUARD_PORT" && key != "SYSTEMD_JOURNAL_GID" && key != "BACKUP_SCHEDULE" && key != "BACKUP_RETENTION_DAYS") || values[key] != "" {
			return activeEnvironment{}, errors.New("active deployment environment is invalid")
		}
		values[key] = value
	}
	domain, err := ValidateDomain(values["BASE_DOMAIN"])
	if err != nil {
		return activeEnvironment{}, errors.New("active deployment base domain is invalid")
	}
	port, err := strconv.ParseUint(values["WIREGUARD_PORT"], 10, 16)
	if err != nil || port == 0 || !release.ValidVersion(values["RELEASE_VERSION"]) {
		return activeEnvironment{}, errors.New("active deployment version or WireGuard port is invalid")
	}
	journalGID := values["SYSTEMD_JOURNAL_GID"]
	if journalGID == "" {
		journalGID = systemdJournalGroupID()
	}
	if _, err := strconv.ParseUint(journalGID, 10, 32); err != nil {
		return activeEnvironment{}, errors.New("deployment environment systemd journal group ID is invalid")
	}
	backupSchedule := values["BACKUP_SCHEDULE"]
	if backupSchedule == "" {
		backupSchedule = "daily"
	}
	if backupSchedule != "daily" && backupSchedule != "weekly" {
		return activeEnvironment{}, errors.New("deployment environment backup schedule is invalid")
	}
	backupRetention := uint64(30)
	if values["BACKUP_RETENTION_DAYS"] != "" {
		backupRetention, err = strconv.ParseUint(values["BACKUP_RETENTION_DAYS"], 10, 8)
		if err != nil || (backupRetention != 7 && backupRetention != 14 && backupRetention != 30) {
			return activeEnvironment{}, errors.New("deployment environment backup retention is invalid")
		}
	}
	return activeEnvironment{Domain: domain, Version: values["RELEASE_VERSION"], WireGuardPort: uint16(port), JournalGID: journalGID, BackupSchedule: backupSchedule, BackupRetentionDays: int(backupRetention)}, nil
}

func validateInstalledLayout(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspect existing installation: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("installation root is not a real directory")
	}
	for _, relative := range []string{"config", "data", "site", "releases"} {
		info, err := os.Lstat(filepath.Join(root, relative))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("installation directory %s is missing or unsafe", relative)
		}
	}
	for _, relative := range []string{".env", "compose.yaml", filepath.Join("config", "Caddyfile"), filepath.Join("config", "admin.json")} {
		info, err := os.Lstat(filepath.Join(root, relative))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("installation file %s is missing or unsafe", relative)
		}
	}
	credentialPath, err := activeCredentialPath(root)
	if err != nil {
		return err
	}
	if _, err := auth.LoadCredential(credentialPath); err != nil {
		return fmt.Errorf("validate active administrator credential: %w", err)
	}
	return nil
}

func readCurrentRelease(root string) (release.Manifest, error) {
	environmentBytes, err := os.ReadFile(filepath.Join(root, ".env"))
	if err != nil {
		return release.Manifest{}, err
	}
	environment, err := readEnvironment(environmentBytes)
	if err != nil {
		return release.Manifest{}, err
	}
	manifest, err := readReleaseManifest(filepath.Join(root, "releases", environment.Version))
	if err != nil {
		return release.Manifest{}, fmt.Errorf("validate active release metadata: %w", err)
	}
	if manifest.Version != environment.Version || manifest.Platform != "linux/amd64" {
		return release.Manifest{}, errors.New("active release metadata is incompatible with this installer")
	}
	if err := validatePackagePortAndVersion(manifest, 51820); err != nil {
		return release.Manifest{}, err
	}
	return manifest, nil
}

func readReleaseManifest(directory string) (release.Manifest, error) {
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return release.Manifest{}, errors.New("release directory is missing or unsafe")
	}
	path := filepath.Join(directory, "manifest.json")
	info, err = os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return release.Manifest{}, errors.New("release manifest is missing or unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return release.Manifest{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 4<<20))
	decoder.DisallowUnknownFields()
	var manifest release.Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return release.Manifest{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return release.Manifest{}, errors.New("release manifest contains trailing data")
	}
	if err := release.ValidateManifest(manifest); err != nil {
		return release.Manifest{}, fmt.Errorf("release manifest is invalid: %w", err)
	}
	return manifest, nil
}

func supportsUpgradeFrom(manifest release.Manifest, version string) bool {
	for _, supported := range manifest.SupportedUpgradeSources {
		if supported == version {
			return true
		}
	}
	return false
}

func validateProxyctlMinimum(manifest release.Manifest) error {
	comparison, err := release.CompareVersions(proxyctlVersion, manifest.MinimumProxyctlVersion)
	if err != nil {
		return fmt.Errorf("compare proxyctl version requirement: %w", err)
	}
	if comparison < 0 {
		return fmt.Errorf("package requires proxyctl %s or newer; installed version is %s", manifest.MinimumProxyctlVersion, proxyctlVersion)
	}
	return nil
}

func sameManifest(left, right release.Manifest) bool {
	leftData, leftErr := json.Marshal(left)
	rightData, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftData) == string(rightData)
}

func mustRead(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

func atomicReplace(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".jellyfin-proxy-update-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func waitForHTTPS(ctx context.Context, domain string, interval time.Duration, attempts int, check func(context.Context, string) error) error {
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := check(ctx, domain); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("public HTTPS readiness check cancelled: %w", ctx.Err())
		case <-time.After(interval):
		}
	}
	return fmt.Errorf("public HTTPS did not become ready: %w", lastErr)
}

func retainActiveAndPrevious(root, active, previous string) error {
	directory := filepath.Join(root, "releases")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == active || name == previous || strings.HasPrefix(name, ".") || !release.ValidVersion(name) {
			continue
		}
		if !entry.IsDir() {
			return fmt.Errorf("unexpected non-directory release artifact %s", name)
		}
		if err := os.RemoveAll(filepath.Join(directory, name)); err != nil {
			return fmt.Errorf("remove old release %s: %w", name, err)
		}
	}
	return nil
}

func rollbackCredential(path string, old []byte) {
	if atomicReplace(path, old, 0o640) == nil {
		_ = os.Chown(path, 0, adminContainerUID)
	}
}

// activeCredentialPath prefers the mutable admin-data credential created by
// the web password-change flow, and otherwise keeps the original config file
// as the source for older installations.
func activeCredentialPath(installRoot string) (string, error) {
	override := filepath.Join(installRoot, "data", "admin-credential.json")
	info, err := os.Lstat(override)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", errors.New("administrator credential override is unsafe")
		}
		return override, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect administrator credential override: %w", err)
	}
	return filepath.Join(installRoot, "config", "admin.json"), nil
}
