package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mytob/project_j/internal/release"
)

const updateJournalName = ".update-transaction.json"

var updateRecoveryFiles = []string{".env", "compose.yaml", filepath.Join("config", "Caddyfile")}

type updateJournal struct {
	Format          int    `json:"format"`
	ID              string `json:"id"`
	PreviousVersion string `json:"previous_version"`
	TargetVersion   string `json:"target_version"`
	Stage           string `json:"stage"`
	State           string `json:"state"`
	BackupPath      string `json:"backup_path"`
	ReleaseCreated  bool   `json:"release_created"`
}

// UpdateRecoveryOptions carries only fixed host configuration needed to
// restore a transaction. It does not accept commands or arbitrary paths.
type UpdateRecoveryOptions struct {
	InstallRoot           string
	Runner                CommandRunner
	WaitInterval          time.Duration
	WaitAttempts          int
	ConfigureHostServices bool
	SystemdUnitDir        string
	BackupDirectory       string
	MaintenanceUpdated    func()
}

func updateJournalPath(root string) string { return filepath.Join(root, updateJournalName) }

func validateUpdateRoot(root string) error {
	if root == "" {
		root = DefaultInstallRoot
	}
	if !filepath.IsAbs(root) {
		return errors.New("installation root must be an absolute path")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("installation root is missing or unsafe")
	}
	return nil
}

func newUpdateStage(root string) (string, string, error) {
	id, err := newInstallID()
	if err != nil {
		return "", "", fmt.Errorf("create update transaction ID: %w", err)
	}
	name := ".update-" + id
	stage := filepath.Join(root, name)
	if err := os.Mkdir(stage, 0o700); err != nil {
		return "", "", fmt.Errorf("create private update recovery directory: %w", err)
	}
	previous := filepath.Join(stage, "previous")
	if err := os.Mkdir(previous, 0o700); err != nil {
		_ = os.RemoveAll(stage)
		return "", "", fmt.Errorf("create update snapshot directory: %w", err)
	}
	if err := syncDirectory(stage); err != nil {
		_ = os.RemoveAll(stage)
		return "", "", err
	}
	if err := syncDirectory(root); err != nil {
		_ = os.RemoveAll(stage)
		return "", "", err
	}
	return id, name, nil
}

func snapshotUpdateFiles(root, stage string) error {
	previous := filepath.Join(root, stage, "previous")
	for _, relative := range updateRecoveryFiles {
		data, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			return fmt.Errorf("read pre-update %s: %w", relative, err)
		}
		mode := os.FileMode(0o644)
		if relative == ".env" {
			mode = 0o640
		}
		if err := writeSyncedFile(filepath.Join(previous, filepath.Base(relative)), data, mode); err != nil {
			return fmt.Errorf("save pre-update %s: %w", relative, err)
		}
	}
	if err := syncDirectory(previous); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(previous))
}

func replaceUpdateFileDurable(path string, data []byte, mode os.FileMode) error {
	if err := atomicReplace(path, data, mode); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func writeSyncedFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func writeUpdateJournal(root string, journal updateJournal) error {
	if err := validateUpdateJournal(journal); err != nil {
		return err
	}
	data, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	if err := atomicReplace(updateJournalPath(root), data, 0o600); err != nil {
		return err
	}
	return syncDirectory(root)
}

func readUpdateJournal(root string) (updateJournal, error) {
	path := updateJournalPath(root)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return updateJournal{}, err
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() > 16<<10 {
		return updateJournal{}, errors.New("update transaction journal is missing or unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return updateJournal{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 16<<10))
	decoder.DisallowUnknownFields()
	var journal updateJournal
	if err := decoder.Decode(&journal); err != nil {
		return updateJournal{}, fmt.Errorf("decode update transaction journal: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return updateJournal{}, errors.New("update transaction journal contains trailing data")
	}
	if err := validateUpdateJournal(journal); err != nil {
		return updateJournal{}, err
	}
	return journal, nil
}

func validateUpdateJournal(journal updateJournal) error {
	if journal.Format != 1 || len(journal.ID) != 32 || strings.Trim(journal.ID, "0123456789abcdef") != "" || journal.Stage != ".update-"+journal.ID {
		return errors.New("update transaction journal metadata is invalid")
	}
	if !release.ValidVersion(journal.PreviousVersion) || !release.ValidVersion(journal.TargetVersion) || journal.PreviousVersion == journal.TargetVersion {
		return errors.New("update transaction release versions are invalid")
	}
	switch journal.State {
	case "prepared", "stopping", "replacing", "starting", "verifying", "committing", "rolling-back":
	default:
		return errors.New("update transaction state is invalid")
	}
	if !filepath.IsAbs(journal.BackupPath) || filepath.Ext(journal.BackupPath) != ".bak" {
		return errors.New("update transaction recovery backup reference is invalid")
	}
	return nil
}

func updateSnapshot(root string, journal updateJournal) (map[string][]byte, error) {
	stage := filepath.Join(root, journal.Stage)
	stageInfo, err := os.Lstat(stage)
	if err != nil || !stageInfo.IsDir() || stageInfo.Mode()&os.ModeSymlink != 0 || stageInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("update recovery snapshot directory is missing or unsafe")
	}
	previous := filepath.Join(stage, "previous")
	previousInfo, err := os.Lstat(previous)
	if err != nil || !previousInfo.IsDir() || previousInfo.Mode()&os.ModeSymlink != 0 || previousInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("update recovery snapshot is missing or unsafe")
	}
	files := make(map[string][]byte, len(updateRecoveryFiles))
	for _, relative := range updateRecoveryFiles {
		path := filepath.Join(previous, filepath.Base(relative))
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 4<<20 {
			return nil, fmt.Errorf("update recovery snapshot %s is missing or unsafe", relative)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		files[relative] = data
	}
	return files, nil
}

// RecoverInterruptedUpdate restores the pre-update active configuration after
// an interrupted update. A transaction is removed only after either the
// previous deployment is healthy or a committed target release is confirmed.
func RecoverInterruptedUpdate(ctx context.Context, options UpdateRecoveryOptions) (bool, error) {
	if options.InstallRoot == "" {
		options.InstallRoot = DefaultInstallRoot
	}
	if err := validateUpdateRoot(options.InstallRoot); err != nil {
		return false, err
	}
	journal, err := readUpdateJournal(options.InstallRoot)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
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
	files, err := updateSnapshot(options.InstallRoot, journal)
	if err != nil {
		return false, fmt.Errorf("interrupted update cannot be recovered safely: %w", err)
	}
	previousManifest, err := readReleaseManifest(filepath.Join(options.InstallRoot, "releases", journal.PreviousVersion))
	if err != nil || previousManifest.Version != journal.PreviousVersion {
		return false, errors.New("the previous update release is missing or invalid; recovery journal and backup were retained")
	}
	environment, err := readEnvironment(files[".env"])
	if err != nil || environment.Version != journal.PreviousVersion {
		return false, errors.New("previous update snapshot does not match its release metadata")
	}
	if journal.State == "prepared" {
		if journal.ReleaseCreated {
			active, activeErr := readCurrentRelease(options.InstallRoot)
			if activeErr == nil && active.Version == journal.TargetVersion {
				return false, errors.New("prepared update unexpectedly activated the target release; recovery journal retained")
			}
			if err := os.RemoveAll(filepath.Join(options.InstallRoot, "releases", journal.TargetVersion)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return false, fmt.Errorf("remove unactivated update release: %w", err)
			}
			if err := syncDirectory(filepath.Join(options.InstallRoot, "releases")); err != nil {
				return false, err
			}
		}
		if err := removeUpdateJournal(options.InstallRoot, journal); err != nil {
			return false, err
		}
		return true, nil
	}

	if journal.State == "committing" {
		current, currentErr := readCurrentRelease(options.InstallRoot)
		if currentErr == nil && current.Version == journal.TargetVersion {
			if err := waitForReadiness(ctx, InstallOptions{InstallRoot: options.InstallRoot, Runner: options.Runner, WaitInterval: options.WaitInterval, WaitAttempts: options.WaitAttempts}); err == nil {
				if err := removeUpdateJournal(options.InstallRoot, journal); err != nil {
					return false, err
				}
				return true, nil
			}
		}
	}
	previousRoot := filepath.Join(options.InstallRoot, journal.Stage, "previous")
	if _, err := options.Runner.Run(ctx, "docker", composeArgsWithFiles(
		options.InstallRoot, filepath.Join(previousRoot, "compose.yaml"), filepath.Join(previousRoot, ".env"), "stop",
	)...); err != nil {
		return false, fmt.Errorf("stop the partially updated application before rollback: %w", err)
	}

	if err := writeUpdateJournal(options.InstallRoot, updateJournal{Format: journal.Format, ID: journal.ID, PreviousVersion: journal.PreviousVersion, TargetVersion: journal.TargetVersion, Stage: journal.Stage, State: "rolling-back", BackupPath: journal.BackupPath, ReleaseCreated: journal.ReleaseCreated}); err != nil {
		return false, fmt.Errorf("mark interrupted update for rollback: %w", err)
	}
	for _, relative := range updateRecoveryFiles {
		mode := os.FileMode(0o644)
		if relative == ".env" {
			mode = 0o640
		}
		if err := replaceUpdateFileDurable(filepath.Join(options.InstallRoot, relative), files[relative], mode); err != nil {
			return false, fmt.Errorf("restore previous %s: %w", relative, err)
		}
	}
	if options.ConfigureHostServices {
		if err := configureHostMaintenanceForOperation(ctx, options.InstallRoot, journal.PreviousVersion, options.SystemdUnitDir, options.BackupDirectory, options.Runner, options.MaintenanceUpdated); err != nil {
			return false, fmt.Errorf("restore previous maintenance service: %w", err)
		}
		if err := ConfigureAutomaticBackups(ctx, options.InstallRoot, journal.PreviousVersion, environment.BackupSchedule, environment.BackupRetentionDays, options.SystemdUnitDir, options.BackupDirectory, options.Runner); err != nil {
			return false, fmt.Errorf("restore previous automatic backup service: %w", err)
		}
	}
	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "up", "--detach", "--force-recreate", "--pull", "never")...); err != nil {
		return false, fmt.Errorf("restart previous release after interrupted update: %w", err)
	}
	if err := waitForReadiness(ctx, InstallOptions{InstallRoot: options.InstallRoot, Runner: options.Runner, WaitInterval: options.WaitInterval, WaitAttempts: options.WaitAttempts}); err != nil {
		return false, fmt.Errorf("previous release did not recover after interrupted update: %w", err)
	}
	if journal.ReleaseCreated {
		if err := os.RemoveAll(filepath.Join(options.InstallRoot, "releases", journal.TargetVersion)); err != nil {
			return false, fmt.Errorf("remove failed update release: %w", err)
		}
		if err := syncDirectory(filepath.Join(options.InstallRoot, "releases")); err != nil {
			return false, err
		}
	}
	if err := removeUpdateJournal(options.InstallRoot, journal); err != nil {
		return false, err
	}
	return true, nil
}

func removeUpdateJournal(root string, journal updateJournal) error {
	if err := os.Remove(updateJournalPath(root)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := syncDirectory(root); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Join(root, journal.Stage)); err != nil {
		return fmt.Errorf("remove completed update recovery snapshot: %w", err)
	}
	return syncDirectory(root)
}
