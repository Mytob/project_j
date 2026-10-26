package deployment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mytob/project_j/internal/monitoring"
	"github.com/Mytob/project_j/internal/release"
	"github.com/Mytob/project_j/internal/security"
	"github.com/Mytob/project_j/internal/webcontent"
)

// stageFreshRecoveryBackup validates and extracts only after the release
// package has been validated. The caller owns and removes stageRoot.
func stageFreshRecoveryBackup(stageRoot, archivePath string, releaseManifest release.Manifest) (string, error) {
	if archivePath == "" {
		return "", nil
	}
	manifest, err := ValidateBackup(archivePath)
	if err != nil {
		return "", fmt.Errorf("verify disaster-recovery backup: %w", err)
	}
	baseVersion := strings.SplitN(strings.SplitN(manifest.Version, "+", 2)[0], "-", 2)[0]
	if baseVersion == "1.5.1" {
		return "", errors.New("fresh-host recovery does not migrate v1.5.1 data")
	}
	if manifest.DatabaseSchema < releaseManifest.DatabaseSchemaMinimum || manifest.DatabaseSchema > releaseManifest.DatabaseSchemaMaximum {
		return "", fmt.Errorf("backup database schema %d is outside package compatibility range %d-%d", manifest.DatabaseSchema, releaseManifest.DatabaseSchemaMinimum, releaseManifest.DatabaseSchemaMaximum)
	}
	destination := filepath.Join(stageRoot, "recovery-backup")
	if _, err := ExtractBackup(archivePath, destination); err != nil {
		return "", fmt.Errorf("extract disaster-recovery backup: %w", err)
	}
	statistics := filepath.Join(destination, "data", "statistics.db")
	if _, err := os.Lstat(statistics); err == nil {
		if err := monitoring.ValidateHistoryDatabase(statistics); err != nil {
			return "", fmt.Errorf("verify recovered statistics database: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := validateRecoveryEventSpool(destination); err != nil {
		return "", err
	}
	return destination, nil
}

// restoreFreshHostState imports only host-independent product state. Installer
// generated credentials, TOTP, WireGuard keys, allowlists, host rules, and
// environment files remain fresh for the new VPS.
func restoreFreshHostState(backupRoot, installRoot string) error {
	if backupRoot == "" {
		return nil
	}
	siteSource := filepath.Join(backupRoot, "site")
	siteFiles, err := countRegularFiles(siteSource)
	if err != nil {
		return fmt.Errorf("inspect recovered public site: %w", err)
	}
	if siteFiles > 0 {
		siteDestination := filepath.Join(installRoot, "site")
		info, err := os.Lstat(siteDestination)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("new installation public site directory is missing or unsafe")
		}
		if err := os.RemoveAll(siteDestination); err != nil {
			return fmt.Errorf("replace default site with recovered public content: %w", err)
		}
		if err := os.Mkdir(siteDestination, 0o755); err != nil {
			return fmt.Errorf("create recovered public site directory: %w", err)
		}
		if err := copyTree(siteSource, siteDestination); err != nil {
			return fmt.Errorf("restore public site content: %w", err)
		}
	}
	siteContentSource := filepath.Join(backupRoot, "data", "site-content")
	if _, err := os.Lstat(filepath.Join(siteContentSource, "current")); err == nil {
		if err := webcontent.CopyCurrentTo(siteContentSource, filepath.Join(installRoot, "data", "site-content")); err != nil {
			return fmt.Errorf("restore active public-site revision: %w", err)
		}
	} else if errors.Is(err, os.ErrNotExist) && siteFiles > 0 {
		if err := webcontent.CopyDirectoryTo(siteSource, filepath.Join(installRoot, "data", "site-content")); err != nil {
			return fmt.Errorf("migrate recovered public site: %w", err)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	statisticsSource := filepath.Join(backupRoot, "data", "statistics.db")
	if _, err := os.Lstat(statisticsSource); err == nil {
		statisticsDestination := filepath.Join(installRoot, "data", "statistics.db")
		if err := replaceRecoveryFile(statisticsSource, statisticsDestination, adminContainerUID, adminContainerUID, 0o600); err != nil {
			return fmt.Errorf("restore statistics history: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	keySource := filepath.Join(backupRoot, "config", "security-event-key", "event.key")
	eventsSource := filepath.Join(backupRoot, "data", "security-events")
	if _, err := os.Lstat(keySource); err == nil {
		keyDestination := filepath.Join(installRoot, "config", "security-event-key", "event.key")
		if err := replaceRecoveryFile(keySource, keyDestination, 0, adminContainerUID, 0o440); err != nil {
			return fmt.Errorf("restore security event verification key: %w", err)
		}
		if info, err := os.Lstat(eventsSource); err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("recovered security event directory is unsafe")
			}
			eventsDestination := filepath.Join(installRoot, "data", "security-events")
			if err := os.RemoveAll(eventsDestination); err != nil {
				return fmt.Errorf("replace empty security event directory: %w", err)
			}
			if err := os.Mkdir(eventsDestination, 0o2770); err != nil {
				return fmt.Errorf("create recovered security event directory: %w", err)
			}
			if err := os.Chown(eventsDestination, adminContainerUID, 0); err != nil {
				return fmt.Errorf("set recovered security event directory ownership: %w", err)
			}
			if err := copyRecoveryEvents(eventsSource, eventsDestination); err != nil {
				return fmt.Errorf("restore verified security events: %w", err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func validateRecoveryEventSpool(root string) error {
	events := filepath.Join(root, "data", "security-events")
	count, err := countRecoveryEventFiles(events)
	if err != nil {
		return fmt.Errorf("inspect recovered security events: %w", err)
	}
	keyPath := filepath.Join(root, "config", "security-event-key", "event.key")
	keyInfo, keyErr := os.Lstat(keyPath)
	if keyErr == nil && (!keyInfo.Mode().IsRegular() || keyInfo.Mode()&os.ModeSymlink != 0 || keyInfo.Size() != 32) {
		return errors.New("backup contains an invalid security-event verification key")
	} else if keyErr != nil && !errors.Is(keyErr, os.ErrNotExist) {
		return keyErr
	}
	if count == 0 {
		return nil
	}
	if keyErr != nil {
		return errors.New("backup contains security events without a valid verification key")
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read recovered security event key: %w", err)
	}
	defer clear(key)
	items, rejected, err := security.ReadSpool(events, key)
	if err != nil {
		return fmt.Errorf("verify recovered security event spool: %w", err)
	}
	if len(rejected) != 0 || len(items) != count {
		return errors.New("backup contains invalid or unverifiable security events")
	}
	return nil
}

func countRecoveryEventFiles(directory string) (int, error) {
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, errors.New("security event path must be a real directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return 0, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return 0, errors.New("security event backup contains a non-regular file")
		}
		if entry.Name() == security.EventWriterHealthFilename {
			if info.Size() > 1024 {
				return 0, errors.New("security event writer heartbeat is unexpectedly large")
			}
			continue
		}
		if filepath.Ext(entry.Name()) != ".json" {
			return 0, errors.New("security event backup contains an unsupported file")
		}
		count++
	}
	return count, nil
}

func copyRecoveryEvents(source, destination string) error {
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(source, entry.Name()))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("security event backup contains an unsupported file")
		}
		if entry.Name() == security.EventWriterHealthFilename {
			if info.Size() > 1024 {
				return errors.New("security event writer heartbeat is unexpectedly large")
			}
			continue
		}
		if filepath.Ext(entry.Name()) != ".json" {
			return errors.New("security event backup contains an unsupported file")
		}
		if err := replaceRecoveryFile(filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name()), adminContainerUID, 0, 0o640); err != nil {
			return err
		}
	}
	return nil
}

func countRegularFiles(root string) (int, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, errors.New("path must be a real directory")
	}
	count := 0
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symbolic links are not allowed in recovery data")
		}
		if entry.IsDir() {
			return nil
		}
		fileInfo, err := entry.Info()
		if err != nil || !fileInfo.Mode().IsRegular() {
			return errors.New("recovery data contains a non-regular file")
		}
		count++
		return nil
	})
	return count, err
}

func replaceRecoveryFile(source, destination string, uid, gid int, mode os.FileMode) error {
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("recovery source file is missing or unsafe")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(destination); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("new installation recovery destination is unsafe")
		}
		if err := os.Remove(destination); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := copyFile(source, destination, mode); err != nil {
		return err
	}
	if err := os.Chown(destination, uid, gid); err != nil {
		return err
	}
	if err := os.Chmod(destination, mode); err != nil {
		return err
	}
	return nil
}

func recoveryPath(path string) (string, error) {
	resolved, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil || filepath.Ext(resolved) != ".bak" {
		return "", errors.New("disaster recovery requires a .bak archive path")
	}
	return resolved, nil
}
