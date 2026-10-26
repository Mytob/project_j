package deployment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Mytob/project_j/internal/backup"
	"github.com/Mytob/project_j/internal/monitoring"
)

const DefaultBackupRoot = "/var/backups/jellyfin-proxy"

var backupNamePattern = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// CreateBackup makes an owner-only, integrity-checked application backup.
// An empty output path creates a dated archive under /var/backups/jellyfin-proxy.
func CreateBackup(installRoot, outputPath string) (string, backup.Manifest, error) {
	if installRoot == "" {
		installRoot = DefaultInstallRoot
	}
	if err := validateInstalledLayout(installRoot); err != nil {
		return "", backup.Manifest{}, err
	}
	current, err := readCurrentRelease(installRoot)
	if err != nil {
		return "", backup.Manifest{}, err
	}
	useDefaultDirectory := outputPath == ""
	if useDefaultDirectory {
		if err := os.MkdirAll(DefaultBackupRoot, 0o700); err != nil {
			return "", backup.Manifest{}, fmt.Errorf("create product backup directory: %w", err)
		}
		if info, err := os.Lstat(DefaultBackupRoot); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", backup.Manifest{}, errors.New("product backup path must be a real directory")
		}
		if err := os.Chmod(DefaultBackupRoot, 0o700); err != nil {
			return "", backup.Manifest{}, fmt.Errorf("secure product backup directory: %w", err)
		}
		version := backupNamePattern.ReplaceAllString(current.Version, "-")
		build := backupNamePattern.ReplaceAllString(current.BuildID, "-")
		outputPath = filepath.Join(DefaultBackupRoot, fmt.Sprintf("jellyfin-proxy-%s-%s-%s.bak", version, build, time.Now().UTC().Format("20060102T150405.000000000Z")))
	}
	path, err := filepath.Abs(outputPath)
	if err != nil {
		return "", backup.Manifest{}, err
	}
	manifest, err := backup.Create(backup.CreateOptions{InstallRoot: installRoot, OutputPath: path, Version: current.Version, BuildID: current.BuildID, DatabaseSchema: monitoring.DatabaseSchemaVersion})
	if err != nil {
		return "", backup.Manifest{}, err
	}
	if _, err := backup.Validate(path); err != nil {
		_ = os.Remove(path)
		_ = os.Remove(path + ".sha256")
		return "", backup.Manifest{}, errors.New("created backup failed independent validation")
	}
	return path, manifest, nil
}

func ValidateBackup(path string) (backup.Manifest, error) {
	return backup.Validate(path)
}

func ExtractBackup(path, destination string) (backup.Manifest, error) {
	return backup.Extract(path, destination)
}

func BackupName(path string) string {
	base := filepath.Base(strings.TrimSpace(path))
	return strings.TrimSuffix(base, filepath.Ext(base))
}
