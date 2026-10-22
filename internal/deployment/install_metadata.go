package deployment

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type installMetadata struct {
	Version    int       `json:"version"`
	InstalledAt time.Time `json:"installed_at"`
}

func initializeInstallMetadata(dataDirectory string, now time.Time) error {
	if !filepath.IsAbs(dataDirectory) {
		return errors.New("installation metadata directory must be absolute")
	}
	path := filepath.Join(dataDirectory, "install-info.json")
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 4096 {
			return errors.New("installation metadata file is unsafe")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var value installMetadata
		if err := json.Unmarshal(data, &value); err != nil || value.Version != 1 || value.InstalledAt.IsZero() {
			return errors.New("existing installation metadata is invalid")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if now.IsZero() {
		now = time.Now()
	}
	data, err := json.Marshal(installMetadata{Version: 1, InstalledAt: now.UTC()})
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(append(data, '\n'))
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.Join(writeErr, closeErr)
	}
	if err := os.Chown(path, adminContainerUID, adminContainerUID); err != nil {
		return fmt.Errorf("set installation metadata ownership: %w", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		return fmt.Errorf("set installation metadata permissions: %w", err)
	}
	directory, err := os.Open(dataDirectory)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
