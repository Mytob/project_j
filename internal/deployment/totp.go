package deployment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Mytob/project_j/internal/auth"
)

// ensureTOTPStorage validates existing protected state or performs the one
// supported v1.0-to-v1.1 migration when neither TOTP file exists.
func ensureTOTPStorage(installRoot string) error {
	keyPath := filepath.Join(installRoot, "config", "totp.key")
	statePath := filepath.Join(installRoot, "data", "totp-state.json")
	_, keyErr := os.Lstat(keyPath)
	_, stateErr := os.Lstat(statePath)
	keyMissing := errors.Is(keyErr, os.ErrNotExist)
	stateMissing := errors.Is(stateErr, os.ErrNotExist)
	if keyErr != nil && !keyMissing {
		return fmt.Errorf("inspect TOTP storage key: %w", keyErr)
	}
	if stateErr != nil && !stateMissing {
		return fmt.Errorf("inspect TOTP state: %w", stateErr)
	}
	if keyMissing != stateMissing {
		return errors.New("TOTP key and state must exist together; refusing an unsafe partial migration")
	}
	createdKey := false
	if keyMissing {
		if err := auth.CreateTOTPKey(keyPath); err != nil {
			return fmt.Errorf("create TOTP migration key: %w", err)
		}
		createdKey = true
		if err := os.Chown(keyPath, 0, adminContainerUID); err != nil {
			_ = os.Remove(keyPath)
			return fmt.Errorf("set TOTP migration key ownership: %w", err)
		}
		if err := os.Chmod(keyPath, 0o640); err != nil {
			_ = os.Remove(keyPath)
			return fmt.Errorf("set TOTP migration key permissions: %w", err)
		}
	}
	key, err := auth.LoadTOTPKey(keyPath)
	if err != nil {
		if createdKey {
			_ = os.Remove(keyPath)
		}
		return err
	}
	defer clear(key)
	if stateMissing {
		_, err := auth.InitializeTOTPStore(statePath, key)
		if err != nil {
			if createdKey {
				_ = os.Remove(keyPath)
			}
			return fmt.Errorf("initialize TOTP migration state: %w", err)
		}
		if err := os.Chown(statePath, adminContainerUID, adminContainerUID); err != nil {
			_ = os.Remove(statePath)
			if createdKey {
				_ = os.Remove(keyPath)
			}
			return fmt.Errorf("set TOTP migration state ownership: %w", err)
		}
		if err := os.Chmod(statePath, 0o600); err != nil {
			_ = os.Remove(statePath)
			if createdKey {
				_ = os.Remove(keyPath)
			}
			return fmt.Errorf("set TOTP migration state permissions: %w", err)
		}
		return nil
	}
	if _, err := auth.NewTOTPStore(statePath, key); err != nil {
		return fmt.Errorf("validate retained TOTP state: %w", err)
	}
	return nil
}
