package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const credentialVersion = 1

type credentialFile struct {
	Version      int    `json:"version"`
	PasswordHash string `json:"password_hash"`
}

// Credential holds only the serialized password hash.
type Credential struct {
	mu           sync.RWMutex
	passwordHash string
}

// SaveCredential creates a new password hash and atomically writes the single
// administrator credential with owner-only file permissions.
func SaveCredential(path, password string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(credentialFile{Version: credentialVersion, PasswordHash: hash}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return atomicCredentialWrite(path, data)
}

// LoadCredential reads and validates the administrator credential file.
func LoadCredential(path string) (*Credential, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(io.LimitReader(file, 4096))
	decoder.DisallowUnknownFields()
	var data credentialFile
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("decode administrator credential: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("administrator credential contains trailing JSON data")
		}
		return nil, fmt.Errorf("decode trailing credential data: %w", err)
	}
	if data.Version != credentialVersion {
		return nil, fmt.Errorf("unsupported administrator credential version %d", data.Version)
	}
	if err := ValidatePasswordHash(data.PasswordHash); err != nil {
		return nil, fmt.Errorf("invalid administrator password hash: %w", err)
	}
	return &Credential{passwordHash: data.PasswordHash}, nil
}

// Verify reports whether password matches the stored hash.
func (c *Credential) Verify(password string) bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	hash := c.passwordHash
	c.mu.RUnlock()
	return VerifyPassword(hash, password)
}

// ReplacePassword validates and persists a replacement before making it
// active in memory. A failed write leaves the current password usable.
func (c *Credential) ReplacePassword(path, password string) error {
	if c == nil {
		return errors.New("administrator credential is unavailable")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(credentialFile{Version: credentialVersion, PasswordHash: hash}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := atomicCredentialWrite(path, data); err != nil {
		return err
	}
	c.mu.Lock()
	c.passwordHash = hash
	c.mu.Unlock()
	return nil
}

func atomicCredentialWrite(path string, data []byte) error {
	if path == "" {
		return errors.New("administrator credential path is empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create credential directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".admin-credential-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary credential: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("restrict temporary credential permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary credential: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary credential: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary credential: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace administrator credential: %w", err)
	}
	return nil
}
