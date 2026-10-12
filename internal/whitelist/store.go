package whitelist

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const persistenceVersion = 1

type persistedEntries struct {
	Version int      `json:"version"`
	Entries []string `json:"entries"`
}

// Store is a small atomic JSON file store. Its path is supplied by the caller
// so production and tests can keep state in their respective data directories.
type Store struct {
	path string
}

func NewStore(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("whitelist store path is empty")
	}
	return &Store{path: path}, nil
}

// Load returns an empty whitelist when the file does not exist. Corrupt or
// unsupported files return an error so callers can fail closed.
func (s *Store) Load() ([]string, error) {
	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var data persistedEntries
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("decode whitelist: %w", err)
	}
	if data.Version != persistenceVersion {
		return nil, fmt.Errorf("unsupported whitelist version %d", data.Version)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("whitelist file contains trailing JSON data")
		}
		return nil, fmt.Errorf("decode trailing whitelist data: %w", err)
	}

	entries, err := Validate(data.Entries)
	if err != nil {
		return nil, fmt.Errorf("validate stored whitelist: %w", err)
	}
	return Strings(entries), nil
}

// Save validates and atomically replaces the persisted list. A validation or
// filesystem error leaves the previous file intact.
func (s *Store) Save(values []string) error {
	entries, err := Validate(values)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(persistedEntries{
		Version: persistenceVersion,
		Entries: Strings(entries),
	}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create whitelist directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".whitelist-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary whitelist: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("restrict temporary whitelist permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary whitelist: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary whitelist: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary whitelist: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace whitelist: %w", err)
	}
	return nil
}
