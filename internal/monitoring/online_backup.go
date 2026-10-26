package monitoring

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"modernc.org/sqlite"
)

const maxHistoryDatabaseBytes = int64(2 << 30)

// OnlineBackupDatabase snapshots an existing SQLite file with SQLite's online
// backup API and verifies the completed destination before returning.
func OnlineBackupDatabase(sourcePath, destination string) (resultErr error) {
	if filepath.Ext(destination) != ".db" {
		return errors.New("SQLite backup destination must use .db")
	}
	sourceInfo, err := os.Lstat(sourcePath)
	if err != nil || !sourceInfo.Mode().IsRegular() || sourceInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("SQLite backup source must be a regular file")
	}
	absPath, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absPath))
	if err != nil {
		return fmt.Errorf("resolve SQLite backup directory: %w", err)
	}
	if parent != filepath.Dir(absPath) {
		return errors.New("SQLite backup directory must not be a symbolic link")
	}
	output, err := os.OpenFile(absPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create SQLite backup destination: %w", err)
	}
	if err := output.Close(); err != nil {
		_ = os.Remove(absPath)
		return err
	}
	completed := false
	defer func() {
		if !completed {
			_ = os.Remove(absPath)
			_ = os.Remove(absPath + "-wal")
			_ = os.Remove(absPath + "-shm")
		}
	}()
	uri := func(path, mode string) string {
		return (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String() + "?mode=" + mode
	}
	source, err := sql.Open("sqlite", uri(sourcePath, "ro"))
	if err != nil {
		return fmt.Errorf("open SQLite backup source: %w", err)
	}
	source.SetMaxOpenConns(1)
	defer source.Close()
	connection, err := source.Conn(context.Background())
	if err != nil {
		return err
	}
	err = connection.Raw(func(raw any) error {
		backupSource, ok := raw.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("SQLite driver does not support online backup")
		}
		backup, err := backupSource.NewBackup(uri(absPath, "rwc"))
		if err != nil {
			return err
		}
		var stepErr error
		for {
			more, err := backup.Step(128)
			if err != nil {
				stepErr = err
				break
			}
			if !more {
				break
			}
		}
		return errors.Join(stepErr, backup.Finish())
	})
	if closeErr := connection.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("copy SQLite database online: %w", err)
	}
	if err := os.Chmod(absPath, 0o600); err != nil {
		return fmt.Errorf("secure SQLite backup: %w", err)
	}
	check, err := sql.Open("sqlite", uri(absPath, "ro"))
	if err != nil {
		return err
	}
	defer check.Close()
	var integrity string
	if err := check.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return errors.New("SQLite online backup failed its integrity check")
	}
	completed = true
	return nil
}

// ValidateHistoryDatabase checks a restored database without changing it.
func ValidateHistoryDatabase(path string) error {
	_, err := HistoryDatabaseSchema(path)
	return err
}

// HistoryDatabaseSchema opens the installed history database read-only,
// verifies its structure and integrity, and returns its actual SQLite schema.
func HistoryDatabaseSchema(path string) (int, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxHistoryDatabaseBytes {
		return 0, errors.New("statistics database must be a non-empty regular file within the size limit")
	}
	uri := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String() + "?mode=ro"
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return 0, fmt.Errorf("open statistics database read-only: %w", err)
	}
	defer db.Close()
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return 0, errors.New("statistics database failed its SQLite integrity check")
	}
	var schema int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&schema); err != nil {
		return 0, fmt.Errorf("read statistics database schema: %w", err)
	}
	if schema < 0 || schema > DatabaseSchemaVersion {
		return 0, fmt.Errorf("statistics database schema %d is unsupported (maximum %d)", schema, DatabaseSchemaVersion)
	}
	if schema == DatabaseSchemaVersion {
		for _, name := range []string{"proxy_samples", "app_settings"} {
			var count int
			if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&count); err != nil || count != 1 {
				return 0, fmt.Errorf("statistics database is missing required table %s", name)
			}
		}
	}
	return schema, nil
}
