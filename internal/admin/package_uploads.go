package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	packageUploadChunkBytes = int64(8 << 20)
	packageUploadMaxBytes   = int64(2 << 30)
	packageUploadMaxParts   = 256
	packageUploadMaxCount   = 16
	packageUploadMaxTotal   = int64(4 << 30)
	packageUploadDiskReserve = int64(64 << 20)
	packageUploadMaxAge     = 7 * 24 * time.Hour
)

var packageUploadIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var packageChecksumPattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
var packageFilenamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,123}\.pkg$`)

type packageUploadRecord struct {
	ID          string    `json:"id"`
	Filename    string    `json:"filename"`
	SizeBytes   int64     `json:"size_bytes"`
	TotalChunks int       `json:"total_chunks"`
	ChunkBytes  int64     `json:"chunk_bytes"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Complete    bool      `json:"complete"`
	SHA256      string    `json:"sha256,omitempty"`
}

type PackageUploadStatus struct {
	ID          string    `json:"id"`
	Filename    string    `json:"filename"`
	SizeBytes   int64     `json:"size_bytes"`
	ChunkBytes  int64     `json:"chunk_bytes"`
	TotalChunks int       `json:"total_chunks"`
	Received    []int     `json:"received_chunks"`
	Complete    bool      `json:"complete"`
	SHA256      string    `json:"sha256,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PackageUploadStore persists bounded, resumable package uploads in the admin
// data volume. The privileged maintenance service only receives generated IDs
// and resolves them under its own fixed upload directory.
type PackageUploadStore struct {
	mu  sync.Mutex
	dir string
	now func() time.Time
}

func NewPackageUploadStore(directory string) (*PackageUploadStore, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) == string(filepath.Separator) {
		return nil, errors.New("package upload directory must be an absolute non-root path")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create package upload directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("package upload directory must be a real directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("secure package upload directory: %w", err)
	}
	store := &PackageUploadStore{dir: filepath.Clean(directory), now: time.Now}
	if err := store.cleanupLocked(); err != nil {
		return nil, err
	}
	return store, nil
}

// StartCleanup removes expired resumable upload state even when no new upload
// arrives. The caller owns the lifecycle context and may report cleanup errors.
func (s *PackageUploadStore) StartCleanup(ctx context.Context, interval time.Duration, onError func(error)) {
	if interval <= 0 {
		interval = time.Hour
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.mu.Lock()
				err := s.cleanupLocked()
				s.mu.Unlock()
				if err != nil && onError != nil {
					onError(err)
				}
			}
		}
	}()
}

func (s *PackageUploadStore) Create(filename string, size int64) (PackageUploadStatus, error) {
	filename = strings.TrimSpace(filename)
	if strings.ContainsAny(filename, `/\\`) || !packageFilenamePattern.MatchString(filename) || size <= 0 || size > packageUploadMaxBytes {
		return PackageUploadStatus{}, errors.New("choose a .pkg file smaller than 2 GiB")
	}
	total := int((size + packageUploadChunkBytes - 1) / packageUploadChunkBytes)
	if total < 1 || total > packageUploadMaxParts {
		return PackageUploadStatus{}, errors.New("package upload exceeds the chunk limit")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.cleanupLocked(); err != nil {
		return PackageUploadStatus{}, err
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return PackageUploadStatus{}, errors.New("package upload store is unavailable")
	}
	uploadCount := 0
	var declaredBytes int64
	var additionalBytes int64
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			uploadCount++
			id := strings.TrimSuffix(entry.Name(), ".json")
			record, readErr := s.readRecord(id)
			if readErr != nil {
				return PackageUploadStatus{}, errors.New("package upload store contains an invalid record")
			}
			declaredBytes += record.SizeBytes
			if !record.Complete {
				stored, storedErr := s.storedChunkBytes(record)
				if storedErr != nil {
					return PackageUploadStatus{}, errors.New("package upload store contains an unsafe chunk")
				}
				additionalBytes += 2*record.SizeBytes - stored
			}
		}
	}
	if uploadCount >= packageUploadMaxCount {
		return PackageUploadStatus{}, errors.New("package upload store has reached its item limit")
	}
	if declaredBytes > packageUploadMaxTotal || size > packageUploadMaxTotal-declaredBytes {
		return PackageUploadStatus{}, errors.New("package upload store has reached its total size limit")
	}
	available, err := availableBytes(s.dir)
	if err != nil {
		return PackageUploadStatus{}, errors.New("available disk space could not be checked")
	}
	if available >= 0 && additionalBytes+2*size+packageUploadDiskReserve > available {
		return PackageUploadStatus{}, errors.New("not enough free disk space for the package upload and safe verification")
	}
	var randomID [16]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return PackageUploadStatus{}, errors.New("could not allocate a package upload")
	}
	now := s.now().UTC()
	record := packageUploadRecord{ID: hex.EncodeToString(randomID[:]), Filename: filename, SizeBytes: size, TotalChunks: total, ChunkBytes: packageUploadChunkBytes, CreatedAt: now, UpdatedAt: now}
	if err := s.writeRecord(record); err != nil {
		return PackageUploadStatus{}, errors.New("could not persist package upload state")
	}
	return s.statusLocked(record)
}

func (s *PackageUploadStore) Status(id string) (PackageUploadStatus, error) {
	if !packageUploadIDPattern.MatchString(id) {
		return PackageUploadStatus{}, errors.New("package upload was not found")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.cleanupLocked(); err != nil {
		return PackageUploadStatus{}, errors.New("package upload state is unavailable")
	}
	record, err := s.readRecord(id)
	if err != nil {
		return PackageUploadStatus{}, errors.New("package upload was not found")
	}
	return s.statusLocked(record)
}

func (s *PackageUploadStore) PutChunk(id string, index int, body io.Reader) (PackageUploadStatus, error) {
	if !packageUploadIDPattern.MatchString(id) || body == nil {
		return PackageUploadStatus{}, errors.New("package upload was not found")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.cleanupLocked(); err != nil {
		return PackageUploadStatus{}, errors.New("package upload state is unavailable")
	}
	record, err := s.readRecord(id)
	if err != nil || record.Complete || index < 0 || index >= record.TotalChunks {
		return PackageUploadStatus{}, errors.New("package upload chunk is invalid")
	}
	expected := packageUploadChunkBytes
	if index == record.TotalChunks-1 {
		expected = record.SizeBytes - int64(index)*packageUploadChunkBytes
	}
	if expected <= 0 || expected > packageUploadChunkBytes {
		return PackageUploadStatus{}, errors.New("package upload chunk size is invalid")
	}
	temp, err := os.CreateTemp(s.dir, ".chunk-*.tmp")
	if err != nil {
		return PackageUploadStatus{}, errors.New("package upload store is unavailable")
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return PackageUploadStatus{}, errors.New("could not secure package upload chunk")
	}
	written, copyErr := io.CopyN(temp, body, expected+1)
	if copyErr != nil && !errors.Is(copyErr, io.EOF) {
		_ = temp.Close()
		return PackageUploadStatus{}, errors.New("could not store package upload chunk")
	}
	if written != expected {
		_ = temp.Close()
		return PackageUploadStatus{}, errors.New("package upload chunk has an unexpected size")
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return PackageUploadStatus{}, errors.New("could not persist package upload chunk")
	}
	if err := temp.Close(); err != nil {
		return PackageUploadStatus{}, errors.New("could not close package upload chunk")
	}
	finalPath := s.chunkPath(id, index)
	if err := os.Remove(finalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return PackageUploadStatus{}, errors.New("could not replace package upload chunk")
	}
	if err := os.Rename(tempPath, finalPath); err != nil {
		return PackageUploadStatus{}, errors.New("could not save package upload chunk")
	}
	record.UpdatedAt = s.now().UTC()
	if err := s.writeRecord(record); err != nil {
		return PackageUploadStatus{}, errors.New("could not persist package upload progress")
	}
	return s.statusLocked(record)
}

func (s *PackageUploadStore) Complete(id, expectedSHA256 string) (PackageUploadStatus, error) {
	if !packageUploadIDPattern.MatchString(id) || !packageChecksumPattern.MatchString(expectedSHA256) {
		return PackageUploadStatus{}, errors.New("enter the independent 64-character SHA-256 checksum")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.cleanupLocked(); err != nil {
		return PackageUploadStatus{}, errors.New("package upload state is unavailable")
	}
	record, err := s.readRecord(id)
	if err != nil {
		return PackageUploadStatus{}, errors.New("package upload was not found")
	}
	expectedSHA256 = strings.ToLower(expectedSHA256)
	if record.Complete {
		if record.SHA256 != expectedSHA256 || !s.packageMatches(record, expectedSHA256) {
			return PackageUploadStatus{}, errors.New("completed upload does not match the supplied checksum")
		}
		return s.statusLocked(record)
	}
	stored, err := s.storedChunkBytes(record)
	if err != nil || stored != record.SizeBytes {
		return PackageUploadStatus{}, errors.New("package upload is incomplete or contains an unsafe chunk")
	}
	available, err := availableBytes(s.dir)
	if err != nil {
		return PackageUploadStatus{}, errors.New("available disk space could not be checked")
	}
	if available >= 0 && available < record.SizeBytes+packageUploadDiskReserve {
		return PackageUploadStatus{}, errors.New("not enough free disk space to assemble the package safely")
	}
	temp, err := os.CreateTemp(s.dir, ".package-*.tmp")
	if err != nil {
		return PackageUploadStatus{}, errors.New("package upload store is unavailable")
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return PackageUploadStatus{}, errors.New("could not secure completed package")
	}
	digest := sha256.New()
	writer := io.MultiWriter(temp, digest)
	var copied int64
	for i := 0; i < record.TotalChunks; i++ {
		part, openErr := os.Open(s.chunkPath(id, i))
		if openErr != nil {
			_ = temp.Close()
			return PackageUploadStatus{}, errors.New("package upload became unavailable during assembly")
		}
		expected := packageUploadChunkBytes
		if i == record.TotalChunks-1 {
			expected = record.SizeBytes - int64(i)*packageUploadChunkBytes
		}
		n, copyErr := io.CopyN(writer, part, expected)
		closeErr := part.Close()
		if copyErr != nil || closeErr != nil || n != expected {
			_ = temp.Close()
			return PackageUploadStatus{}, errors.New("package upload chunk failed integrity checks")
		}
		copied += n
	}
	if copied != record.SizeBytes || hex.EncodeToString(digest.Sum(nil)) != expectedSHA256 {
		_ = temp.Close()
		return PackageUploadStatus{}, errors.New("package checksum does not match the independently supplied SHA-256")
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return PackageUploadStatus{}, errors.New("could not persist completed package")
	}
	if err := temp.Close(); err != nil {
		return PackageUploadStatus{}, errors.New("could not close completed package")
	}
	if err := os.Rename(tempPath, s.packagePath(id)); err != nil {
		return PackageUploadStatus{}, errors.New("could not finalize completed package")
	}
	record.Complete = true
	record.SHA256 = expectedSHA256
	record.UpdatedAt = s.now().UTC()
	if err := s.writeRecord(record); err != nil {
		_ = os.Remove(s.packagePath(id))
		return PackageUploadStatus{}, errors.New("could not persist completed package state")
	}
	for i := 0; i < record.TotalChunks; i++ {
		_ = os.Remove(s.chunkPath(id, i))
	}
	return s.statusLocked(record)
}

func (s *PackageUploadStore) PackagePath(id string) (string, error) {
	if !packageUploadIDPattern.MatchString(id) {
		return "", errors.New("package upload was not found")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.cleanupLocked(); err != nil {
		return "", errors.New("package upload state is unavailable")
	}
	record, err := s.readRecord(id)
	if err != nil || !record.Complete {
		return "", errors.New("completed package upload was not found")
	}
	path := s.packagePath(id)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != record.SizeBytes {
		return "", errors.New("completed package upload is unavailable")
	}
	return path, nil
}

func (s *PackageUploadStore) packageMatches(record packageUploadRecord, sha string) bool {
	path := s.packagePath(record.ID)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != record.SizeBytes {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, io.LimitReader(file, record.SizeBytes+1))
	closeErr := file.Close()
	return copyErr == nil && closeErr == nil && hex.EncodeToString(hash.Sum(nil)) == sha
}

func (s *PackageUploadStore) storedChunkBytes(record packageUploadRecord) (int64, error) {
	var total int64
	for i := 0; i < record.TotalChunks; i++ {
		path := s.chunkPath(record.ID, i)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 {
			return 0, errors.New("chunk is missing or unsafe")
		}
		expected := packageUploadChunkBytes
		if i == record.TotalChunks-1 {
			expected = record.SizeBytes - int64(i)*packageUploadChunkBytes
		}
		if info.Size() != expected {
			return 0, errors.New("chunk has an unexpected size")
		}
		total += info.Size()
	}
	return total, nil
}

func (s *PackageUploadStore) statusLocked(record packageUploadRecord) (PackageUploadStatus, error) {
	status := PackageUploadStatus{ID: record.ID, Filename: record.Filename, SizeBytes: record.SizeBytes, ChunkBytes: record.ChunkBytes, TotalChunks: record.TotalChunks, Received: make([]int, 0, record.TotalChunks), Complete: record.Complete, SHA256: record.SHA256, UpdatedAt: record.UpdatedAt}
	for i := 0; i < record.TotalChunks; i++ {
		info, err := os.Lstat(s.chunkPath(record.ID, i))
		if err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			status.Received = append(status.Received, i)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return PackageUploadStatus{}, errors.New("package upload state is unavailable")
		}
	}
	if record.Complete {
		info, err := os.Lstat(s.packagePath(record.ID))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != record.SizeBytes {
			return PackageUploadStatus{}, errors.New("completed package is unavailable")
		}
	}
	return status, nil
}

func (s *PackageUploadStore) readRecord(id string) (packageUploadRecord, error) {
	if !packageUploadIDPattern.MatchString(id) {
		return packageUploadRecord{}, errors.New("package upload ID is invalid")
	}
	path := s.recordPath(id)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 8<<10 || info.Mode().Perm()&0o077 != 0 {
		return packageUploadRecord{}, errors.New("package upload record is unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return packageUploadRecord{}, err
	}
	var record packageUploadRecord
	if err := json.Unmarshal(data, &record); err != nil || record.ID != id || !packageUploadIDPattern.MatchString(record.ID) || !packageFilenamePattern.MatchString(record.Filename) || record.SizeBytes <= 0 || record.SizeBytes > packageUploadMaxBytes || record.ChunkBytes != packageUploadChunkBytes || record.TotalChunks != int((record.SizeBytes+packageUploadChunkBytes-1)/packageUploadChunkBytes) || record.TotalChunks < 1 || record.TotalChunks > packageUploadMaxParts || record.CreatedAt.IsZero() || record.UpdatedAt.IsZero() || (record.Complete && !packageChecksumPattern.MatchString(record.SHA256)) {
		return packageUploadRecord{}, errors.New("package upload record is invalid")
	}
	return record, nil
}

func (s *PackageUploadStore) writeRecord(record packageUploadRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(s.dir, ".record-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, s.recordPath(record.ID)); err != nil {
		return err
	}
	return nil
}

func (s *PackageUploadStore) cleanupLocked() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return errors.New("package upload store is unavailable")
	}
	cutoff := s.now().Add(-packageUploadMaxAge)
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".package-") || strings.HasPrefix(name, ".chunk-") || strings.HasPrefix(name, ".record-") {
			info, statErr := entry.Info()
			if statErr == nil && info.ModTime().Before(s.now().Add(-time.Hour)) && info.Mode().IsRegular() {
				_ = os.Remove(filepath.Join(s.dir, name))
			}
			continue
		}
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		record, readErr := s.readRecord(id)
		if readErr != nil {
			return errors.New("package upload store contains an invalid record")
		}
		if record.UpdatedAt.Before(cutoff) {
			if err := s.removeRecordAndFiles(record); err != nil {
				return errors.New("expired package upload could not be removed safely")
			}
		}
	}
	return nil
}

func (s *PackageUploadStore) removeRecordAndFiles(record packageUploadRecord) error {
	for i := 0; i < record.TotalChunks; i++ {
		if err := os.Remove(s.chunkPath(record.ID, i)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Remove(s.packagePath(record.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(s.recordPath(record.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *PackageUploadStore) recordPath(id string) string  { return filepath.Join(s.dir, id+".json") }
func (s *PackageUploadStore) packagePath(id string) string { return filepath.Join(s.dir, id+".pkg") }
func (s *PackageUploadStore) chunkPath(id string, index int) string {
	return filepath.Join(s.dir, fmt.Sprintf("%s.part.%03d", id, index))
}
