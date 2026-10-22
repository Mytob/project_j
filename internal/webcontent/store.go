// Package webcontent validates and atomically publishes administrator-managed
// static public-site archives.
package webcontent

import (
	"archive/zip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	MaxArchiveBytes    int64 = 25 << 20
	MaxExpandedBytes   int64 = 50 << 20
	MaxFileBytes       int64 = 10 << 20
	MaxFiles                 = 500
	maximumPathBytes         = 240
	BackupPointersFile       = ".backup-pointers.json"
)

var allowedExtensions = map[string]bool{
	".html": true, ".css": true, ".js": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".webp": true, ".avif": true, ".ico": true,
}

var defaultErrors = map[string]string{
	"403.html": `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access denied</title><main><h1>Access denied</h1><p>This request is not allowed.</p></main></html>`,
	"404.html": `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Not found</title><main><h1>Not found</h1><p>The requested page could not be found.</p></main></html>`,
	"502.html": `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Gateway unavailable</title><main><h1>Gateway unavailable</h1><p>The Jellyfin service is temporarily unavailable.</p></main></html>`,
	"503.html": `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Service unavailable</title><main><h1>Service unavailable</h1><p>Please try again shortly.</p></main></html>`,
}

var publicationMu sync.Mutex

type Status struct {
	Current  string `json:"current_revision,omitempty"`
	Previous string `json:"previous_revision,omitempty"`
}

type backupPointers struct {
	Version  int    `json:"version"`
	Current  string `json:"current"`
	Previous string `json:"previous,omitempty"`
}

// BackupPointerMetadata serializes only the two fixed internal pointers used by
// the public-site revision store. Backup archives never contain symlinks.
func BackupPointerMetadata(root string) ([]byte, error) {
	if err := ensureRealDirectory(root); err != nil {
		return nil, err
	}
	current, err := readPointer(root, "current")
	if err != nil {
		return nil, err
	}
	previous, err := readPointer(root, "previous")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if previous == current {
		return nil, errors.New("web content current and previous revisions must differ")
	}
	return json.Marshal(backupPointers{Version: 1, Current: current, Previous: previous})
}

// ValidateBackupPointerMetadata checks pointer identifiers and ensures each
// referenced revision has a root homepage represented in the backup manifest.
func ValidateBackupPointerMetadata(data []byte, hasRevision func(string) bool) error {
	pointers, err := parseBackupPointers(data)
	if err != nil {
		return err
	}
	if hasRevision == nil || !hasRevision("data/site-content/revisions/"+pointers.Current+"/index.html") {
		return errors.New("backup public-site current revision is incomplete")
	}
	if pointers.Previous != "" && !hasRevision("data/site-content/revisions/"+pointers.Previous+"/index.html") {
		return errors.New("backup public-site previous revision is incomplete")
	}
	return nil
}

// RestoreBackupPointers recreates validated fixed-name symlinks from a regular
// metadata file after the backup extractor has written and verified all files.
func RestoreBackupPointers(root string) error {
	metadataPath := filepath.Join(root, BackupPointersFile)
	info, err := os.Lstat(metadataPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 4096 {
		return errors.New("backup public-site pointer metadata is missing or unsafe")
	}
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return err
	}
	pointers, err := parseBackupPointers(data)
	if err != nil {
		return err
	}
	if err := ensureRealDirectory(root); err != nil {
		return err
	}
	if err := ensureRealDirectory(filepath.Join(root, "revisions")); err != nil {
		return err
	}
	for _, revision := range []string{pointers.Current, pointers.Previous} {
		if revision == "" {
			continue
		}
		revisionRoot := filepath.Join(root, "revisions", revision)
		if err := ensureRealDirectory(revisionRoot); err != nil {
			return errors.New("backup public-site pointer refers to a missing revision")
		}
		index := filepath.Join(revisionRoot, "index.html")
		indexInfo, err := os.Lstat(index)
		if err != nil || !indexInfo.Mode().IsRegular() || indexInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("backup public-site revision homepage is missing or unsafe")
		}
	}
	if err := setPointer(root, "current", pointers.Current); err != nil {
		return err
	}
	if pointers.Previous != "" {
		if err := setPointer(root, "previous", pointers.Previous); err != nil {
			return err
		}
	} else if err := removePointer(root, "previous"); err != nil {
		return err
	}
	if err := os.Remove(metadataPath); err != nil {
		return err
	}
	return syncDirectory(root)
}

// CopyCurrentTo imports the active public revision into a fresh installation,
// applying the same path, file type, extension, and size limits as ZIP uploads.
func CopyCurrentTo(sourceRoot, destinationRoot string) error {
	current, err := readPointer(sourceRoot, "current")
	if err != nil {
		return err
	}
	return CopyDirectoryTo(filepath.Join(sourceRoot, "revisions", current), destinationRoot)
}

// CopyDirectoryTo imports a complete static site directory into a fresh
// installation using the same path, file type, extension, and size limits as
// ZIP uploads.
func CopyDirectoryTo(sourceRoot, destinationRoot string) error {
	if err := ensureRealDirectory(sourceRoot); err != nil {
		return err
	}
	files := make(map[string][]byte)
	var expanded int64
	err := filepath.WalkDir(sourceRoot, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filePath == sourceRoot {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("public-site revision contains a symbolic link")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("public-site revision contains a non-regular file")
		}
		relative, err := filepath.Rel(sourceRoot, filePath)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		if err := validateEntryName(name); err != nil || strings.HasSuffix(name, "/") || !allowedExtensions[strings.ToLower(filepath.Ext(name))] {
			return fmt.Errorf("public-site revision contains an unsupported path: %s", name)
		}
		if len(files) >= MaxFiles || info.Size() < 0 || info.Size() > MaxFileBytes || expanded > MaxExpandedBytes-info.Size() {
			return errors.New("public-site revision exceeds its file or size limit")
		}
		data, err := os.ReadFile(filePath)
		if err != nil || int64(len(data)) != info.Size() {
			return errors.New("public-site revision file changed during recovery")
		}
		files[name] = data
		expanded += int64(len(data))
		return nil
	})
	if err != nil {
		return err
	}
	if _, ok := files["index.html"]; !ok {
		return errors.New("public-site import has no root index.html")
	}
	for name, content := range defaultErrors {
		if _, exists := files["errors/"+name]; !exists {
			files["errors/"+name] = []byte(content)
		}
	}
	return publishFiles(destinationRoot, files, "")
}

func parseBackupPointers(data []byte) (backupPointers, error) {
	var pointers backupPointers
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pointers); err != nil {
		return backupPointers{}, errors.New("backup public-site pointer metadata is invalid")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return backupPointers{}, errors.New("backup public-site pointer metadata contains trailing data")
	}
	if pointers.Version != 1 || !validRevisionID(pointers.Current) || (pointers.Previous != "" && (!validRevisionID(pointers.Previous) || pointers.Previous == pointers.Current)) {
		return backupPointers{}, errors.New("backup public-site pointer metadata has invalid revisions")
	}
	return pointers, nil
}

func validRevisionID(revision string) bool {
	if revision == "default" {
		return true
	}
	if len(revision) != 32 {
		return false
	}
	for _, character := range revision {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

// Initialize creates the initial immutable revision from the packaged default
// homepage. Existing content is left in place.
func Initialize(root, packagedSite string) error {
	if _, err := os.Lstat(filepath.Join(root, "current")); err == nil {
		current, err := readPointer(root, "current")
		if err != nil {
			return err
		}
		return ensureDefaultErrorPages(root, current)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	index := filepath.Join(packagedSite, "index.html")
	info, err := os.Lstat(index)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 || info.Size() > MaxFileBytes {
		return errors.New("packaged default homepage is missing or unsafe")
	}
	data, err := os.ReadFile(index)
	if err != nil {
		return err
	}
	files := map[string][]byte{"index.html": data}
	for name, content := range defaultErrors {
		files["errors/"+name] = []byte(content)
	}
	return publishFiles(root, files, "default")
}

// EnsureDefaultErrorPages upgrades an existing public-site store with newly
// introduced built-in error pages. It leaves an uninitialized store alone so
// the deployment layer can seed it from the packaged homepage.
func EnsureDefaultErrorPages(root string) error {
	current, err := readPointer(root, "current")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return ensureDefaultErrorPages(root, current)
}

// ensureDefaultErrorPages adds newly introduced built-in pages to older
// installations without changing any page the administrator has published.
// It publishes a new immutable revision only when a default page is missing.
func ensureDefaultErrorPages(root, current string) error {
	revisionRoot := filepath.Join(root, "revisions", current)
	if err := ensureRealDirectory(revisionRoot); err != nil {
		return errors.New("active public-site revision is missing or unsafe")
	}
	errorRoot := filepath.Join(revisionRoot, "errors")
	errorInfo, err := os.Lstat(errorRoot)
	if errors.Is(err, os.ErrNotExist) {
		return CopyDirectoryTo(revisionRoot, root)
	}
	if err != nil {
		return err
	}
	if !errorInfo.IsDir() || errorInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("active public-site error pages are unsafe")
	}
	for name := range defaultErrors {
		path := filepath.Join(errorRoot, name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return CopyDirectoryTo(revisionRoot, root)
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > MaxFileBytes {
			return errors.New("active public-site error page is unsafe")
		}
	}
	return nil
}

// PublishZip validates a bounded static-site ZIP and atomically switches the
// public Caddy root to the new immutable revision. The archive must contain an
// index.html; optional errors/{403,404,502,503}.html replace built-in pages.
func PublishZip(root string, source io.ReaderAt, size int64) (Status, error) {
	if source == nil || size <= 0 || size > MaxArchiveBytes {
		return Status{}, errors.New("web content archive exceeds its size limit or is empty")
	}
	archive, err := zip.NewReader(source, size)
	if err != nil {
		return Status{}, errors.New("web content archive is not a valid ZIP")
	}
	if len(archive.File) > MaxFiles*2 {
		return Status{}, errors.New("web content archive contains too many entries")
	}
	files := make(map[string][]byte)
	seen := make(map[string]struct{})
	var expanded int64
	fileCount := 0
	for _, entry := range archive.File {
		name := entry.Name
		if err := validateEntryName(name); err != nil {
			return Status{}, err
		}
		mode := entry.Mode()
		if mode&os.ModeSymlink != 0 || (!entry.FileInfo().IsDir() && !entry.Mode().IsRegular()) {
			return Status{}, fmt.Errorf("web content archive contains an unsupported file type: %s", name)
		}
		if entry.FileInfo().IsDir() {
			continue
		}
		if !allowedExtensions[strings.ToLower(filepath.Ext(name))] {
			return Status{}, fmt.Errorf("web content archive contains a disallowed file extension: %s", name)
		}
		canonical := strings.ToLower(name)
		if _, exists := seen[canonical]; exists {
			return Status{}, fmt.Errorf("web content archive contains duplicate paths: %s", name)
		}
		seen[canonical] = struct{}{}
		fileCount++
		if fileCount > MaxFiles || entry.UncompressedSize64 > uint64(MaxFileBytes) || entry.UncompressedSize64 > uint64(MaxExpandedBytes-expanded) {
			return Status{}, errors.New("web content archive exceeds its file-count or expanded-size limit")
		}
		expanded += int64(entry.UncompressedSize64)
		file, err := entry.Open()
		if err != nil {
			return Status{}, fmt.Errorf("open web content file %s: %w", name, err)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, MaxFileBytes+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || int64(len(data)) != int64(entry.UncompressedSize64) || int64(len(data)) > MaxFileBytes {
			return Status{}, fmt.Errorf("web content file is truncated or exceeds its limit: %s", name)
		}
		files[name] = data
	}
	if _, ok := files["index.html"]; !ok {
		return Status{}, errors.New("web content archive must contain a root index.html")
	}
	for name, content := range defaultErrors {
		if _, exists := files["errors/"+name]; !exists {
			files["errors/"+name] = []byte(content)
		}
	}
	if err := publishFiles(root, files, ""); err != nil {
		return Status{}, err
	}
	return GetStatus(root)
}

// Rollback atomically restores the last published revision.
func Rollback(root string) (Status, error) {
	publicationMu.Lock()
	defer publicationMu.Unlock()
	current, err := readPointer(root, "current")
	if err != nil {
		return Status{}, err
	}
	previous, err := readPointer(root, "previous")
	if err != nil {
		return Status{}, errors.New("there is no previous public-site revision to restore")
	}
	if current == previous {
		return Status{}, errors.New("current and previous public-site revisions are identical")
	}
	if err := switchPointers(root, current, previous); err != nil {
		return Status{}, err
	}
	cleanupRevisions(root)
	return GetStatus(root)
}

func GetStatus(root string) (Status, error) {
	current, err := readPointer(root, "current")
	if err != nil {
		return Status{}, err
	}
	previous, _ := readPointer(root, "previous")
	return Status{Current: current, Previous: previous}, nil
}

func validateEntryName(name string) error {
	if name == "" || len(name) > maximumPathBytes || strings.ContainsAny(name, `\:`) || strings.HasPrefix(name, "/") || path.Clean(name) != name || strings.HasSuffix(name, "/") {
		if strings.HasSuffix(name, "/") && path.Clean(name) == strings.TrimSuffix(name, "/") && !strings.ContainsAny(name, `\:`) && !strings.HasPrefix(name, "/") {
			name = strings.TrimSuffix(name, "/")
		} else {
			return fmt.Errorf("web content archive contains an unsafe path: %q", name)
		}
	}
	for _, part := range strings.Split(strings.TrimSuffix(name, "/"), "/") {
		if part == "" || part == "." || part == ".." || strings.HasPrefix(part, ".") {
			return fmt.Errorf("web content archive contains an unsafe path: %q", name)
		}
		for _, character := range part {
			if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("._-", character)) {
				return fmt.Errorf("web content archive path contains an unsupported character: %q", name)
			}
		}
	}
	return nil
}

func publishFiles(root string, files map[string][]byte, fixedID string) error {
	publicationMu.Lock()
	defer publicationMu.Unlock()
	if !filepath.IsAbs(root) {
		return errors.New("web content root must be absolute")
	}
	if err := os.MkdirAll(filepath.Join(root, "revisions"), 0o750); err != nil {
		return err
	}
	if err := ensureRealDirectory(root); err != nil {
		return err
	}
	revisions := filepath.Join(root, "revisions")
	if err := ensureRealDirectory(revisions); err != nil {
		return err
	}
	if fixedID == "" {
		fixedID = revisionID()
	}
	if fixedID == "" || strings.ContainsAny(fixedID, `/\.`) {
		return errors.New("could not allocate a valid web content revision")
	}
	stage, err := os.MkdirTemp(revisions, ".staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0o755); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := validateEntryName(name); err != nil || strings.HasSuffix(name, "/") {
			return fmt.Errorf("invalid validated web content path %q", name)
		}
		target := filepath.Join(stage, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(files[name])
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if err := syncDirectory(stage); err != nil {
		return err
	}
	revision := filepath.Join(revisions, fixedID)
	if err := os.Rename(stage, revision); err != nil {
		return fmt.Errorf("publish static-site revision directory: %w", err)
	}
	if err := syncDirectory(revisions); err != nil {
		return fmt.Errorf("persist static-site revision directory: %w", err)
	}
	current, currentErr := readPointer(root, "current")
	if currentErr != nil && !errors.Is(currentErr, os.ErrNotExist) {
		return currentErr
	}
	if current != "" {
		if err := setPointer(root, "previous", current); err != nil {
			return err
		}
	}
	if err := setPointer(root, "current", fixedID); err != nil {
		return err
	}
	cleanupRevisions(root)
	return syncDirectory(root)
}

func switchPointers(root, current, previous string) error {
	if err := setPointer(root, "previous", current); err != nil {
		return err
	}
	return setPointer(root, "current", previous)
}

func setPointer(root, name, revision string) error {
	if name != "current" && name != "previous" || !validRevisionID(revision) {
		return errors.New("web content pointer is invalid")
	}
	path := filepath.Join(root, name)
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("refusing to replace non-symlink web content pointer %s", name)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary := filepath.Join(root, "."+name+"-"+revision)
	_ = os.Remove(temporary)
	if err := os.Symlink(filepath.Join("revisions", revision), temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDirectory(root)
}

func removePointer(root, name string) error {
	if name != "current" && name != "previous" {
		return errors.New("web content pointer is invalid")
	}
	path := filepath.Join(root, name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("refusing to remove non-symlink web content pointer %s", name)
	}
	if _, err := readPointer(root, name); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(root)
}

func readPointer(root, name string) (string, error) {
	if name != "current" && name != "previous" {
		return "", errors.New("web content pointer is invalid")
	}
	target, err := os.Readlink(filepath.Join(root, name))
	if err != nil {
		return "", err
	}
	parts := strings.Split(filepath.ToSlash(target), "/")
	if len(parts) != 2 || parts[0] != "revisions" || parts[1] == "" || strings.HasPrefix(parts[1], ".") || filepath.Base(parts[1]) != parts[1] {
		return "", errors.New("web content pointer target is unsafe")
	}
	info, err := os.Lstat(filepath.Join(root, "revisions", parts[1]))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("web content pointer refers to a missing or unsafe revision")
	}
	return parts[1], nil
}

func cleanupRevisions(root string) {
	current, _ := readPointer(root, "current")
	previous, _ := readPointer(root, "previous")
	entries, err := os.ReadDir(filepath.Join(root, "revisions"))
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.Name() == current || entry.Name() == previous || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		if len(entry.Name()) == 32 {
			_ = os.RemoveAll(filepath.Join(root, "revisions", entry.Name()))
		}
	}
}

func ensureRealDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("web content storage path must be a real directory")
	}
	return nil
}

func revisionID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(bytes[:])
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
