package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Mytob/project_j/internal/monitoring"
	"github.com/Mytob/project_j/internal/webcontent"
)

const (
	FormatVersion  = 1
	maxArchiveSize = int64(2 << 30)
	maxEntries     = 10000
	maxManifest    = 8 << 20
	manifestName   = "backup-manifest.json"
)

type File struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	FormatVersion  int       `json:"format_version"`
	CreatedAt      time.Time `json:"created_at"`
	Version        string    `json:"version"`
	BuildID        string    `json:"build_id"`
	DatabaseSchema int       `json:"database_schema"`
	Files          []File    `json:"files"`
}

type CreateOptions struct {
	InstallRoot    string
	OutputPath     string
	Version        string
	BuildID        string
	DatabaseSchema int
	CreatedAt      time.Time
}

func Create(options CreateOptions) (manifest Manifest, resultErr error) {
	if options.Version == "" || options.BuildID == "" || options.DatabaseSchema < 1 {
		return manifest, errors.New("backup version, build ID, and database schema are required")
	}
	if filepath.Ext(options.OutputPath) != ".bak" {
		return manifest, errors.New("backup archive must use the .bak extension")
	}
	root, err := filepath.Abs(options.InstallRoot)
	if err != nil {
		return manifest, err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return manifest, errors.New("installation root must be a real directory")
	}
	if resolved, err := filepath.EvalSymlinks(root); err != nil || resolved != root {
		return manifest, errors.New("installation root must not be a symbolic link")
	}
	for _, required := range []string{"config", "data", "site", "compose.yaml", ".env"} {
		if _, err := os.Lstat(filepath.Join(root, required)); err != nil {
			return manifest, fmt.Errorf("required backup path %s is unavailable", required)
		}
	}
	output, err := filepath.Abs(options.OutputPath)
	if err != nil {
		return manifest, err
	}
	parent := filepath.Dir(output)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return manifest, err
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return manifest, errors.New("backup destination must be inside a real directory")
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || resolvedParent != parent {
		return manifest, errors.New("backup destination directory must not be reached through a symbolic link")
	}
	archiveFile, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return manifest, fmt.Errorf("create backup archive: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = archiveFile.Close()
			_ = os.Remove(output)
			_ = os.Remove(output + ".sha256")
		}
	}()
	stage, err := os.MkdirTemp("", "jellyfin-proxy-backup-")
	if err != nil {
		return manifest, err
	}
	defer os.RemoveAll(stage)
	manifest = Manifest{FormatVersion: FormatVersion, CreatedAt: options.CreatedAt.UTC(), Version: options.Version, BuildID: options.BuildID, DatabaseSchema: options.DatabaseSchema}
	if manifest.CreatedAt.IsZero() {
		manifest.CreatedAt = time.Now().UTC()
	}
	var pointerMetadata []byte
	siteContentRoot := filepath.Join(root, "data", "site-content")
	if _, err := os.Lstat(siteContentRoot); err == nil {
		pointerMetadata, err = webcontent.BackupPointerMetadata(siteContentRoot)
		if err != nil {
			return manifest, fmt.Errorf("validate public-site revision pointers: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return manifest, err
	}
	var expanded int64
	for _, base := range []string{"config", "data", "site", "compose.yaml", ".env"} {
		source := filepath.Join(root, base)
		info, err := os.Lstat(source)
		if err != nil {
			return manifest, err
		}
		if info.IsDir() {
			err = filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if entry.Type()&os.ModeSymlink != 0 {
					relative, relErr := filepath.Rel(root, path)
					if relErr == nil && pointerMetadata != nil {
						relative = filepath.ToSlash(relative)
						if relative == "data/site-content/current" || relative == "data/site-content/previous" {
							return nil
						}
					}
					return fmt.Errorf("backup refuses symbolic link %s", path)
				}
				if entry.IsDir() {
					return nil
				}
				if strings.HasSuffix(entry.Name(), "-wal") || strings.HasSuffix(entry.Name(), "-shm") {
					return nil
				}
				return stageFile(root, stage, path, &manifest, &expanded)
			})
		} else {
			err = stageFile(root, stage, source, &manifest, &expanded)
		}
		if err != nil {
			return manifest, err
		}
	}
	if pointerMetadata != nil {
		metadataPath := "data/site-content/" + webcontent.BackupPointersFile
		if err := stageBytes(stage, metadataPath, pointerMetadata, &manifest, &expanded, 0o600); err != nil {
			return manifest, fmt.Errorf("stage public-site backup pointers: %w", err)
		}
		available := make(map[string]bool, len(manifest.Files))
		for _, item := range manifest.Files {
			available[item.Path] = true
		}
		if err := webcontent.ValidateBackupPointerMetadata(pointerMetadata, func(path string) bool { return available[path] }); err != nil {
			return manifest, fmt.Errorf("public-site revision changed or is incomplete during backup: %w", err)
		}
	}
	whitelistFound := false
	for _, item := range manifest.Files {
		if item.Path == "data/whitelist.json" {
			whitelistFound = true
			break
		}
	}
	if !whitelistFound {
		path := filepath.Join(stage, "data", "whitelist.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return manifest, err
		}
		contents := []byte(`{"version":2,"entries":[]}`)
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			return manifest, err
		}
		digest := sha256.Sum256(contents)
		manifest.Files = append(manifest.Files, File{Path: "data/whitelist.json", Mode: 0o600, Size: int64(len(contents)), SHA256: hex.EncodeToString(digest[:])})
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	manifestBytes, err := json.Marshal(manifest)
	if err != nil || len(manifestBytes) > maxManifest {
		return manifest, errors.New("backup manifest could not be encoded within its size limit")
	}
	hasher := sha256.New()
	compressed, err := gzip.NewWriterLevel(io.MultiWriter(archiveFile, hasher), gzip.BestCompression)
	if err != nil {
		return manifest, err
	}
	tarWriter := tar.NewWriter(compressed)
	writeErr := tarWriter.WriteHeader(&tar.Header{Name: manifestName, Mode: 0o600, Size: int64(len(manifestBytes)), Typeflag: tar.TypeReg, ModTime: manifest.CreatedAt})
	if writeErr == nil {
		_, writeErr = tarWriter.Write(manifestBytes)
	}
	for _, item := range manifest.Files {
		if writeErr != nil {
			break
		}
		path := filepath.Join(stage, filepath.FromSlash(item.Path))
		file, openErr := os.Open(path)
		if openErr != nil {
			writeErr = openErr
			break
		}
		writeErr = tarWriter.WriteHeader(&tar.Header{Name: item.Path, Mode: int64(item.Mode & 0o777), Size: item.Size, Typeflag: tar.TypeReg, ModTime: manifest.CreatedAt})
		if writeErr == nil {
			_, writeErr = io.Copy(tarWriter, file)
		}
		if closeErr := file.Close(); writeErr == nil {
			writeErr = closeErr
		}
	}
	if closeErr := tarWriter.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if closeErr := compressed.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return manifest, fmt.Errorf("write backup archive: %w", writeErr)
	}
	if err := archiveFile.Sync(); err != nil {
		return manifest, err
	}
	if err := archiveFile.Close(); err != nil {
		return manifest, err
	}
	if info, err := os.Stat(output); err != nil || info.Size() <= 0 || info.Size() > maxArchiveSize {
		return manifest, errors.New("backup archive is empty or exceeds the compressed-size limit")
	}
	checksum := hex.EncodeToString(hasher.Sum(nil))
	if err := os.WriteFile(output+".sha256", []byte(checksum+"  "+filepath.Base(output)+"\n"), 0o600); err != nil {
		return manifest, fmt.Errorf("write backup checksum: %w", err)
	}
	complete = true
	return manifest, nil
}

func stageFile(root, stage, source string, manifest *Manifest, expanded *int64) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("backup supports regular files only: %s", source)
	}
	if len(manifest.Files) >= maxEntries {
		return errors.New("backup contains too many files")
	}
	rel, err := filepath.Rel(root, source)
	if err != nil {
		return err
	}
	rel = filepath.ToSlash(rel)
	if !safePath(rel) {
		return errors.New("backup source contains an unsafe path")
	}
	if info.Size() < 0 || *expanded > maxArchiveSize-info.Size() {
		return errors.New("backup contents exceed the expanded-size limit")
	}
	destination := filepath.Join(stage, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	if filepath.Base(rel) == "statistics.db" {
		if err := monitoring.OnlineBackupDatabase(source, destination); err != nil {
			return fmt.Errorf("snapshot statistics database: %w", err)
		}
	} else {
		input, err := os.Open(source)
		if err != nil {
			return err
		}
		output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(info.Mode().Perm()&0o777))
		if err != nil {
			input.Close()
			return err
		}
		_, copyErr := io.Copy(output, input)
		inputErr := input.Close()
		outputErr := output.Close()
		if copyErr != nil || inputErr != nil || outputErr != nil {
			return errors.Join(copyErr, inputErr, outputErr)
		}
	}
	staged, err := os.Open(destination)
	if err != nil {
		return err
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, io.LimitReader(staged, maxArchiveSize+1))
	closeErr := staged.Close()
	if copyErr != nil || closeErr != nil {
		return errors.Join(copyErr, closeErr)
	}
	if size > maxArchiveSize || *expanded > maxArchiveSize-size {
		return errors.New("backup contents exceed the expanded-size limit")
	}
	manifest.Files = append(manifest.Files, File{Path: rel, Mode: uint32(info.Mode().Perm() & 0o777), Size: size, SHA256: hex.EncodeToString(hash.Sum(nil))})
	*expanded += size
	return nil
}

func stageBytes(stage, relative string, contents []byte, manifest *Manifest, expanded *int64, mode os.FileMode) error {
	if !safePath(relative) || len(manifest.Files) >= maxEntries || int64(len(contents)) > maxArchiveSize-*expanded {
		return errors.New("backup generated file exceeds its path or size limit")
	}
	destination := filepath.Join(stage, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(contents)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.Join(writeErr, closeErr)
	}
	digest := sha256.Sum256(contents)
	manifest.Files = append(manifest.Files, File{Path: relative, Mode: uint32(mode.Perm()), Size: int64(len(contents)), SHA256: hex.EncodeToString(digest[:])})
	*expanded += int64(len(contents))
	return nil
}

func safePath(name string) bool {
	if name == "" || strings.Contains(name, "\\") || filepath.IsAbs(name) || strings.ContainsRune(name, 0) {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func readManifest(reader *tar.Reader) (Manifest, error) {
	header, err := reader.Next()
	if err != nil || header.Name != manifestName || header.Typeflag != tar.TypeReg || header.Size < 1 || header.Size > maxManifest {
		return Manifest{}, errors.New("backup manifest is missing or invalid")
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxManifest+1))
	if err != nil || int64(len(data)) != header.Size || len(data) > maxManifest {
		return Manifest{}, errors.New("backup manifest is truncated or oversized")
	}
	var manifest Manifest
	decoderErr := json.Unmarshal(data, &manifest)
	if decoderErr != nil || manifest.FormatVersion != FormatVersion || manifest.Version == "" || manifest.BuildID == "" || manifest.DatabaseSchema < 1 || len(manifest.Files) > maxEntries {
		return Manifest{}, errors.New("backup manifest metadata is invalid or incompatible")
	}
	return manifest, nil
}

// Validate checks the full compressed stream, safe paths, required contents,
// per-file hashes, and compatibility before returning the manifest.
func Validate(path string) (Manifest, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxArchiveSize {
		return Manifest{}, errors.New("backup must be a regular .bak file within the size limit")
	}
	if filepath.Ext(path) != ".bak" {
		return Manifest{}, errors.New("backup archive must use the .bak extension")
	}
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, err
	}
	defer file.Close()
	gz, err := gzip.NewReader(io.LimitReader(file, maxArchiveSize+1))
	if err != nil {
		return Manifest{}, errors.New("backup gzip stream is invalid")
	}
	defer gz.Close()
	tarReader := tar.NewReader(gz)
	manifest, err := readManifest(tarReader)
	if err != nil {
		return Manifest{}, err
	}
	expected := make(map[string]File, len(manifest.Files))
	for _, item := range manifest.Files {
		if !safePath(item.Path) || item.Size < 0 || item.Size > maxArchiveSize || len(item.SHA256) != 64 || strings.ToLower(item.SHA256) != item.SHA256 {
			return Manifest{}, errors.New("backup manifest contains an invalid file entry")
		}
		if _, exists := expected[item.Path]; exists {
			return Manifest{}, errors.New("backup manifest contains a duplicate file path")
		}
		expected[item.Path] = item
	}
	seen := make(map[string]bool, len(expected))
	var pointerMetadata bytes.Buffer
	var expanded int64
	for path := range expected {
		if path == "data/site-content/current" || path == "data/site-content/previous" {
			return Manifest{}, errors.New("backup must store public-site pointers as validated metadata")
		}
	}
	for entries := 0; ; entries++ {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, errors.New("backup archive is truncated or corrupt")
		}
		if entries >= maxEntries || header.Typeflag != tar.TypeReg || !safePath(header.Name) || header.Size < 0 || header.Size > maxArchiveSize-expanded {
			return Manifest{}, errors.New("backup archive contains an unsafe or oversized entry")
		}
		item, ok := expected[header.Name]
		isPointerMetadata := header.Name == "data/site-content/"+webcontent.BackupPointersFile
		if !ok || seen[header.Name] || item.Size != header.Size || uint32(header.Mode&0o777) != item.Mode || (isPointerMetadata && (item.Size < 1 || item.Size > 4096 || item.Mode != 0o600)) {
			return Manifest{}, errors.New("backup archive does not match its manifest")
		}
		hash := sha256.New()
		var target io.Writer = hash
		if isPointerMetadata {
			target = io.MultiWriter(hash, &pointerMetadata)
		}
		written, err := io.Copy(target, io.LimitReader(tarReader, item.Size+1))
		if err != nil || written != item.Size || hex.EncodeToString(hash.Sum(nil)) != item.SHA256 {
			return Manifest{}, errors.New("backup file checksum or size is invalid")
		}
		seen[header.Name] = true
		expanded += written
	}
	if len(seen) != len(expected) || !seen[".env"] || !seen["compose.yaml"] || !seen["config/admin.json"] || !seen["config/totp.key"] || !seen["data/whitelist.json"] || !seen["data/totp-state.json"] {
		return Manifest{}, errors.New("backup is missing required application state")
	}
	if pointerMetadata.Len() > 0 {
		if err := webcontent.ValidateBackupPointerMetadata(pointerMetadata.Bytes(), func(path string) bool { _, ok := expected[path]; return ok }); err != nil {
			return Manifest{}, err
		}
	}
	return manifest, nil
}

// Extract validates the complete archive before creating the destination and
// writes only regular files beneath a newly-created private directory.
func Extract(path, destination string) (Manifest, error) {
	manifest, err := Validate(path)
	if err != nil {
		return Manifest{}, err
	}
	if _, err := os.Lstat(destination); err == nil {
		return Manifest{}, errors.New("backup restore staging destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, err
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return Manifest{}, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(destination)
		}
	}()
	for _, name := range []string{"config", "data", "site"} {
		if err := os.Mkdir(filepath.Join(destination, name), 0o700); err != nil {
			return Manifest{}, err
		}
	}
	input, err := os.Open(path)
	if err != nil {
		return Manifest{}, err
	}
	defer input.Close()
	gz, err := gzip.NewReader(io.LimitReader(input, maxArchiveSize+1))
	if err != nil {
		return Manifest{}, err
	}
	defer gz.Close()
	tarReader := tar.NewReader(gz)
	secondManifest, err := readManifest(tarReader)
	if err != nil {
		return Manifest{}, err
	}
	expected := make(map[string]File, len(secondManifest.Files))
	for _, item := range secondManifest.Files {
		expected[item.Path] = item
	}
	seen := make(map[string]bool, len(expected))
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header.Typeflag != tar.TypeReg || !safePath(header.Name) {
			return Manifest{}, errors.New("backup changed after validation")
		}
		item, ok := expected[header.Name]
		if !ok || seen[header.Name] || item.Size != header.Size || uint32(header.Mode&0o777) != item.Mode {
			return Manifest{}, errors.New("backup changed after validation")
		}
		path := filepath.Join(destination, filepath.FromSlash(header.Name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return Manifest{}, err
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(header.Mode&0o777))
		if err != nil {
			return Manifest{}, err
		}
		hash := sha256.New()
		copied, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(tarReader, header.Size))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || copied != item.Size || hex.EncodeToString(hash.Sum(nil)) != item.SHA256 {
			return Manifest{}, errors.Join(errors.New("backup file checksum or size changed after validation"), copyErr, closeErr)
		}
		seen[header.Name] = true
	}
	if len(seen) != len(expected) {
		return Manifest{}, errors.New("backup changed after validation")
	}
	if err := webcontent.RestoreBackupPointers(filepath.Join(destination, "data", "site-content")); err != nil {
		return Manifest{}, fmt.Errorf("restore validated public-site pointers: %w", err)
	}
	complete = true
	return manifest, nil
}
