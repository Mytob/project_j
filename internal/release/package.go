// Package release validates and safely extracts self-contained application
// packages produced by packaging/package.ps1.
package release

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	maxPackageBytes      int64 = 2 << 30
	maxArchiveEntries          = 10000
	packageSchemaVersion       = 2
)

var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

// ValidVersion reports whether a value matches the release package version
// format accepted by this installer.
func ValidVersion(value string) bool { return versionPattern.MatchString(value) }

type Manifest struct {
	SchemaVersion           int            `json:"schema_version"`
	Version                 string         `json:"version"`
	BuildID                 string         `json:"build_id"`
	TargetOS                string         `json:"target_os"`
	Architecture            string         `json:"architecture"`
	Platform                string         `json:"platform"`
	SupportedUpgradeSources []string       `json:"supported_upgrade_sources"`
	MinimumProxyctlVersion  string         `json:"minimum_proxyctl_version"`
	DatabaseSchemaMinimum   int            `json:"database_schema_minimum"`
	DatabaseSchemaMaximum   int            `json:"database_schema_maximum"`
	Images                  []Image        `json:"images"`
	Files                   []ManifestFile `json:"files"`
}

type Image struct {
	Reference string `json:"reference"`
	ImageID   string `json:"image_id"`
}

type ManifestFile struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

// SHA256File returns the lowercase SHA-256 checksum for a regular file.
func SHA256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("checksum source is not a regular file")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// ValidatePackage performs full archive and manifest validation without
// retaining extracted files. It is used before any host changes are approved.
func ValidatePackage(archivePath, expectedSHA256 string) (Manifest, error) {
	directory, err := os.MkdirTemp("", "jellyfin-proxy-package-check-")
	if err != nil {
		return Manifest{}, fmt.Errorf("create package validation workspace: %w", err)
	}
	defer os.RemoveAll(directory)
	return ExtractAndValidate(archivePath, filepath.Join(directory, "package"), expectedSHA256)
}

// ExtractAndValidate verifies the independently supplied whole-package SHA-256
// before expanding an untrusted .pkg archive into an empty destination. It
// then rejects unsafe entries and verifies every regular file against the
// package manifest.
func ExtractAndValidate(archivePath, destination, expectedSHA256 string) (Manifest, error) {
	if archivePath == "" || destination == "" {
		return Manifest{}, errors.New("package and destination paths are required")
	}
	if filepath.Ext(archivePath) != ".pkg" {
		return Manifest{}, errors.New("release package must use the .pkg extension")
	}
	if len(expectedSHA256) != sha256.Size*2 {
		return Manifest{}, errors.New("an independently supplied 64-character package SHA-256 is required")
	}
	if _, err := hex.DecodeString(expectedSHA256); err != nil {
		return Manifest{}, errors.New("expected package SHA-256 must contain only hexadecimal characters")
	}
	packageInfo, err := os.Stat(archivePath)
	if err != nil || !packageInfo.Mode().IsRegular() {
		return Manifest{}, errors.New("release package is not a readable regular file")
	}
	if packageInfo.Size() <= 0 || packageInfo.Size() > maxPackageBytes {
		return Manifest{}, errors.New("release package exceeds the 2 GiB compressed size limit or is empty")
	}
	actualSHA256, err := SHA256File(archivePath)
	if err != nil {
		return Manifest{}, fmt.Errorf("hash release package: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(actualSHA256), []byte(strings.ToLower(expectedSHA256))) != 1 {
		return Manifest{}, errors.New("release package SHA-256 does not match the independently supplied checksum")
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return Manifest{}, fmt.Errorf("create package extraction directory: %w", err)
	}
	file, err := os.Open(archivePath)
	if err != nil {
		return Manifest{}, fmt.Errorf("open release package: %w", err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return Manifest{}, fmt.Errorf("open release archive: %w", err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	seen := map[string]bool{}
	var expanded int64
	entries := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("read release archive: %w", err)
		}
		entries++
		if entries > maxArchiveEntries {
			return Manifest{}, errors.New("release package exceeds the 10000-entry limit")
		}
		if header.Name == "." || header.Name == "./" {
			if header.Typeflag != tar.TypeDir {
				return Manifest{}, fmt.Errorf("unsafe package path %q", header.Name)
			}
			continue
		}
		name := strings.TrimPrefix(header.Name, "./")
		if name == "" || strings.Contains(name, "\\") || !filepath.IsLocal(filepath.FromSlash(name)) {
			return Manifest{}, fmt.Errorf("unsafe package path %q", header.Name)
		}
		name = filepath.Clean(filepath.FromSlash(name))
		if name == "." {
			continue
		}
		if seen[name] {
			return Manifest{}, fmt.Errorf("duplicate package path %q", name)
		}
		seen[name] = true
		target := filepath.Join(destination, name)
		if !within(destination, target) {
			return Manifest{}, fmt.Errorf("package path escapes destination: %q", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			delete(seen, name)
			if err := os.MkdirAll(target, 0o755); err != nil {
				return Manifest{}, err
			}
		case tar.TypeReg, legacyTarRegularTypeflag:
			if header.Size < 0 || expanded+header.Size > maxPackageBytes {
				return Manifest{}, errors.New("release package exceeds the 2 GiB expanded size limit")
			}
			expanded += header.Size
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return Manifest{}, err
			}
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return Manifest{}, fmt.Errorf("create package file %s: %w", name, err)
			}
			_, copyErr := io.CopyN(out, reader, header.Size)
			closeErr := out.Close()
			if copyErr != nil {
				return Manifest{}, fmt.Errorf("extract package file %s: %w", name, copyErr)
			}
			if closeErr != nil {
				return Manifest{}, closeErr
			}
			// Windows-built release archives may not preserve Unix executable
			// bits. Restore executable permission only for the two known Linux
			// programs; never trust arbitrary archive mode bits.
			mode := os.FileMode(0o644)
			if name == "bin/admin-linux-amd64" || name == "bin/proxyctl-linux-amd64" || name == "bin/maintenance-linux-amd64" {
				mode = 0o755
			}
			if err := os.Chmod(target, mode); err != nil {
				return Manifest{}, err
			}
		default:
			return Manifest{}, fmt.Errorf("unsupported package entry type %d at %q", header.Typeflag, header.Name)
		}
	}
	manifestPath := filepath.Join(destination, "manifest.json")
	manifestInfo, err := os.Stat(manifestPath)
	if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Size() > 4<<20 {
		return Manifest{}, errors.New("package manifest is missing, not a regular file, or too large")
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return Manifest{}, fmt.Errorf("package manifest is missing: %w", err)
	}
	var manifest Manifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode package manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("package manifest contains trailing JSON data")
	}
	if err := ValidateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	listed := make(map[string]ManifestFile, len(manifest.Files))
	for _, entry := range manifest.Files {
		if entry.Path == "" || strings.Contains(entry.Path, "\\") || !filepath.IsLocal(filepath.FromSlash(entry.Path)) || entry.Path == "manifest.json" {
			return Manifest{}, fmt.Errorf("unsafe manifest path %q", entry.Path)
		}
		clean := filepath.Clean(filepath.FromSlash(entry.Path))
		if clean != filepath.FromSlash(entry.Path) {
			return Manifest{}, fmt.Errorf("non-canonical manifest path %q", entry.Path)
		}
		if _, exists := listed[clean]; exists {
			return Manifest{}, fmt.Errorf("duplicate manifest path %q", clean)
		}
		if entry.SizeBytes < 0 || len(entry.SHA256) != 64 {
			return Manifest{}, fmt.Errorf("invalid manifest metadata for %q", clean)
		}
		if _, err := hex.DecodeString(entry.SHA256); err != nil {
			return Manifest{}, fmt.Errorf("invalid SHA-256 for %q", clean)
		}
		listed[clean] = entry
	}
	for path := range seen {
		if path == "manifest.json" {
			continue
		}
		entry, ok := listed[path]
		if !ok {
			return Manifest{}, fmt.Errorf("unlisted file in release package: %s", path)
		}
		fullPath := filepath.Join(destination, path)
		info, err := os.Lstat(fullPath)
		if err != nil || !info.Mode().IsRegular() {
			return Manifest{}, fmt.Errorf("manifest path is not a regular file: %s", path)
		}
		if info.Size() != entry.SizeBytes {
			return Manifest{}, fmt.Errorf("package file size mismatch: %s", path)
		}
		hash, err := fileSHA256(fullPath)
		if err != nil || hash != entry.SHA256 {
			return Manifest{}, fmt.Errorf("package file SHA-256 mismatch: %s", path)
		}
		delete(listed, path)
	}
	if len(listed) != 0 {
		for path := range listed {
			return Manifest{}, fmt.Errorf("manifest file is missing from archive: %s", path)
		}
	}
	for _, required := range []string{"images.tar", "bin/admin-linux-amd64", "bin/proxyctl-linux-amd64", "bin/maintenance-linux-amd64", "compose.yaml", ".env.example", "config/Caddyfile", "config/whitelist.caddy", "site/index.html", "DEPLOYMENT.md"} {
		if _, err := os.Stat(filepath.Join(destination, required)); err != nil {
			return Manifest{}, fmt.Errorf("release package is missing required file %s", required)
		}
	}
	return manifest, nil
}

// ValidateManifest checks release compatibility metadata and the exact
// supported image set. Files are verified separately during extraction.
func ValidateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != packageSchemaVersion || manifest.Platform != "linux/amd64" ||
		manifest.TargetOS != "ubuntu-26.04" || manifest.Architecture != "amd64" ||
		!versionPattern.MatchString(manifest.Version) || !validBuildID(manifest.BuildID) ||
		!versionPattern.MatchString(manifest.MinimumProxyctlVersion) ||
		manifest.DatabaseSchemaMinimum < 1 || manifest.DatabaseSchemaMaximum < manifest.DatabaseSchemaMinimum {
		return errors.New("unsupported package schema, version, or platform")
	}
	if len(manifest.Files) > maxArchiveEntries || len(manifest.Images) == 0 || len(manifest.SupportedUpgradeSources) > 100 {
		return errors.New("package manifest exceeds supported collection limits")
	}
	upgradeSources := make(map[string]bool, len(manifest.SupportedUpgradeSources))
	for _, source := range manifest.SupportedUpgradeSources {
		if !versionPattern.MatchString(source) || source == manifest.Version || upgradeSources[source] {
			return fmt.Errorf("invalid or duplicate supported upgrade source %q", source)
		}
		baseVersion := strings.SplitN(strings.SplitN(source, "-", 2)[0], "+", 2)[0]
		if baseVersion == "1.5.1" {
			return errors.New("v1.5.1 is not a supported migration source for the fresh-install v1.6 release")
		}
		upgradeSources[source] = true
	}
	return validateImages(manifest)
}

// VerifyRetainedFiles rechecks package contents already present on disk, such
// as when resuming an install after reboot. It refuses links, unsafe paths,
// missing files, unexpected files, size changes, and checksum changes.
func VerifyRetainedFiles(directory string, manifest Manifest) error {
	if err := ValidateManifest(manifest); err != nil {
		return err
	}
	root, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("retained release root is missing or unsafe")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	expected := make(map[string]ManifestFile, len(manifest.Files))
	for _, entry := range manifest.Files {
		if entry.Path == "" || strings.Contains(entry.Path, "\\") || !filepath.IsLocal(filepath.FromSlash(entry.Path)) || entry.Path == "manifest.json" {
			return fmt.Errorf("unsafe retained manifest path %q", entry.Path)
		}
		clean := filepath.Clean(filepath.FromSlash(entry.Path))
		if clean != filepath.FromSlash(entry.Path) {
			return fmt.Errorf("non-canonical retained manifest path %q", entry.Path)
		}
		if _, exists := expected[clean]; exists {
			return fmt.Errorf("duplicate retained manifest path %q", clean)
		}
		expected[clean] = entry
	}
	seen := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, item os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if item.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("retained release contains a symbolic link: %s", path)
		}
		if item.IsDir() {
			return nil
		}
		if !item.Type().IsRegular() {
			return fmt.Errorf("retained release contains a non-regular file: %s", path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative == "manifest.json" {
			return nil
		}
		entry, ok := expected[relative]
		if !ok {
			return fmt.Errorf("retained release contains an unlisted file: %s", relative)
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || (resolved != resolvedRoot && !strings.HasPrefix(resolved, resolvedRoot+string(os.PathSeparator))) {
			return fmt.Errorf("retained package path escapes release root: %s", relative)
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() != entry.SizeBytes {
			return fmt.Errorf("retained release file size changed: %s", relative)
		}
		hash, err := SHA256File(path)
		if err != nil || hash != entry.SHA256 {
			return fmt.Errorf("retained release checksum changed: %s", relative)
		}
		seen[relative] = true
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return errors.New("retained release is missing one or more manifest files")
	}
	return nil
}

func validateImages(manifest Manifest) error {
	want := map[string]bool{
		"jellyfin-proxy/admin:" + manifest.Version:       false,
		"jellyfin-proxy/hostmetrics:" + manifest.Version: false,
		"jellyfin-proxy/wireguard:" + manifest.Version:   false,
		"jellyfin-proxy/caddy:" + manifest.Version:       false,
		"jellyfin-proxy/security:" + manifest.Version:    false,
		"alpine:3.24.2": false,
	}
	if len(manifest.Images) != len(want) {
		return errors.New("package must contain exactly the six supported deployment images")
	}
	for _, image := range manifest.Images {
		if _, ok := want[image.Reference]; !ok || want[image.Reference] {
			return fmt.Errorf("unsupported or duplicate package image %q", image.Reference)
		}
		if !strings.HasPrefix(image.ImageID, "sha256:") || len(image.ImageID) != len("sha256:")+64 {
			return fmt.Errorf("invalid package image digest for %s", image.Reference)
		}
		if _, err := hex.DecodeString(strings.TrimPrefix(image.ImageID, "sha256:")); err != nil {
			return fmt.Errorf("invalid package image digest for %s", image.Reference)
		}
		want[image.Reference] = true
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func validBuildID(value string) bool {
	if strings.HasSuffix(value, "-dirty") {
		value = strings.TrimSuffix(value, "-dirty")
	}
	return len(value) >= 7 && len(value) <= 40 && isLowerHex(value)
}

func isLowerHex(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return value != ""
}

func within(root, target string) bool {
	r, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	t, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(r, t)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
