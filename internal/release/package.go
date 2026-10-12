// Package release validates and safely extracts self-contained application
// packages produced by packaging/package.ps1.
package release

import (
	"archive/tar"
	"compress/gzip"
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
)

const maxPackageBytes int64 = 2 << 30

var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

// ValidVersion reports whether a value matches the release package version
// format accepted by this installer.
func ValidVersion(value string) bool { return versionPattern.MatchString(value) }

type Manifest struct {
	SchemaVersion int            `json:"schema_version"`
	Version       string         `json:"version"`
	Platform      string         `json:"platform"`
	Images        []Image        `json:"images"`
	Files         []ManifestFile `json:"files"`
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

// ExtractAndValidate expands an untrusted archive into an empty destination,
// rejects path traversal and links, then verifies every regular file against
// the package's manifest before returning it.
func ExtractAndValidate(archivePath, destination string) (Manifest, error) {
	if archivePath == "" || destination == "" {
		return Manifest{}, errors.New("package and destination paths are required")
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
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("read release archive: %w", err)
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
		case tar.TypeReg, tar.TypeRegA:
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
			mode := os.FileMode(0o644)
			if header.Mode&0o111 != 0 {
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
	if manifest.SchemaVersion != 1 || manifest.Platform != "linux/amd64" || !versionPattern.MatchString(manifest.Version) {
		return Manifest{}, errors.New("unsupported package schema, version, or platform")
	}
	if err := validateImages(manifest); err != nil {
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
	for _, required := range []string{"images.tar", "bin/admin-linux-amd64", "bin/proxyctl-linux-amd64", "compose.yaml", ".env.example", "config/Caddyfile", "config/whitelist.caddy", "site/index.html", "DEPLOYMENT.md"} {
		if _, err := os.Stat(filepath.Join(destination, required)); err != nil {
			return Manifest{}, fmt.Errorf("release package is missing required file %s", required)
		}
	}
	return manifest, nil
}

func validateImages(manifest Manifest) error {
	want := map[string]bool{
		"jellyfin-proxy/admin:" + manifest.Version:     false,
		"jellyfin-proxy/wireguard:" + manifest.Version: false,
		"caddy:2.10.2-alpine":                          false,
		"alpine:3.22":                                  false,
	}
	if len(manifest.Images) != len(want) {
		return errors.New("package must contain exactly the four supported deployment images")
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
