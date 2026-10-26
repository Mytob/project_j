package release

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractAndValidatePackage(t *testing.T) {
	archive := makePackageArchive(t, "1.0.0-dev", false)
	destination := filepath.Join(t.TempDir(), "extracted")
	manifest, err := ExtractAndValidate(archive, destination, mustPackageHash(t, archive))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != "1.0.0-dev" || manifest.Platform != "linux/amd64" {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	if data, err := os.ReadFile(filepath.Join(destination, "site", "index.html")); err != nil || string(data) != "site" {
		t.Fatalf("extracted site: %q, %v", data, err)
	}
	for _, path := range []string{"bin/admin-linux-amd64", "bin/proxyctl-linux-amd64", "bin/maintenance-linux-amd64"} {
		info, err := os.Stat(filepath.Join(destination, path))
		if err != nil || info.Mode().Perm() != 0o755 {
			t.Fatalf("extracted executable %s mode = %v, %v", path, info, err)
		}
	}
	info, err := os.Stat(filepath.Join(destination, "compose.yaml"))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("extracted data file mode = %v, %v", info, err)
	}
}

func TestExtractAndValidatePackageAcceptsLegacyZeroRegularFileFlag(t *testing.T) {
	archive := makePackageArchive(t, "1.0.0-dev", false, legacyTarRegularTypeflag)
	destination := filepath.Join(t.TempDir(), "extracted")
	if _, err := ExtractAndValidate(archive, destination, mustPackageHash(t, archive)); err != nil {
		t.Fatalf("extract package with legacy regular-file flag: %v", err)
	}
}

func TestExtractAndValidateRejectsTamperedFile(t *testing.T) {
	archive := makePackageArchive(t, "1.0.0-dev", true)
	_, err := ExtractAndValidate(archive, filepath.Join(t.TempDir(), "extracted"), mustPackageHash(t, archive))
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("tampered package error = %v", err)
	}
}

func TestExtractAndValidateRequiresIndependentWholePackageChecksum(t *testing.T) {
	archive := makePackageArchive(t, "1.0.0-dev", false)
	destination := filepath.Join(t.TempDir(), "must-not-be-created")
	if _, err := ExtractAndValidate(archive, destination, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong package checksum error = %v", err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("destination was created before checksum verification: %v", err)
	}
	if _, err := ExtractAndValidate(archive, destination, ""); err == nil || !strings.Contains(err.Error(), "independently supplied") {
		t.Fatalf("missing package checksum error = %v", err)
	}
}

func TestExtractAndValidateRejectsLegacyPackageExtension(t *testing.T) {
	archive := makePackageArchive(t, "1.0.0-dev", false)
	legacyPath := filepath.Join(t.TempDir(), "legacy.tar.gz")
	if err := os.Rename(archive, legacyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractAndValidate(legacyPath, filepath.Join(t.TempDir(), "extracted"), mustPackageHash(t, legacyPath)); err == nil || !strings.Contains(err.Error(), ".pkg extension") {
		t.Fatalf("legacy package extension error = %v", err)
	}
}

func TestValidateManifestRejectsV151UpgradeSource(t *testing.T) {
	archive := makePackageArchive(t, "1.6.0-dev", false)
	manifest, err := ValidatePackage(archive, mustPackageHash(t, archive))
	if err != nil {
		t.Fatal(err)
	}
	manifest.SupportedUpgradeSources = []string{"1.5.1-dev"}
	if err := ValidateManifest(manifest); err == nil || !strings.Contains(err.Error(), "not a supported migration source") {
		t.Fatalf("v1.5.1 migration source error = %v", err)
	}
}

func TestVerifyRetainedReleaseFilesRejectsTamperingAndLinks(t *testing.T) {
	archive := makePackageArchive(t, "1.6.0-dev", false)
	destination := filepath.Join(t.TempDir(), "release")
	manifest, err := ExtractAndValidate(archive, destination, mustPackageHash(t, archive))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRetainedFiles(destination, manifest); err != nil {
		t.Fatalf("verify intact retained release: %v", err)
	}
	if err := os.WriteFile(filepath.Join(destination, "site", "index.html"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRetainedFiles(destination, manifest); err == nil || !strings.Contains(err.Error(), "size changed") {
		t.Fatalf("tampered retained file error = %v", err)
	}
	if err := os.Remove(filepath.Join(destination, "site", "index.html")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(destination, "compose.yaml"), filepath.Join(destination, "site", "index.html")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := VerifyRetainedFiles(destination, manifest); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("retained symlink error = %v", err)
	}
}

func TestExtractAndValidateRejectsPathTraversal(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "bad.pkg")
	file, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(file)
	writer := tar.NewWriter(compressed)
	if err := writer.WriteHeader(&tar.Header{Name: "../outside", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = ExtractAndValidate(archive, filepath.Join(t.TempDir(), "extracted"), mustPackageHash(t, archive))
	if err == nil || !strings.Contains(err.Error(), "unsafe package path") {
		t.Fatalf("path traversal error = %v", err)
	}
}

func makePackageArchive(t *testing.T, version string, tamper bool, regularTypeflag ...byte) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"images.tar":                  "docker images",
		"bin/admin-linux-amd64":       "admin",
		"bin/proxyctl-linux-amd64":    "proxyctl",
		"bin/maintenance-linux-amd64": "maintenance",
		"compose.yaml":                "services: {}\n",
		".env.example":                "BASE_DOMAIN=example.invalid\n",
		"config/Caddyfile":            "example.invalid {}\n",
		"config/whitelist.caddy":      "respond 403\n",
		"site/index.html":             "site",
		"DEPLOYMENT.md":               "deployment",
	}
	manifest := Manifest{SchemaVersion: 2, Version: version, BuildID: "abcdef123456", TargetOS: "ubuntu-26.04", Architecture: "amd64", Platform: "linux/amd64", MinimumProxyctlVersion: "1.6.0", DatabaseSchemaMinimum: 1, DatabaseSchemaMaximum: 1, SupportedUpgradeSources: []string{}, Images: []Image{
		{Reference: "jellyfin-proxy/admin:" + version, ImageID: "sha256:" + strings.Repeat("a", 64)},
		{Reference: "jellyfin-proxy/hostmetrics:" + version, ImageID: "sha256:" + strings.Repeat("b", 64)},
		{Reference: "jellyfin-proxy/wireguard:" + version, ImageID: "sha256:" + strings.Repeat("c", 64)},
		{Reference: "jellyfin-proxy/caddy:" + version, ImageID: "sha256:" + strings.Repeat("d", 64)},
		{Reference: "jellyfin-proxy/security:" + version, ImageID: "sha256:" + strings.Repeat("e", 64)},
		{Reference: "alpine:3.24.2", ImageID: "sha256:" + strings.Repeat("f", 64)},
	}}
	for path, content := range files {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256([]byte(content))
		manifest.Files = append(manifest.Files, ManifestFile{Path: path, SizeBytes: int64(len(content)), SHA256: hex.EncodeToString(hash[:])})
	}
	if tamper {
		if err := os.WriteFile(filepath.Join(root, "site", "index.html"), []byte("evil"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "package.pkg")
	file, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(file)
	writer := tar.NewWriter(compressed)
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := "./"
		if rel != "." {
			name += filepath.ToSlash(rel)
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = name
		if info.Mode().IsRegular() && len(regularTypeflag) > 0 {
			header.Typeflag = regularTypeflag[0]
		}
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		_, err = io.Copy(writer, input)
		return err
	})
	if err == nil {
		err = writer.Close()
	}
	if err == nil {
		err = compressed.Close()
	}
	if err == nil {
		err = file.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	return archive
}

func mustPackageHash(t *testing.T, path string) string {
	t.Helper()
	hash, err := SHA256File(path)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}
