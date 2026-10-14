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
	manifest, err := ExtractAndValidate(archive, destination)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != "1.0.0-dev" || manifest.Platform != "linux/amd64" {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	if data, err := os.ReadFile(filepath.Join(destination, "site", "index.html")); err != nil || string(data) != "site" {
		t.Fatalf("extracted site: %q, %v", data, err)
	}
	for _, path := range []string{"bin/admin-linux-amd64", "bin/proxyctl-linux-amd64"} {
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

func TestExtractAndValidateRejectsTamperedFile(t *testing.T) {
	archive := makePackageArchive(t, "1.0.0-dev", true)
	_, err := ExtractAndValidate(archive, filepath.Join(t.TempDir(), "extracted"))
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("tampered package error = %v", err)
	}
}

func TestExtractAndValidateRejectsPathTraversal(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "bad.tar.gz")
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
	_, err = ExtractAndValidate(archive, filepath.Join(t.TempDir(), "extracted"))
	if err == nil || !strings.Contains(err.Error(), "unsafe package path") {
		t.Fatalf("path traversal error = %v", err)
	}
}

func makePackageArchive(t *testing.T, version string, tamper bool) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"images.tar":               "docker images",
		"bin/admin-linux-amd64":    "admin",
		"bin/proxyctl-linux-amd64": "proxyctl",
		"compose.yaml":             "services: {}\n",
		".env.example":             "BASE_DOMAIN=example.invalid\n",
		"config/Caddyfile":         "example.invalid {}\n",
		"config/whitelist.caddy":   "respond 403\n",
		"site/index.html":          "site",
		"DEPLOYMENT.md":            "deployment",
	}
	manifest := Manifest{SchemaVersion: 1, Version: version, Platform: "linux/amd64", Images: []Image{
		{Reference: "jellyfin-proxy/admin:" + version, ImageID: "sha256:" + strings.Repeat("a", 64)},
		{Reference: "jellyfin-proxy/hostmetrics:" + version, ImageID: "sha256:" + strings.Repeat("b", 64)},
		{Reference: "jellyfin-proxy/wireguard:" + version, ImageID: "sha256:" + strings.Repeat("c", 64)},
		{Reference: "jellyfin-proxy/caddy:" + version, ImageID: "sha256:" + strings.Repeat("d", 64)},
		{Reference: "alpine:3.22", ImageID: "sha256:" + strings.Repeat("e", 64)},
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
	archive := filepath.Join(t.TempDir(), "package.tar.gz")
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
