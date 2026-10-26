package release

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyImageArchiveMatchesConfigDigestsAndPlatforms(t *testing.T) {
	expected, archive := makeDockerArchiveFixture(t)
	if err := VerifyImageArchive(archive, expected); err != nil {
		t.Fatal(err)
	}
}

func TestRegularTarTypeAcceptsLegacyZeroFlag(t *testing.T) {
	if !isRegularTarType(legacyTarRegularTypeflag) || !isRegularTarType(tar.TypeReg) {
		t.Fatal("regular tar type check rejected a supported regular-file flag")
	}
	if isRegularTarType(tar.TypeDir) || isRegularTarType(tar.TypeSymlink) {
		t.Fatal("regular tar type check accepted a directory or symlink")
	}
}

func TestVerifyImageArchiveRejectsDigestMismatch(t *testing.T) {
	expected, archive := makeDockerArchiveFixture(t)
	expected[0].ImageID = "sha256:" + strings.Repeat("f", 64)
	if err := VerifyImageArchive(archive, expected); err == nil || !strings.Contains(err.Error(), "config digest") {
		t.Fatalf("digest mismatch error = %v", err)
	}
}

func TestVerifyImageArchiveRejectsWrongPlatform(t *testing.T) {
	expected, archive := makeDockerArchiveFixture(t)
	if err := os.Remove(archive); err != nil {
		t.Fatal(err)
	}
	archive = writeDockerArchive(t, expected, "arm64")
	if err := VerifyImageArchive(archive, expected); err == nil || !strings.Contains(err.Error(), "not linux/amd64") {
		t.Fatalf("wrong platform error = %v", err)
	}
}

func makeDockerArchiveFixture(t *testing.T) ([]Image, string) {
	t.Helper()
	refs := []string{"jellyfin-proxy/admin:1.0.0-dev", "jellyfin-proxy/hostmetrics:1.0.0-dev", "jellyfin-proxy/wireguard:1.0.0-dev", "jellyfin-proxy/caddy:1.0.0-dev", "jellyfin-proxy/security:1.0.0-dev", "alpine:3.24.2"}
	configs := make(map[string][]byte, len(refs))
	expected := make([]Image, 0, len(refs))
	for _, reference := range refs {
		config, err := json.Marshal(map[string]string{"os": "linux", "architecture": "amd64", "comment": reference})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(config)
		configs[reference] = config
		expected = append(expected, Image{Reference: reference, ImageID: "sha256:" + hex.EncodeToString(digest[:])})
	}
	return expected, writeDockerArchiveWithConfigs(t, expected, configs)
}

func writeDockerArchive(t *testing.T, expected []Image, architecture string) string {
	t.Helper()
	configs := make(map[string][]byte, len(expected))
	for _, image := range expected {
		config, err := json.Marshal(map[string]string{"os": "linux", "architecture": architecture, "comment": image.Reference})
		if err != nil {
			t.Fatal(err)
		}
		configs[image.Reference] = config
	}
	return writeDockerArchiveWithConfigs(t, expected, configs)
}

func writeDockerArchiveWithConfigs(t *testing.T, expected []Image, configs map[string][]byte) string {
	t.Helper()
	type archiveEntry struct {
		Config   string   `json:"Config"`
		RepoTags []string `json:"RepoTags"`
	}
	entries := make([]archiveEntry, 0, len(expected))
	configPaths := make(map[string][]byte, len(expected))
	for _, image := range expected {
		digest := sha256.Sum256(configs[image.Reference])
		configPath := "blobs/sha256/" + hex.EncodeToString(digest[:])
		entries = append(entries, archiveEntry{Config: configPath, RepoTags: []string{image.Reference}})
		configPaths[configPath] = configs[image.Reference]
	}
	manifest, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "images.tar")
	file, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	write := func(name string, data []byte) {
		t.Helper()
		if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range configPaths {
		write(name, data)
	}
	write("manifest.json", manifest)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return archive
}
