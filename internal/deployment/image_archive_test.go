package deployment

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Mytob/project_j/internal/release"
)

func fakeReleaseImages(version string) ([]release.Image, map[string][]byte) {
	refs := []string{"jellyfin-proxy/admin:" + version, "jellyfin-proxy/hostmetrics:" + version, "jellyfin-proxy/wireguard:" + version, "jellyfin-proxy/caddy:" + version, "jellyfin-proxy/security:" + version, "alpine:3.24.2"}
	images := make([]release.Image, 0, len(refs))
	configs := make(map[string][]byte, len(refs))
	for _, reference := range refs {
		config, _ := fakeImageConfig(reference)
		digest := sha256.Sum256(config)
		images = append(images, release.Image{Reference: reference, ImageID: "sha256:" + hex.EncodeToString(digest[:])})
		configs[reference] = config
	}
	return images, configs
}

func writeFakeDockerArchive(path string, references []string) error {
	images := make([]release.Image, 0, len(references))
	configs := make(map[string][]byte, len(references))
	for _, reference := range references {
		config, err := fakeImageConfig(reference)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(config)
		images = append(images, release.Image{Reference: reference, ImageID: "sha256:" + hex.EncodeToString(digest[:])})
		configs[reference] = config
	}
	data, err := makeFakeDockerArchive(images, configs)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func fakeImageConfig(reference string) ([]byte, error) {
	return json.Marshal(struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Comment      string `json:"comment"`
	}{OS: "linux", Architecture: "amd64", Comment: reference})
}

func makeFakeDockerArchive(images []release.Image, configs map[string][]byte) ([]byte, error) {
	type archiveEntry struct {
		Config   string   `json:"Config"`
		RepoTags []string `json:"RepoTags"`
	}
	entries := make([]archiveEntry, 0, len(images))
	configPaths := make(map[string][]byte, len(images))
	for _, image := range images {
		config, ok := configs[image.Reference]
		if !ok {
			return nil, fmt.Errorf("missing fake config for %s", image.Reference)
		}
		digest := sha256.Sum256(config)
		configPath := "blobs/sha256/" + hex.EncodeToString(digest[:])
		entries = append(entries, archiveEntry{Config: configPath, RepoTags: []string{image.Reference}})
		configPaths[configPath] = config
	}
	manifest, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	write := func(name string, data []byte) error {
		if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data))}); err != nil {
			return err
		}
		_, err := writer.Write(data)
		return err
	}
	if err := write("manifest.json", manifest); err != nil {
		return nil, err
	}
	for name, config := range configPaths {
		if err := write(name, config); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
