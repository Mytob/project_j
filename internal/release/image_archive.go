package release

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"strings"
)

const maxImageConfigBytes = 16 << 20

type dockerArchiveImage struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
}

type dockerImageConfig struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

// VerifyImageArchive checks the platform-specific config digests and tags in a
// Docker image-save archive. Config digests remain stable across Docker Engine
// versions, unlike image inspect's Id, which may be an OCI manifest digest.
func VerifyImageArchive(archivePath string, expected []Image) error {
	if archivePath == "" || len(expected) == 0 {
		return errors.New("image archive path and expected images are required")
	}
	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open Docker image archive: %w", err)
	}
	defer file.Close()

	want := make(map[string]Image, len(expected))
	for _, image := range expected {
		if image.Reference == "" || !strings.HasPrefix(image.ImageID, "sha256:") || len(image.ImageID) != len("sha256:")+64 {
			return errors.New("invalid expected Docker image reference or config digest")
		}
		if _, err := hex.DecodeString(strings.TrimPrefix(image.ImageID, "sha256:")); err != nil {
			return errors.New("invalid expected Docker image config digest")
		}
		if _, duplicate := want[image.Reference]; duplicate {
			return fmt.Errorf("duplicate expected Docker image %q", image.Reference)
		}
		want[image.Reference] = image
	}

	reader := tar.NewReader(file)
	var configsByPath map[string][]Image
	seenManifest := false
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read Docker image archive: %w", err)
		}
		if header.Name == "manifest.json" {
			if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
				return errors.New("Docker image archive manifest is not a regular file")
			}
			if seenManifest || header.Size < 0 || header.Size > 1<<20 {
				return errors.New("Docker image archive has a duplicate or oversized manifest")
			}
			seenManifest = true
			manifestBytes, err := io.ReadAll(io.LimitReader(reader, (1<<20)+1))
			if err != nil || int64(len(manifestBytes)) != header.Size {
				return errors.New("could not read Docker image archive manifest")
			}
			var entries []dockerArchiveImage
			if err := json.Unmarshal(manifestBytes, &entries); err != nil || len(entries) != len(expected) {
				return errors.New("Docker image archive has an invalid image manifest")
			}
			configsByPath = make(map[string][]Image, len(expected))
			seenReferences := make(map[string]bool, len(expected))
			for _, entry := range entries {
				configPath := entry.Config
				if configPath == "" || strings.Contains(configPath, "\\") || pathpkg.IsAbs(configPath) || pathpkg.Clean(configPath) != configPath || configPath == "." || strings.HasPrefix(configPath, "../") {
					return errors.New("Docker image archive contains an unsafe config path")
				}
				for _, reference := range entry.RepoTags {
					image, ok := want[reference]
					if !ok || seenReferences[reference] {
						return fmt.Errorf("Docker image archive contains an unsupported or duplicate image tag %q", reference)
					}
					seenReferences[reference] = true
					configsByPath[configPath] = append(configsByPath[configPath], image)
				}
			}
			if len(seenReferences) != len(expected) {
				return errors.New("Docker image archive is missing an expected image tag")
			}
		}
	}
	if !seenManifest {
		return errors.New("Docker image archive manifest is missing")
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close Docker image archive after reading manifest: %w", err)
	}
	file, err = os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("reopen Docker image archive to verify configs: %w", err)
	}
	defer file.Close()
	reader = tar.NewReader(file)
	seenConfigs := make(map[string]bool, len(configsByPath))
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read Docker image archive configs: %w", err)
		}
		images, isConfig := configsByPath[header.Name]
		if !isConfig {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || seenConfigs[header.Name] || header.Size < 0 || header.Size > maxImageConfigBytes {
			return errors.New("Docker image archive has a non-regular, duplicate, or oversized image config")
		}
		seenConfigs[header.Name] = true
		configBytes, err := io.ReadAll(io.LimitReader(reader, maxImageConfigBytes+1))
		if err != nil || int64(len(configBytes)) != header.Size {
			return fmt.Errorf("could not read Docker image config %q", header.Name)
		}
		digest := sha256.Sum256(configBytes)
		configID := "sha256:" + hex.EncodeToString(digest[:])
		var config dockerImageConfig
		if err := json.Unmarshal(configBytes, &config); err != nil || config.OS != "linux" || config.Architecture != "amd64" {
			return fmt.Errorf("Docker image config %q is not linux/amd64", header.Name)
		}
		for _, image := range images {
			if image.ImageID != configID {
				return fmt.Errorf("Docker image %s config digest did not match the package manifest", image.Reference)
			}
		}
	}
	if len(seenConfigs) != len(configsByPath) {
		return errors.New("Docker image archive is missing an image config")
	}
	return nil
}
