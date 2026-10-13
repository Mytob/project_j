package deployment

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Mytob/project_j/internal/release"
)

func verifyLoadedImages(ctx context.Context, runner CommandRunner, images []release.Image) error {
	file, err := os.CreateTemp("", "jellyfin-proxy-loaded-images-*.tar")
	if err != nil {
		return fmt.Errorf("create temporary image verification archive: %w", err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close temporary image verification archive: %w", err)
	}
	defer os.Remove(path)

	refs := make([]string, 0, len(images))
	for _, image := range images {
		refs = append(refs, image.Reference)
	}
	if _, err := runner.Run(ctx, "docker", append([]string{"image", "save", "--output", path}, refs...)...); err != nil {
		return fmt.Errorf("save loaded deployment images for verification: %w", err)
	}
	if err := release.VerifyImageArchive(path, images); err != nil {
		return fmt.Errorf("loaded deployment images did not match the verified package: %w", err)
	}
	return nil
}

func imageReferences(images []release.Image) string {
	refs := make([]string, 0, len(images))
	for _, image := range images {
		refs = append(refs, image.Reference)
	}
	return strings.Join(refs, ", ")
}
