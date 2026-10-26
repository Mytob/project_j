package deployment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mytob/project_j/internal/webcontent"
)

// initializeWebContentStore creates or validates the persistent public site,
// preserving any previously published revisions during application updates.
func initializeWebContentStore(root, defaultSite string) error {
	if !filepath.IsAbs(root) || !filepath.IsAbs(defaultSite) {
		return errors.New("static website paths must be absolute")
	}
	if err := webcontent.Initialize(root, defaultSite); err != nil {
		return err
	}
	if _, err := webcontent.GetStatus(root); err != nil {
		return fmt.Errorf("validate active static website revision: %w", err)
	}
	return secureWebContentPermissions(root)
}

func secureWebContentPermissions(root string) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("static website storage root is missing or unsafe")
	}
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if path == filepath.Join(root, "current") || path == filepath.Join(root, "previous") {
				return nil
			}
			return fmt.Errorf("unexpected symbolic link in static website storage: %s", path)
		}
		if entry.IsDir() {
			mode := os.FileMode(0o755)
			if path == root || path == filepath.Join(root, "revisions") {
				mode = 0o2770
			}
			if err := os.Chown(path, 0, adminContainerUID); err != nil {
				return fmt.Errorf("set static website directory group: %w", err)
			}
			if err := os.Chmod(path, mode); err != nil {
				return fmt.Errorf("set static website directory mode: %w", err)
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unsupported file in static website storage: %s", strings.TrimPrefix(path, root+string(filepath.Separator)))
		}
		if err := os.Chown(path, 0, adminContainerUID); err != nil {
			return fmt.Errorf("set static website file group: %w", err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			return fmt.Errorf("set static website file mode: %w", err)
		}
		return nil
	})
}
