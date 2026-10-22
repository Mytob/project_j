package deployment

import (
	"context"
	"time"

	"github.com/Mytob/project_j/internal/release"
)

// ValidateInstalledLayoutForDoctor checks the active deployment without
// changing it.
func ValidateInstalledLayoutForDoctor(root string) error { return validateInstalledLayout(root) }

// CurrentReleaseForDoctor returns the checked manifest for the installed
// release.
func CurrentReleaseForDoctor(root string) (release.Manifest, error) { return readCurrentRelease(root) }

// ComposeServicesHealthyForDoctor parses the required service health records.
func ComposeServicesHealthyForDoctor(output string) bool { return composeServicesHealthy(output) }

// WaitForReadinessForDoctor waits for the required application services.
func WaitForReadinessForDoctor(ctx context.Context, root string, runner CommandRunner, interval time.Duration, attempts int) error {
	return waitForReadiness(ctx, InstallOptions{InstallRoot: root, Runner: runner, WaitInterval: interval, WaitAttempts: attempts})
}
