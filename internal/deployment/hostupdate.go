package deployment

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type HostUpdateOptions struct {
	InstallRoot        string
	Runner             CommandRunner
	RebootRequiredPath string
}

type HostUpdateResult struct {
	RebootRequired bool
	ApplicationOK  bool
}

// PreviewHostUpdates refreshes APT metadata and simulates an upgrade without
// installing packages. It is called only by the explicit host-update command.
func PreviewHostUpdates(ctx context.Context, options HostUpdateOptions) (string, error) {
	if options.InstallRoot == "" {
		options.InstallRoot = DefaultInstallRoot
	}
	if options.Runner == nil {
		options.Runner = ExecRunner{}
	}
	if err := validateInstalledLayout(options.InstallRoot); err != nil {
		return "", err
	}
	status, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "ps", "--format", "json")...)
	if err != nil || !composeServicesHealthy(status) {
		return "", errors.New("refusing host updates while the Jellyfin Proxy services are unhealthy")
	}
	if _, err := options.Runner.Run(ctx, "apt-get", "update"); err != nil {
		return "", fmt.Errorf("refresh Ubuntu package metadata: %w", err)
	}
	preview, err := options.Runner.Run(ctx, "apt-get", "--simulate", "upgrade")
	if err != nil {
		return "", fmt.Errorf("simulate Ubuntu package updates: %w", err)
	}
	return preview, nil
}

// ApplyHostUpdates installs only the changes from the preceding manual preview
// and verifies Docker plus the application afterward. It never reboots.
func ApplyHostUpdates(ctx context.Context, options HostUpdateOptions) (HostUpdateResult, error) {
	if options.InstallRoot == "" {
		options.InstallRoot = DefaultInstallRoot
	}
	if options.Runner == nil {
		options.Runner = ExecRunner{}
	}
	if options.RebootRequiredPath == "" {
		options.RebootRequiredPath = "/var/run/reboot-required"
	}
	if _, err := options.Runner.Run(ctx, "apt-get", "upgrade", "-y"); err != nil {
		return HostUpdateResult{}, fmt.Errorf("apply confirmed Ubuntu package updates: %w", err)
	}
	if _, err := options.Runner.Run(ctx, "docker", "info"); err != nil {
		return HostUpdateResult{}, fmt.Errorf("host packages were updated, but Docker did not pass its post-update check: %w", err)
	}
	if _, err := options.Runner.Run(ctx, "docker", "compose", "version"); err != nil {
		return HostUpdateResult{}, fmt.Errorf("host packages were updated, but Docker Compose did not pass its post-update check: %w", err)
	}
	status, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "ps", "--format", "json")...)
	if err != nil {
		return HostUpdateResult{}, fmt.Errorf("host packages were updated, but application health could not be checked: %w", err)
	}
	applicationOK := composeServicesHealthy(status)
	if !applicationOK {
		return HostUpdateResult{ApplicationOK: false, RebootRequired: rebootRequired(options.RebootRequiredPath)}, errors.New("host packages were updated, but application services are not healthy; run proxyctl doctor")
	}
	return HostUpdateResult{ApplicationOK: true, RebootRequired: rebootRequired(options.RebootRequiredPath)}, nil
}

func rebootRequired(path string) bool {
	info, err := os.Stat(filepath.Clean(path))
	return err == nil && info.Mode().IsRegular()
}

// SummarizeHostUpdatePreview keeps the user-facing confirmation concise while
// still showing the complete apt simulation separately when requested.
func SummarizeHostUpdatePreview(preview string) string {
	lines := 0
	for _, line := range strings.Split(strings.TrimSpace(preview), "\n") {
		if strings.TrimSpace(line) != "" {
			lines++
		}
	}
	return fmt.Sprintf("The APT simulation reports %d non-empty lines. Docker Engine and Compose are included if Ubuntu lists them. No packages have been installed yet.", lines)
}
