package deployment

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const dockerGPGURL = "https://download.docker.com/linux/ubuntu/gpg"

// DockerSourcesFile returns the official Docker deb822 source for the
// validated Ubuntu release codename.
func DockerSourcesFile(codename string) (string, error) {
	if !codenamePattern.MatchString(codename) {
		return "", errors.New("invalid Ubuntu codename for Docker APT source")
	}
	return fmt.Sprintf("Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: %s\nComponents: stable\nArchitectures: amd64\nSigned-By: /etc/apt/keyrings/docker.asc\n", codename), nil
}

// InstallDockerEngine installs Docker Engine and Compose from Docker's
// official Ubuntu APT repository. It does not use the convenience script.
func InstallDockerEngine(ctx context.Context, runner CommandRunner, codename string) error {
	if runner == nil {
		return errors.New("Docker installer command runner is unavailable")
	}
	source, err := DockerSourcesFile(codename)
	if err != nil {
		return err
	}
	commands := [][]string{
		{"apt-get", "update"},
		{"apt-get", "install", "-y", "ca-certificates", "curl"},
		{"install", "-m", "0755", "-d", "/etc/apt/keyrings"},
		{"curl", "-fsSL", dockerGPGURL, "-o", "/etc/apt/keyrings/docker.asc"},
		{"chmod", "a+r", "/etc/apt/keyrings/docker.asc"},
	}
	for _, command := range commands {
		if _, err := runner.Run(ctx, command[0], command[1:]...); err != nil {
			return fmt.Errorf("install Docker repository prerequisite: %w", err)
		}
	}
	if err := writeSystemFile("/etc/apt/sources.list.d/docker.sources", source, 0o644); err != nil {
		return fmt.Errorf("configure official Docker APT source: %w", err)
	}
	for _, command := range [][]string{
		{"apt-get", "update"},
		{"apt-get", "install", "-y", "docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"},
		{"systemctl", "enable", "--now", "docker"},
		{"docker", "info"},
		{"docker", "compose", "version"},
	} {
		if _, err := runner.Run(ctx, command[0], command[1:]...); err != nil {
			return fmt.Errorf("install or verify Docker Engine and Compose: %w", err)
		}
	}
	return nil
}

func writeSystemFile(path, content string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".docker-sources-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.WriteString(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// IsDockerDaemonError adds an operator-directed hint without assuming the
// daemon is absent when its client is installed but the service is stopped.
func IsDockerDaemonError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("Docker is installed but its engine is not available: %s. Start the Docker service and rerun proxyctl install", strings.TrimSpace(err.Error()))
}
