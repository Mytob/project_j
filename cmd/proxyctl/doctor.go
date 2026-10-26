package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mytob/project_j/internal/deployment"
)

func doctor(ctx context.Context, root string, runner deployment.CommandRunner, output io.Writer) error {
	failed := false
	check := func(name string, err error, details string) {
		if err != nil {
			failed = true
			fmt.Fprintf(output, "FAIL  %-30s %s (%v)\n", name, details, err)
			return
		}
		fmt.Fprintf(output, "PASS  %-30s %s\n", name, details)
	}
	layoutErr := deployment.ValidateInstalledLayoutForDoctor(root)
	check("Installation files", layoutErr, root)
	if layoutErr == nil {
		manifest, err := deployment.CurrentReleaseForDoctor(root)
		check("Release metadata", err, fmt.Sprintf("version %s · build %s", manifest.Version, manifest.BuildID))
		if err == nil {
			compose, configErr := runner.Run(ctx, "docker", doctorComposeArgs(root, "config", "--quiet")...)
			_ = compose
			check("Compose configuration", configErr, "configuration parses")
			status, statusErr := runner.Run(ctx, "docker", doctorComposeArgs(root, "ps", "--format", "json")...)
			if statusErr == nil && !deployment.ComposeServicesHealthyForDoctor(status) {
				statusErr = errors.New("one or more required services are not healthy")
			}
			check("Application services", statusErr, "admin, Caddy, host metrics, securityd and WireGuard")
		}
		if _, err := os.Lstat(filepath.Join(root, ".restore-transaction.json")); err == nil {
			check("Restore recovery", errors.New("an interrupted restore journal needs repair"), "run sudo proxyctl repair")
		} else if errors.Is(err, os.ErrNotExist) {
			check("Restore recovery", nil, "no interrupted restore")
		} else {
			check("Restore recovery", err, "journal could not be inspected")
		}
		if _, err := os.Lstat(filepath.Join(root, ".update-transaction.json")); err == nil {
			check("Update recovery", errors.New("an interrupted update journal needs repair"), "run sudo proxyctl repair")
		} else if errors.Is(err, os.ErrNotExist) {
			check("Update recovery", nil, "no interrupted update")
		} else {
			check("Update recovery", err, "journal could not be inspected")
		}
	}
	_, dockerErr := runner.Run(ctx, "docker", "info")
	check("Docker Engine", dockerErr, "daemon responds")
	_, composeErr := runner.Run(ctx, "docker", "compose", "version")
	check("Docker Compose", composeErr, "plugin responds")
	disk, diskErr := runner.Run(ctx, "df", "-h", root)
	check("Host storage", diskErr, strings.TrimSpace(disk))
	if failed {
		return errors.New("doctor found problems that require attention")
	}
	return nil
}

func repair(ctx context.Context, root string, runner deployment.CommandRunner, input io.Reader, output io.Writer) error {
	updateRecovered, err := deployment.RecoverInterruptedUpdate(ctx, deployment.UpdateRecoveryOptions{
		InstallRoot: root, Runner: runner, ConfigureHostServices: true,
	})
	if err != nil {
		return err
	}
	if updateRecovered {
		fmt.Fprintln(output, "The interrupted update was recovered and the application stack is healthy.")
		return nil
	}
	recovered, err := deployment.RecoverInterruptedRestore(ctx, root, runner)
	if err != nil {
		return err
	}
	if recovered {
		fmt.Fprintln(output, "The interrupted restore was rolled back and the previous stack is healthy.")
		return nil
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "."+filepath.Base(root)+".install-checkpoint.json")); err == nil {
		return errors.New("an interrupted first install is available; run sudo proxyctl install --resume")
	}
	if err := deployment.ValidateInstalledLayoutForDoctor(root); err != nil {
		return err
	}
	if _, err := runner.Run(ctx, "docker", doctorComposeArgs(root, "config", "--quiet")...); err != nil {
		return fmt.Errorf("configuration check failed; no repair was attempted: %w", err)
	}
	if err := deployment.RefreshHostServices(ctx, root, "", "", runner); err != nil {
		return fmt.Errorf("could not reconcile the managed host services: %w", err)
	}
	status, err := runner.Run(ctx, "docker", doctorComposeArgs(root, "ps", "--format", "json")...)
	if err == nil && deployment.ComposeServicesHealthyForDoctor(status) {
		fmt.Fprintln(output, "Managed host services are current and the required application services are healthy.")
		return nil
	}
	approved, err := runApprovalForm(input, output, "Start the Jellyfin Proxy application stack", "This fixed operation starts only the jellyfin-proxy Compose project. It does not change host firewall, SSH, or unrelated Docker resources.")
	if err != nil {
		return err
	}
	if !approved {
		return errors.New("repair cancelled")
	}
	if _, err := runner.Run(ctx, "docker", doctorComposeArgs(root, "up", "--detach", "--pull", "never")...); err != nil {
		return err
	}
	if err := deployment.WaitForReadinessForDoctor(ctx, root, runner, 2*time.Second, 60); err != nil {
		return err
	}
	fmt.Fprintln(output, "The approved application stack repair completed and all required services are healthy.")
	return nil
}

func doctorComposeArgs(root string, args ...string) []string {
	return append([]string{"compose", "--project-name", "jellyfin-proxy", "--file", filepath.Join(root, "compose.yaml"), "--env-file", filepath.Join(root, ".env")}, args...)
}
