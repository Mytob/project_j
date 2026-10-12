package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Mytob/project_j/internal/deployment"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "proxyctl:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, _ = fmt.Fprintln(stdout, "Usage: proxyctl install <release-package.tar.gz> | update <release-package.tar.gz> | reset-password")
		return nil
	}
	if args[0] != "install" && args[0] != "update" && args[0] != "reset-password" {
		return fmt.Errorf("unknown command %q; run proxyctl help", args[0])
	}
	if (args[0] == "install" || args[0] == "update") && len(args) != 2 {
		return fmt.Errorf("usage: proxyctl %s <release-package.tar.gz>", args[0])
	}
	if args[0] == "reset-password" && len(args) != 1 {
		return errors.New("usage: proxyctl reset-password")
	}

	runner := deployment.ExecRunner{}
	facts, err := deployment.DetectHostFacts(ctx, runner)
	if err != nil {
		return err
	}
	if err := deployment.ValidateHost(facts); err != nil {
		return err
	}
	reader := bufio.NewReader(stdin)
	if err := ensureDocker(ctx, runner, facts.Codename, reader, stdout); err != nil {
		return err
	}
	if args[0] == "reset-password" {
		password, err := promptSecret(reader, stdout, "New administrator password (12+ characters): ")
		if err != nil {
			return err
		}
		confirmation, err := promptSecret(reader, stdout, "Confirm new administrator password: ")
		if err != nil {
			return err
		}
		if password != confirmation {
			return errors.New("passwords do not match")
		}
		if err := deployment.ResetPassword(ctx, deployment.DefaultInstallRoot, password, runner); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "Administrator password reset. Existing admin sessions have been invalidated.")
		return nil
	}
	packagePath, err := filepath.Abs(args[1])
	if err != nil {
		return fmt.Errorf("resolve package path: %w", err)
	}
	if info, err := os.Stat(packagePath); err != nil || !info.Mode().IsRegular() {
		return errors.New("release package is not a readable regular file")
	}
	if args[0] == "update" {
		manifest, err := deployment.Update(ctx, deployment.UpdateOptions{PackagePath: packagePath, InstallRoot: deployment.DefaultInstallRoot, Host: facts, Runner: runner})
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Jellyfin Proxy updated to %s. The active and previous release are retained.\n", manifest.Version)
		return nil
	}
	if _, err := os.Lstat(deployment.DefaultInstallRoot); err == nil {
		return errors.New("/opt/jellyfin-proxy already exists; refusing to overwrite installation data")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect installation root: %w", err)
	}

	domainInput, err := promptLine(reader, stdout, "Base domain (for example example.com): ")
	if err != nil {
		return err
	}
	domain, err := deployment.ValidateDomain(domainInput)
	if err != nil {
		return err
	}
	addresses, err := deployment.CheckDNS(ctx, domain, nil)
	if err != nil {
		return err
	}
	for host, ips := range addresses {
		values := make([]string, 0, len(ips))
		for _, ip := range ips {
			values = append(values, ip.String())
		}
		fmt.Fprintf(stdout, "DNS %s -> %s\n", host, strings.Join(values, ", "))
	}
	if !askYesNo(reader, stdout, "Confirm these hostnames point to this VPS? [y/N]: ") {
		return errors.New("DNS target was not confirmed; no installation files were written")
	}
	password, err := promptSecret(reader, stdout, "Initial administrator password (12+ characters): ")
	if err != nil {
		return err
	}
	confirmation, err := promptSecret(reader, stdout, "Confirm administrator password: ")
	if err != nil {
		return err
	}
	if password != confirmation {
		return errors.New("passwords do not match")
	}
	portText, err := promptLine(reader, stdout, "Public WireGuard UDP port [51820]: ")
	if err != nil {
		return err
	}
	port := uint64(51820)
	if strings.TrimSpace(portText) != "" {
		port, err = strconv.ParseUint(strings.TrimSpace(portText), 10, 16)
		if err != nil || port == 0 {
			return errors.New("WireGuard UDP port must be between 1 and 65535")
		}
	}
	fmt.Fprintln(stdout, "Installing Jellyfin Proxy. Only this deployment's published HTTP, HTTPS, and WireGuard traffic will be allowed in its network namespace.")
	manifest, err := deployment.Install(ctx, deployment.InstallOptions{
		PackagePath: packagePath, InstallRoot: deployment.DefaultInstallRoot, Domain: domain,
		Password: password, WireGuardPort: uint16(port), Host: facts, Runner: runner,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Jellyfin Proxy %s is ready. Open https://admin.%s to sign in.\n", manifest.Version, domain)
	fmt.Fprintf(stdout, "Download the Windows WireGuard config after signing in, then allow Jellyfin TCP only from 10.66.66.1 in Windows Firewall.\n")
	return nil
}

func ensureDocker(ctx context.Context, runner deployment.CommandRunner, codename string, reader *bufio.Reader, stdout io.Writer) error {
	if _, err := exec.LookPath("docker"); errors.Is(err, exec.ErrNotFound) {
		if !askYesNo(reader, stdout, "Docker is not installed. Install Docker Engine and Compose from Docker's official APT repository? [y/N]: ") {
			return errors.New("Docker is required to continue")
		}
		fmt.Fprintln(stdout, "Installing Docker Engine and Compose from Docker's official Ubuntu repository...")
		return deployment.InstallDockerEngine(ctx, runner, codename)
	} else if err != nil {
		return err
	}
	if _, err := runner.Run(ctx, "docker", "info"); err != nil {
		return deployment.IsDockerDaemonError(err)
	}
	if _, err := runner.Run(ctx, "docker", "compose", "version"); err == nil {
		return nil
	}
	if !askYesNo(reader, stdout, "Docker Compose plugin is missing. Install it from Docker's official APT repository? [y/N]: ") {
		return errors.New("Docker Compose plugin is required to continue")
	}
	fmt.Fprintln(stdout, "Installing Docker Engine and Compose from Docker's official Ubuntu repository...")
	return deployment.InstallDockerEngine(ctx, runner, codename)
}

func promptLine(reader *bufio.Reader, output io.Writer, prompt string) (string, error) {
	fmt.Fprint(output, prompt)
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if errors.Is(err, io.EOF) && value == "" {
		return "", errors.New("input ended before the prompt was answered")
	}
	return strings.TrimSpace(value), nil
}

func askYesNo(reader *bufio.Reader, output io.Writer, prompt string) bool {
	answer, err := promptLine(reader, output, prompt)
	return err == nil && (strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes"))
}

func promptSecret(reader *bufio.Reader, output io.Writer, prompt string) (string, error) {
	stateCommand := exec.Command("stty", "-g")
	stateCommand.Stdin = os.Stdin
	state, err := stateCommand.Output()
	if err != nil {
		return "", errors.New("hidden password input requires an interactive terminal")
	}
	fmt.Fprint(output, prompt)
	echoOff := exec.Command("stty", "-echo")
	echoOff.Stdin = os.Stdin
	if err := echoOff.Run(); err != nil {
		return "", errors.New("could not disable terminal echo for password input")
	}
	value, readErr := reader.ReadString('\n')
	restore := exec.Command("stty", strings.TrimSpace(string(state)))
	restore.Stdin = os.Stdin
	restoreErr := restore.Run()
	fmt.Fprintln(output)
	if restoreErr != nil {
		return "", errors.New("could not restore terminal settings after password input")
	}
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return "", readErr
	}
	if errors.Is(readErr, io.EOF) && value == "" {
		return "", errors.New("input ended before the password was entered")
	}
	return strings.TrimSuffix(strings.TrimSuffix(value, "\n"), "\r"), nil
}
