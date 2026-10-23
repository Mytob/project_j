package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Mytob/project_j/internal/deployment"
	"github.com/Mytob/project_j/internal/release"
)

var version = "development"

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "proxyctl:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		_, _ = fmt.Fprintf(stdout, "proxyctl %s\n", version)
		return nil
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, _ = fmt.Fprintln(stdout, "Usage: proxyctl [--version] install <release-package.pkg> | install --resume | update <release-package.pkg> | rollback | recover <release-package.pkg> <archive.bak> | backup [archive.bak] | verify-backup <archive.bak> | restore <archive.bak> | doctor | repair | host-update | reset-password | reset-totp | disable-totp | replace-totp")
		return nil
	}
	if runningAsRoot() {
		if err := deployment.RecoverPersistentProxyctl("", ""); err != nil {
			return fmt.Errorf("recover interrupted proxyctl replacement: %w", err)
		}
	}
	if args[0] == "doctor" {
		if len(args) != 1 || !runningAsRoot() {
			return errors.New("doctor must be run as root: sudo proxyctl doctor")
		}
		return doctor(ctx, deployment.DefaultInstallRoot, deployment.ExecRunner{}, stdout)
	}
	if args[0] == "repair" {
		if len(args) != 1 || !runningAsRoot() {
			return errors.New("repair must be run as root: sudo proxyctl repair")
		}
		return repair(ctx, deployment.DefaultInstallRoot, deployment.ExecRunner{}, stdin, stdout)
	}
	if args[0] == "host-update" {
		if len(args) != 1 || !runningAsRoot() {
			return errors.New("manual host updates must be run as root: sudo proxyctl host-update")
		}
		return manualHostUpdate(ctx, stdin, stdout)
	}
	if args[0] == "sync-host-services" {
		if !runningAsRoot() || (len(args) != 1 && !(len(args) == 2 && args[1] == "--defer-maintenance-restart")) {
			return errors.New("host service reconciliation must be run as root")
		}
		if len(args) == 2 {
			return deployment.RefreshHostServicesDeferred(ctx, deployment.DefaultInstallRoot, "", "", deployment.ExecRunner{})
		}
		return deployment.RefreshHostServices(ctx, deployment.DefaultInstallRoot, "", "", deployment.ExecRunner{})
	}
	if args[0] == "rollback" {
		if len(args) != 1 || !runningAsRoot() {
			return errors.New("rollback must be run as root with no arguments: sudo proxyctl rollback")
		}
		previous, err := deployment.PreviousReleaseForRollback(deployment.DefaultInstallRoot)
		if err != nil {
			return err
		}
		current, err := deployment.CurrentReleaseForDoctor(deployment.DefaultInstallRoot)
		if err != nil {
			return err
		}
		approved, err := runApprovalForm(stdin, stdout, "Roll back to the previous release", fmt.Sprintf("This activates version %s (build %s) and preserves the current application data, administrator credentials, WireGuard identity, and current release for another rollback. A verified safety backup is created first.", previous.Version, previous.BuildID))
		if err != nil {
			return fmt.Errorf("rollback confirmation: %w", err)
		}
		if !approved {
			return errors.New("rollback cancelled")
		}
		if current.Version == previous.Version {
			return errors.New("the previous release is already active")
		}
		progress, finish := newUpdateProgressReporter(stdout)
		manifest, err := deployment.RollbackPrevious(ctx, deployment.RollbackOptions{InstallRoot: deployment.DefaultInstallRoot, Runner: deployment.ExecRunner{}, ConfigureHostServices: true, Progress: progress})
		finish(err == nil)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Jellyfin Proxy rolled back to %s. The newer release and current data are retained.\n", manifest.Version)
		return nil
	}
	if args[0] != "install" && args[0] != "update" && args[0] != "recover" && args[0] != "backup" && args[0] != "verify-backup" && args[0] != "restore" && args[0] != "reset-password" && args[0] != "reset-totp" && args[0] != "disable-totp" && args[0] != "replace-totp" {
		return fmt.Errorf("unknown command %q; run proxyctl help", args[0])
	}
	if args[0] == "install" && len(args) == 2 && args[1] == "--resume" {
		return resumeInstall(ctx, stdin, stdout)
	}
	if (args[0] == "install" || args[0] == "update" || args[0] == "verify-backup" || args[0] == "restore") && len(args) != 2 {
		if args[0] == "verify-backup" {
			return errors.New("usage: proxyctl verify-backup <archive.bak>")
		}
		if args[0] == "restore" {
			return errors.New("usage: proxyctl restore <archive.bak>")
		}
		return fmt.Errorf("usage: proxyctl %s <release-package.pkg>", args[0])
	}
	if args[0] == "recover" && len(args) != 3 {
		return errors.New("usage: proxyctl recover <release-package.pkg> <archive.bak>")
	}
	if args[0] == "backup" && (len(args) < 1 || len(args) > 2) {
		return errors.New("usage: proxyctl backup [archive.bak]")
	}
	if args[0] == "reset-password" && len(args) != 1 {
		return errors.New("usage: proxyctl reset-password")
	}
	if args[0] != "install" && args[0] != "update" && args[0] != "recover" && args[0] != "backup" && args[0] != "verify-backup" && args[0] != "restore" && args[0] != "reset-password" && len(args) != 1 {
		return fmt.Errorf("usage: proxyctl %s", args[0])
	}
	if args[0] == "reset-totp" || args[0] == "disable-totp" || args[0] == "replace-totp" {
		if !runningAsRoot() {
			return errors.New("TOTP recovery commands must be run as root")
		}
		action := map[string]deployment.TOTPRecoveryAction{
			"reset-totp":   deployment.TOTPReset,
			"disable-totp": deployment.TOTPDisable,
			"replace-totp": deployment.TOTPReplace,
		}[args[0]]
		if err := deployment.RecoverTOTP(ctx, deployment.DefaultInstallRoot, action, deployment.ExecRunner{}); err != nil {
			return err
		}
		switch action {
		case deployment.TOTPDisable:
			fmt.Fprintln(stdout, "Authenticator disabled. The next administrator login can use the existing password.")
		case deployment.TOTPReplace:
			fmt.Fprintln(stdout, "Authenticator replaced. Sign in with the existing password and complete enrollment of the new authenticator before using the dashboard.")
		default:
			fmt.Fprintln(stdout, "Authenticator reset. Sign in with the existing password and complete a new authenticator enrollment before using the dashboard.")
		}
		return nil
	}
	if args[0] == "backup" {
		if !runningAsRoot() {
			return errors.New("backup requires root privileges; use sudo proxyctl backup")
		}
		outputPath := ""
		if len(args) == 2 {
			outputPath = args[1]
		}
		path, manifest, err := deployment.CreateBackup(deployment.DefaultInstallRoot, outputPath)
		if err != nil {
			return err
		}
		_, retention, err := deployment.ReadBackupSettings(deployment.DefaultInstallRoot)
		if err != nil {
			return fmt.Errorf("read automatic backup retention: %w", err)
		}
		removed, err := deployment.CleanupBackups(deployment.DefaultBackupRoot, retention, time.Now())
		if err != nil {
			return fmt.Errorf("backup created at %s, but automatic retention cleanup failed: %w", path, err)
		}
		checksum, err := release.SHA256File(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Verified backup created: %s\nVersion: %s · Build: %s\nSHA-256: %s\nExpired backups removed: %d\n", path, manifest.Version, manifest.BuildID, checksum, removed)
		return nil
	}
	if args[0] == "verify-backup" {
		manifest, err := deployment.ValidateBackup(args[1])
		if err != nil {
			return fmt.Errorf("backup verification failed: %w", err)
		}
		fmt.Fprintf(stdout, "Backup verified: version %s · Build %s · %d files\n", manifest.Version, manifest.BuildID, len(manifest.Files))
		return nil
	}
	if args[0] == "restore" {
		if !runningAsRoot() {
			return errors.New("restore requires root privileges; use sudo proxyctl restore <archive.bak>")
		}
		manifest, err := deployment.ValidateBackup(args[1])
		if err != nil {
			return fmt.Errorf("restore backup verification failed: %w", err)
		}
		approved, err := runApprovalForm(stdin, stdout, "Restore application data", fmt.Sprintf("This replaces configuration, credentials, WireGuard material, statistics, and website files with backup version %s (build %s). Host SSH and firewall settings are not restored. A new safety backup will be created before changes.", manifest.Version, manifest.BuildID))
		if err != nil {
			return fmt.Errorf("restore confirmation: %w", err)
		}
		if !approved {
			return errors.New("restore cancelled")
		}
		progress, finish := newUpdateProgressReporter(stdout)
		_, err = deployment.Restore(ctx, deployment.RestoreOptions{
			BackupPath: args[1], InstallRoot: deployment.DefaultInstallRoot, Runner: deployment.ExecRunner{},
			ConfigureHostServices: true, Progress: progress,
		})
		finish(err == nil)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Restore to version %s completed and passed service and HTTPS checks.\n", manifest.Version)
		return nil
	}

	runner := deployment.ExecRunner{}
	reader := bufio.NewReader(stdin)
	packagePath := ""
	packageSHA256 := ""
	if args[0] == "install" || args[0] == "update" || args[0] == "recover" {
		var err error
		packagePath, err = filepath.Abs(args[1])
		if err != nil {
			return fmt.Errorf("resolve package path: %w", err)
		}
		if filepath.Ext(packagePath) != ".pkg" {
			return errors.New("release package must use the .pkg extension")
		}
		if info, err := os.Stat(packagePath); err != nil || !info.Mode().IsRegular() {
			return errors.New("release package is not a readable regular file")
		}
		err = runTextForm(stdin, stdout, "Expected package SHA-256", "Copy the checksum independently from the .pkg.sha256 file.", &packageSHA256, validateSHA256Input, false)
		if err != nil {
			return fmt.Errorf("package checksum input: %w", err)
		}
		if _, err := hex.DecodeString(packageSHA256); err != nil || len(packageSHA256) != 64 {
			return errors.New("expected package checksum must be a 64-character SHA-256 value")
		}
		if _, err := release.ValidatePackage(packagePath, packageSHA256); err != nil {
			return fmt.Errorf("package validation failed before host changes: %w", err)
		}
	}
	recoveryBackupPath := ""
	if args[0] == "recover" {
		var err error
		recoveryBackupPath, err = filepath.Abs(args[2])
		if err != nil || filepath.Ext(recoveryBackupPath) != ".bak" {
			return errors.New("recovery backup must be a readable .bak archive")
		}
		if info, err := os.Stat(recoveryBackupPath); err != nil || !info.Mode().IsRegular() {
			return errors.New("recovery backup is not a readable regular file")
		}
		if _, err := deployment.ValidateBackup(recoveryBackupPath); err != nil {
			return fmt.Errorf("recovery backup validation failed before host changes: %w", err)
		}
	}
	if args[0] == "update" {
		fmt.Fprintln(stdout, "Preparing update: checking the Ubuntu host and Docker installation...")
	}
	facts, err := deployment.DetectHostFacts(ctx, runner)
	if err != nil {
		return err
	}
	if err := deployment.ValidateHost(facts); err != nil {
		return err
	}
	var installConfig installSettings
	var initialAllowedIPs []string
	if args[0] == "install" || args[0] == "recover" {
		if _, err := os.Lstat(deployment.DefaultInstallRoot); err == nil {
			return errors.New("/opt/jellyfin-proxy already exists; refusing to overwrite installation data")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect installation root: %w", err)
		}
		preflight, preflightErr := deployment.InspectInstallResources(deployment.DefaultInstallRoot, "/var/lib/docker")
		if preflightErr != nil {
			return fmt.Errorf("installation host preflight failed: %w", preflightErr)
		}
		fmt.Fprintln(stdout, preflight.Summary())
		if !preflight.WireGuardKernelAvailable {
			return errors.New("the Ubuntu host does not have WireGuard kernel support; install a supported kernel/module and rerun proxyctl install")
		}
		installConfig, err = runInstallWizardWithPreflight(stdin, stdout, preflight)
		if err != nil {
			return err
		}
		domainAddresses, err := deployment.CheckDNS(ctx, installConfig.domain, nil)
		if err != nil {
			return err
		}
		for host, ips := range domainAddresses {
			values := make([]string, 0, len(ips))
			for _, ip := range ips {
				values = append(values, ip.String())
			}
			fmt.Fprintf(stdout, "DNS %s -> %s\n", host, strings.Join(values, ", "))
		}
		approved, err := runApprovalForm(stdin, stdout, "Confirm DNS target", "Confirm that every hostname above resolves to this VPS before Docker or application files are changed.")
		if err != nil {
			return fmt.Errorf("DNS target confirmation: %w", err)
		}
		if !approved {
			return errors.New("DNS target was not confirmed; no installation files were written")
		}
		if args[0] == "recover" {
			approved, err = runApprovalForm(stdin, stdout, "Recover this fresh VPS", "The backup's public website, statistics database, and verifiable security-event history will be restored. Administrator credentials, TOTP setup, WireGuard keys, allowlist, environment, SSH, and firewall settings will be generated or configured anew; no host SSH/firewall settings are restored.")
			if err != nil {
				return fmt.Errorf("disaster recovery confirmation: %w", err)
			}
			if !approved {
				return errors.New("disaster recovery cancelled; no installation files were written")
			}
		}
		initialAllowedIPs, err = parseAllowedIPs(installConfig.allowed)
		if err != nil {
			return err
		}
	}
	if err := ensureDocker(ctx, runner, facts.Codename, reader, stdout); err != nil {
		return err
	}
	if args[0] == "install" || args[0] == "recover" {
		sshConfig := deployment.SSHAdministratorConfig{
			Username: installConfig.sshUsername, Authentication: deployment.SSHAuthentication(installConfig.sshAuthentication),
			Password: installConfig.sshPassword, PublicKey: installConfig.sshPublicKey,
		}
		sshChange, err := deployment.ConfigureSSHAdministrator(ctx, sshConfig, runner)
		if err != nil {
			return fmt.Errorf("configure the SSH administrator: %w", err)
		}
		fmt.Fprintf(stdout, "SSH account %s is configured. Before continuing, verify it from a separate SSH session.\n", sshConfig.Username)
		verified, verifyErr := runApprovalForm(stdin, stdout, "Confirm alternate SSH administrator login", deployment.SSHAdministratorLoginPrompt(sshConfig))
		if verifyErr != nil || !verified {
			rollbackErr := deployment.RollbackSSHAdministrator(context.Background(), sshChange, runner)
			if verifyErr != nil {
				return errors.Join(fmt.Errorf("SSH administrator verification: %w", verifyErr), rollbackErr)
			}
			return errors.Join(errors.New("SSH administrator login was not verified; no application installation was started"), rollbackErr)
		}
		if installConfig.disableRootSSH {
			if err := deployment.DisableRootSSHLogin(ctx, sshChange, sshConfig, runner); err != nil {
				rollbackErr := deployment.RollbackSSHAdministrator(context.Background(), sshChange, runner)
				return errors.Join(fmt.Errorf("disable root SSH login after verification: %w", err), rollbackErr)
			}
		}
		installConfig.sshPassword = ""
		installConfig.sshConfirm = ""
		installConfig.sshPublicKey = ""
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
	if args[0] == "update" {
		progress, finishProgress := newUpdateProgressReporter(stdout)
		manifest, err := deployment.Update(ctx, deployment.UpdateOptions{PackagePath: packagePath, PackageSHA256: packageSHA256, InstallRoot: deployment.DefaultInstallRoot, Host: facts, Runner: runner, ConfigureHostServices: true, Progress: progress})
		finishProgress(err == nil)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Jellyfin Proxy updated to %s. The active and previous release are retained.\n", manifest.Version)
		return nil
	}
	port := uint64(51820)
	if strings.TrimSpace(installConfig.port) != "" {
		port, err = strconv.ParseUint(strings.TrimSpace(installConfig.port), 10, 16)
		if err != nil || port == 0 {
			return errors.New("WireGuard UDP port must be between 1 and 65535")
		}
	}
	backupSchedule := strings.ToLower(strings.TrimSpace(installConfig.backupSchedule))
	if backupSchedule == "" {
		backupSchedule = "daily"
	}
	backupRetention := uint64(30)
	if strings.TrimSpace(installConfig.backupRetention) != "" {
		backupRetention, err = strconv.ParseUint(strings.TrimSpace(installConfig.backupRetention), 10, 8)
		if err != nil || (backupRetention != 7 && backupRetention != 14 && backupRetention != 30) {
			return errors.New("backup retention must be 7, 14, or 30 days")
		}
	}
	fmt.Fprintln(stdout, "Installing Jellyfin Proxy. Only this deployment's published HTTP, HTTPS, and WireGuard traffic will be allowed in its network namespace.")
	manifest, err := deployment.Install(ctx, deployment.InstallOptions{
		PackagePath: packagePath, PackageSHA256: packageSHA256, InstallRoot: deployment.DefaultInstallRoot, Domain: installConfig.domain,
		Password: installConfig.password, InitialAllowedIPs: initialAllowedIPs, WireGuardPort: uint16(port), BackupSchedule: backupSchedule,
		BackupRetentionDays: int(backupRetention), RecoveryBackupPath: recoveryBackupPath, ConfigureHostServices: true, Host: facts, Runner: runner,
	})
	if err != nil {
		return err
	}
	installConfig.password = ""
	installConfig.confirm = ""
	fmt.Fprintf(stdout, "Jellyfin Proxy %s is ready. Open https://admin.%s to sign in.\n", manifest.Version, installConfig.domain)
	fmt.Fprintf(stdout, "Download the Windows WireGuard config after signing in, then allow Jellyfin TCP only from 10.66.66.1 in Windows Firewall.\n")
	if recoveryBackupPath != "" {
		fmt.Fprintln(stdout, "Disaster recovery completed with fresh administrator credentials, TOTP setup, WireGuard keys, environment, allowlist, and host settings. Restore any additional host networking manually after reviewing it.")
	}
	return nil
}

func manualHostUpdate(ctx context.Context, input io.Reader, output io.Writer) error {
	if !runningAsRoot() {
		return errors.New("manual host updates require root privileges")
	}
	runner := deployment.ExecRunner{}
	facts, err := deployment.DetectHostFacts(ctx, runner)
	if err != nil {
		return err
	}
	if err := deployment.ValidateHost(facts); err != nil {
		return err
	}
	preview, err := deployment.PreviewHostUpdates(ctx, deployment.HostUpdateOptions{InstallRoot: deployment.DefaultInstallRoot, Runner: runner})
	if err != nil {
		return err
	}
	fmt.Fprintln(output, "Ubuntu package update preview (simulation only):")
	fmt.Fprintln(output, preview)
	approved, err := runApprovalForm(input, output, "Apply these Ubuntu updates", deployment.SummarizeHostUpdatePreview(preview)+" This installs packages now; it will not schedule future updates or reboot this server.")
	if err != nil {
		return err
	}
	if !approved {
		return errors.New("host update cancelled; no packages were installed")
	}
	result, err := deployment.ApplyHostUpdates(ctx, deployment.HostUpdateOptions{InstallRoot: deployment.DefaultInstallRoot, Runner: runner})
	if err != nil {
		return err
	}
	fmt.Fprintln(output, "Ubuntu package updates completed. Docker and application health checks passed.")
	if result.RebootRequired {
		fmt.Fprintln(output, "Ubuntu reports that a reboot is required. Reboot manually when the server is ready; proxyctl will not reboot it.")
	} else {
		fmt.Fprintln(output, "Ubuntu does not currently report a required reboot.")
	}
	return nil
}

func resumeInstall(ctx context.Context, input io.Reader, output io.Writer) error {
	if !runningAsRoot() {
		return errors.New("resuming installation requires root privileges; use sudo proxyctl install --resume")
	}
	runner := deployment.ExecRunner{}
	facts, err := deployment.DetectHostFacts(ctx, runner)
	if err != nil {
		return err
	}
	if err := deployment.ValidateHost(facts); err != nil {
		return err
	}
	preflight, err := deployment.InspectInstallResources(deployment.DefaultInstallRoot, "/var/lib/docker")
	if err != nil {
		return fmt.Errorf("installation resume preflight failed: %w", err)
	}
	fmt.Fprintln(output, preflight.Summary())
	if !preflight.WireGuardKernelAvailable {
		return errors.New("the Ubuntu host does not have WireGuard kernel support; resolve it before resuming installation")
	}
	phase, err := deployment.InstallResumePhase(deployment.DefaultInstallRoot)
	if err != nil {
		return err
	}
	domain, err := deployment.InstallResumeDomain(deployment.DefaultInstallRoot)
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
		fmt.Fprintf(output, "DNS %s -> %s\n", host, strings.Join(values, ", "))
	}
	approved, err := runApprovalForm(input, output, "Resume the installation", "The installer will recheck this domain and continue from the last durable checkpoint. The configured SSH access and host firewall rules remain untouched.")
	if err != nil {
		return err
	}
	if !approved {
		return errors.New("installation resume cancelled")
	}
	reader := bufio.NewReader(input)
	if err := ensureDocker(ctx, runner, facts.Codename, reader, output); err != nil {
		return err
	}
	password := ""
	if phase == "preparing" {
		password, err = runInitialPasswordForm(input, output)
		if err != nil {
			return fmt.Errorf("administrator password: %w", err)
		}
	}
	manifest, resumedPhase, err := deployment.ResumeInstall(ctx, deployment.InstallOptions{InstallRoot: deployment.DefaultInstallRoot, Host: facts, Runner: runner, Password: password, ConfigureHostServices: true})
	password = ""
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "Jellyfin Proxy %s installation resumed and is ready at https://admin.%s.\n", manifest.Version, domain)
	if resumedPhase != "complete" {
		return fmt.Errorf("installation stopped at checkpoint phase %s", resumedPhase)
	}
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
