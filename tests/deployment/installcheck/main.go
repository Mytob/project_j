// installcheck exercises the real installer against a disposable Docker-in-
// Docker daemon after the release archive has been loaded without networking.
package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mytob/project_j/internal/auth"
	"github.com/Mytob/project_j/internal/deployment"
	"github.com/Mytob/project_j/internal/monitoring"
	"github.com/Mytob/project_j/internal/release"
	"github.com/Mytob/project_j/internal/totp"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "installer integration:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return errors.New("usage: installcheck <release-package.tar.gz>")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	runner := installcheckRunner{}
	packagePath, err := filepath.Abs(os.Args[1])
	if err != nil {
		return err
	}
	options := deployment.InstallOptions{
		PackagePath: packagePath, InstallRoot: deployment.DefaultInstallRoot, Domain: "installcheck.example.invalid",
		Password: "correct horse battery staple", WireGuardPort: 51820,
		Host:   deployment.HostFacts{OSID: "ubuntu", VersionID: "26.04", Codename: "resolute", Arch: "x86_64", EffectiveUID: 0},
		Runner: runner, WaitInterval: time.Second, WaitAttempts: 60,
		DNSLookup:  func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("127.0.0.1")}, nil },
		HTTPSCheck: func(context.Context, string) error { return nil },
	}
	hostInputBefore, err := runner.Run(ctx, "iptables", "-S", "INPUT")
	if err != nil {
		return fmt.Errorf("capture isolated host firewall before install: %w", err)
	}
	manifest, err := deployment.Install(ctx, options)
	if err != nil {
		return fmt.Errorf("fresh install failed: %w", err)
	}
	if manifest.Version == "" {
		return errors.New("installer returned an empty release version")
	}
	updateVersion, err := bumpPatchVersion(manifest.Version, 1)
	if err != nil {
		return fmt.Errorf("derive offline update version: %w", err)
	}
	rollbackVersion, err := bumpPatchVersion(manifest.Version, 2)
	if err != nil {
		return fmt.Errorf("derive rollback version: %w", err)
	}
	// Published Docker ports bypass many host INPUT policies after DNAT. Confirm
	// the production WireGuard namespace installs its own narrow ingress filter.
	for _, family := range []struct{ firewall, chain string }{
		{firewall: "iptables", chain: "JELLYFIN_PROXY_INPUT"},
		{firewall: "ip6tables", chain: "JELLYFIN_PROXY_INPUT6"},
	} {
		rules, err := runner.Run(ctx, "docker", "compose", "--project-name", "jellyfin-proxy", "--file", filepath.Join(options.InstallRoot, "compose.yaml"), "--env-file", filepath.Join(options.InstallRoot, ".env"), "exec", "--no-TTY", "wireguard", family.firewall, "-S", family.chain)
		if err != nil {
			return fmt.Errorf("inspect deployment %s firewall: %w", family.firewall, err)
		}
		fmt.Printf("Deployment %s ingress firewall rules:\n%s\n", family.firewall, rules)
		for _, expected := range []string{
			"--dport 80 -j ACCEPT",
			"--dport 443 -j ACCEPT",
			"--dport 51820 -j ACCEPT",
			"-j DROP",
		} {
			if !strings.Contains(rules, expected) {
				return fmt.Errorf("deployment %s firewall is missing %q", family.firewall, expected)
			}
		}
	}
	hostInputAfter, err := runner.Run(ctx, "iptables", "-S", "INPUT")
	if err != nil || hostInputAfter != hostInputBefore {
		return fmt.Errorf("installer changed the isolated host INPUT firewall: before=%q after=%q err=%v", hostInputBefore, hostInputAfter, err)
	}
	// Exercise an actual offline update, persistent-data preservation, failed
	// update rollback, and a local administrator password reset in the same
	// isolated daemon.
	options.InstallRoot = deployment.DefaultInstallRoot
	enrollmentCode, enrollmentTime, err := enableTOTP(options.InstallRoot)
	if err != nil {
		return fmt.Errorf("enable test TOTP before package update: %w", err)
	}
	preserved := map[string][]byte{}
	for _, relative := range []string{"config/admin.json", "config/wireguard/server.conf", "data/wireguard-client/windows.conf", "config/totp.key", "data/totp-state.json", "data/whitelist.json", "site/index.html"} {
		path := filepath.Join(options.InstallRoot, relative)
		data, err := os.ReadFile(path)
		if err != nil {
			if relative != "data/whitelist.json" || !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("read persistent %s before update: %w", relative, err)
			}
		}
		if relative == "data/whitelist.json" {
			data = []byte(`{"version":1,"entries":["203.0.113.10/32"]}`)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				return fmt.Errorf("write update whitelist fixture: %w", err)
			}
			if err := os.Chown(path, 65532, 65532); err != nil {
				return fmt.Errorf("set update whitelist owner: %w", err)
			}
		}
		preserved[relative] = data
	}
	statisticsPath := filepath.Join(options.InstallRoot, "data", "statistics")
	if err := os.MkdirAll(statisticsPath, 0o700); err != nil {
		return fmt.Errorf("create statistics history fixture: %w", err)
	}
	if err := os.Chown(statisticsPath, 65532, 65532); err != nil {
		return fmt.Errorf("set statistics directory owner: %w", err)
	}
	statistics, err := monitoring.OpenHistory(statisticsPath)
	if err != nil {
		return fmt.Errorf("open statistics history fixture: %w", err)
	}
	cpu := 42.0
	sampleAt := time.Now().UTC().Truncate(time.Minute)
	if err := statistics.Append(monitoring.Snapshot{CapturedAt: sampleAt, Host: &monitoring.HostMetrics{CapturedAt: sampleAt, CPUPercent: &cpu}}); err != nil {
		return fmt.Errorf("write statistics history fixture: %w", err)
	}
	historyRelative := filepath.Join("data", "statistics", sampleAt.Format("2006-01-02")+".json.gz")
	historyFile := filepath.Join(options.InstallRoot, historyRelative)
	if err := os.Chown(historyFile, 65532, 65532); err != nil {
		return fmt.Errorf("set statistics file owner: %w", err)
	}
	if err := os.WriteFile(filepath.Join(options.InstallRoot, "site", "operator-page.txt"), []byte("preserve operator site"), 0o644); err != nil {
		return fmt.Errorf("write operator site fixture: %w", err)
	}
	updatePackage, updatePackageDir, err := makeUpdatePackage(ctx, runner, os.Args[1], updateVersion)
	if err != nil {
		return fmt.Errorf("prepare update package: %w", err)
	}
	defer os.RemoveAll(updatePackageDir)
	updated, err := deployment.Update(ctx, deployment.UpdateOptions{
		PackagePath: updatePackage, InstallRoot: options.InstallRoot, Host: options.Host, Runner: runner,
		WaitInterval: time.Second, WaitAttempts: 60, HTTPSCheck: func(context.Context, string) error { return nil },
	})
	if err != nil {
		return fmt.Errorf("offline update failed: %w", err)
	}
	if updated.Version != updateVersion {
		return fmt.Errorf("offline update selected unexpected version %s", updated.Version)
	}
	for relative, expected := range preserved {
		data, err := os.ReadFile(filepath.Join(options.InstallRoot, relative))
		if err != nil || string(data) != string(expected) {
			return fmt.Errorf("update changed persistent %s: %q (%v)", relative, data, err)
		}
	}
	reopenedHistory, err := monitoring.OpenHistory(statisticsPath)
	if err != nil || len(reopenedHistory.Range(sampleAt.Add(-time.Second), sampleAt.Add(time.Second), 10)) != 1 {
		return fmt.Errorf("statistics history did not survive update/reopen: %v", err)
	}
	if err := verifyEnabledTOTP(options.InstallRoot, enrollmentCode, enrollmentTime); err != nil {
		return fmt.Errorf("TOTP did not survive the packaged update: %w", err)
	}
	if data, err := os.ReadFile(filepath.Join(options.InstallRoot, "site", "operator-page.txt")); err != nil || string(data) != "preserve operator site" {
		return fmt.Errorf("update changed operator website: %q (%v)", data, err)
	}
	for _, version := range []string{manifest.Version, updateVersion} {
		if _, err := os.Stat(filepath.Join(options.InstallRoot, "releases", version)); err != nil {
			return fmt.Errorf("active/previous release %s was not retained: %w", version, err)
		}
	}
	rollbackPackage, rollbackPackageDir, err := makeUpdatePackage(ctx, runner, os.Args[1], rollbackVersion)
	if err != nil {
		return fmt.Errorf("prepare rollback package: %w", err)
	}
	defer os.RemoveAll(rollbackPackageDir)
	if _, err := deployment.Update(ctx, deployment.UpdateOptions{
		PackagePath: rollbackPackage, InstallRoot: options.InstallRoot, Host: options.Host, Runner: runner,
		WaitInterval: time.Second, WaitAttempts: 60,
		HTTPSCheck: func(context.Context, string) error { return errors.New("forced post-update HTTPS failure") },
	}); err == nil {
		return errors.New("update unexpectedly survived forced HTTPS failure")
	}
	environment, err := os.ReadFile(filepath.Join(options.InstallRoot, ".env"))
	if err != nil || !strings.Contains(string(environment), "RELEASE_VERSION="+updateVersion+"\n") {
		return fmt.Errorf("failed update did not restore active version: %q (%v)", environment, err)
	}
	if _, err := os.Lstat(filepath.Join(options.InstallRoot, "releases", rollbackVersion)); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed update release was not cleaned up: %v", err)
	}
	reopenedHistory, err = monitoring.OpenHistory(statisticsPath)
	if err != nil || len(reopenedHistory.Range(sampleAt.Add(-time.Second), sampleAt.Add(time.Second), 10)) != 1 {
		return fmt.Errorf("statistics history did not survive failed update rollback: %v", err)
	}
	if _, err := deployment.Update(ctx, deployment.UpdateOptions{
		PackagePath: rollbackPackage, InstallRoot: options.InstallRoot, Host: options.Host, Runner: runner,
		WaitInterval: time.Second, WaitAttempts: 60, HTTPSCheck: func(context.Context, string) error { return nil },
	}); err != nil {
		return fmt.Errorf("successful update after rollback failed: %w", err)
	}
	for _, version := range []string{updateVersion, rollbackVersion} {
		if _, err := os.Stat(filepath.Join(options.InstallRoot, "releases", version)); err != nil {
			return fmt.Errorf("active/previous release %s was not retained after successful cleanup: %w", version, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(options.InstallRoot, "releases", manifest.Version)); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("older release was not removed after successful update: %v", err)
	}
	reopenedHistory, err = monitoring.OpenHistory(statisticsPath)
	if err != nil || len(reopenedHistory.Range(sampleAt.Add(-time.Second), sampleAt.Add(time.Second), 10)) != 1 {
		return fmt.Errorf("statistics history did not survive update after rollback: %v", err)
	}
	for relative, expected := range preserved {
		data, err := os.ReadFile(filepath.Join(options.InstallRoot, relative))
		if err != nil || string(data) != string(expected) {
			return fmt.Errorf("rollback/update changed persistent %s: %q (%v)", relative, data, err)
		}
	}
	if err := backupRestoreEnabledTOTP(ctx, runner, options.InstallRoot, enrollmentCode, enrollmentTime); err != nil {
		return fmt.Errorf("TOTP backup/restore check failed: %w", err)
	}
	if err := exercisePackagedTOTPRecovery(ctx, runner, options.InstallRoot, rollbackVersion); err != nil {
		return fmt.Errorf("packaged TOTP recovery CLI check failed: %w", err)
	}
	if err := deployment.ResetPassword(ctx, options.InstallRoot, "reset password for installcheck", runner); err != nil {
		return fmt.Errorf("local password reset failed: %w", err)
	}
	credential, err := auth.LoadCredential(filepath.Join(options.InstallRoot, "config", "admin.json"))
	if err != nil || !credential.Verify("reset password for installcheck") || credential.Verify("correct horse battery staple") {
		return fmt.Errorf("password reset credential verification failed: %v", err)
	}
	if err := cleanupDeployment(runner, options.InstallRoot); err != nil {
		return err
	}

	// Reserve a published port to force Compose startup failure after preflight.
	// The installer must remove its own partial deployment while leaving this
	// unrelated container alone.
	conflictName := "jellyfin-proxy-installcheck-port-conflict"
	if _, err := runner.Run(ctx, "docker", "run", "--detach", "--name", conflictName, "--publish", "80:80", "alpine:3.24.2", "sleep", "240"); err != nil {
		return fmt.Errorf("create scoped port-conflict fixture: %w", err)
	}
	defer func() { _, _ = runner.Run(context.Background(), "docker", "rm", "--force", conflictName) }()
	failureOptions := options
	failureOptions.InstallRoot = "/opt/jellyfin-proxy-installcheck-failure"
	if _, err := deployment.Install(ctx, failureOptions); err == nil {
		return errors.New("installer unexpectedly succeeded while public port 80 was already allocated")
	}
	if _, err := os.Lstat(failureOptions.InstallRoot); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed installation left partial files at %s", failureOptions.InstallRoot)
	}
	state, err := runner.Run(ctx, "docker", "inspect", "--format", "{{.State.Running}}", conflictName)
	if err != nil || strings.TrimSpace(state) != "true" {
		return errors.New("failed installation changed or removed the unrelated port-conflict container")
	}
	fmt.Printf("M8 installation and M9 update, preservation, rollback, retention, and password reset passed (starting package %s).\n", manifest.Version)
	return nil
}

type installcheckRunner struct{}

func (installcheckRunner) Run(ctx context.Context, executable string, args ...string) (string, error) {
	command := executable + " " + strings.Join(args, " ")
	trace := strings.Contains(command, " ps --format json") || strings.Contains(command, " up --detach") || strings.Contains(command, " stop admin")
	if trace {
		fmt.Printf("Install-check command started: %s\n", command)
	}
	output, err := (deployment.ExecRunner{}).Run(ctx, executable, args...)
	if err != nil && executable == "docker" {
		for index, argument := range args {
			if argument != "up" || index+1 >= len(args) || args[index+1] != "--detach" {
				continue
			}
			logArgs := append(append([]string(nil), args[:index]...), "logs", "--no-color", "--tail", "80")
			logs, logErr := (deployment.ExecRunner{}).Run(ctx, executable, logArgs...)
			if logErr == nil && strings.TrimSpace(logs) != "" {
				err = fmt.Errorf("%w; deployment service logs:\n%s", err, logs)
			}
			break
		}
	}
	if trace {
		if err != nil {
			fmt.Printf("Install-check command failed: %s: %v\n", command, err)
		} else {
			fmt.Printf("Install-check command completed: %s\n", command)
		}
	}
	return output, err
}

func cleanupDeployment(runner deployment.CommandRunner, root string) error {
	_, err := runner.Run(context.Background(), "docker", "compose", "--project-name", "jellyfin-proxy", "--file", filepath.Join(root, "compose.yaml"), "--env-file", filepath.Join(root, ".env"), "down", "--remove-orphans", "--volumes")
	if err != nil {
		return fmt.Errorf("stop successful installer fixture: %w", err)
	}
	if err := os.RemoveAll(root); err != nil {
		return fmt.Errorf("remove installer fixture: %w", err)
	}
	return nil
}

func enableTOTP(root string) (string, time.Time, error) {
	key, err := auth.LoadTOTPKey(filepath.Join(root, "config", "totp.key"))
	if err != nil {
		return "", time.Time{}, err
	}
	defer clear(key)
	statePath := filepath.Join(root, "data", "totp-state.json")
	store, err := auth.NewTOTPStore(statePath, key)
	if err != nil {
		return "", time.Time{}, err
	}
	secret, err := store.BeginEnrollment()
	if err != nil {
		return "", time.Time{}, err
	}
	at := time.Now().UTC().Truncate(totp.Period)
	code, err := totp.Code(secret, at)
	clear(secret)
	if err != nil {
		return "", time.Time{}, err
	}
	if err := store.ConfirmEnrollment(code, at); err != nil {
		return "", time.Time{}, err
	}
	if err := os.Chown(statePath, 65532, 65532); err != nil {
		return "", time.Time{}, err
	}
	if err := os.Chmod(statePath, 0o600); err != nil {
		return "", time.Time{}, err
	}
	return code, at, nil
}

func verifyEnabledTOTP(root, consumedCode string, at time.Time) error {
	key, err := auth.LoadTOTPKey(filepath.Join(root, "config", "totp.key"))
	if err != nil {
		return err
	}
	defer clear(key)
	store, err := auth.NewTOTPStore(filepath.Join(root, "data", "totp-state.json"), key)
	if err != nil {
		return err
	}
	if store.Status() != auth.TOTPEnabled {
		return fmt.Errorf("TOTP status is %s, not enabled", store.Status())
	}
	accepted, err := store.Verify(consumedCode, at)
	if err != nil {
		return err
	}
	if accepted {
		return errors.New("a consumed enrollment code became reusable")
	}
	return nil
}

func backupRestoreEnabledTOTP(ctx context.Context, runner deployment.CommandRunner, root, consumedCode string, at time.Time) error {
	backupRoot, err := os.MkdirTemp("", "jellyfin-proxy-totp-backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(backupRoot)
	keyPath := filepath.Join(root, "config", "totp.key")
	statePath := filepath.Join(root, "data", "totp-state.json")
	keyBackup, stateBackup := filepath.Join(backupRoot, "totp.key"), filepath.Join(backupRoot, "totp-state.json")
	for _, file := range []struct {
		source, destination string
		mode                os.FileMode
	}{
		{source: keyPath, destination: keyBackup, mode: 0o640},
		{source: statePath, destination: stateBackup, mode: 0o600},
	} {
		data, err := os.ReadFile(file.source)
		if err != nil {
			return err
		}
		if err := os.WriteFile(file.destination, data, file.mode); err != nil {
			return err
		}
	}
	if _, err := runner.Run(ctx, "docker", composeArgs(root, "stop", "admin")...); err != nil {
		return fmt.Errorf("stop admin for restore: %w", err)
	}
	if err := os.Remove(statePath); err != nil {
		return err
	}
	if err := os.Remove(keyPath); err != nil {
		return err
	}
	for _, file := range []struct {
		source, destination string
		mode                os.FileMode
		uid, gid            int
	}{
		{source: keyBackup, destination: keyPath, mode: 0o640, uid: 0, gid: 65532},
		{source: stateBackup, destination: statePath, mode: 0o600, uid: 65532, gid: 65532},
	} {
		data, err := os.ReadFile(file.source)
		if err != nil {
			return err
		}
		if err := os.WriteFile(file.destination, data, file.mode); err != nil {
			return err
		}
		if err := os.Chown(file.destination, file.uid, file.gid); err != nil {
			return err
		}
		if err := os.Chmod(file.destination, file.mode); err != nil {
			return err
		}
	}
	if err := verifyEnabledTOTP(root, consumedCode, at); err != nil {
		return fmt.Errorf("restored key/state pair failed validation: %w", err)
	}
	if _, err := runner.Run(ctx, "docker", composeArgs(root, "up", "--detach", "--no-deps", "--force-recreate", "--pull", "never", "admin")...); err != nil {
		return fmt.Errorf("restart admin after restore: %w", err)
	}
	return waitAdminHealthy(ctx, runner, root)
}

func exercisePackagedTOTPRecovery(ctx context.Context, runner deployment.CommandRunner, root, version string) error {
	cliPath := filepath.Join(root, "releases", version, "bin", "proxyctl-linux-amd64")
	credentialPath := filepath.Join(root, "config", "admin.json")
	credentialBefore, err := os.ReadFile(credentialPath)
	if err != nil {
		return err
	}
	runCLI := func(command string) error {
		output, err := exec.CommandContext(ctx, cliPath, command).CombinedOutput()
		if err != nil {
			return fmt.Errorf("proxyctl %s: %w: %s", command, err, strings.TrimSpace(string(output)))
		}
		return nil
	}
	readStatus := func(want auth.TOTPStatus) error {
		key, err := auth.LoadTOTPKey(filepath.Join(root, "config", "totp.key"))
		if err != nil {
			return err
		}
		defer clear(key)
		store, err := auth.NewTOTPStore(filepath.Join(root, "data", "totp-state.json"), key)
		if err != nil {
			return err
		}
		if store.Status() != want {
			return fmt.Errorf("TOTP status is %s, want %s", store.Status(), want)
		}
		return waitAdminHealthy(ctx, runner, root)
	}
	if err := runCLI("reset-totp"); err != nil {
		return err
	}
	if err := readStatus(auth.TOTPRecovery); err != nil {
		return err
	}
	if err := runCLI("disable-totp"); err != nil {
		return err
	}
	if err := readStatus(auth.TOTPUnconfigured); err != nil {
		return err
	}
	if _, _, err := enableTOTP(root); err != nil {
		return fmt.Errorf("prepare enabled factor for replace-totp: %w", err)
	}
	if err := runCLI("replace-totp"); err != nil {
		return err
	}
	if err := readStatus(auth.TOTPRecovery); err != nil {
		return err
	}
	stateBefore, err := os.ReadFile(filepath.Join(root, "data", "totp-state.json"))
	if err != nil {
		return err
	}
	output, err := exec.CommandContext(ctx, cliPath, "replace-totp").CombinedOutput()
	if err == nil || !strings.Contains(string(output), "requires an enabled authenticator") {
		return fmt.Errorf("replace-totp accepted recovery state: err=%v output=%s", err, strings.TrimSpace(string(output)))
	}
	stateAfter, err := os.ReadFile(filepath.Join(root, "data", "totp-state.json"))
	if err != nil || string(stateAfter) != string(stateBefore) {
		return fmt.Errorf("rejected replace changed state: %v", err)
	}
	if err := runCLI("disable-totp"); err != nil {
		return err
	}
	if err := readStatus(auth.TOTPUnconfigured); err != nil {
		return err
	}
	credentialAfter, err := os.ReadFile(credentialPath)
	if err != nil || string(credentialAfter) != string(credentialBefore) {
		return fmt.Errorf("TOTP recovery changed the administrator password: %v", err)
	}
	return nil
}

func waitAdminHealthy(ctx context.Context, runner deployment.CommandRunner, root string) error {
	for attempt := 0; attempt < 60; attempt++ {
		output, err := runner.Run(ctx, "docker", composeArgs(root, "ps", "--format", "json")...)
		if err == nil {
			for _, line := range strings.Split(output, "\n") {
				var service struct {
					Service string
					Health  string
				}
				if json.Unmarshal([]byte(line), &service) == nil && service.Service == "admin" && service.Health == "healthy" {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("admin did not become healthy after restart")
}

func composeArgs(root string, args ...string) []string {
	base := []string{"compose", "--project-name", "jellyfin-proxy", "--file", filepath.Join(root, "compose.yaml"), "--env-file", filepath.Join(root, ".env")}
	return append(base, args...)
}

func makeUpdatePackage(ctx context.Context, runner deployment.CommandRunner, sourceArchive, version string) (archivePath, workDirectory string, resultErr error) {
	workDirectory, err := os.MkdirTemp("", "jellyfin-proxy-update-package-")
	if err != nil {
		return "", "", err
	}
	defer func() {
		if resultErr != nil {
			_ = os.RemoveAll(workDirectory)
		}
	}()
	packageDirectory := filepath.Join(workDirectory, "package")
	manifest, err := release.ExtractAndValidate(sourceArchive, packageDirectory)
	if err != nil {
		return "", "", err
	}
	oldVersion := manifest.Version
	for _, image := range []string{"admin", "hostmetrics", "containerhealth", "wireguard", "caddy"} {
		oldRef := "jellyfin-proxy/" + image + ":" + oldVersion
		newRef := "jellyfin-proxy/" + image + ":" + version
		if _, err := runner.Run(ctx, "docker", "image", "tag", oldRef, newRef); err != nil {
			return "", "", err
		}
	}
	newImages := []string{
		"jellyfin-proxy/admin:" + version,
		"jellyfin-proxy/hostmetrics:" + version,
		"jellyfin-proxy/containerhealth:" + version,
		"jellyfin-proxy/wireguard:" + version,
		"jellyfin-proxy/caddy:" + version,
		"alpine:3.24.2",
	}
	imagesPath := filepath.Join(packageDirectory, "images-update.tar")
	if _, err := runner.Run(ctx, "docker", append([]string{"image", "save", "--output", imagesPath}, newImages...)...); err != nil {
		return "", "", err
	}
	if err := os.Rename(imagesPath, filepath.Join(packageDirectory, "images.tar")); err != nil {
		return "", "", err
	}
	manifest.Version = version
	for i := range manifest.Images {
		manifest.Images[i].Reference = strings.Replace(manifest.Images[i].Reference, ":"+oldVersion, ":"+version, 1)
	}
	manifest.Files = nil
	if err := filepath.WalkDir(packageDirectory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || path == filepath.Join(packageDirectory, "manifest.json") {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("unexpected update package entry %s", path)
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		relative, err := filepath.Rel(packageDirectory, path)
		if err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, release.ManifestFile{
			Path: filepath.ToSlash(relative), SizeBytes: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil)),
		})
		return nil
	}); err != nil {
		return "", "", err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(filepath.Join(packageDirectory, "manifest.json"), append(encoded, '\n'), 0o644); err != nil {
		return "", "", err
	}
	archivePath = filepath.Join(workDirectory, "update.tar.gz")
	archive, err := os.Create(archivePath)
	if err != nil {
		return "", "", err
	}
	compressed := gzip.NewWriter(archive)
	writer := tar.NewWriter(compressed)
	err = filepath.Walk(packageDirectory, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(packageDirectory, path)
		if err != nil {
			return err
		}
		name := "."
		if relative != "." {
			name = filepath.ToSlash(relative)
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = name
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(writer, input)
		closeErr := input.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err == nil {
		err = writer.Close()
	}
	if err == nil {
		err = compressed.Close()
	}
	if err == nil {
		err = archive.Close()
	} else {
		_ = writer.Close()
		_ = compressed.Close()
		_ = archive.Close()
	}
	if err != nil {
		return "", "", err
	}
	return archivePath, workDirectory, nil
}
