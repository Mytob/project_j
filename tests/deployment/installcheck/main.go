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
	"path/filepath"
	"strings"
	"time"

	"github.com/Mytob/project_j/internal/auth"
	"github.com/Mytob/project_j/internal/deployment"
	"github.com/Mytob/project_j/internal/release"
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
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	runner := deployment.ExecRunner{}
	packagePath, err := filepath.Abs(os.Args[1])
	if err != nil {
		return err
	}
	options := deployment.InstallOptions{
		PackagePath: packagePath, InstallRoot: "/opt/jellyfin-proxy-installcheck", Domain: "installcheck.example.invalid",
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
	options.InstallRoot = "/opt/jellyfin-proxy-installcheck"
	preserved := map[string][]byte{}
	for _, relative := range []string{"config/admin.json", "config/wireguard/server.conf", "config/wireguard/windows.conf", "data/whitelist.json", "site/index.html"} {
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
	if err := os.WriteFile(filepath.Join(options.InstallRoot, "site", "operator-page.txt"), []byte("preserve operator site"), 0o644); err != nil {
		return fmt.Errorf("write operator site fixture: %w", err)
	}
	updatePackage, updatePackageDir, err := makeUpdatePackage(ctx, runner, os.Args[1], "1.0.1-dev")
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
	if updated.Version != "1.0.1-dev" {
		return fmt.Errorf("offline update selected unexpected version %s", updated.Version)
	}
	for relative, expected := range preserved {
		data, err := os.ReadFile(filepath.Join(options.InstallRoot, relative))
		if err != nil || string(data) != string(expected) {
			return fmt.Errorf("update changed persistent %s: %q (%v)", relative, data, err)
		}
	}
	if data, err := os.ReadFile(filepath.Join(options.InstallRoot, "site", "operator-page.txt")); err != nil || string(data) != "preserve operator site" {
		return fmt.Errorf("update changed operator website: %q (%v)", data, err)
	}
	for _, version := range []string{"1.0.0-dev", "1.0.1-dev"} {
		if _, err := os.Stat(filepath.Join(options.InstallRoot, "releases", version)); err != nil {
			return fmt.Errorf("active/previous release %s was not retained: %w", version, err)
		}
	}
	rollbackPackage, rollbackPackageDir, err := makeUpdatePackage(ctx, runner, os.Args[1], "1.0.2-dev")
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
	if err != nil || !strings.Contains(string(environment), "RELEASE_VERSION=1.0.1-dev\n") {
		return fmt.Errorf("failed update did not restore active version: %q (%v)", environment, err)
	}
	if _, err := os.Lstat(filepath.Join(options.InstallRoot, "releases", "1.0.2-dev")); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed update release was not cleaned up: %v", err)
	}
	if _, err := deployment.Update(ctx, deployment.UpdateOptions{
		PackagePath: rollbackPackage, InstallRoot: options.InstallRoot, Host: options.Host, Runner: runner,
		WaitInterval: time.Second, WaitAttempts: 60, HTTPSCheck: func(context.Context, string) error { return nil },
	}); err != nil {
		return fmt.Errorf("successful update after rollback failed: %w", err)
	}
	for _, version := range []string{"1.0.1-dev", "1.0.2-dev"} {
		if _, err := os.Stat(filepath.Join(options.InstallRoot, "releases", version)); err != nil {
			return fmt.Errorf("active/previous release %s was not retained after successful cleanup: %w", version, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(options.InstallRoot, "releases", "1.0.0-dev")); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("older release was not removed after successful update: %v", err)
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
	if _, err := runner.Run(ctx, "docker", "run", "--detach", "--name", conflictName, "--publish", "80:80", "alpine:3.22", "sleep", "240"); err != nil {
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
	for _, image := range []string{"admin", "wireguard"} {
		oldRef := "jellyfin-proxy/" + image + ":" + oldVersion
		newRef := "jellyfin-proxy/" + image + ":" + version
		if _, err := runner.Run(ctx, "docker", "image", "tag", oldRef, newRef); err != nil {
			return "", "", err
		}
	}
	newImages := []string{
		"jellyfin-proxy/admin:" + version,
		"jellyfin-proxy/wireguard:" + version,
		"caddy:2.10.2-alpine",
		"alpine:3.22",
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
