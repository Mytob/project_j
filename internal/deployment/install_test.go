package deployment

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mytob/project_j/internal/auth"
	"github.com/Mytob/project_j/internal/release"
	"github.com/Mytob/project_j/internal/totp"
)

type fakeRunner struct {
	commands          []string
	failOn            string
	unhealthy         bool
	existingResources bool
}

func (r *fakeRunner) Run(_ context.Context, executable string, args ...string) (string, error) {
	command := executable + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	if r.failOn != "" && strings.Contains(command, r.failOn) {
		return "simulated command failure", fmt.Errorf("simulated failure: %s", r.failOn)
	}
	if strings.Contains(command, "--filter label=com.docker.compose.project=jellyfin-proxy") {
		if r.existingResources {
			return "existing-resource", nil
		}
		return "", nil
	}
	if strings.Contains(command, " ps --format json") {
		if r.unhealthy {
			return "{\"Service\":\"wireguard\",\"State\":\"running\",\"Health\":\"starting\"}\n", nil
		}
		return "{\"Service\":\"wireguard\",\"State\":\"running\",\"Health\":\"healthy\"}\n" +
			"{\"Service\":\"caddy\",\"State\":\"running\",\"Health\":\"healthy\"}\n" +
			"{\"Service\":\"admin\",\"State\":\"running\",\"Health\":\"healthy\"}\n", nil
	}
	if len(args) >= 5 && args[0] == "image" && args[1] == "save" && args[2] == "--output" {
		if err := writeFakeDockerArchive(args[3], args[4:]); err != nil {
			return "", err
		}
		return "", nil
	}
	return "ok", nil
}

func TestInstallCreatesFreshDefaultDenyDeployment(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("installer filesystem test requires a root Linux test container")
	}
	packagePath := makeInstallPackage(t)
	root := filepath.Join(t.TempDir(), "jellyfin-proxy")
	runner := &fakeRunner{}
	manifest, err := Install(context.Background(), InstallOptions{
		PackagePath: packagePath, InstallRoot: root, Domain: "Example.com", Password: "correct horse battery staple",
		WireGuardPort: 51820, Host: validHost(), Runner: runner, WaitInterval: time.Millisecond, WaitAttempts: 1,
		DNSLookup: func(_ context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.20")}, nil
		},
		HTTPSCheck: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != "1.0.0-dev" {
		t.Fatalf("installed manifest version %q", manifest.Version)
	}
	if _, err := os.Stat(filepath.Join(root, "data", "whitelist.json")); !os.IsNotExist(err) {
		t.Fatalf("first install should have no allowed clients: %v", err)
	}
	credential, err := auth.LoadCredential(filepath.Join(root, "config", "admin.json"))
	if err != nil || !credential.Verify("correct horse battery staple") {
		t.Fatalf("administrator credential: %v", err)
	}
	adminInfo, err := os.Stat(filepath.Join(root, "config", "admin.json"))
	if err != nil || adminInfo.Mode().Perm() != 0o640 {
		t.Fatalf("admin credential mode = %v, %v", adminInfo, err)
	}
	serverInfo, err := os.Stat(filepath.Join(root, "config", "wireguard", "server.conf"))
	if err != nil || serverInfo.Mode().Perm() != 0o600 {
		t.Fatalf("server key mode = %v, %v", serverInfo, err)
	}
	clientInfo, err := os.Stat(filepath.Join(root, "config", "wireguard", "windows.conf"))
	if err != nil || clientInfo.Mode().Perm() != 0o640 {
		t.Fatalf("Windows config mode = %v, %v", clientInfo, err)
	}
	totpKeyPath := filepath.Join(root, "config", "totp.key")
	totpKey, err := auth.LoadTOTPKey(totpKeyPath)
	if err != nil || len(totpKey) != 32 {
		t.Fatalf("administrator TOTP key length=%d err=%v", len(totpKey), err)
	}
	clear(totpKey)
	if info, err := os.Stat(totpKeyPath); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("TOTP key mode = %v, %v", info, err)
	}
	totpStatePath := filepath.Join(root, "data", "totp-state.json")
	totpStore, err := auth.NewTOTPStore(totpStatePath, mustLoadTOTPKey(t, totpKeyPath))
	if err != nil || totpStore.Status() != auth.TOTPUnconfigured {
		t.Fatalf("initial TOTP state = %v, %v", totpStore, err)
	}
	if info, err := os.Stat(totpStatePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("TOTP state mode = %v, %v", info, err)
	}
	environment, err := os.ReadFile(filepath.Join(root, ".env"))
	if err != nil || !strings.Contains(string(environment), "BASE_DOMAIN=example.com\n") || !strings.Contains(string(environment), "WIREGUARD_PORT=51820\n") {
		t.Fatalf("deployment environment: %q, %v", environment, err)
	}
	for _, expected := range []string{"docker image load --input", "compose --project-name jellyfin-proxy", "up --detach"} {
		if !strings.Contains(strings.Join(runner.commands, "\n"), expected) {
			t.Errorf("installer did not run %q: %v", expected, runner.commands)
		}
	}
	for _, command := range runner.commands {
		if strings.HasPrefix(command, "docker pull ") || strings.Contains(command, " compose pull ") {
			t.Fatalf("installer attempted to pull an application image: %s", command)
		}
	}
}

func TestInstallHTTPSFailureRollsBackFreshRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("installer filesystem test requires a root Linux test container")
	}
	root := filepath.Join(t.TempDir(), "jellyfin-proxy")
	runner := &fakeRunner{}
	_, err := Install(context.Background(), InstallOptions{
		PackagePath: makeInstallPackage(t), InstallRoot: root, Domain: "example.com", Password: "correct horse battery staple",
		Host: validHost(), Runner: runner, WaitInterval: time.Millisecond, WaitAttempts: 1,
		DNSLookup:  func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.20")}, nil },
		HTTPSCheck: func(context.Context, string) error { return fmt.Errorf("certificate is not ready") },
	})
	if err == nil || !strings.Contains(err.Error(), "public HTTPS did not become ready") {
		t.Fatalf("HTTPS readiness error = %v", err)
	}
	if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
		t.Fatalf("partial install root remains after HTTPS failure: %v", statErr)
	}
	if !strings.Contains(strings.Join(runner.commands, "\n"), "down --remove-orphans") {
		t.Fatalf("Compose services were not stopped after HTTPS failure: %v", runner.commands)
	}
}

func TestInstallFailureStopsDeploymentAndRemovesPartialFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("installer filesystem test requires a root Linux test container")
	}
	root := filepath.Join(t.TempDir(), "jellyfin-proxy")
	runner := &fakeRunner{failOn: "up --detach"}
	_, err := Install(context.Background(), InstallOptions{
		PackagePath: makeInstallPackage(t), InstallRoot: root, Domain: "example.com", Password: "correct horse battery staple",
		Host: validHost(), Runner: runner, WaitInterval: time.Millisecond, WaitAttempts: 1,
		DNSLookup: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.20")}, nil },
	})
	if err == nil {
		t.Fatal("install unexpectedly succeeded")
	}
	if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
		t.Fatalf("partial install root remains after failure: %v", statErr)
	}
	if !strings.Contains(strings.Join(runner.commands, "\n"), "down --remove-orphans") {
		t.Fatalf("partial Compose deployment was not stopped: %v", runner.commands)
	}
}

func TestInstallRefusesExistingData(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "keep-me")
	if err := os.WriteFile(marker, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	_, err := Install(context.Background(), InstallOptions{
		PackagePath: "missing", InstallRoot: root, Domain: "example.com", Password: "correct horse battery staple",
		Host: validHost(), Runner: runner,
		DNSLookup: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.20")}, nil },
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing root error = %v", err)
	}
	if data, readErr := os.ReadFile(marker); readErr != nil || string(data) != "existing" {
		t.Fatalf("existing data changed: %q, %v", data, readErr)
	}
}

func TestInstallRefusesExistingComposeProjectResources(t *testing.T) {
	root := filepath.Join(t.TempDir(), "jellyfin-proxy")
	runner := &fakeRunner{existingResources: true}
	_, err := Install(context.Background(), InstallOptions{
		PackagePath: "missing", InstallRoot: root, Domain: "example.com", Password: "correct horse battery staple",
		Host: validHost(), Runner: runner,
		DNSLookup: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.20")}, nil },
	})
	if err == nil || !strings.Contains(err.Error(), "Docker resources") {
		t.Fatalf("existing Compose resources error = %v", err)
	}
	if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
		t.Fatalf("existing project created an install root: %v", statErr)
	}
	if strings.Contains(strings.Join(runner.commands, "\n"), " compose ") {
		t.Fatalf("installer tried to change existing Compose resources: %v", runner.commands)
	}
}

func TestComposeReadinessRequiresAllServicesHealthy(t *testing.T) {
	healthy := "{\"Service\":\"wireguard\",\"State\":\"running\",\"Health\":\"healthy\"}\n" +
		"{\"Service\":\"caddy\",\"State\":\"running\",\"Health\":\"healthy\"}\n" +
		"{\"Service\":\"admin\",\"State\":\"running\",\"Health\":\"healthy\"}\n" +
		"{\"Service\":\"caddy-socket-init\",\"State\":\"exited\"}\n"
	if !composeServicesHealthy(healthy) {
		t.Fatal("healthy production services were rejected")
	}
	if composeServicesHealthy(strings.Replace(healthy, `"Health":"healthy"`, `"Health":"starting"`, 1)) {
		t.Fatal("unhealthy service was accepted")
	}
}

func TestDockerSourcesFileUsesOfficialRepositoryAndValidatedCodename(t *testing.T) {
	source, err := DockerSourcesFile("resolute")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"https://download.docker.com/linux/ubuntu", "Suites: resolute", "Architectures: amd64", "Signed-By: /etc/apt/keyrings/docker.asc"} {
		if !strings.Contains(source, expected) {
			t.Errorf("Docker source missing %q", expected)
		}
	}
	if _, err := DockerSourcesFile("resolute\nURIs: https://attacker.example"); err == nil {
		t.Fatal("invalid codename accepted")
	}
}

func TestUpdatePreservesPersistentDataAndRetainsActiveAndPrevious(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("installer filesystem test requires a root Linux test container")
	}
	root := filepath.Join(t.TempDir(), "jellyfin-proxy")
	runner := &fakeRunner{}
	installFixture(t, root, runner)
	totpKey := mustLoadTOTPKey(t, filepath.Join(root, "config", "totp.key"))
	totpStore, err := auth.NewTOTPStore(filepath.Join(root, "data", "totp-state.json"), totpKey)
	clear(totpKey)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := totpStore.BeginEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	enrolledAt := time.Unix(1_700_000_010, 0)
	enrollmentCode, err := totp.Code(secret, enrolledAt)
	clear(secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := totpStore.ConfirmEnrollment(enrollmentCode, enrolledAt); err != nil {
		t.Fatal(err)
	}
	preserved := map[string][]byte{}
	for _, relative := range []string{
		"config/admin.json", "config/wireguard/server.conf", "config/wireguard/windows.conf",
		"config/totp.key", "data/totp-state.json", "data/whitelist.json", "site/index.html",
	} {
		path := filepath.Join(root, relative)
		data, err := os.ReadFile(path)
		if err != nil {
			if relative == "data/whitelist.json" && os.IsNotExist(err) {
				data = []byte(`{"version":1,"entries":["203.0.113.10/32"]}`)
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				t.Fatal(err)
			}
		}
		preserved[relative] = data
	}
	if err := os.WriteFile(filepath.Join(root, "site", "operator-page.txt"), []byte("keep site content"), 0o644); err != nil {
		t.Fatal(err)
	}
	packagePath := makeInstallPackageVersion(t, "1.0.1-dev")
	manifest, err := Update(context.Background(), UpdateOptions{
		PackagePath: packagePath, InstallRoot: root, Host: validHost(), Runner: runner,
		WaitInterval: time.Millisecond, WaitAttempts: 1, HTTPSCheck: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != "1.0.1-dev" {
		t.Fatalf("updated version = %s", manifest.Version)
	}
	for relative, expected := range preserved {
		actual, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil || string(actual) != string(expected) {
			t.Errorf("update changed persistent %s: got %q, err=%v", relative, actual, err)
		}
	}
	preservedKey := mustLoadTOTPKey(t, filepath.Join(root, "config", "totp.key"))
	preservedTOTP, err := auth.NewTOTPStore(filepath.Join(root, "data", "totp-state.json"), preservedKey)
	clear(preservedKey)
	if err != nil || preservedTOTP.Status() != auth.TOTPEnabled {
		t.Fatalf("TOTP state after update: store=%v err=%v", preservedTOTP, err)
	}
	accepted, err := preservedTOTP.Verify(enrollmentCode, enrolledAt)
	if err != nil || accepted {
		t.Fatalf("update allowed enrollment-code replay accepted=%v err=%v", accepted, err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "site", "operator-page.txt")); err != nil || string(data) != "keep site content" {
		t.Errorf("update changed operator site file: %q, %v", data, err)
	}
	environment, err := os.ReadFile(filepath.Join(root, ".env"))
	if err != nil || !strings.Contains(string(environment), "RELEASE_VERSION=1.0.1-dev\n") {
		t.Fatalf("active environment not updated: %q, %v", environment, err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "releases"))
	if err != nil {
		t.Fatal(err)
	}
	versions := []string{}
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			versions = append(versions, entry.Name())
		}
	}
	if strings.Join(versions, ",") != "1.0.0-dev,1.0.1-dev" {
		t.Fatalf("active and previous releases = %v", versions)
	}
	commands := strings.Join(runner.commands, "\n")
	if strings.Contains(commands, "docker pull ") || strings.Contains(commands, " compose pull ") || !strings.Contains(commands, "--force-recreate --pull never") {
		t.Fatalf("update pulled images or did not force an offline controlled recreate: %s", commands)
	}
}

func TestUpdateMigratesLegacyV10AndRefusesPartialTOTPState(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("installer filesystem test requires a root Linux test container")
	}
	root := filepath.Join(t.TempDir(), "jellyfin-proxy")
	runner := &fakeRunner{}
	installFixture(t, root, runner)
	if err := os.Remove(filepath.Join(root, "config", "totp.key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "data", "totp-state.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Update(context.Background(), UpdateOptions{
		PackagePath: makeInstallPackageVersion(t, "1.0.1-dev"), InstallRoot: root, Host: validHost(), Runner: runner,
		WaitInterval: time.Millisecond, WaitAttempts: 1, HTTPSCheck: func(context.Context, string) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	key := mustLoadTOTPKey(t, filepath.Join(root, "config", "totp.key"))
	store, err := auth.NewTOTPStore(filepath.Join(root, "data", "totp-state.json"), key)
	clear(key)
	if err != nil || store.Status() != auth.TOTPUnconfigured {
		t.Fatalf("migrated TOTP state: store=%v err=%v", store, err)
	}
	if err := os.Remove(filepath.Join(root, "data", "totp-state.json")); err != nil {
		t.Fatal(err)
	}
	if err := ensureTOTPStorage(root); err == nil {
		t.Fatal("missing state with an existing key was accepted as a legacy install")
	}
}

func mustLoadTOTPKey(t *testing.T, path string) []byte {
	t.Helper()
	key, err := auth.LoadTOTPKey(path)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestUpdateHTTPSFailureRestoresPreviousRelease(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("installer filesystem test requires a root Linux test container")
	}
	root := filepath.Join(t.TempDir(), "jellyfin-proxy")
	runner := &fakeRunner{}
	installFixture(t, root, runner)
	oldEnvironment, _ := os.ReadFile(filepath.Join(root, ".env"))
	oldCompose, _ := os.ReadFile(filepath.Join(root, "compose.yaml"))
	oldCaddyfile, _ := os.ReadFile(filepath.Join(root, "config", "Caddyfile"))
	_, err := Update(context.Background(), UpdateOptions{
		PackagePath: makeInstallPackageVersion(t, "1.0.1-dev"), InstallRoot: root, Host: validHost(), Runner: runner,
		WaitInterval: time.Millisecond, WaitAttempts: 1, HTTPSCheck: func(context.Context, string) error { return fmt.Errorf("simulated public TLS failure") },
	})
	if err == nil || !strings.Contains(err.Error(), "previous release was restored") {
		t.Fatalf("update failure error = %v", err)
	}
	for relative, expected := range map[string][]byte{".env": oldEnvironment, "compose.yaml": oldCompose, filepath.Join("config", "Caddyfile"): oldCaddyfile} {
		actual, readErr := os.ReadFile(filepath.Join(root, relative))
		if readErr != nil || string(actual) != string(expected) {
			t.Errorf("rollback did not restore %s: got %q err=%v", relative, actual, readErr)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "releases", "1.0.1-dev")); !os.IsNotExist(err) {
		t.Errorf("failed release was retained after complete rollback: %v", err)
	}
	if !strings.Contains(strings.Join(runner.commands, "\n"), "up --detach --force-recreate --pull never") {
		t.Fatal("rollback did not recreate the previous deployment")
	}
}

func TestResetPasswordRecreatesOnlyAdminAndChangesCredential(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("installer filesystem test requires a root Linux test container")
	}
	root := filepath.Join(t.TempDir(), "jellyfin-proxy")
	runner := &fakeRunner{}
	installFixture(t, root, runner)
	path := filepath.Join(root, "config", "admin.json")
	if err := ResetPassword(context.Background(), root, "a different secure administrator password", runner); err != nil {
		t.Fatal(err)
	}
	credential, err := auth.LoadCredential(path)
	if err != nil || !credential.Verify("a different secure administrator password") || credential.Verify("correct horse battery staple") {
		t.Fatalf("reset administrator credential: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("reset credential permissions = %v, %v", info, err)
	}
	commands := strings.Join(runner.commands, "\n")
	if !strings.Contains(commands, "--no-deps --force-recreate --pull never admin") {
		t.Fatal("password reset did not recreate only the admin service")
	}
}

func installFixture(t *testing.T, root string, runner CommandRunner) {
	t.Helper()
	_, err := Install(context.Background(), InstallOptions{
		PackagePath: makeInstallPackage(t), InstallRoot: root, Domain: "example.com", Password: "correct horse battery staple",
		WireGuardPort: 51820, Host: validHost(), Runner: runner, WaitInterval: time.Millisecond, WaitAttempts: 1,
		DNSLookup:  func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.20")}, nil },
		HTTPSCheck: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
}

func validHost() HostFacts {
	return HostFacts{OSID: "ubuntu", VersionID: "26.04", Codename: "resolute", Arch: "x86_64", EffectiveUID: 0}
}

func makeInstallPackage(t *testing.T) string {
	return makeInstallPackageVersion(t, "1.0.0-dev")
}

func makeInstallPackageVersion(t *testing.T, version string) string {
	t.Helper()
	root := t.TempDir()
	images, configs := fakeReleaseImages(version)
	imageArchive, err := makeFakeDockerArchive(images, configs)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"images.tar":               imageArchive,
		"bin/admin-linux-amd64":    []byte("admin"),
		"bin/proxyctl-linux-amd64": []byte("proxyctl"),
		"compose.yaml":             []byte("services: {}\n"),
		".env.example":             []byte("BASE_DOMAIN=example.invalid\n"),
		"config/Caddyfile":         []byte("admin unix//run/caddy-admin/admin.sock|0220\n{$BASE_DOMAIN} {}\n"),
		"config/whitelist.caddy":   []byte("respond 403\n"),
		"site/index.html":          []byte("Jellyfin Proxy"),
		"DEPLOYMENT.md":            []byte("deployment notes"),
	}
	manifest := release.Manifest{SchemaVersion: 1, Version: version, Platform: "linux/amd64", Images: images}
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(content)
		manifest.Files = append(manifest.Files, release.ManifestFile{Path: name, SizeBytes: int64(len(content)), SHA256: hex.EncodeToString(hash[:])})
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), manifestJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "release.tar.gz")
	archiveFile, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(archiveFile)
	writer := tar.NewWriter(compressed)
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := "./"
		if rel != "." {
			name += filepath.ToSlash(rel)
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
		defer input.Close()
		_, err = io.Copy(writer, input)
		return err
	})
	if err == nil {
		err = writer.Close()
	}
	if err == nil {
		err = compressed.Close()
	}
	if err == nil {
		err = archiveFile.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	return archivePath
}
