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
	if strings.Contains(command, " image inspect ") {
		for reference, digest := range map[string]string{
			"jellyfin-proxy/admin:1.0.0-dev":     "sha256:" + strings.Repeat("a", 64),
			"jellyfin-proxy/wireguard:1.0.0-dev": "sha256:" + strings.Repeat("b", 64),
			"caddy:2.10.2-alpine":                "sha256:" + strings.Repeat("c", 64),
			"alpine:3.22":                        "sha256:" + strings.Repeat("d", 64),
		} {
			if strings.HasSuffix(command, reference) {
				return digest, nil
			}
		}
		return "", fmt.Errorf("unexpected image inspection")
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

func validHost() HostFacts {
	return HostFacts{OSID: "ubuntu", VersionID: "26.04", Codename: "resolute", Arch: "x86_64", EffectiveUID: 0}
}

func makeInstallPackage(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"images.tar":               "test-image-archive",
		"bin/admin-linux-amd64":    "admin",
		"bin/proxyctl-linux-amd64": "proxyctl",
		"compose.yaml":             "services: {}\n",
		".env.example":             "BASE_DOMAIN=example.invalid\n",
		"config/Caddyfile":         "admin unix//run/caddy-admin/admin.sock|0220\n{$BASE_DOMAIN} {}\n",
		"config/whitelist.caddy":   "respond 403\n",
		"site/index.html":          "Jellyfin Proxy",
		"DEPLOYMENT.md":            "deployment notes",
	}
	manifest := release.Manifest{SchemaVersion: 1, Version: "1.0.0-dev", Platform: "linux/amd64", Images: []release.Image{
		{Reference: "jellyfin-proxy/admin:1.0.0-dev", ImageID: "sha256:" + strings.Repeat("a", 64)},
		{Reference: "jellyfin-proxy/wireguard:1.0.0-dev", ImageID: "sha256:" + strings.Repeat("b", 64)},
		{Reference: "caddy:2.10.2-alpine", ImageID: "sha256:" + strings.Repeat("c", 64)},
		{Reference: "alpine:3.22", ImageID: "sha256:" + strings.Repeat("d", 64)},
	}}
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256([]byte(content))
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
