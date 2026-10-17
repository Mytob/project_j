package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Mytob/project_j/internal/auth"
	"github.com/Mytob/project_j/internal/release"
	"github.com/Mytob/project_j/internal/wireguard"
)

const (
	DefaultInstallRoot   = "/opt/jellyfin-proxy"
	defaultReleaseImage  = "jellyfin-proxy/admin"
	serverTunnelPrefix   = "10.66.66.1/24"
	clientTunnelPrefix   = "10.66.66.2/24"
	defaultWireGuardPort = 51820
	adminContainerUID    = 65532
)

// CommandRunner isolates host commands for deterministic installer tests.
type CommandRunner interface {
	Run(context.Context, string, ...string) (string, error)
}

// ExecRunner executes a host command and includes its output in any error.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, executable string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, executable, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s %s: %w: %s", executable, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

// InstallOptions contain only values collected by the guided installer.
type InstallOptions struct {
	PackagePath   string
	InstallRoot   string
	Domain        string
	Password      string
	WireGuardPort uint16
	Host          HostFacts
	DNSLookup     LookupIPFunc
	Runner        CommandRunner
	WaitInterval  time.Duration
	WaitAttempts  int
	HTTPSCheck    func(context.Context, string) error
}

// Install validates a package and host, lays down the first deployment, loads
// only bundled image archives, starts the scoped Compose project, and rolls
// back files and containers if deployment or readiness fails.
func Install(ctx context.Context, options InstallOptions) (manifest release.Manifest, resultErr error) {
	if err := ValidateHost(options.Host); err != nil {
		return manifest, err
	}
	domain, err := ValidateDomain(options.Domain)
	if err != nil {
		return manifest, err
	}
	if options.Password == "" {
		return manifest, errors.New("administrator password is required")
	}
	if _, err := auth.HashPassword(options.Password); err != nil {
		return manifest, fmt.Errorf("invalid administrator password: %w", err)
	}
	if options.WireGuardPort == 0 {
		options.WireGuardPort = defaultWireGuardPort
	}
	if options.InstallRoot == "" {
		options.InstallRoot = DefaultInstallRoot
	}
	if !filepath.IsAbs(options.InstallRoot) {
		return manifest, errors.New("installation root must be an absolute path")
	}
	if options.Runner == nil {
		options.Runner = ExecRunner{}
	}
	if options.WaitInterval <= 0 {
		options.WaitInterval = time.Second
	}
	if options.WaitAttempts <= 0 {
		options.WaitAttempts = 90
	}
	if _, err := CheckDNS(ctx, domain, options.DNSLookup); err != nil {
		return manifest, err
	}

	if info, err := os.Lstat(options.InstallRoot); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return manifest, errors.New("installation root already exists and is not a real directory")
		}
		return manifest, errors.New("installation root already exists; refusing to overwrite existing data")
	} else if !errors.Is(err, os.ErrNotExist) {
		return manifest, fmt.Errorf("inspect installation root: %w", err)
	}
	if err := refuseExistingComposeProject(ctx, options.Runner); err != nil {
		return manifest, err
	}
	if err := os.MkdirAll(filepath.Dir(options.InstallRoot), 0o755); err != nil {
		return manifest, fmt.Errorf("create installation parent: %w", err)
	}
	packageStage, err := os.MkdirTemp("", "jellyfin-proxy-package-*")
	if err != nil {
		return manifest, fmt.Errorf("create temporary package directory: %w", err)
	}
	defer os.RemoveAll(packageStage)
	manifest, err = release.ExtractAndValidate(options.PackagePath, filepath.Join(packageStage, "package"))
	if err != nil {
		return manifest, err
	}
	if err := validatePackagePortAndVersion(manifest, options.WireGuardPort); err != nil {
		return manifest, err
	}
	packageDir := filepath.Join(packageStage, "package")

	rootCreated := false
	composeMayBeRunning := false
	defer func() {
		if resultErr == nil {
			return
		}
		if composeMayBeRunning {
			_, _ = options.Runner.Run(context.Background(), "docker", composeArgs(options.InstallRoot, "down", "--remove-orphans", "--volumes")...)
		}
		if rootCreated {
			_ = os.RemoveAll(options.InstallRoot)
		}
	}()
	if err := os.Mkdir(options.InstallRoot, 0o755); err != nil {
		return manifest, fmt.Errorf("create installation root: %w", err)
	}
	rootCreated = true
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Join(options.InstallRoot, "config"), 0o750},
		{filepath.Join(options.InstallRoot, "data"), 0o700},
		{filepath.Join(options.InstallRoot, "site"), 0o755},
		{filepath.Join(options.InstallRoot, "releases", manifest.Version), 0o755},
	} {
		if err := os.MkdirAll(directory.path, directory.mode); err != nil {
			return manifest, fmt.Errorf("create installation directory: %w", err)
		}
		if err := os.Chmod(directory.path, directory.mode); err != nil {
			return manifest, fmt.Errorf("set installation directory permissions: %w", err)
		}
	}
	releaseDir := filepath.Join(options.InstallRoot, "releases", manifest.Version)
	if err := copyTree(packageDir, releaseDir); err != nil {
		return manifest, fmt.Errorf("retain release package: %w", err)
	}
	if err := copyFile(filepath.Join(packageDir, "compose.yaml"), filepath.Join(options.InstallRoot, "compose.yaml"), 0o644); err != nil {
		return manifest, err
	}
	if err := copyFile(filepath.Join(packageDir, "config", "Caddyfile"), filepath.Join(options.InstallRoot, "config", "Caddyfile"), 0o644); err != nil {
		return manifest, err
	}
	if err := copyFile(filepath.Join(packageDir, "config", "whitelist.caddy"), filepath.Join(options.InstallRoot, "config", "whitelist.caddy"), 0o644); err != nil {
		return manifest, err
	}
	if err := copyTree(filepath.Join(packageDir, "site"), filepath.Join(options.InstallRoot, "site")); err != nil {
		return manifest, fmt.Errorf("install static website: %w", err)
	}
	if err := writeEnvironment(options.InstallRoot, domain, manifest.Version, options.WireGuardPort); err != nil {
		return manifest, err
	}
	credentialPath := filepath.Join(options.InstallRoot, "config", "admin.json")
	if err := auth.SaveCredential(credentialPath, options.Password); err != nil {
		return manifest, fmt.Errorf("save initial administrator credential: %w", err)
	}
	if err := os.Chown(credentialPath, 0, adminContainerUID); err != nil {
		return manifest, fmt.Errorf("set administrator credential ownership: %w", err)
	}
	if err := os.Chmod(credentialPath, 0o640); err != nil {
		return manifest, fmt.Errorf("set administrator credential permissions: %w", err)
	}
	totpKeyPath := filepath.Join(options.InstallRoot, "config", "totp.key")
	if err := auth.CreateTOTPKey(totpKeyPath); err != nil {
		return manifest, fmt.Errorf("create administrator TOTP key: %w", err)
	}
	if err := os.Chown(totpKeyPath, 0, adminContainerUID); err != nil {
		return manifest, fmt.Errorf("set administrator TOTP key ownership: %w", err)
	}
	if err := os.Chmod(totpKeyPath, 0o640); err != nil {
		return manifest, fmt.Errorf("set administrator TOTP key permissions: %w", err)
	}
	if err := os.Chown(filepath.Join(options.InstallRoot, "data"), adminContainerUID, adminContainerUID); err != nil {
		return manifest, fmt.Errorf("set admin data ownership: %w", err)
	}
	if err := os.Chmod(filepath.Join(options.InstallRoot, "data"), 0o700); err != nil {
		return manifest, fmt.Errorf("set admin data permissions: %w", err)
	}
	totpKey, err := auth.LoadTOTPKey(totpKeyPath)
	if err != nil {
		return manifest, fmt.Errorf("validate generated administrator TOTP key: %w", err)
	}
	_, initializeErr := auth.InitializeTOTPStore(filepath.Join(options.InstallRoot, "data", "totp-state.json"), totpKey)
	clear(totpKey)
	if initializeErr != nil {
		return manifest, fmt.Errorf("initialize administrator TOTP state: %w", initializeErr)
	}
	totpStatePath := filepath.Join(options.InstallRoot, "data", "totp-state.json")
	if err := os.Chown(totpStatePath, adminContainerUID, adminContainerUID); err != nil {
		return manifest, fmt.Errorf("set administrator TOTP state ownership: %w", err)
	}
	if err := os.Chmod(totpStatePath, 0o600); err != nil {
		return manifest, fmt.Errorf("set administrator TOTP state permissions: %w", err)
	}
	serverAddress, _ := netip.ParsePrefix(serverTunnelPrefix)
	clientAddress, _ := netip.ParsePrefix(clientTunnelPrefix)
	peerFiles, err := wireguard.EnsureProvisioned(filepath.Join(options.InstallRoot, "config", "wireguard"), wireguard.ProvisionOptions{
		Endpoint: net.JoinHostPort(domain, strconv.Itoa(int(options.WireGuardPort))), ListenPort: defaultWireGuardPort,
		ServerAddress: serverAddress, ClientAddress: clientAddress, Keepalive: 25,
	})
	if err != nil {
		return manifest, fmt.Errorf("provision WireGuard peer pair: %w", err)
	}
	if err := os.Chown(peerFiles.ServerPath, 0, 0); err != nil {
		return manifest, fmt.Errorf("set WireGuard server ownership: %w", err)
	}
	if err := os.Chmod(peerFiles.ServerPath, 0o600); err != nil {
		return manifest, fmt.Errorf("set WireGuard server permissions: %w", err)
	}
	clientConfigDir := filepath.Join(options.InstallRoot, "data", "wireguard-client")
	if err := os.MkdirAll(clientConfigDir, 0o2770); err != nil {
		return manifest, fmt.Errorf("create one-time Windows configuration directory: %w", err)
	}
	if err := os.Chown(clientConfigDir, 0, adminContainerUID); err != nil {
		return manifest, fmt.Errorf("set Windows configuration directory ownership: %w", err)
	}
	if err := os.Chmod(clientConfigDir, 0o2770); err != nil {
		return manifest, fmt.Errorf("set Windows configuration directory permissions: %w", err)
	}
	clientConfigPath := filepath.Join(clientConfigDir, "windows.conf")
	if err := os.Rename(peerFiles.ClientPath, clientConfigPath); err != nil {
		return manifest, fmt.Errorf("move Windows peer config into persistent one-time storage: %w", err)
	}
	if err := os.Chown(clientConfigPath, 0, adminContainerUID); err != nil {
		return manifest, fmt.Errorf("set Windows peer ownership: %w", err)
	}
	if err := os.Chmod(clientConfigPath, 0o640); err != nil {
		return manifest, fmt.Errorf("set Windows peer permissions: %w", err)
	}
	if err := os.Chown(filepath.Join(options.InstallRoot, "config", "wireguard"), 0, adminContainerUID); err != nil {
		return manifest, fmt.Errorf("set WireGuard directory ownership: %w", err)
	}
	if err := os.Chmod(filepath.Join(options.InstallRoot, "config", "wireguard"), 0o750); err != nil {
		return manifest, fmt.Errorf("set WireGuard directory permissions: %w", err)
	}

	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "config", "--quiet")...); err != nil {
		return manifest, fmt.Errorf("validate Compose configuration: %w", err)
	}
	if _, err := options.Runner.Run(ctx, "docker", "image", "load", "--input", filepath.Join(releaseDir, "images.tar")); err != nil {
		return manifest, fmt.Errorf("load bundled deployment images: %w", err)
	}
	if err := verifyLoadedImages(ctx, options.Runner, manifest.Images); err != nil {
		return manifest, fmt.Errorf("verify bundled deployment images (%s): %w", imageReferences(manifest.Images), err)
	}
	composeMayBeRunning = true
	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "up", "--detach", "--pull", "never")...); err != nil {
		return manifest, fmt.Errorf("start Jellyfin Proxy services: %w", err)
	}
	if err := waitForReadiness(ctx, options); err != nil {
		return manifest, err
	}
	if options.HTTPSCheck == nil {
		options.HTTPSCheck = checkPublicHTTPS
	}
	var lastErr error
	for attempt := 0; attempt < options.WaitAttempts; attempt++ {
		if err := options.HTTPSCheck(ctx, domain); err == nil {
			return manifest, nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return manifest, fmt.Errorf("public HTTPS readiness check cancelled: %w", ctx.Err())
		case <-time.After(options.WaitInterval):
		}
	}
	return manifest, fmt.Errorf("public HTTPS did not become ready; the installation was rolled back: %w", lastErr)
}

func refuseExistingComposeProject(ctx context.Context, runner CommandRunner) error {
	projectLabel := "label=com.docker.compose.project=jellyfin-proxy"
	for _, query := range [][]string{
		{"ps", "--all", "--filter", projectLabel, "--format", "{{.Names}}"},
		{"volume", "ls", "--filter", projectLabel, "--format", "{{.Name}}"},
		{"network", "ls", "--filter", projectLabel, "--format", "{{.Name}}"},
	} {
		output, err := runner.Run(ctx, "docker", query...)
		if err != nil {
			return fmt.Errorf("check for existing Jellyfin Proxy Docker resources: %w", err)
		}
		if strings.TrimSpace(output) != "" {
			return errors.New("Docker resources for the jellyfin-proxy Compose project already exist; refusing to alter existing services or data")
		}
	}
	return nil
}

func validatePackagePortAndVersion(manifest release.Manifest, port uint16) error {
	if port == 0 {
		return errors.New("WireGuard UDP port must be between 1 and 65535")
	}
	for _, image := range manifest.Images {
		if image.Reference == defaultReleaseImage+":"+manifest.Version {
			return nil
		}
	}
	return errors.New("package does not contain the versioned admin image")
}

func composeArgs(root string, args ...string) []string {
	return append([]string{"compose", "--project-name", "jellyfin-proxy", "--file", filepath.Join(root, "compose.yaml"), "--env-file", filepath.Join(root, ".env")}, args...)
}

func waitForReadiness(ctx context.Context, options InstallOptions) error {
	for attempt := 0; attempt < options.WaitAttempts; attempt++ {
		output, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "ps", "--format", "json")...)
		if err == nil && composeServicesHealthy(output) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("deployment readiness check cancelled: %w", ctx.Err())
		case <-time.After(options.WaitInterval):
		}
	}
	return errors.New("services did not become healthy in time; the installation was rolled back")
}

func checkPublicHTTPS(ctx context.Context, domain string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/", nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 8 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("https://%s/ returned HTTP %d", domain, response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	return nil
}

func composeServicesHealthy(output string) bool {
	// Compose emits one JSON object per line. Parse only the three long-running
	// services; the one-shot socket-init service is expected to exit.
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var service struct {
			Service string `json:"Service"`
			State   string `json:"State"`
			Health  string `json:"Health"`
		}
		if json.Unmarshal([]byte(line), &service) != nil {
			return false
		}
		if service.Service == "wireguard" || service.Service == "caddy" || service.Service == "admin" {
			if service.State != "running" || service.Health != "healthy" {
				return false
			}
			seen[service.Service] = true
		}
	}
	return seen["wireguard"] && seen["caddy"] && seen["admin"]
}

func writeEnvironment(root, domain, version string, wireGuardPort uint16) error {
	value := fmt.Sprintf("BASE_DOMAIN=%s\nRELEASE_VERSION=%s\nWIREGUARD_PORT=%d\n", domain, version, wireGuardPort)
	path := filepath.Join(root, ".env")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return fmt.Errorf("create deployment environment: %w", err)
	}
	if _, err := io.WriteString(file, value); err != nil {
		_ = file.Close()
		return fmt.Errorf("write deployment environment: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync deployment environment: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close deployment environment: %w", err)
	}
	return nil
}

func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := destination
		if rel != "." {
			target = filepath.Join(destination, rel)
		}
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to copy non-regular package file %s", path)
		}
		mode := os.FileMode(0o644)
		if info.Mode()&0o111 != 0 {
			mode = 0o755
		}
		return copyFile(path, target, mode)
	})
}

func copyFile(source, destination string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open %s: %w", source, err)
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", destination, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("copy %s: %w", source, err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return fmt.Errorf("sync %s: %w", destination, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", destination, err)
	}
	return os.Chmod(destination, mode)
}
