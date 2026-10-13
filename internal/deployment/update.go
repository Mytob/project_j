package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Mytob/project_j/internal/auth"
	"github.com/Mytob/project_j/internal/release"
)

// UpdateOptions describe a package update and contain test seams for the host
// facts, command runner, and readiness checks.
type UpdateOptions struct {
	PackagePath  string
	InstallRoot  string
	Host         HostFacts
	Runner       CommandRunner
	WaitInterval time.Duration
	WaitAttempts int
	HTTPSCheck   func(context.Context, string) error
}

// Update installs a verified release over an existing deployment while
// preserving operator-owned data and restoring the previous release if the
// new one fails its health or HTTPS checks.
func Update(ctx context.Context, options UpdateOptions) (manifest release.Manifest, resultErr error) {
	if err := ValidateHost(options.Host); err != nil {
		return manifest, err
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
	if err := validateInstalledLayout(options.InstallRoot); err != nil {
		return manifest, err
	}
	current, err := readCurrentRelease(options.InstallRoot)
	if err != nil {
		return manifest, err
	}
	if _, err := auth.LoadCredential(filepath.Join(options.InstallRoot, "config", "admin.json")); err != nil {
		return manifest, fmt.Errorf("validate retained administrator credential: %w", err)
	}
	composeStatus, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "ps", "--format", "json")...)
	if err != nil || !composeServicesHealthy(composeStatus) {
		return manifest, errors.New("the existing Jellyfin Proxy deployment is not healthy; restore it before updating")
	}

	stageRoot, err := os.MkdirTemp(filepath.Join(options.InstallRoot, "releases"), ".update-")
	if err != nil {
		return manifest, fmt.Errorf("create update staging directory: %w", err)
	}
	defer os.RemoveAll(stageRoot)
	packageDir := filepath.Join(stageRoot, "package")
	manifest, err = release.ExtractAndValidate(options.PackagePath, packageDir)
	if err != nil {
		return manifest, err
	}
	if err := validatePackagePortAndVersion(manifest, 51820); err != nil {
		return manifest, err
	}
	if manifest.Version == current.Version {
		return manifest, errors.New("release version is already active")
	}
	if err := ensureTOTPStorage(options.InstallRoot); err != nil {
		return manifest, fmt.Errorf("validate or initialize persistent TOTP storage: %w", err)
	}
	finalRelease := filepath.Join(options.InstallRoot, "releases", manifest.Version)
	createdRelease := false
	rollbackComplete := true
	if _, err := os.Lstat(finalRelease); err == nil {
		stored, readErr := readReleaseManifest(finalRelease)
		if readErr != nil || !sameManifest(stored, manifest) {
			return manifest, errors.New("a different package with this release version is already retained")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return manifest, fmt.Errorf("inspect retained release directory: %w", err)
	} else if err := os.Rename(packageDir, finalRelease); err != nil {
		return manifest, fmt.Errorf("retain verified update package: %w", err)
	} else {
		createdRelease = true
	}
	if createdRelease {
		defer func() {
			if resultErr != nil && rollbackComplete {
				_ = os.RemoveAll(finalRelease)
			}
		}()
	}

	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "config", "--quiet")...); err != nil {
		return manifest, fmt.Errorf("validate current Compose configuration: %w", err)
	}
	imagesPath := filepath.Join(finalRelease, "images.tar")
	if _, err := options.Runner.Run(ctx, "docker", "image", "load", "--input", imagesPath); err != nil {
		return manifest, fmt.Errorf("load bundled update images: %w", err)
	}
	if err := verifyLoadedImages(ctx, options.Runner, manifest.Images); err != nil {
		return manifest, fmt.Errorf("verify bundled update images (%s): %w", imageReferences(manifest.Images), err)
	}

	paths := []string{".env", "compose.yaml", filepath.Join("config", "Caddyfile")}
	previous := make(map[string][]byte, len(paths))
	for _, relative := range paths {
		data, err := os.ReadFile(filepath.Join(options.InstallRoot, relative))
		if err != nil {
			return manifest, fmt.Errorf("read active %s: %w", relative, err)
		}
		previous[relative] = data
	}
	environment, err := readEnvironment(previous[".env"])
	if err != nil {
		return manifest, err
	}
	if environment.Version != current.Version {
		return manifest, errors.New("active release metadata changed while update was being prepared")
	}
	newEnvironment := fmt.Sprintf("BASE_DOMAIN=%s\nRELEASE_VERSION=%s\nWIREGUARD_PORT=%d\n", environment.Domain, manifest.Version, environment.WireGuardPort)
	changed := false
	composeMayBeRunning := false
	defer func() {
		if resultErr == nil || !changed {
			return
		}
		var restoreErrors []string
		for _, relative := range paths {
			mode := os.FileMode(0o644)
			if relative == ".env" {
				mode = 0o640
			}
			if err := atomicReplace(filepath.Join(options.InstallRoot, relative), previous[relative], mode); err != nil {
				restoreErrors = append(restoreErrors, fmt.Sprintf("restore %s: %v", relative, err))
			}
		}
		if composeMayBeRunning {
			if _, err := options.Runner.Run(context.Background(), "docker", composeArgs(options.InstallRoot, "up", "--detach", "--force-recreate", "--pull", "never")...); err != nil {
				restoreErrors = append(restoreErrors, fmt.Sprintf("restart previous release: %v", err))
			} else if err := waitForReadiness(context.Background(), InstallOptions{InstallRoot: options.InstallRoot, Runner: options.Runner, WaitInterval: options.WaitInterval, WaitAttempts: options.WaitAttempts}); err != nil {
				restoreErrors = append(restoreErrors, fmt.Sprintf("previous release readiness: %v", err))
			}
		}
		if len(restoreErrors) > 0 {
			rollbackComplete = false
			resultErr = fmt.Errorf("%w; automatic rollback encountered errors: %s", resultErr, strings.Join(restoreErrors, "; "))
		}
	}()
	for _, file := range []struct {
		relative string
		content  []byte
		mode     os.FileMode
	}{
		{relative: ".env", content: []byte(newEnvironment), mode: 0o640},
		{relative: "compose.yaml", content: mustRead(filepath.Join(finalRelease, "compose.yaml")), mode: 0o644},
		{relative: filepath.Join("config", "Caddyfile"), content: mustRead(filepath.Join(finalRelease, "config", "Caddyfile")), mode: 0o644},
	} {
		if file.content == nil {
			return manifest, errors.New("verified release template is unavailable")
		}
		if err := atomicReplace(filepath.Join(options.InstallRoot, file.relative), file.content, file.mode); err != nil {
			return manifest, fmt.Errorf("activate release file %s: %w", file.relative, err)
		}
		changed = true
	}
	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "config", "--quiet")...); err != nil {
		return manifest, fmt.Errorf("validate updated Compose configuration: %w", err)
	}
	composeMayBeRunning = true
	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "up", "--detach", "--force-recreate", "--pull", "never")...); err != nil {
		return manifest, fmt.Errorf("start updated Jellyfin Proxy services: %w", err)
	}
	if err := waitForReadiness(ctx, InstallOptions{InstallRoot: options.InstallRoot, Runner: options.Runner, WaitInterval: options.WaitInterval, WaitAttempts: options.WaitAttempts}); err != nil {
		return manifest, fmt.Errorf("updated services did not become healthy; the previous release was restored: %w", err)
	}
	if options.HTTPSCheck == nil {
		options.HTTPSCheck = checkPublicHTTPS
	}
	if err := waitForHTTPS(ctx, environment.Domain, options.WaitInterval, options.WaitAttempts, options.HTTPSCheck); err != nil {
		return manifest, fmt.Errorf("updated release public HTTPS check failed; the previous release was restored: %w", err)
	}
	if err := retainActiveAndPrevious(options.InstallRoot, manifest.Version, current.Version); err != nil {
		return manifest, fmt.Errorf("update succeeded, but release retention cleanup failed: %w", err)
	}
	changed = false
	return manifest, nil
}

// ResetPassword replaces the local administrator password and recreates only
// the admin container. Sessions are in-memory, so its restart invalidates all
// existing sessions without touching the other services or persistent data.
func ResetPassword(ctx context.Context, installRoot, password string, runner CommandRunner) error {
	if installRoot == "" {
		installRoot = DefaultInstallRoot
	}
	if !filepath.IsAbs(installRoot) {
		return errors.New("installation root must be an absolute path")
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	if err := validateInstalledLayout(installRoot); err != nil {
		return err
	}
	credentialPath := filepath.Join(installRoot, "config", "admin.json")
	old, err := os.ReadFile(credentialPath)
	if err != nil {
		return fmt.Errorf("read current administrator credential: %w", err)
	}
	if _, err := auth.LoadCredential(credentialPath); err != nil {
		return fmt.Errorf("validate current administrator credential: %w", err)
	}
	if _, err := runner.Run(ctx, "docker", composeArgs(installRoot, "ps", "--format", "json")...); err != nil {
		return fmt.Errorf("check admin deployment: %w", err)
	}
	if err := auth.SaveCredential(credentialPath, password); err != nil {
		return fmt.Errorf("save new administrator password: %w", err)
	}
	if err := os.Chown(credentialPath, 0, adminContainerUID); err != nil {
		_ = atomicReplace(credentialPath, old, 0o640)
		_ = os.Chown(credentialPath, 0, adminContainerUID)
		return fmt.Errorf("set administrator credential ownership: %w", err)
	}
	if err := os.Chmod(credentialPath, 0o640); err != nil {
		_ = atomicReplace(credentialPath, old, 0o640)
		_ = os.Chown(credentialPath, 0, adminContainerUID)
		return fmt.Errorf("set administrator credential permissions: %w", err)
	}
	if _, err := runner.Run(ctx, "docker", composeArgs(installRoot, "up", "--detach", "--no-deps", "--force-recreate", "--pull", "never", "admin")...); err != nil {
		rollbackCredential(credentialPath, old)
		_, _ = runner.Run(context.Background(), "docker", composeArgs(installRoot, "up", "--detach", "--no-deps", "--force-recreate", "--pull", "never", "admin")...)
		return fmt.Errorf("restart admin with the new credential: %w", err)
	}
	if err := waitForReadiness(ctx, InstallOptions{InstallRoot: installRoot, Runner: runner, WaitInterval: time.Second, WaitAttempts: 90}); err != nil {
		rollbackCredential(credentialPath, old)
		_, _ = runner.Run(context.Background(), "docker", composeArgs(installRoot, "up", "--detach", "--no-deps", "--force-recreate", "--pull", "never", "admin")...)
		return fmt.Errorf("admin did not become healthy after password reset; the previous credential was restored: %w", err)
	}
	return nil
}

// TOTPRecoveryAction identifies a local privileged TOTP state transition.
type TOTPRecoveryAction string

const (
	TOTPReset   TOTPRecoveryAction = "reset"
	TOTPDisable TOTPRecoveryAction = "disable"
	TOTPReplace TOTPRecoveryAction = "replace"
)

// RecoverTOTP changes the persistent authenticator state and recreates only
// the admin service. On any failure after the transition, it restores the
// original state file and restarts the previous admin service.
func RecoverTOTP(ctx context.Context, installRoot string, action TOTPRecoveryAction, runner CommandRunner) (resultErr error) {
	if installRoot == "" {
		installRoot = DefaultInstallRoot
	}
	if !filepath.IsAbs(installRoot) {
		return errors.New("installation root must be an absolute path")
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	if action != TOTPReset && action != TOTPDisable && action != TOTPReplace {
		return errors.New("unknown TOTP recovery action")
	}
	if err := validateInstalledLayout(installRoot); err != nil {
		return err
	}
	statePath := filepath.Join(installRoot, "data", "totp-state.json")
	stateInfo, err := os.Lstat(statePath)
	if err != nil || stateInfo.Mode()&os.ModeSymlink != 0 || !stateInfo.Mode().IsRegular() {
		return errors.New("TOTP state file is missing or unsafe")
	}
	previous, err := os.ReadFile(statePath)
	if err != nil {
		return fmt.Errorf("read current TOTP state: %w", err)
	}
	key, err := auth.LoadTOTPKey(filepath.Join(installRoot, "config", "totp.key"))
	if err != nil {
		return fmt.Errorf("validate TOTP storage key: %w", err)
	}
	defer clear(key)
	store, err := auth.NewTOTPStore(statePath, key)
	if err != nil {
		return fmt.Errorf("validate current TOTP state: %w", err)
	}
	if action == TOTPReplace && store.Status() != auth.TOTPEnabled {
		return errors.New("replace-totp requires an enabled authenticator; use reset-totp for recovery")
	}
	composeStatus, err := runner.Run(ctx, "docker", composeArgs(installRoot, "ps", "--format", "json")...)
	if err != nil || !composeServicesHealthy(composeStatus) {
		return errors.New("the existing Jellyfin Proxy deployment is not healthy; restore it before changing TOTP")
	}
	if _, err := runner.Run(ctx, "docker", composeArgs(installRoot, "stop", "admin")...); err != nil {
		if _, restartErr := runner.Run(context.Background(), "docker", composeArgs(installRoot, "up", "--detach", "--no-deps", "--force-recreate", "--pull", "never", "admin")...); restartErr != nil {
			return fmt.Errorf("stop admin before changing TOTP: %w; admin restart also failed: %v", err, restartErr)
		}
		return fmt.Errorf("stop admin before changing TOTP: %w", err)
	}
	changed := false
	rollback := func() error {
		var failures []string
		if changed {
			if err := atomicReplace(statePath, previous, 0o600); err != nil {
				failures = append(failures, "restore TOTP state: "+err.Error())
			} else if err := os.Chown(statePath, adminContainerUID, adminContainerUID); err != nil {
				failures = append(failures, "restore TOTP state ownership: "+err.Error())
			}
		}
		if _, err := runner.Run(context.Background(), "docker", composeArgs(installRoot, "up", "--detach", "--no-deps", "--force-recreate", "--pull", "never", "admin")...); err != nil {
			failures = append(failures, "restart admin: "+err.Error())
		} else if err := waitForReadiness(context.Background(), InstallOptions{InstallRoot: installRoot, Runner: runner, WaitInterval: time.Second, WaitAttempts: 90}); err != nil {
			failures = append(failures, "admin readiness: "+err.Error())
		}
		if len(failures) != 0 {
			return errors.New(strings.Join(failures, "; "))
		}
		return nil
	}
	defer func() {
		if resultErr == nil {
			return
		}
		if rollbackErr := rollback(); rollbackErr != nil {
			resultErr = fmt.Errorf("%w; recovery rollback failed: %v", resultErr, rollbackErr)
		}
	}()
	switch action {
	case TOTPReset, TOTPReplace:
		if err := store.RequireFreshEnrollment(); err != nil {
			return fmt.Errorf("require fresh authenticator enrollment: %w", err)
		}
	case TOTPDisable:
		if err := store.Disable(); err != nil {
			return fmt.Errorf("disable authenticator: %w", err)
		}
	}
	changed = true
	if err := os.Chown(statePath, adminContainerUID, adminContainerUID); err != nil {
		return fmt.Errorf("set TOTP state ownership: %w", err)
	}
	if err := os.Chmod(statePath, 0o600); err != nil {
		return fmt.Errorf("set TOTP state permissions: %w", err)
	}
	if _, err := runner.Run(ctx, "docker", composeArgs(installRoot, "up", "--detach", "--no-deps", "--force-recreate", "--pull", "never", "admin")...); err != nil {
		return fmt.Errorf("restart admin with the updated authenticator state: %w", err)
	}
	if err := waitForReadiness(ctx, InstallOptions{InstallRoot: installRoot, Runner: runner, WaitInterval: time.Second, WaitAttempts: 90}); err != nil {
		return fmt.Errorf("admin did not become healthy after TOTP recovery: %w", err)
	}
	return nil
}

type activeEnvironment struct {
	Domain        string
	Version       string
	WireGuardPort uint16
}

func readEnvironment(data []byte) (activeEnvironment, error) {
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || (key != "BASE_DOMAIN" && key != "RELEASE_VERSION" && key != "WIREGUARD_PORT") || values[key] != "" {
			return activeEnvironment{}, errors.New("active deployment environment is invalid")
		}
		values[key] = value
	}
	domain, err := ValidateDomain(values["BASE_DOMAIN"])
	if err != nil {
		return activeEnvironment{}, errors.New("active deployment base domain is invalid")
	}
	port, err := strconv.ParseUint(values["WIREGUARD_PORT"], 10, 16)
	if err != nil || port == 0 || !release.ValidVersion(values["RELEASE_VERSION"]) {
		return activeEnvironment{}, errors.New("active deployment version or WireGuard port is invalid")
	}
	return activeEnvironment{Domain: domain, Version: values["RELEASE_VERSION"], WireGuardPort: uint16(port)}, nil
}

func validateInstalledLayout(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspect existing installation: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("installation root is not a real directory")
	}
	for _, relative := range []string{"config", "data", "site", "releases"} {
		info, err := os.Lstat(filepath.Join(root, relative))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("installation directory %s is missing or unsafe", relative)
		}
	}
	for _, relative := range []string{".env", "compose.yaml", filepath.Join("config", "Caddyfile"), filepath.Join("config", "admin.json")} {
		info, err := os.Lstat(filepath.Join(root, relative))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("installation file %s is missing or unsafe", relative)
		}
	}
	return nil
}

func readCurrentRelease(root string) (release.Manifest, error) {
	environmentBytes, err := os.ReadFile(filepath.Join(root, ".env"))
	if err != nil {
		return release.Manifest{}, err
	}
	environment, err := readEnvironment(environmentBytes)
	if err != nil {
		return release.Manifest{}, err
	}
	manifest, err := readReleaseManifest(filepath.Join(root, "releases", environment.Version))
	if err != nil {
		return release.Manifest{}, fmt.Errorf("validate active release metadata: %w", err)
	}
	if manifest.Version != environment.Version || manifest.Platform != "linux/amd64" {
		return release.Manifest{}, errors.New("active release metadata is incompatible with this installer")
	}
	if err := validatePackagePortAndVersion(manifest, 51820); err != nil {
		return release.Manifest{}, err
	}
	return manifest, nil
}

func readReleaseManifest(directory string) (release.Manifest, error) {
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return release.Manifest{}, errors.New("release directory is missing or unsafe")
	}
	path := filepath.Join(directory, "manifest.json")
	info, err = os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return release.Manifest{}, errors.New("release manifest is missing or unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return release.Manifest{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 4<<20))
	decoder.DisallowUnknownFields()
	var manifest release.Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return release.Manifest{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return release.Manifest{}, errors.New("release manifest contains trailing data")
	}
	if !release.ValidVersion(manifest.Version) || manifest.SchemaVersion != 1 || manifest.Platform != "linux/amd64" {
		return release.Manifest{}, errors.New("release manifest is invalid")
	}
	return manifest, nil
}

func sameManifest(left, right release.Manifest) bool {
	leftData, leftErr := json.Marshal(left)
	rightData, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftData) == string(rightData)
}

func mustRead(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

func atomicReplace(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".jellyfin-proxy-update-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func waitForHTTPS(ctx context.Context, domain string, interval time.Duration, attempts int, check func(context.Context, string) error) error {
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := check(ctx, domain); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("public HTTPS readiness check cancelled: %w", ctx.Err())
		case <-time.After(interval):
		}
	}
	return fmt.Errorf("public HTTPS did not become ready: %w", lastErr)
}

func retainActiveAndPrevious(root, active, previous string) error {
	directory := filepath.Join(root, "releases")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == active || name == previous || strings.HasPrefix(name, ".") || !release.ValidVersion(name) {
			continue
		}
		if !entry.IsDir() {
			return fmt.Errorf("unexpected non-directory release artifact %s", name)
		}
		if err := os.RemoveAll(filepath.Join(directory, name)); err != nil {
			return fmt.Errorf("remove old release %s: %w", name, err)
		}
	}
	return nil
}

func rollbackCredential(path string, old []byte) {
	if atomicReplace(path, old, 0o640) == nil {
		_ = os.Chown(path, 0, adminContainerUID)
	}
}
