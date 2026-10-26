package deployment

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mytob/project_j/internal/release"
	"github.com/Mytob/project_j/internal/whitelist"
)

type installCheckpoint struct {
	Version             int      `json:"version"`
	ID                  string   `json:"id"`
	Phase               string   `json:"phase"`
	PackagePath         string   `json:"package_path"`
	PackageSHA          string   `json:"package_sha256"`
	RecoveryBackupPath  string   `json:"recovery_backup_path,omitempty"`
	Domain              string   `json:"domain"`
	WireGuardPort       uint16   `json:"wireguard_port"`
	AllowedIPs          []string `json:"initial_allowed_ips,omitempty"`
	BackupSchedule      string   `json:"backup_schedule,omitempty"`
	BackupRetentionDays int      `json:"backup_retention_days,omitempty"`
}

func checkpointPath(root string) string {
	return filepath.Join(filepath.Dir(root), "."+filepath.Base(root)+".install-checkpoint.json")
}

func newInstallID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}

func writeInstallCheckpoint(root string, checkpoint installCheckpoint) error {
	if checkpoint.Version != 1 || checkpoint.ID == "" || (checkpoint.Phase != "preparing" && checkpoint.Phase != "ready" && checkpoint.Phase != "complete") {
		return errors.New("install checkpoint values are invalid")
	}
	data, err := json.Marshal(checkpoint)
	if err != nil {
		return err
	}
	return atomicReplace(checkpointPath(root), data, 0o600)
}

func readInstallCheckpoint(root string) (installCheckpoint, error) {
	path := checkpointPath(root)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() > 64<<10 {
		return installCheckpoint{}, errors.New("no valid private install checkpoint was found")
	}
	file, err := os.Open(path)
	if err != nil {
		return installCheckpoint{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	var checkpoint installCheckpoint
	if err := decoder.Decode(&checkpoint); err != nil {
		return installCheckpoint{}, fmt.Errorf("decode install checkpoint: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return installCheckpoint{}, errors.New("install checkpoint contains trailing data")
	}
	if checkpoint.Version != 1 || len(checkpoint.ID) != 32 || strings.Trim(checkpoint.ID, "0123456789abcdef") != "" || (checkpoint.Phase != "preparing" && checkpoint.Phase != "ready" && checkpoint.Phase != "complete") || checkpoint.WireGuardPort == 0 {
		return installCheckpoint{}, errors.New("install checkpoint metadata is invalid")
	}
	if !filepath.IsAbs(checkpoint.PackagePath) || filepath.Ext(checkpoint.PackagePath) != ".pkg" || len(checkpoint.PackageSHA) != 64 {
		return installCheckpoint{}, errors.New("install checkpoint package reference is invalid")
	}
	if checkpoint.RecoveryBackupPath != "" && (!filepath.IsAbs(checkpoint.RecoveryBackupPath) || filepath.Ext(checkpoint.RecoveryBackupPath) != ".bak") {
		return installCheckpoint{}, errors.New("install checkpoint recovery backup reference is invalid")
	}
	if _, err := ValidateDomain(checkpoint.Domain); err != nil {
		return installCheckpoint{}, errors.New("install checkpoint domain is invalid")
	}
	if len(checkpoint.AllowedIPs) > 0 {
		if err := validateAllowedIPs(checkpoint.AllowedIPs); err != nil {
			return installCheckpoint{}, err
		}
	}
	if checkpoint.BackupSchedule == "" {
		checkpoint.BackupSchedule = "daily"
	}
	if checkpoint.BackupSchedule != "daily" && checkpoint.BackupSchedule != "weekly" {
		return installCheckpoint{}, errors.New("install checkpoint backup schedule is invalid")
	}
	if checkpoint.BackupRetentionDays == 0 {
		checkpoint.BackupRetentionDays = 30
	}
	if checkpoint.BackupRetentionDays != 7 && checkpoint.BackupRetentionDays != 14 && checkpoint.BackupRetentionDays != 30 {
		return installCheckpoint{}, errors.New("install checkpoint backup retention is invalid")
	}
	return checkpoint, nil
}

func InstallResumePhase(root string) (string, error) {
	checkpoint, err := readInstallCheckpoint(root)
	if err != nil {
		return "", err
	}
	return checkpoint.Phase, nil
}

func InstallResumeDomain(root string) (string, error) {
	checkpoint, err := readInstallCheckpoint(root)
	if err != nil {
		return "", err
	}
	return checkpoint.Domain, nil
}

func validateAllowedIPs(values []string) error {
	if _, err := whitelist.Validate(values); err != nil {
		return fmt.Errorf("install checkpoint allowlist is invalid: %w", err)
	}
	return nil
}

func validateInstallMarker(root, expected string) error {
	path := filepath.Join(root, ".install-id")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("incomplete installation has no valid ownership marker")
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(data)) != expected {
		return errors.New("incomplete installation is not owned by this checkpoint")
	}
	return nil
}

// ResumeInstall continues a fully staged first install or safely restarts its
// pre-container file preparation. The password is deliberately never stored
// in the checkpoint and is requested again when needed.
func ResumeInstall(ctx context.Context, options InstallOptions) (manifest release.Manifest, phase string, resultErr error) {
	if options.InstallRoot == "" {
		options.InstallRoot = DefaultInstallRoot
	}
	checkpoint, err := readInstallCheckpoint(options.InstallRoot)
	if err != nil {
		return manifest, "", err
	}
	if err := ValidateHost(options.Host); err != nil {
		return manifest, checkpoint.Phase, err
	}
	if _, err := CheckDNS(ctx, checkpoint.Domain, options.DNSLookup); err != nil {
		return manifest, checkpoint.Phase, err
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
	options.Domain = checkpoint.Domain
	options.WireGuardPort = checkpoint.WireGuardPort
	options.InitialAllowedIPs = checkpoint.AllowedIPs
	options.BackupSchedule = checkpoint.BackupSchedule
	options.BackupRetentionDays = checkpoint.BackupRetentionDays
	options.PackagePath = checkpoint.PackagePath
	options.PackageSHA256 = checkpoint.PackageSHA
	options.RecoveryBackupPath = checkpoint.RecoveryBackupPath
	markerPath := filepath.Join(options.InstallRoot, ".install-id")
	if checkpoint.Phase == "preparing" {
		if options.Password == "" {
			return manifest, checkpoint.Phase, errors.New("enter the initial administrator password again to restart file preparation")
		}
		if _, err := release.ValidatePackage(checkpoint.PackagePath, checkpoint.PackageSHA); err != nil {
			return manifest, checkpoint.Phase, fmt.Errorf("checkpointed package is no longer valid: %w", err)
		}
		if _, err := os.Lstat(options.InstallRoot); err == nil {
			if err := validateInstallMarker(options.InstallRoot, checkpoint.ID); err != nil {
				entries, readErr := os.ReadDir(options.InstallRoot)
				if readErr != nil || len(entries) != 0 {
					return manifest, checkpoint.Phase, err
				}
			}
			resources, err := options.Runner.Run(ctx, "docker", "ps", "--all", "--filter", "label=com.docker.compose.project=jellyfin-proxy", "--format", "{{.Names}}")
			if err != nil {
				return manifest, checkpoint.Phase, err
			}
			if strings.TrimSpace(resources) != "" {
				return manifest, checkpoint.Phase, errors.New("Docker resources exist for the incomplete install; refusing to remove them")
			}
			if err := os.RemoveAll(options.InstallRoot); err != nil {
				return manifest, checkpoint.Phase, fmt.Errorf("remove only the incomplete install marked by this checkpoint: %w", err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return manifest, checkpoint.Phase, err
		}
		if options.Password == "" {
			return manifest, checkpoint.Phase, errors.New("enter the initial administrator password again to restart file preparation")
		}
		manifest, err = Install(ctx, options)
		if err != nil {
			return manifest, checkpoint.Phase, err
		}
		return manifest, "complete", nil
	}
	if checkpoint.Phase == "complete" {
		if err := validateInstalledLayout(options.InstallRoot); err != nil {
			return manifest, checkpoint.Phase, err
		}
		manifest, err = readCurrentRelease(options.InstallRoot)
		if err != nil {
			return manifest, checkpoint.Phase, err
		}
		if options.ConfigureHostServices {
			if err := ConfigureHostMaintenance(ctx, options.InstallRoot, manifest.Version, options.SystemdUnitDir, options.Runner); err != nil {
				return manifest, checkpoint.Phase, fmt.Errorf("finish restricted maintenance service setup: %w", err)
			}
			if err := ConfigureAutomaticBackups(ctx, options.InstallRoot, manifest.Version, checkpoint.BackupSchedule, checkpoint.BackupRetentionDays, options.SystemdUnitDir, options.BackupDirectory, options.Runner); err != nil {
				return manifest, checkpoint.Phase, fmt.Errorf("finish automatic backup service setup: %w", err)
			}
			if err := InstallPersistentProxyctl(options.InstallRoot, manifest.Version, options.ProxyctlDirectory, options.ProxyctlStateDirectory); err != nil {
				return manifest, checkpoint.Phase, fmt.Errorf("finish persistent proxyctl setup: %w", err)
			}
		}
		_ = os.Remove(checkpointPath(options.InstallRoot))
		_ = os.Remove(markerPath)
		return manifest, "complete", nil
	}
	if err := validateInstallMarker(options.InstallRoot, checkpoint.ID); err != nil {
		return manifest, checkpoint.Phase, err
	}
	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "config", "--quiet")...); err != nil {
		return manifest, checkpoint.Phase, fmt.Errorf("validate staged install: %w", err)
	}
	manifest, err = readCurrentRelease(options.InstallRoot)
	if err != nil {
		return manifest, checkpoint.Phase, err
	}
	if options.ConfigureHostServices {
		if err := ConfigureHostMaintenance(ctx, options.InstallRoot, manifest.Version, options.SystemdUnitDir, options.Runner); err != nil {
			return manifest, checkpoint.Phase, fmt.Errorf("resume restricted host maintenance setup: %w", err)
		}
	}
	if err := release.VerifyRetainedFiles(filepath.Join(options.InstallRoot, "releases", manifest.Version), manifest); err != nil {
		return manifest, checkpoint.Phase, err
	}
	if _, err := options.Runner.Run(ctx, "docker", "image", "load", "--input", filepath.Join(options.InstallRoot, "releases", manifest.Version, "images.tar")); err != nil {
		return manifest, checkpoint.Phase, fmt.Errorf("resume bundled image load: %w", err)
	}
	if err := verifyLoadedImages(ctx, options.Runner, manifest.Images); err != nil {
		return manifest, checkpoint.Phase, fmt.Errorf("verify resumed application images: %w", err)
	}
	if _, err := options.Runner.Run(ctx, "docker", composeArgs(options.InstallRoot, "up", "--detach", "--pull", "never")...); err != nil {
		return manifest, checkpoint.Phase, fmt.Errorf("resume application startup: %w", err)
	}
	if err := waitForReadiness(ctx, InstallOptions{InstallRoot: options.InstallRoot, Runner: options.Runner, WaitInterval: options.WaitInterval, WaitAttempts: options.WaitAttempts}); err != nil {
		return manifest, checkpoint.Phase, err
	}
	if options.HTTPSCheck == nil {
		options.HTTPSCheck = checkPublicHTTPS
	}
	if err := waitForHTTPS(ctx, checkpoint.Domain, options.WaitInterval, options.WaitAttempts, options.HTTPSCheck); err != nil {
		return manifest, checkpoint.Phase, err
	}
	if options.ConfigureHostServices {
		if err := ConfigureAutomaticBackups(ctx, options.InstallRoot, manifest.Version, checkpoint.BackupSchedule, checkpoint.BackupRetentionDays, options.SystemdUnitDir, options.BackupDirectory, options.Runner); err != nil {
			return manifest, checkpoint.Phase, fmt.Errorf("configure automatic backups after resume: %w", err)
		}
	}
	_ = writeInstallCheckpoint(options.InstallRoot, installCheckpoint{Version: 1, ID: checkpoint.ID, Phase: "complete", PackagePath: checkpoint.PackagePath, PackageSHA: checkpoint.PackageSHA, RecoveryBackupPath: checkpoint.RecoveryBackupPath, Domain: checkpoint.Domain, WireGuardPort: checkpoint.WireGuardPort, AllowedIPs: checkpoint.AllowedIPs, BackupSchedule: checkpoint.BackupSchedule, BackupRetentionDays: checkpoint.BackupRetentionDays})
	_ = os.Remove(markerPath)
	_ = os.Remove(checkpointPath(options.InstallRoot))
	return manifest, "complete", nil
}
