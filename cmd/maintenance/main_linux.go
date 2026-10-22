//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Mytob/project_j/internal/containerhealth"
	"github.com/Mytob/project_j/internal/deployment"
	"github.com/Mytob/project_j/internal/maintenance"
	"github.com/Mytob/project_j/internal/release"
	"golang.org/x/sys/unix"
)

func main() {
	socketPath := flag.String("socket", "/run/jellyfin-proxy-maintenance/maintenance.sock", "restricted maintenance Unix socket")
	dockerSocket := flag.String("docker-socket", "/var/run/docker.sock", "host Docker socket used only by the allowlisted observer")
	flag.Parse()
	if os.Geteuid() != 0 {
		fatal("maintenance service must run as root")
	}
	if *socketPath != "/run/jellyfin-proxy-maintenance/maintenance.sock" || *dockerSocket != "/var/run/docker.sock" {
		fatal("maintenance service paths must use the fixed host socket locations")
	}
	listener, err := listen(*socketPath)
	if err != nil {
		fatal("prepare maintenance socket: " + err.Error())
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(*socketPath)
	}()
	if err := os.Chown(*socketPath, 0, int(maintenance.AuthorizedAdminUID)); err != nil {
		fatal("set maintenance socket group: " + err.Error())
	}
	if err := os.Chmod(*socketPath, 0o660); err != nil {
		fatal("set maintenance socket permissions: " + err.Error())
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	server := maintenance.NewServer(*dockerSocket)
	server.ConfigureBackupOperation(func() (string, error) {
		path, err := createMaintenanceBackup()
		return filepath.Base(path), err
	})
	server.ConfigureOperations(maintenance.Operations{ValidateUpdate: validateUpdate, ReleaseState: releaseState, Run: runOperation, RestartMaintenance: scheduleMaintenanceRestart})
	if err := server.ConfigureRecovery(maintenance.DefaultRecoveryStatePath); err != nil {
		logger.Error("configure bounded application service recovery", "error", err)
	} else {
		server.StartRecovery(ctx, 10*time.Second, func(err error) {
			logger.Error("observe or recover managed application services", "error", err)
		})
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	logger.Info("restricted maintenance observer listening", "socket", *socketPath)
	if err := maintenance.Serve(listener, server.Handler(), peerUID); err != nil && !errors.Is(err, net.ErrClosed) {
		fatal("maintenance service stopped: " + err.Error())
	}
}

var uploadID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var safeBackupName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,180}\.bak$`)

func createMaintenanceBackup() (string, error) {
	path, _, err := deployment.CreateBackup(deployment.DefaultInstallRoot, "")
	if err != nil {
		return "", err
	}
	_, retention, err := deployment.ReadBackupSettings(deployment.DefaultInstallRoot)
	if err != nil {
		return path, err
	}
	if _, err := deployment.CleanupBackups(deployment.DefaultBackupRoot, retention, time.Now()); err != nil {
		return path, err
	}
	return path, nil
}

func validateUpdate(ctx context.Context, id, checksum string) (maintenance.UpdateReview, error) {
	path, err := safePackageUploadPath(id)
	if err != nil {
		return maintenance.UpdateReview{}, err
	}
	preview, err := deployment.PreviewUpdatePackage(ctx, deployment.DefaultInstallRoot, path, checksum)
	if err != nil {
		return maintenance.UpdateReview{}, err
	}
	return maintenance.UpdateReview{CurrentVersion: preview.CurrentVersion, CurrentBuildID: preview.CurrentBuildID, CandidateVersion: preview.CandidateVersion, CandidateBuildID: preview.CandidateBuildID, TargetOS: preview.TargetOS, Architecture: preview.Architecture, DatabaseSchemaMin: preview.DatabaseSchemaMin, DatabaseSchemaMax: preview.DatabaseSchemaMax}, nil
}

func releaseState(context.Context) (maintenance.ReleaseState, error) {
	current, err := deployment.CurrentReleaseForDoctor(deployment.DefaultInstallRoot)
	if err != nil {
		return maintenance.ReleaseState{}, err
	}
	state := maintenance.ReleaseState{Current: maintenance.ReleaseVersion{Version: current.Version, BuildID: current.BuildID}}
	previous, err := deployment.PreviousReleaseForRollback(deployment.DefaultInstallRoot)
	if errors.Is(err, deployment.ErrNoPreviousRelease) {
		return state, nil
	}
	if err != nil {
		return maintenance.ReleaseState{}, err
	}
	state.Previous = maintenance.ReleaseVersion{Version: previous.Version, BuildID: previous.BuildID}
	return state, nil
}

func runOperation(ctx context.Context, operation maintenance.OperationRequest, report func(maintenance.OperationProgress)) (string, error) {
	toProgress := func(progress deployment.UpdateProgress) {
		report(maintenance.OperationProgress{Step: progress.Step, Total: progress.Total, Message: progress.Message})
	}
	switch operation.Action {
	case "backup":
		path, err := createMaintenanceBackup()
		if err != nil {
			return "", err
		}
		report(maintenance.OperationProgress{Step: 2, Total: 2, Message: "Backup created and verified"})
		return filepath.Base(path), nil
	case "cleanup":
		report(maintenance.OperationProgress{Step: 1, Total: 2, Message: "Checking active, rollback and in-use images"})
		result, err := cleanupUnusedApplicationImages(ctx)
		if err != nil {
			return "", err
		}
		report(maintenance.OperationProgress{Step: 2, Total: 2, Message: "Unused application image cleanup completed"})
		return fmt.Sprintf("Removed %d unused image(s); kept %d protected or in-use image(s)", result.RemovedImages, result.KeptImages), nil
	case "update":
		path, err := safePackageUploadPath(operation.UploadID)
		if err != nil {
			return "", err
		}
		host, err := deployment.DetectHostFacts(ctx, deployment.ExecRunner{})
		if err != nil {
			return "", err
		}
		manifest, err := deployment.Update(ctx, deployment.UpdateOptions{PackagePath: path, PackageSHA256: operation.SHA256, InstallRoot: deployment.DefaultInstallRoot, Host: host, Runner: deployment.ExecRunner{}, ConfigureHostServices: true, MaintenanceUpdated: operation.MaintenanceUpdated, Progress: toProgress})
		if err != nil {
			return "", err
		}
		return manifest.Version + " · " + manifest.BuildID, nil
	case "restore":
		path, err := safeBackupPath(operation.BackupName)
		if err != nil {
			return "", err
		}
		manifest, err := deployment.Restore(ctx, deployment.RestoreOptions{InstallRoot: deployment.DefaultInstallRoot, BackupPath: path, Runner: deployment.ExecRunner{}, ConfigureHostServices: true, MaintenanceUpdated: operation.MaintenanceUpdated, Progress: toProgress})
		if err != nil {
			return "", err
		}
		return manifest.Version + " · " + manifest.BuildID, nil
	case "rollback":
		manifest, err := deployment.RollbackPrevious(ctx, deployment.RollbackOptions{InstallRoot: deployment.DefaultInstallRoot, Runner: deployment.ExecRunner{}, ConfigureHostServices: true, MaintenanceUpdated: operation.MaintenanceUpdated, Progress: toProgress})
		if err != nil {
			return "", err
		}
		return manifest.Version + " · " + manifest.BuildID, nil
	default:
		return "", errors.New("unsupported maintenance operation")
	}
}

func scheduleMaintenanceRestart(ctx context.Context, jobID string) error {
	if !uploadID.MatchString(jobID) {
		return errors.New("maintenance job identifier is invalid")
	}
	unit := "jellyfin-proxy-maintenance-refresh-" + jobID
	if _, err := (deployment.ExecRunner{}).Run(ctx, "/usr/bin/systemd-run", "--quiet", "--collect", "--unit="+unit, "--on-active=5s", "/usr/bin/systemctl", "restart", "jellyfin-proxy-maintenance.service"); err != nil {
		return fmt.Errorf("schedule the maintenance service refresh: %w", err)
	}
	return nil
}

func cleanupUnusedApplicationImages(ctx context.Context) (containerhealth.ImageCleanupResult, error) {
	current, err := deployment.CurrentReleaseForDoctor(deployment.DefaultInstallRoot)
	if err != nil {
		return containerhealth.ImageCleanupResult{}, fmt.Errorf("read active release before image cleanup: %w", err)
	}
	protected, err := applicationImageReferences(current.Images)
	if err != nil {
		return containerhealth.ImageCleanupResult{}, fmt.Errorf("validate active release images: %w", err)
	}
	previous, err := deployment.PreviousReleaseForRollback(deployment.DefaultInstallRoot)
	if err == nil {
		previousRefs, refsErr := applicationImageReferences(previous.Images)
		if refsErr != nil {
			return containerhealth.ImageCleanupResult{}, fmt.Errorf("validate rollback release images: %w", refsErr)
		}
		protected = append(protected, previousRefs...)
	} else if !errors.Is(err, deployment.ErrNoPreviousRelease) {
		return containerhealth.ImageCleanupResult{}, fmt.Errorf("read rollback release before image cleanup: %w", err)
	}
	observer := containerhealth.New("/var/run/docker.sock")
	return observer.RemoveUnusedApplicationImages(ctx, protected)
}

func applicationImageReferences(images []release.Image) ([]string, error) {
	wanted := map[string]bool{"admin": false, "caddy": false, "hostmetrics": false, "security": false, "wireguard": false}
	refs := make([]string, 0, len(wanted))
	for _, image := range images {
		if !strings.HasPrefix(image.Reference, "jellyfin-proxy/") {
			continue
		}
		name := strings.TrimPrefix(image.Reference, "jellyfin-proxy/")
		separator := strings.IndexByte(name, ':')
		if separator < 1 {
			return nil, errors.New("application image reference is malformed")
		}
		component := name[:separator]
		if _, exists := wanted[component]; !exists || wanted[component] {
			return nil, errors.New("application image manifest has an unexpected or duplicate component")
		}
		wanted[component] = true
		refs = append(refs, image.Reference)
	}
	for component, found := range wanted {
		if !found {
			return nil, fmt.Errorf("application image manifest is missing %s", component)
		}
	}
	return refs, nil
}

func safePackageUploadPath(id string) (string, error) {
	if !uploadID.MatchString(id) {
		return "", errors.New("package upload identifier is invalid")
	}
	directory := maintenance.DefaultPackageUploadDirectory
	if err := requireOwnedDirectory(directory, maintenance.AuthorizedAdminUID, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(directory, id+".pkg")
	if err := requireOwnedRegular(path, maintenance.AuthorizedAdminUID, 0o600, 2<<30); err != nil {
		return "", err
	}
	return path, nil
}

func safeBackupPath(name string) (string, error) {
	if !safeBackupName.MatchString(name) || filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
		return "", errors.New("backup name is invalid")
	}
	if err := requireOwnedDirectory(deployment.DefaultBackupRoot, 0, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(deployment.DefaultBackupRoot, name)
	if err := requireOwnedRegular(path, 0, 0o600, 2<<30); err != nil {
		return "", err
	}
	if _, err := deployment.ValidateBackup(path); err != nil {
		return "", fmt.Errorf("stored backup failed validation: %w", err)
	}
	return path, nil
}

func requireOwnedDirectory(path string, uid uint32, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode {
		return errors.New("maintenance data directory is missing or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid {
		return errors.New("maintenance data directory has unexpected ownership")
	}
	return nil
}

func requireOwnedRegular(path string, uid uint32, mode os.FileMode, maxBytes int64) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode || info.Size() <= 0 || info.Size() > maxBytes {
		return errors.New("maintenance file is missing or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid {
		return errors.New("maintenance file has unexpected ownership")
	}
	return nil
}

func listen(socketPath string) (net.Listener, error) {
	if !filepath.IsAbs(socketPath) || socketPath != "/run/jellyfin-proxy-maintenance/maintenance.sock" {
		return nil, errors.New("socket path must use the fixed maintenance location")
	}
	parent := filepath.Dir(socketPath)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return nil, err
	}
	if err := os.Chown(parent, 0, int(maintenance.AuthorizedAdminUID)); err != nil {
		return nil, err
	}
	if err := os.Chmod(parent, 0o750); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to replace non-socket path %q", socketPath)
		}
		probe, dialErr := net.DialTimeout("unix", socketPath, 250*time.Millisecond)
		if dialErr == nil {
			_ = probe.Close()
			return nil, fmt.Errorf("another maintenance service is already listening at %q", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return net.Listen("unix", socketPath)
}

func peerUID(connection net.Conn) (uint32, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, errors.New("maintenance socket requires Unix peer credentials")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credentials *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if controlErr != nil {
		return 0, controlErr
	}
	return credentials.Uid, nil
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
