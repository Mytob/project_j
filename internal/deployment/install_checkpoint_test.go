package deployment

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResumeInstallRestartsPreparingStageWithoutPersistingPassword(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("install checkpoint ownership test requires root")
	}
	root := filepath.Join(t.TempDir(), "install")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	packagePath := makeInstallPackage(t)
	password := "correct horse battery staple"
	checkpoint := installCheckpoint{Version: 1, ID: "0123456789abcdef0123456789abcdef", Phase: "preparing", PackagePath: packagePath, PackageSHA: mustPackageHash(t, packagePath), Domain: "resume.example.com", WireGuardPort: 51820}
	if err := writeInstallCheckpoint(root, checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".install-id"), []byte(checkpoint.ID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(checkpointPath(root))
	if err != nil || strings.Contains(string(stored), password) {
		t.Fatalf("checkpoint contains password or cannot be read: %q, %v", stored, err)
	}
	runner := &fakeRunner{}
	manifest, phase, err := ResumeInstall(context.Background(), InstallOptions{
		InstallRoot: root, Host: validHost(), Runner: runner, Password: password,
		WaitInterval: time.Millisecond, WaitAttempts: 1,
		DNSLookup:  func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.20")}, nil },
		HTTPSCheck: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if phase != "complete" || manifest.Version != "1.0.0-dev" {
		t.Fatalf("resume result = phase %q, version %q", phase, manifest.Version)
	}
	if _, err := os.Stat(checkpointPath(root)); !os.IsNotExist(err) {
		t.Fatalf("resumed install left checkpoint: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "config", "admin.json")); err != nil {
		t.Fatalf("resumed install did not create credentials: %v", err)
	}
}

func TestInstallCheckpointRetainsDisasterRecoveryBackupReference(t *testing.T) {
	root := filepath.Join(t.TempDir(), "install")
	packagePath := makeInstallPackage(t)
	backupPath := filepath.Join(t.TempDir(), "recovery.bak")
	checkpoint := installCheckpoint{
		Version: 1, ID: "0123456789abcdef0123456789abcdef", Phase: "preparing",
		PackagePath: packagePath, PackageSHA: mustPackageHash(t, packagePath), RecoveryBackupPath: backupPath,
		Domain: "resume.example.com", WireGuardPort: 51820,
	}
	if err := writeInstallCheckpoint(root, checkpoint); err != nil {
		t.Fatal(err)
	}
	got, err := readInstallCheckpoint(root)
	if err != nil {
		t.Fatal(err)
	}
	if got.RecoveryBackupPath != backupPath {
		t.Fatalf("checkpoint recovery backup = %q; want %q", got.RecoveryBackupPath, backupPath)
	}
}

func TestResumeInstallContinuesReadyStageAfterReboot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("install checkpoint ownership test requires root")
	}
	root := filepath.Join(t.TempDir(), "install")
	packagePath := makeInstallPackage(t)
	runner := &fakeRunner{}
	_, err := Install(context.Background(), InstallOptions{
		PackagePath: packagePath, PackageSHA256: mustPackageHash(t, packagePath), InstallRoot: root,
		Domain: "ready.example.com", Password: "correct horse battery staple", Host: validHost(), Runner: runner,
		WaitInterval: time.Millisecond, WaitAttempts: 1,
		DNSLookup:  func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.20")}, nil },
		HTTPSCheck: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := installCheckpoint{Version: 1, ID: "abcdef0123456789abcdef0123456789", Phase: "ready", PackagePath: packagePath, PackageSHA: mustPackageHash(t, packagePath), Domain: "ready.example.com", WireGuardPort: 51820}
	if err := writeInstallCheckpoint(root, checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".install-id"), []byte(checkpoint.ID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, phase, err := ResumeInstall(context.Background(), InstallOptions{
		InstallRoot: root, Host: validHost(), Runner: runner, WaitInterval: time.Millisecond, WaitAttempts: 1,
		DNSLookup:  func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.20")}, nil },
		HTTPSCheck: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if phase != "complete" || manifest.Version != "1.0.0-dev" {
		t.Fatalf("resume result = phase %q, version %q", phase, manifest.Version)
	}
	if _, err := os.Stat(checkpointPath(root)); !os.IsNotExist(err) {
		t.Fatalf("ready-stage resume left checkpoint: %v", err)
	}
}
