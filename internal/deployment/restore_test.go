package deployment

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Mytob/project_j/internal/monitoring"
	"github.com/Mytob/project_j/internal/security"
)

func TestRestoreUsesVerifiedSafetyBackupAndRestoresApplicationFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("restore filesystem ownership test requires root")
	}
	root := filepath.Join(t.TempDir(), "install")
	runner := &fakeRunner{}
	packagePath := makeInstallPackage(t)
	_, err := Install(context.Background(), InstallOptions{
		PackagePath: packagePath, PackageSHA256: mustPackageHash(t, packagePath), InstallRoot: root,
		Domain: "restore.example.com", Password: "correct horse battery staple", Host: validHost(), Runner: runner,
		WaitInterval: time.Millisecond, WaitAttempts: 1,
		DNSLookup:  func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.20")}, nil },
		HTTPSCheck: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(root, "config", "Caddyfile"))
	if err != nil {
		t.Fatal(err)
	}
	history, err := monitoring.OpenHistory(filepath.Join(root, "data", "statistics"))
	if err != nil {
		t.Fatal(err)
	}
	if err := history.Close(); err != nil {
		t.Fatal(err)
	}
	eventKeyPath := filepath.Join(root, "config", "security-event-key", "event.key")
	if err := os.WriteFile(eventKeyPath, []byte(strings.Repeat("k", 32)), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(eventKeyPath, 0, adminContainerUID); err != nil {
		t.Fatal(err)
	}
	eventKey, err := os.ReadFile(eventKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	event, err := security.NewEvent(security.Admin, security.LoginFailure, "192.0.2.10", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	eventPath, err := security.AppendEvent(filepath.Join(root, "data", "security-events"), event, eventKey)
	if err != nil {
		t.Fatal(err)
	}
	clear(eventKey)
	backupPath := filepath.Join(t.TempDir(), "manual.bak")
	if _, _, err := CreateBackup(root, backupPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config", "Caddyfile"), []byte("corrupted current config"), 0o644); err != nil {
		t.Fatal(err)
	}
	safetyBackup := filepath.Join(t.TempDir(), "before-restore.bak")
	var progressUpdates []UpdateProgress
	manifest, err := Restore(context.Background(), RestoreOptions{
		InstallRoot: root, BackupPath: backupPath, SafetyBackupPath: safetyBackup,
		Runner: runner, WaitInterval: time.Millisecond, WaitAttempts: 1,
		HTTPSCheck: func(context.Context, string) error { return nil },
		Progress:   func(update UpdateProgress) { progressUpdates = append(progressUpdates, update) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != "1.0.0-dev" {
		t.Fatalf("restore selected version %q", manifest.Version)
	}
	actual, err := os.ReadFile(filepath.Join(root, "config", "Caddyfile"))
	if err != nil || string(actual) != string(original) {
		t.Fatalf("restored Caddyfile = %q, err=%v", actual, err)
	}
	assertRestoredOwner(t, filepath.Join(root, "data", "whitelist.json"), adminContainerUID, adminContainerUID, 0o600)
	assertRestoredOwner(t, filepath.Join(root, "data", "statistics", "statistics.db"), adminContainerUID, adminContainerUID, 0o600)
	assertRestoredOwner(t, filepath.Join(root, "data", "security-events", filepath.Base(eventPath)), adminContainerUID, 0, 0o640)
	if _, err := os.Stat(safetyBackup); err != nil {
		t.Fatalf("mandatory pre-restore backup missing: %v", err)
	}
	if !strings.Contains(strings.Join(runner.commands, "\n"), "compose --project-name jellyfin-proxy") || !strings.Contains(strings.Join(runner.commands, "\n"), " down") {
		t.Fatalf("restore did not stop and restart the scoped Compose project: %v", runner.commands)
	}
	if _, err := os.Stat(filepath.Join(root, ".restore-transaction.json")); !os.IsNotExist(err) {
		t.Fatalf("completed restore left a journal: %v", err)
	}
	if len(progressUpdates) < 8 || progressUpdates[len(progressUpdates)-1] != (UpdateProgress{Step: 7, Total: 7, Message: "Restore verified and committed", Done: true}) {
		t.Fatalf("restore progress did not report the final verified milestone: %+v", progressUpdates)
	}
}

func assertRestoredOwner(t *testing.T, path string, uid, gid uint32, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat restored path %s: %v", path, err)
	}
	if info.Mode().Perm() != mode {
		t.Fatalf("restored path %s mode = %04o, want %04o", path, info.Mode().Perm(), mode)
	}
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	uidField, gidField := value.FieldByName("Uid"), value.FieldByName("Gid")
	if !uidField.IsValid() || !gidField.IsValid() || uidField.Uint() != uint64(uid) || gidField.Uint() != uint64(gid) {
		t.Fatalf("restored path %s owner/group = %v/%v, want %d/%d", path, uidField, gidField, uid, gid)
	}
}

func TestInterruptedRestoreRecoveryRestoresMovedFilesAndRestarts(t *testing.T) {
	root := t.TempDir()
	stage := filepath.Join(root, ".restore-test")
	old := filepath.Join(stage, "old")
	if err := os.MkdirAll(filepath.Join(old, "config"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "config"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "config", "Caddyfile"), []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config", "Caddyfile"), []byte("partial restore"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeRestoreJournal(filepath.Join(root, ".restore-transaction.json"), restoreJournal{Version: "1.0.0", Stage: filepath.Base(stage), State: "replacing"}); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	recovered, err := RecoverInterruptedRestore(context.Background(), root, runner)
	if err != nil || !recovered {
		t.Fatalf("recovery = %v, %v", recovered, err)
	}
	actual, err := os.ReadFile(filepath.Join(root, "config", "Caddyfile"))
	if err != nil || string(actual) != "previous" {
		t.Fatalf("recovered Caddyfile = %q, err=%v", actual, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".restore-transaction.json")); !os.IsNotExist(err) {
		t.Fatalf("recovery left journal: %v", err)
	}
}
