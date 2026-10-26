package deployment

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCleanupBackupsHonorsRetentionAndProductOwnedNames(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	oldName := "jellyfin-proxy-1.6.0-dev-abcdef123456-20261001T030405.123456789Z.bak"
	newName := "jellyfin-proxy-1.6.0-dev-abcdef123456-20261021T030405.123456789Z.bak"
	for _, name := range []string{oldName, newName, "operator-backup.bak", "jellyfin-proxy-1.6.0-dev-abcdef123456-20261001T030405.123456789Z.bak.notes"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("archive"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, oldName+".sha256"), []byte("digest"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(directory, oldName), now.Add(-31*24*time.Hour), now.Add(-31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(directory, oldName+".sha256"), now.Add(-31*24*time.Hour), now.Add(-31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	removed, err := CleanupBackups(directory, 30, now)
	if err != nil || removed != 1 {
		t.Fatalf("CleanupBackups() = %d, %v", removed, err)
	}
	for _, name := range []string{oldName, oldName + ".sha256"} {
		if _, err := os.Lstat(filepath.Join(directory, name)); !os.IsNotExist(err) {
			t.Errorf("expired product backup %q remains: %v", name, err)
		}
	}
	for _, name := range []string{newName, "operator-backup.bak", "jellyfin-proxy-1.6.0-dev-abcdef123456-20261001T030405.123456789Z.bak.notes"} {
		if _, err := os.Lstat(filepath.Join(directory, name)); err != nil {
			t.Errorf("cleanup removed or lost unrelated/recent file %q: %v", name, err)
		}
	}
}

func TestCleanupBackupsKeepsNewestManagedLimit(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	for i := 0; i < MaxManagedBackups+2; i++ {
		name := fmt.Sprintf("jellyfin-proxy-1.6.0-dev-build-%04d-%s.bak", i, now.Add(time.Duration(i)*time.Second).Format("20060102T150405.000000000Z"))
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("archive"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, now.Add(time.Duration(i)*time.Second), now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "operator-backup.bak"), []byte("operator archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	removed, err := CleanupBackups(directory, 30, now.Add(time.Hour))
	if err != nil || removed != 2 {
		t.Fatalf("CleanupBackups() = %d, %v; want 2 count-pruned archives", removed, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	managedCount := 0
	for _, entry := range entries {
		if generatedBackupName.MatchString(entry.Name()) {
			managedCount++
		}
	}
	if managedCount != MaxManagedBackups {
		t.Fatalf("managed backups remaining = %d, want %d", managedCount, MaxManagedBackups)
	}
	if _, err := os.Stat(filepath.Join(directory, "operator-backup.bak")); err != nil {
		t.Fatalf("operator backup was removed: %v", err)
	}
}

func TestCleanupBackupsCountsProtectedRecoveryBackupTowardLimit(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	paths := make([]string, MaxManagedBackups+1)
	for i := range paths {
		name := fmt.Sprintf("jellyfin-proxy-1.6.0-dev-build-%04d-%s.bak", i, now.Add(time.Duration(i)*time.Second).Format("20060102T150405.000000000Z"))
		paths[i] = filepath.Join(directory, name)
		if err := os.WriteFile(paths[i], []byte("archive"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(paths[i], now.Add(time.Duration(i)*time.Second), now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	id, err := newInstallID()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeUpdateJournal(root, updateJournal{
		Format: 1, ID: id, PreviousVersion: "1.5.0-dev", TargetVersion: "1.6.0-dev",
		Stage: ".update-" + id, State: "verifying", BackupPath: paths[0],
	}); err != nil {
		t.Fatal(err)
	}
	removed, err := cleanupBackups(directory, root, 30, now.Add(time.Hour))
	if err != nil || removed != 1 {
		t.Fatalf("cleanupBackups() = %d, %v; want one excess archive removed", removed, err)
	}
	if _, err := os.Stat(paths[0]); err != nil {
		t.Fatalf("active recovery archive was removed: %v", err)
	}
	if _, err := os.Stat(paths[1]); !os.IsNotExist(err) {
		t.Fatalf("oldest unprotected archive remains: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	managedCount := 0
	for _, entry := range entries {
		if generatedBackupName.MatchString(entry.Name()) {
			managedCount++
		}
	}
	if managedCount != MaxManagedBackups {
		t.Fatalf("managed backups remaining = %d, want %d including recovery copy", managedCount, MaxManagedBackups)
	}
}

func TestConfigureAutomaticBackupsWritesOwnedUnitsAndEnablesTimer(t *testing.T) {
	root := t.TempDir()
	program := filepath.Join(root, "releases", "1.6.0-dev", "bin", "proxyctl-linux-amd64")
	if err := os.MkdirAll(filepath.Dir(program), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(program, []byte("test executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	units := t.TempDir()
	backups := filepath.Join(t.TempDir(), "backups")
	runner := &fakeRunner{}
	if err := ConfigureAutomaticBackups(context.Background(), root, "1.6.0-dev", "weekly", 14, units, backups, runner); err != nil {
		t.Fatal(err)
	}
	service, err := os.ReadFile(filepath.Join(units, backupServiceName))
	if err != nil {
		t.Fatal(err)
	}
	timer, err := os.ReadFile(filepath.Join(units, backupTimerName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(service), "Managed by Jellyfin Proxy v1.6") || !strings.Contains(string(service), program+" backup") || !strings.Contains(string(service), "ReadWritePaths="+backups) || !strings.Contains(string(timer), "OnCalendar=Sun *-*-* 03:20:00") {
		t.Fatalf("unexpected systemd unit contents:\n%s\n%s", service, timer)
	}
	if len(runner.commands) == 0 || !strings.Contains(runner.commands[len(runner.commands)-1], "systemctl enable --now "+backupTimerName) {
		t.Fatalf("backup timer was not enabled: %v", runner.commands)
	}
}

func TestConfigureAutomaticBackupsRefusesUnmanagedUnit(t *testing.T) {
	root := t.TempDir()
	program := filepath.Join(root, "releases", "1.6.0-dev", "bin", "proxyctl-linux-amd64")
	if err := os.MkdirAll(filepath.Dir(program), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(program, []byte("test executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	units := t.TempDir()
	backups := filepath.Join(t.TempDir(), "backups")
	path := filepath.Join(units, backupServiceName)
	if err := os.WriteFile(path, []byte("[Service]\nExecStart=/usr/bin/example"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ConfigureAutomaticBackups(context.Background(), root, "1.6.0-dev", "daily", 30, units, backups, &fakeRunner{}); err == nil {
		t.Fatal("unmanaged systemd unit was replaced")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "[Service]\nExecStart=/usr/bin/example" {
		t.Fatalf("unmanaged unit changed: %q, %v", data, err)
	}
}

func TestReadEnvironmentSupportsLegacyAndConfiguredBackupPolicy(t *testing.T) {
	legacy := "BASE_DOMAIN=example.com\nRELEASE_VERSION=1.5.0\nWIREGUARD_PORT=51820\nSYSTEMD_JOURNAL_GID=0\n"
	environment, err := readEnvironment([]byte(legacy))
	if err != nil || environment.BackupSchedule != "daily" || environment.BackupRetentionDays != 30 {
		t.Fatalf("legacy backup policy = %#v, %v", environment, err)
	}
	configured := legacy + "BACKUP_SCHEDULE=weekly\nBACKUP_RETENTION_DAYS=14\n"
	environment, err = readEnvironment([]byte(configured))
	if err != nil || environment.BackupSchedule != "weekly" || environment.BackupRetentionDays != 14 {
		t.Fatalf("configured backup policy = %#v, %v", environment, err)
	}
	if _, err := readEnvironment([]byte(configured + "BACKUP_RETENTION_DAYS=90\n")); err == nil {
		t.Fatal("duplicate or unsupported backup policy was accepted")
	}
}

func TestCleanupBackupsRejectsUnsupportedRetention(t *testing.T) {
	if _, err := CleanupBackups(t.TempDir(), 90, time.Now()); err == nil {
		t.Fatal("unsupported retention was accepted")
	}
}

func TestActiveUpdateBackupIsProtectedFromRetention(t *testing.T) {
	root := t.TempDir()
	backupPath := filepath.Join(t.TempDir(), "jellyfin-proxy-1.6.0-dev-abcdef123456-20261001T030405.123456789Z.bak")
	id, err := newInstallID()
	if err != nil {
		t.Fatal(err)
	}
	journal := updateJournal{
		Format: 1, ID: id, PreviousVersion: "1.5.0-dev", TargetVersion: "1.6.0-dev",
		Stage: ".update-" + id, State: "verifying", BackupPath: backupPath,
	}
	if err := writeUpdateJournal(root, journal); err != nil {
		t.Fatal(err)
	}
	protected, err := updateBackupProtected(root, backupPath)
	if err != nil || !protected {
		t.Fatalf("active update backup protection = %v, %v", protected, err)
	}
	otherBackup := filepath.Join(filepath.Dir(backupPath), "operator-backup.bak")
	protected, err = updateBackupProtected(root, otherBackup)
	if err != nil || protected {
		t.Fatalf("unrelated backup protection = %v, %v", protected, err)
	}
	if err := os.Remove(updateJournalPath(root)); err != nil {
		t.Fatal(err)
	}
	protected, err = updateBackupProtected(root, backupPath)
	if err != nil || protected {
		t.Fatalf("completed update backup protection = %v, %v", protected, err)
	}
}

func TestDeleteStoredBackupRemovesOnlySelectedArchiveAndChecksum(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "operator-backup.bak"
	archive := filepath.Join(directory, name)
	checksum := archive + ".sha256"
	for path, content := range map[string]string{archive: "archive", checksum: "digest", filepath.Join(directory, "keep.bak"): "keep"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := DeleteStoredBackup(directory, t.TempDir(), name); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{archive, checksum} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("selected file %q remains: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(directory, "keep.bak")); err != nil {
		t.Fatalf("unselected backup was removed: %v", err)
	}
	if err := DeleteStoredBackup(directory, t.TempDir(), "../keep.bak"); err == nil {
		t.Fatal("path traversal backup name was accepted")
	}
}

func TestDeleteStoredBackupProtectsActiveUpdateRecoveryArchive(t *testing.T) {
	root := t.TempDir()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "operator-backup.bak"
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := newInstallID()
	if err != nil {
		t.Fatal(err)
	}
	journal := updateJournal{Format: 1, ID: id, PreviousVersion: "1.5.0", TargetVersion: "1.6.0", Stage: ".update-" + id, State: "verifying", BackupPath: path}
	if err := writeUpdateJournal(root, journal); err != nil {
		t.Fatal(err)
	}
	if err := DeleteStoredBackup(directory, root, name); err == nil {
		t.Fatal("active recovery backup was deleted")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("protected recovery backup disappeared: %v", err)
	}
}

func TestCleanupBackupsRefusesSymlinkAndPublicDirectory(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "backup-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupBackups(link, 30, time.Now()); err == nil {
		t.Fatal("cleanup followed a symlinked backup directory")
	}
	public := t.TempDir()
	if err := os.Chmod(public, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupBackups(public, 30, time.Now()); err == nil {
		t.Fatal("cleanup accepted a backup directory accessible to other users")
	}
}
