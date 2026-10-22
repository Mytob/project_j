package deployment

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mytob/project_j/internal/release"
)

func TestRecoverInterruptedUpdateRestoresPreviousConfiguration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("deployment ownership fixture requires root")
	}
	root := filepath.Join(t.TempDir(), "jellyfin-proxy")
	runner := &fakeRunner{}
	installFixture(t, root, runner)
	before := make(map[string][]byte, len(updateRecoveryFiles))
	for _, relative := range updateRecoveryFiles {
		data, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		before[relative] = data
	}
	id, stage, err := newUpdateStage(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshotUpdateFiles(root, stage); err != nil {
		t.Fatal(err)
	}
	journal := updateJournal{
		Format: 1, ID: id, PreviousVersion: "1.0.0-dev", TargetVersion: "1.0.1-dev",
		Stage: stage, State: "replacing", BackupPath: filepath.Join(t.TempDir(), "pre-update.bak"),
		ReleaseCreated: true,
	}
	if err := writeUpdateJournal(root, journal); err != nil {
		t.Fatal(err)
	}
	for _, relative := range updateRecoveryFiles {
		content := []byte("partially activated target release\n")
		if relative == ".env" {
			content = []byte(strings.Replace(string(before[relative]), "RELEASE_VERSION=1.0.0-dev", "RELEASE_VERSION=1.0.1-dev", 1))
		}
		if err := atomicReplace(filepath.Join(root, relative), content, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "releases", "1.0.1-dev"), 0o700); err != nil {
		t.Fatal(err)
	}

	recovered, err := RecoverInterruptedUpdate(context.Background(), UpdateRecoveryOptions{
		InstallRoot: root, Runner: runner, WaitInterval: time.Millisecond, WaitAttempts: 1,
	})
	if err != nil || !recovered {
		t.Fatalf("recover interrupted update = %v, %v", recovered, err)
	}
	for _, relative := range updateRecoveryFiles {
		actual, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil || string(actual) != string(before[relative]) {
			t.Errorf("recovered %s = %q, %v; want %q", relative, actual, err, before[relative])
		}
	}
	if _, err := os.Lstat(updateJournalPath(root)); !os.IsNotExist(err) {
		t.Errorf("recovery journal remains: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, stage)); !os.IsNotExist(err) {
		t.Errorf("recovery snapshot remains: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "releases", "1.0.1-dev")); !os.IsNotExist(err) {
		t.Errorf("failed target release remains: %v", err)
	}
	if !strings.Contains(strings.Join(runner.commands, "\n"), "up --detach --force-recreate --pull never") {
		t.Fatalf("recovery did not restart the previous release: %v", runner.commands)
	}
}

func TestRecoverPreparedUpdateRemovesOnlyItsUnactivatedRelease(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("deployment ownership fixture requires root")
	}
	root := filepath.Join(t.TempDir(), "jellyfin-proxy")
	runner := &fakeRunner{}
	installFixture(t, root, runner)
	id, stage, err := newUpdateStage(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshotUpdateFiles(root, stage); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "releases", "1.0.1-dev"), 0o700); err != nil {
		t.Fatal(err)
	}
	journal := updateJournal{
		Format: 1, ID: id, PreviousVersion: "1.0.0-dev", TargetVersion: "1.0.1-dev", Stage: stage,
		State: "prepared", BackupPath: filepath.Join(t.TempDir(), "pre-update.bak"), ReleaseCreated: true,
	}
	if err := writeUpdateJournal(root, journal); err != nil {
		t.Fatal(err)
	}
	commandCount := len(runner.commands)
	recovered, err := RecoverInterruptedUpdate(context.Background(), UpdateRecoveryOptions{InstallRoot: root, Runner: runner})
	if err != nil || !recovered {
		t.Fatalf("recover prepared update = %v, %v", recovered, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "releases", "1.0.1-dev")); !os.IsNotExist(err) {
		t.Errorf("unactivated release remains: %v", err)
	}
	for _, command := range runner.commands[commandCount:] {
		if strings.Contains(command, " up --") {
			t.Errorf("prepared update unnecessarily restarted application: %v", runner.commands[commandCount:])
		}
	}
}

func TestRecoverInterruptedUpdateRejectsMalformedJournalWithoutDeletingIt(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(updateJournalPath(root), []byte(`{"format":1,"state":"activate"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := RecoverInterruptedUpdate(context.Background(), UpdateRecoveryOptions{InstallRoot: root})
	if err == nil || recovered {
		t.Fatalf("malformed journal recovery = %v, %v", recovered, err)
	}
	if _, err := os.Lstat(updateJournalPath(root)); err != nil {
		t.Fatalf("malformed journal was removed: %v", err)
	}
}

func TestRecoverInterruptedUpdateRetainsJournalUntilPreviousReleaseIsHealthy(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("deployment ownership fixture requires root")
	}
	root := filepath.Join(t.TempDir(), "jellyfin-proxy")
	runner := &fakeRunner{}
	installFixture(t, root, runner)
	runner.unhealthy = true
	id, stage, err := newUpdateStage(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshotUpdateFiles(root, stage); err != nil {
		t.Fatal(err)
	}
	journal := updateJournal{
		Format: 1, ID: id, PreviousVersion: "1.0.0-dev", TargetVersion: "1.0.1-dev",
		Stage: stage, State: "verifying", BackupPath: filepath.Join(t.TempDir(), "pre-update.bak"),
	}
	if err := writeUpdateJournal(root, journal); err != nil {
		t.Fatal(err)
	}
	if err := atomicReplace(filepath.Join(root, ".env"), []byte("BASE_DOMAIN=example.com\nRELEASE_VERSION=1.0.1-dev\nWIREGUARD_PORT=51820\nSYSTEMD_JOURNAL_GID=0\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if recovered, err := RecoverInterruptedUpdate(context.Background(), UpdateRecoveryOptions{InstallRoot: root, Runner: runner, WaitInterval: time.Millisecond, WaitAttempts: 1}); err == nil || recovered {
		t.Fatalf("unhealthy rollback recovery = %v, %v", recovered, err)
	}
	if _, err := os.Lstat(updateJournalPath(root)); err != nil {
		t.Fatalf("failed recovery removed its retry journal: %v", err)
	}
	runner.unhealthy = false
	recovered, err := RecoverInterruptedUpdate(context.Background(), UpdateRecoveryOptions{InstallRoot: root, Runner: runner, WaitInterval: time.Millisecond, WaitAttempts: 1})
	if err != nil || !recovered {
		t.Fatalf("retry interrupted update recovery = %v, %v", recovered, err)
	}
	if _, err := os.Lstat(updateJournalPath(root)); !os.IsNotExist(err) {
		t.Fatalf("successful retry left its journal: %v", err)
	}
}

func TestRecoverCommittedUpdateKeepsHealthyTargetRelease(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("deployment ownership fixture requires root")
	}
	root := filepath.Join(t.TempDir(), "jellyfin-proxy")
	runner := &fakeRunner{}
	installFixture(t, root, runner)
	id, stage, err := newUpdateStage(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshotUpdateFiles(root, stage); err != nil {
		t.Fatal(err)
	}
	packagePath := makeInstallPackageVersion(t, "1.0.1-dev")
	if _, err := release.ExtractAndValidate(packagePath, filepath.Join(root, "releases", "1.0.1-dev"), mustPackageHash(t, packagePath)); err != nil {
		t.Fatal(err)
	}
	oldEnvironment, err := os.ReadFile(filepath.Join(root, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	targetEnvironment := []byte(strings.Replace(string(oldEnvironment), "RELEASE_VERSION=1.0.0-dev", "RELEASE_VERSION=1.0.1-dev", 1))
	if err := atomicReplace(filepath.Join(root, ".env"), targetEnvironment, 0o640); err != nil {
		t.Fatal(err)
	}
	journal := updateJournal{
		Format: 1, ID: id, PreviousVersion: "1.0.0-dev", TargetVersion: "1.0.1-dev",
		Stage: stage, State: "committing", BackupPath: filepath.Join(t.TempDir(), "pre-update.bak"), ReleaseCreated: true,
	}
	if err := writeUpdateJournal(root, journal); err != nil {
		t.Fatal(err)
	}
	recovered, err := RecoverInterruptedUpdate(context.Background(), UpdateRecoveryOptions{InstallRoot: root, Runner: runner, WaitInterval: time.Millisecond, WaitAttempts: 1})
	if err != nil || !recovered {
		t.Fatalf("recover committed update = %v, %v", recovered, err)
	}
	active, err := os.ReadFile(filepath.Join(root, ".env"))
	if err != nil || string(active) != string(targetEnvironment) {
		t.Fatalf("committed target configuration = %q, %v", active, err)
	}
	if _, err := os.Stat(filepath.Join(root, "releases", "1.0.1-dev")); err != nil {
		t.Fatalf("committed target release was removed: %v", err)
	}
}
