package deployment

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRollbackPreviousPreservesStateAndRetainsBothReleases(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("rollback filesystem test requires a root Linux test container")
	}
	root := filepath.Join(t.TempDir(), "jellyfin-proxy")
	runner := &fakeRunner{}
	installFixture(t, root, runner)
	operatorData := filepath.Join(root, "data", "operator-state.txt")
	if err := os.WriteFile(operatorData, []byte("preserve this state"), 0o600); err != nil {
		t.Fatal(err)
	}
	packagePath := makeInstallPackageVersion(t, "1.0.1-dev")
	backupDirectory := t.TempDir()
	if _, err := Update(context.Background(), UpdateOptions{
		PackagePath: packagePath, PackageSHA256: mustPackageHash(t, packagePath), InstallRoot: root,
		BackupPath: filepath.Join(backupDirectory, "pre-update.bak"),
		Host:       validHost(), Runner: runner, WaitInterval: time.Millisecond, WaitAttempts: 1,
		HTTPSCheck: func(context.Context, string) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	credentialBefore, err := os.ReadFile(filepath.Join(root, "config", "admin.json"))
	if err != nil {
		t.Fatal(err)
	}
	progress := []UpdateProgress{}
	manifest, err := RollbackPrevious(context.Background(), RollbackOptions{
		InstallRoot: root, Runner: runner, BackupPath: filepath.Join(backupDirectory, "pre-rollback.bak"), WaitInterval: time.Millisecond, WaitAttempts: 1,
		HTTPSCheck: func(context.Context, string) error { return nil },
		Progress:   func(value UpdateProgress) { progress = append(progress, value) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != "1.0.0-dev" {
		t.Fatalf("rollback activated %s, want 1.0.0-dev", manifest.Version)
	}
	active, err := readCurrentRelease(root)
	if err != nil || active.Version != "1.0.0-dev" {
		t.Fatalf("active release after rollback = %q, %v", active.Version, err)
	}
	credentialAfter, err := os.ReadFile(filepath.Join(root, "config", "admin.json"))
	if err != nil || string(credentialAfter) != string(credentialBefore) {
		t.Fatalf("rollback changed administrator credentials: %v", err)
	}
	actual, err := os.ReadFile(operatorData)
	if err != nil || string(actual) != "preserve this state" {
		t.Fatalf("rollback changed operator data: %q, %v", actual, err)
	}
	for _, version := range []string{"1.0.0-dev", "1.0.1-dev"} {
		if _, err := os.Stat(filepath.Join(root, "releases", version)); err != nil {
			t.Errorf("active/rollback release %s was not retained: %v", version, err)
		}
	}
	if _, err := os.Stat(updateJournalPath(root)); !os.IsNotExist(err) {
		t.Errorf("successful rollback left a recovery journal: %v", err)
	}
	if _, err := ValidateBackup(filepath.Join(backupDirectory, "pre-rollback.bak")); err != nil {
		t.Errorf("pre-rollback safety backup did not verify: %v", err)
	}
	if len(progress) != 14 {
		t.Fatalf("rollback progress events = %d, want 14", len(progress))
	}
	commands := strings.Join(runner.commands, "\n")
	if strings.Contains(commands, "docker pull ") || strings.Contains(commands, " compose pull ") || !strings.Contains(commands, "--force-recreate --pull never") {
		t.Fatalf("rollback pulled images or omitted offline recreation: %s", commands)
	}
}

func TestRollbackPreviousRefusesWhenNoPreviousReleaseExists(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("rollback filesystem test requires a root Linux test container")
	}
	root := filepath.Join(t.TempDir(), "jellyfin-proxy")
	runner := &fakeRunner{}
	installFixture(t, root, runner)
	if _, err := RollbackPrevious(context.Background(), RollbackOptions{InstallRoot: root, Runner: runner, BackupPath: filepath.Join(t.TempDir(), "must-not-exist.bak")}); err == nil || !strings.Contains(err.Error(), "no retained previous release") {
		t.Fatalf("rollback without a previous release = %v", err)
	}
	active, err := readCurrentRelease(root)
	if err != nil || active.Version != "1.0.0-dev" {
		t.Fatalf("refused rollback changed active version: %q, %v", active.Version, err)
	}
}

func TestRollbackPreviousRequiresHealthyDeploymentAndCompatibleDatabase(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("rollback filesystem test requires a root Linux test container")
	}
	t.Run("unhealthy current deployment", func(t *testing.T) {
		root, runner := rollbackFixtureWithPreviousRelease(t)
		runner.unhealthy = true
		backup := filepath.Join(t.TempDir(), "must-not-be-created.bak")
		if _, err := RollbackPrevious(context.Background(), RollbackOptions{InstallRoot: root, Runner: runner, BackupPath: backup}); err == nil || !strings.Contains(err.Error(), "deployment is not healthy") {
			t.Fatalf("rollback with unhealthy current deployment = %v", err)
		}
		if _, err := os.Stat(backup); !os.IsNotExist(err) {
			t.Fatalf("unhealthy deployment created a pre-rollback backup: %v", err)
		}
	})
	t.Run("database schema incompatible", func(t *testing.T) {
		root, runner := rollbackFixtureWithPreviousRelease(t)
		previous := filepath.Join(root, "releases", "1.0.0-dev", "manifest.json")
		manifest, err := readReleaseManifest(filepath.Dir(previous))
		if err != nil {
			t.Fatal(err)
		}
		manifest.DatabaseSchemaMinimum = 2
		manifest.DatabaseSchemaMaximum = 2
		encoded, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(previous, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		backup := filepath.Join(t.TempDir(), "must-not-be-created.bak")
		if _, err := RollbackPrevious(context.Background(), RollbackOptions{InstallRoot: root, Runner: runner, BackupPath: backup}); err == nil || !strings.Contains(err.Error(), "does not support database schema") {
			t.Fatalf("rollback with incompatible retained database schema = %v", err)
		}
		if _, err := os.Stat(backup); !os.IsNotExist(err) {
			t.Fatalf("incompatible rollback created a pre-rollback backup: %v", err)
		}
	})
}

func rollbackFixtureWithPreviousRelease(t *testing.T) (string, *fakeRunner) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "jellyfin-proxy")
	runner := &fakeRunner{}
	installFixture(t, root, runner)
	packagePath := makeInstallPackageVersion(t, "1.0.1-dev")
	if _, err := Update(context.Background(), UpdateOptions{
		PackagePath: packagePath, PackageSHA256: mustPackageHash(t, packagePath), InstallRoot: root,
		BackupPath: filepath.Join(t.TempDir(), "pre-update.bak"), Host: validHost(), Runner: runner,
		WaitInterval: time.Millisecond, WaitAttempts: 1, HTTPSCheck: func(context.Context, string) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	return root, runner
}

func TestUpdateRefusesIncompatibleDatabaseSchemaBeforeBackup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("deployment filesystem test requires a root Linux test container")
	}
	root := filepath.Join(t.TempDir(), "jellyfin-proxy")
	runner := &fakeRunner{}
	installFixture(t, root, runner)
	packagePath := makeInstallPackageVersionWithDatabaseSchema(t, "1.0.1-dev", 2, 2)
	backup := filepath.Join(t.TempDir(), "must-not-be-created.bak")
	if _, err := Update(context.Background(), UpdateOptions{
		PackagePath: packagePath, PackageSHA256: mustPackageHash(t, packagePath), InstallRoot: root,
		BackupPath: backup, Host: validHost(), Runner: runner, WaitInterval: time.Millisecond, WaitAttempts: 1,
		HTTPSCheck: func(context.Context, string) error { return nil },
	}); err == nil || !strings.Contains(err.Error(), "does not support the installed database schema") {
		t.Fatalf("update with incompatible database schema = %v", err)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("incompatible update created a pre-update backup: %v", err)
	}
	active, err := readCurrentRelease(root)
	if err != nil || active.Version != "1.0.0-dev" {
		t.Fatalf("incompatible update changed active release to %q: %v", active.Version, err)
	}
}
