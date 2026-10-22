package deployment

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mytob/project_j/internal/auth"
)

func TestPreviewHostUpdatesOnlySimulatesAfterHealthyPrecheck(t *testing.T) {
	root := createInstalledLayoutFixture(t)
	runner := &fakeRunner{}
	preview, err := PreviewHostUpdates(context.Background(), HostUpdateOptions{InstallRoot: root, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(runner.commands, "\n")
	if !strings.Contains(commands, "apt-get update") || !strings.Contains(commands, "apt-get --simulate upgrade") || strings.Contains(commands, "apt-get upgrade -y") {
		t.Fatalf("preview ran unexpected commands: %v", runner.commands)
	}
	if preview != "ok" {
		t.Fatalf("APT preview = %q", preview)
	}
}

func TestApplyHostUpdatesReportsRebootWithoutRebooting(t *testing.T) {
	root := createInstalledLayoutFixture(t)
	rebootFlag := filepath.Join(t.TempDir(), "reboot-required")
	if err := os.WriteFile(rebootFlag, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	result, err := ApplyHostUpdates(context.Background(), HostUpdateOptions{InstallRoot: root, Runner: runner, RebootRequiredPath: rebootFlag})
	if err != nil {
		t.Fatal(err)
	}
	if !result.ApplicationOK || !result.RebootRequired {
		t.Fatalf("host update result = %#v", result)
	}
	commands := strings.Join(runner.commands, "\n")
	if !strings.Contains(commands, "apt-get upgrade -y") || strings.Contains(commands, "reboot") {
		t.Fatalf("host update ran unexpected commands: %v", runner.commands)
	}
}

func TestApplyHostUpdatesStopsWhenDockerHealthChecksFail(t *testing.T) {
	root := createInstalledLayoutFixture(t)
	runner := &fakeRunner{failOn: "docker info"}
	if _, err := ApplyHostUpdates(context.Background(), HostUpdateOptions{InstallRoot: root, Runner: runner}); err == nil {
		t.Fatal("expected failed Docker post-update check")
	}
	if strings.Contains(strings.Join(runner.commands, "\n"), "reboot") {
		t.Fatalf("host update attempted a reboot: %v", runner.commands)
	}
}

func createInstalledLayoutFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{"config", "data", "site", "releases"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{".env", "compose.yaml", filepath.Join("config", "Caddyfile")} {
		if err := os.WriteFile(filepath.Join(root, file), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := auth.SaveCredential(filepath.Join(root, "config", "admin.json"), "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	return root
}
