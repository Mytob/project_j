package deployment

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigureHostMaintenanceWritesRestrictedOwnedUnit(t *testing.T) {
	root := t.TempDir()
	program := filepath.Join(root, "releases", "1.6.0-dev", "bin", "maintenance-linux-amd64")
	if err := os.MkdirAll(filepath.Dir(program), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(program, []byte("test executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	unitDir := t.TempDir()
	runner := &fakeRunner{}
	if err := ConfigureHostMaintenance(context.Background(), root, "1.6.0-dev", unitDir, runner); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(unitDir, maintenanceServiceName))
	if err != nil {
		t.Fatal(err)
	}
	unit := string(data)
	for _, expected := range []string{
		"Managed by Jellyfin Proxy v1.6",
		"User=root",
		"ExecStart=" + program,
		"--docker-socket /var/run/docker.sock",
		"ProtectSystem=strict",
		"CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
		"RuntimeDirectoryMode=0750",
		"RuntimeDirectoryPreserve=yes",
		"StateDirectory=jellyfin-proxy-maintenance",
		"ReadWritePaths=" + root + " /usr/local/sbin /usr/local/lib/jellyfin-proxy " + unitDir + " /var/backups/jellyfin-proxy",
		"ReadOnlyPaths=/var/run/docker.sock",
		"[Install]\nWantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, expected) {
			t.Errorf("maintenance unit missing %q:\n%s", expected, unit)
		}
	}
	if strings.Contains(unit, "Network=host") || strings.Contains(unit, "ExecStartPre=") {
		t.Fatalf("maintenance unit unexpectedly enables other host access:\n%s", unit)
	}
	commands := strings.Join(runner.commands, "\n")
	if !strings.Contains(commands, "systemctl enable --now "+maintenanceServiceName) ||
		!strings.Contains(commands, "systemctl restart "+maintenanceServiceName) {
		t.Fatalf("maintenance unit was not enabled and restarted to apply the new definition: %v", runner.commands)
	}
}

func TestDashboardMaintenanceUpdateDefersRestartUntilJobCompletion(t *testing.T) {
	root := t.TempDir()
	program := filepath.Join(root, "releases", "1.6.0-dev", "bin", "maintenance-linux-amd64")
	if err := os.MkdirAll(filepath.Dir(program), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(program, []byte("test executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	configured := false
	if err := configureHostMaintenanceForOperation(context.Background(), root, "1.6.0-dev", t.TempDir(), t.TempDir(), runner, func() { configured = true }); err != nil {
		t.Fatal(err)
	}
	if !configured {
		t.Fatal("maintenance completion callback was not notified after unit configuration")
	}
	for _, command := range runner.commands {
		if strings.Contains(command, "systemctl restart "+maintenanceServiceName) {
			t.Fatalf("dashboard update restarted its own maintenance service before job completion: %v", runner.commands)
		}
	}
	if !strings.Contains(strings.Join(runner.commands, "\n"), "systemctl daemon-reload") {
		t.Fatalf("updated unit was not loaded by systemd: %v", runner.commands)
	}
}

func TestRefreshHostServicesReconcilesActiveReleaseUnits(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("installer filesystem fixture requires root in the isolated Linux test container")
	}
	root := filepath.Join(t.TempDir(), "jellyfin-proxy")
	installFixture(t, root, &fakeRunner{})
	unitDir := filepath.Join(t.TempDir(), "systemd")
	backupDir := filepath.Join(t.TempDir(), "backups")
	runner := &fakeRunner{}
	if err := RefreshHostServices(context.Background(), root, unitDir, backupDir, runner); err != nil {
		t.Fatal(err)
	}
	maintenance, err := os.ReadFile(filepath.Join(unitDir, maintenanceServiceName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(maintenance), "ExecStart="+filepath.Join(root, "releases", "1.0.0-dev", "bin", "maintenance-linux-amd64")) ||
		!strings.Contains(string(maintenance), "StateDirectory=jellyfin-proxy-maintenance") ||
		!strings.Contains(string(maintenance), "ReadWritePaths=") || !strings.Contains(string(maintenance), " "+backupDir) {
		t.Fatalf("maintenance unit was not reconciled from the active release and backup path:\n%s", maintenance)
	}
	backupService, err := os.ReadFile(filepath.Join(unitDir, backupServiceName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(backupService), filepath.Join(root, "releases", "1.0.0-dev", "bin", "proxyctl-linux-amd64")) ||
		!strings.Contains(string(backupService), "ReadWritePaths="+backupDir) {
		t.Fatalf("backup service was not reconciled from the active release:\n%s", backupService)
	}
	info, err := os.Stat(backupDir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("backup directory is not private: info=%v err=%v", info, err)
	}
}

func TestConfigureHostMaintenanceRefusesUnmanagedUnit(t *testing.T) {
	root := t.TempDir()
	program := filepath.Join(root, "releases", "1.6.0-dev", "bin", "maintenance-linux-amd64")
	if err := os.MkdirAll(filepath.Dir(program), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(program, []byte("test executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	unitDir := t.TempDir()
	path := filepath.Join(unitDir, maintenanceServiceName)
	const unmanaged = "[Service]\nExecStart=/usr/bin/example\n"
	if err := os.WriteFile(path, []byte(unmanaged), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ConfigureHostMaintenance(context.Background(), root, "1.6.0-dev", unitDir, &fakeRunner{}); err == nil {
		t.Fatal("unmanaged maintenance unit was replaced")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != unmanaged {
		t.Fatalf("unmanaged maintenance unit changed: %q, %v", data, err)
	}
}

func TestConfigureHostMaintenanceRejectsUnsafeExecutable(t *testing.T) {
	root := t.TempDir()
	program := filepath.Join(root, "releases", "1.6.0-dev", "bin", "maintenance-linux-amd64")
	if err := os.MkdirAll(filepath.Dir(program), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/true", program); err != nil {
		t.Fatal(err)
	}
	if err := ConfigureHostMaintenance(context.Background(), root, "1.6.0-dev", t.TempDir(), &fakeRunner{}); err == nil {
		t.Fatal("symlink maintenance executable was accepted")
	}
}
