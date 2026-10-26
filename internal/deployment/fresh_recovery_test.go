package deployment

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Mytob/project_j/internal/auth"
	"github.com/Mytob/project_j/internal/monitoring"
	"github.com/Mytob/project_j/internal/security"
	"github.com/Mytob/project_j/internal/whitelist"
)

func TestFreshRecoveryRestoresSafeStateAndRegeneratesIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("fresh recovery ownership checks require root")
	}
	packagePath := makeInstallPackage(t)
	backupRoot := filepath.Join(t.TempDir(), "previous-install")
	backupRunner := &fakeRunner{}
	oldAllowed := []string{"192.0.2.20/32"}
	if _, err := Install(context.Background(), InstallOptions{
		PackagePath: packagePath, PackageSHA256: mustPackageHash(t, packagePath), InstallRoot: backupRoot,
		Domain: "previous.example.com", Password: "old administrator password", InitialAllowedIPs: oldAllowed,
		Host: validHost(), Runner: backupRunner, WaitInterval: time.Millisecond, WaitAttempts: 1,
		DNSLookup:  func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.20")}, nil },
		HTTPSCheck: func(context.Context, string) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}

	customPage := []byte("restored homepage content")
	if err := os.WriteFile(filepath.Join(backupRoot, "site", "index.html"), customPage, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupRoot, "data", "site-content", "current", "index.html"), customPage, 0o644); err != nil {
		t.Fatal(err)
	}
	statistics, err := monitoring.OpenHistory(filepath.Join(backupRoot, "data", "statistics.db"))
	if err != nil {
		t.Fatal(err)
	}
	sampleAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	if err := statistics.Append(monitoring.Snapshot{CapturedAt: sampleAt, Proxy: &monitoring.ProxyMetrics{AllowedRequests: 17}}); err != nil {
		t.Fatal(err)
	}
	if err := statistics.Close(); err != nil {
		t.Fatal(err)
	}
	eventKey := bytes.Repeat([]byte{0x6b}, 32)
	eventKeyPath := filepath.Join(backupRoot, "config", "security-event-key", "event.key")
	if err := os.WriteFile(eventKeyPath, eventKey, 0o440); err != nil {
		t.Fatal(err)
	}
	eventAt := time.Now().UTC().Add(-time.Minute)
	event, err := security.NewEvent(security.Admin, security.LoginFailure, "192.0.2.45", eventAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := security.AppendEvent(filepath.Join(backupRoot, "data", "security-events"), event, eventKey); err != nil {
		t.Fatal(err)
	}
	if err := security.WriteEventWriterHealth(filepath.Join(backupRoot, "data", "security-events"), eventKey, true, eventAt); err != nil {
		t.Fatal(err)
	}

	oldCredential, err := os.ReadFile(filepath.Join(backupRoot, "config", "admin.json"))
	if err != nil {
		t.Fatal(err)
	}
	oldTOTPKey, err := auth.LoadTOTPKey(filepath.Join(backupRoot, "config", "totp.key"))
	if err != nil {
		t.Fatal(err)
	}
	oldWireGuardServer, err := os.ReadFile(filepath.Join(backupRoot, "config", "wireguard", "server.conf"))
	if err != nil {
		t.Fatal(err)
	}
	oldWireGuardClient, err := os.ReadFile(filepath.Join(backupRoot, "data", "wireguard-client", "windows.conf"))
	if err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "disaster-recovery.bak")
	if _, _, err := CreateBackup(backupRoot, backupPath); err != nil {
		t.Fatal(err)
	}

	newRoot := filepath.Join(t.TempDir(), "fresh-install")
	newAllowed := []string{"198.51.100.24/32"}
	newPassword := "new administrator password"
	newRunner := &fakeRunner{}
	if _, err := Install(context.Background(), InstallOptions{
		PackagePath: packagePath, PackageSHA256: mustPackageHash(t, packagePath), RecoveryBackupPath: backupPath,
		InstallRoot: newRoot, Domain: "recovery.example.com", Password: newPassword, InitialAllowedIPs: newAllowed,
		Host: validHost(), Runner: newRunner, WaitInterval: time.Millisecond, WaitAttempts: 1,
		DNSLookup:  func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.24")}, nil },
		HTTPSCheck: func(context.Context, string) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}

	if actual, err := os.ReadFile(filepath.Join(newRoot, "site", "index.html")); err != nil || !bytes.Equal(actual, customPage) {
		t.Fatalf("recovered public site = %q, %v", actual, err)
	}
	if actual, err := os.ReadFile(filepath.Join(newRoot, "data", "site-content", "current", "index.html")); err != nil || !bytes.Equal(actual, customPage) {
		t.Fatalf("recovered published homepage = %q, %v", actual, err)
	}
	newCredential, err := auth.LoadCredential(filepath.Join(newRoot, "config", "admin.json"))
	if err != nil || !newCredential.Verify(newPassword) || newCredential.Verify("old administrator password") {
		t.Fatalf("fresh administrator credential does not accept the new password: %v", err)
	}
	if bytes.Equal(oldCredential, readFreshFile(t, filepath.Join(newRoot, "config", "admin.json"))) {
		t.Fatal("disaster recovery restored the previous administrator credential")
	}
	newTOTPKey, err := auth.LoadTOTPKey(filepath.Join(newRoot, "config", "totp.key"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oldTOTPKey, newTOTPKey) {
		t.Fatal("disaster recovery restored the previous TOTP encryption key")
	}
	totpStore, err := auth.NewTOTPStore(filepath.Join(newRoot, "data", "totp-state.json"), newTOTPKey)
	if err != nil || totpStore.Status() != auth.TOTPUnconfigured {
		t.Fatalf("fresh TOTP enrollment state = %v, %v", totpStore, err)
	}
	newWireGuardServer := readFreshFile(t, filepath.Join(newRoot, "config", "wireguard", "server.conf"))
	newWireGuardClient := readFreshFile(t, filepath.Join(newRoot, "data", "wireguard-client", "windows.conf"))
	if privateKeyFromConfig(t, oldWireGuardServer) == privateKeyFromConfig(t, newWireGuardServer) || privateKeyFromConfig(t, oldWireGuardClient) == privateKeyFromConfig(t, newWireGuardClient) {
		t.Fatal("disaster recovery restored the previous WireGuard key material")
	}
	newWhitelist, err := whitelist.NewStore(filepath.Join(newRoot, "data", "whitelist.json"))
	if err != nil {
		t.Fatal(err)
	}
	if entries, err := newWhitelist.Load(); err != nil || !slices.Equal(entries, newAllowed) {
		t.Fatalf("recovery allowlist = %v, %v; want the fresh install allowlist", entries, err)
	}
	recoveredStatistics, err := monitoring.OpenHistory(filepath.Join(newRoot, "data", "statistics.db"))
	if err != nil {
		t.Fatal(err)
	}
	latest, ok := recoveredStatistics.LatestAt()
	_ = recoveredStatistics.Close()
	if !ok || !latest.Equal(sampleAt) {
		t.Fatalf("recovered statistics latest sample = %v (present %v), want %v", latest, ok, sampleAt)
	}
	newKey := readFreshFile(t, filepath.Join(newRoot, "config", "security-event-key", "event.key"))
	items, rejected, err := security.ReadSpool(filepath.Join(newRoot, "data", "security-events"), newKey)
	if err != nil || len(rejected) != 0 || len(items) != 1 || items[0].Event.ID != event.ID {
		t.Fatalf("recovered security event spool = %d items, %d rejected, %v", len(items), len(rejected), err)
	}
	if _, err := os.Lstat(filepath.Join(newRoot, "data", "security-events", security.EventWriterHealthFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery copied the stale writer heartbeat: %v", err)
	}
}

func readFreshFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func privateKeyFromConfig(t *testing.T, config []byte) string {
	t.Helper()
	for _, line := range strings.Split(string(config), "\n") {
		if strings.HasPrefix(line, "PrivateKey = ") {
			return strings.TrimPrefix(line, "PrivateKey = ")
		}
	}
	t.Fatal("WireGuard configuration has no private key")
	return ""
}
