package wireguard

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureProvisionedRetainsProtectedPairForRepeatDownloads(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "wireguard")
	options := ProvisionOptions{
		Endpoint: "vpn.example.test:51820", ListenPort: 51820,
		ServerAddress: netip.MustParsePrefix("10.66.66.1/24"),
		ClientAddress: netip.MustParsePrefix("10.66.66.2/32"), Keepalive: 25,
	}
	paths, err := EnsureProvisioned(directory, options)
	if err != nil {
		t.Fatal(err)
	}
	serverBefore, err := os.ReadFile(paths.ServerPath)
	if err != nil {
		t.Fatal(err)
	}
	clientBefore, err := LoadRetainedClientConfig(paths.ClientPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"[Interface]", "Endpoint = vpn.example.test:51820", "AllowedIPs = 10.66.66.1/32", "PersistentKeepalive = 25"} {
		if !strings.Contains(string(clientBefore), expected) {
			t.Errorf("Windows config missing %q: %s", expected, clientBefore)
		}
	}
	for path, want := range map[string]os.FileMode{directory: 0o700, paths.ServerPath: 0o600, paths.ClientPath: 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("permissions for %s = %04o, want %04o", path, got, want)
		}
	}

	options.Endpoint = "changed.example.test:51820"
	second, err := EnsureProvisioned(directory, options)
	if err != nil {
		t.Fatal(err)
	}
	serverAfter, _ := os.ReadFile(second.ServerPath)
	clientAfter, err := LoadRetainedClientConfig(second.ClientPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(serverBefore) != string(serverAfter) || string(clientBefore) != string(clientAfter) {
		t.Fatal("repeat provisioning rotated or replaced the retained WireGuard keypair")
	}
}

func TestRetainedConfigRejectsBroadPermissionsAndMalformedContents(t *testing.T) {
	paths, err := EnsureProvisioned(filepath.Join(t.TempDir(), "wireguard"), ProvisionOptions{
		Endpoint: "vpn.example.test:51820", ListenPort: 51820,
		ServerAddress: netip.MustParsePrefix("10.66.66.1/24"),
		ClientAddress: netip.MustParsePrefix("10.66.66.2/32"), Keepalive: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.ClientPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRetainedClientConfig(paths.ClientPath); err == nil {
		t.Fatal("world-readable WireGuard config accepted")
	}
	if err := os.Chmod(paths.ClientPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.ClientPath, []byte("[Interface]\nPrivateKey = invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRetainedClientConfig(paths.ClientPath); err == nil {
		t.Fatal("malformed WireGuard config accepted")
	}
}

func TestEnsureProvisionedRejectsIncompletePairWithoutReplacingIt(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "wireguard")
	paths, err := EnsureProvisioned(directory, ProvisionOptions{
		Endpoint: "vpn.example.test:51820", ListenPort: 51820,
		ServerAddress: netip.MustParsePrefix("10.66.66.1/24"),
		ClientAddress: netip.MustParsePrefix("10.66.66.2/32"), Keepalive: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(paths.ServerPath); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureProvisioned(directory, ProvisionOptions{}); err == nil {
		t.Fatal("incomplete retained pair accepted")
	}
	if _, err := os.Stat(paths.ClientPath); err != nil {
		t.Fatal("failed validation removed or replaced the existing Windows config")
	}
}

func TestEnsureProvisionedRejectsAValidButMismatchedPeerPair(t *testing.T) {
	options := ProvisionOptions{
		Endpoint: "vpn.example.test:51820", ListenPort: 51820,
		ServerAddress: netip.MustParsePrefix("10.66.66.1/24"),
		ClientAddress: netip.MustParsePrefix("10.66.66.2/32"), Keepalive: 25,
	}
	first, err := EnsureProvisioned(filepath.Join(t.TempDir(), "first"), options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EnsureProvisioned(filepath.Join(t.TempDir(), "second"), options)
	if err != nil {
		t.Fatal(err)
	}
	otherServerConfig, err := os.ReadFile(second.ServerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first.ServerPath, otherServerConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureProvisioned(filepath.Dir(first.ServerPath), options); err == nil {
		t.Fatal("valid but mismatched WireGuard keys were accepted as a pair")
	}
}
