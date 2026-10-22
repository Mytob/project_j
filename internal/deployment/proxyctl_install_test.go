package deployment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallPersistentProxyctlRetainsPreviousExecutable(t *testing.T) {
	root := t.TempDir()
	binaryDir := filepath.Join(t.TempDir(), "sbin")
	stateDir := filepath.Join(t.TempDir(), "state")
	first := writeReleaseProxyctl(t, root, "1.6.0-dev", "first utility")
	if err := InstallPersistentProxyctl(root, "1.6.0-dev", binaryDir, stateDir); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(binaryDir, "proxyctl")
	if got, want := readBytes(t, destination), readBytes(t, first); string(got) != string(want) {
		t.Fatalf("installed utility = %q, want %q", got, want)
	}
	if info, err := os.Stat(destination); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("persistent utility mode = %v, %v", info, err)
	}
	second := writeReleaseProxyctl(t, root, "1.6.1-dev", "second utility")
	if err := InstallPersistentProxyctl(root, "1.6.1-dev", binaryDir, stateDir); err != nil {
		t.Fatal(err)
	}
	if got, want := readBytes(t, destination), readBytes(t, second); string(got) != string(want) {
		t.Fatalf("updated utility = %q, want %q", got, want)
	}
	if got := readBytes(t, filepath.Join(stateDir, proxyctlPreviousName)); string(got) != "first utility" {
		t.Fatalf("retained previous utility = %q", got)
	}
	marker, err := readProxyctlMarker(filepath.Join(stateDir, proxyctlMarkerName))
	if err != nil || marker.Release != "1.6.1-dev" || marker.Previous != mustFileHash(t, first) {
		t.Fatalf("managed executable metadata = %#v, %v", marker, err)
	}
}

func TestRecoverPersistentProxyctlCompletesAtomicReplacement(t *testing.T) {
	binaryDir := t.TempDir()
	stateDir := t.TempDir()
	destination := filepath.Join(binaryDir, "proxyctl")
	if err := os.WriteFile(destination, []byte("new utility"), 0o755); err != nil {
		t.Fatal(err)
	}
	journal := proxyctlReplacement{Version: 1, Owner: "jellyfin-proxy", Stage: "prepared", VersionString: "1.6.0-dev", TargetSHA256: mustFileHash(t, destination)}
	data, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, proxyctlJournalName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RecoverPersistentProxyctl(binaryDir, stateDir); err != nil {
		t.Fatal(err)
	}
	marker, err := readProxyctlMarker(filepath.Join(stateDir, proxyctlMarkerName))
	if err != nil || marker.Current != mustFileHash(t, destination) || marker.Release != "1.6.0-dev" {
		t.Fatalf("recovered managed executable = %#v, %v", marker, err)
	}
	if _, err := os.Lstat(filepath.Join(stateDir, proxyctlJournalName)); !os.IsNotExist(err) {
		t.Fatalf("replacement journal remains: %v", err)
	}
}

func TestInstallPersistentProxyctlRefusesUnownedExecutable(t *testing.T) {
	root := t.TempDir()
	binaryDir := t.TempDir()
	stateDir := t.TempDir()
	writeReleaseProxyctl(t, root, "1.6.0-dev", "product utility")
	destination := filepath.Join(binaryDir, "proxyctl")
	if err := os.WriteFile(destination, []byte("unrelated utility"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := InstallPersistentProxyctl(root, "1.6.0-dev", binaryDir, stateDir); err == nil {
		t.Fatal("unowned utility was overwritten")
	}
	if got := string(readBytes(t, destination)); got != "unrelated utility" {
		t.Fatalf("unowned utility changed to %q", got)
	}
}

func writeReleaseProxyctl(t *testing.T, root, version, contents string) string {
	t.Helper()
	path := filepath.Join(root, "releases", version, "bin", "proxyctl-linux-amd64")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustFileHash(t *testing.T, path string) string {
	t.Helper()
	data := readBytes(t, path)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
