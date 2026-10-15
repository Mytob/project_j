package wireguard

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type recordingWGCommand struct {
	calls [][]string
	fail  func([]string) bool
}

func (f *recordingWGCommand) Run(_ context.Context, args ...string) error {
	f.calls = append(f.calls, append([]string(nil), args...))
	if f.fail != nil && f.fail(args) {
		return errors.New("simulated peer update failure")
	}
	return nil
}

func newControllerFixture(t *testing.T) (*PeerController, []byte, PeerStatus, *recordingWGCommand) {
	t.Helper()
	root := t.TempDir()
	serverPrefix := netip.MustParsePrefix("10.66.66.1/24")
	clientPrefix := netip.MustParsePrefix("10.66.66.2/24")
	provisioned, err := EnsureProvisioned(filepath.Join(root, "config"), ProvisionOptions{
		Endpoint: "proxy.example.test:51820", ListenPort: 51820,
		ServerAddress: serverPrefix, ClientAddress: clientPrefix, Keepalive: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	clientDir := filepath.Join(root, "client")
	if err := os.Mkdir(clientDir, 0o700); err != nil {
		t.Fatal(err)
	}
	clientPath := filepath.Join(clientDir, "windows.conf")
	if err := os.Rename(provisioned.ClientPath, clientPath); err != nil {
		t.Fatal(err)
	}
	oldClient, err := LoadRetainedClientConfig(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := NewPeerController(provisioned.ServerPath, clientPath, "wg0", "wg")
	if err != nil {
		t.Fatal(err)
	}
	commands := &recordingWGCommand{}
	controller.command = commands
	status, err := controller.Status()
	if err != nil {
		t.Fatal(err)
	}
	return controller, oldClient, status, commands
}

func replacementConfig(t *testing.T, status PeerStatus) ([]byte, string) {
	t.Helper()
	data, public, err := ClientConfiguration("proxy.example.test:51820", status, 25)
	if err != nil {
		t.Fatal(err)
	}
	return data, public
}

func TestPeerControllerRotationReplacesPeerAndPublishesNewConfig(t *testing.T) {
	controller, oldClient, oldStatus, commands := newControllerFixture(t)
	replacement, newPublic := replacementConfig(t, oldStatus)
	if err := controller.Rotate(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	newStatus, err := controller.Status()
	if err != nil {
		t.Fatal(err)
	}
	if newStatus.PeerPublicKey != newPublic || !newStatus.ConfigAvailable {
		t.Fatalf("rotation status = %+v, want peer %s with config available", newStatus, newPublic)
	}
	stored, err := LoadRetainedClientConfig(controller.ClientConfigPath)
	if err != nil || string(stored) != string(replacement) {
		t.Fatalf("replacement config stored=%q err=%v", stored, err)
	}
	serverData, err := loadRetainedServerConfig(controller.ServerConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	server, err := parseServerConfig(string(serverData))
	if err != nil || server.PeerKey != newPublic {
		t.Fatalf("server peer=%q err=%v", server.PeerKey, err)
	}
	if len(commands.calls) != 2 || strings.Join(commands.calls[0], " ") != "set wg0 peer "+newPublic+" allowed-ips 10.66.66.2/32" || strings.Join(commands.calls[1], " ") != "set wg0 peer "+oldStatus.PeerPublicKey+" remove" {
		t.Fatalf("peer update sequence = %#v", commands.calls)
	}
	if strings.Contains(strings.Join(commands.calls[0], " "), string(oldClient)) || strings.Contains(strings.Join(commands.calls[1], " "), string(replacement)) {
		t.Fatal("WireGuard commands unexpectedly included private configuration data")
	}
	if _, err := os.Stat(controller.ClientConfigPath + ".rotation-pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending private config remained after rotation: %v", err)
	}
}

func TestPeerControllerRollsBackWhenOldPeerCannotBeRevoked(t *testing.T) {
	controller, oldClient, oldStatus, commands := newControllerFixture(t)
	replacement, newPublic := replacementConfig(t, oldStatus)
	commands.fail = func(args []string) bool {
		return len(args) == 5 && args[0] == "set" && args[4] == "remove" && args[3] == oldStatus.PeerPublicKey
	}
	if err := controller.Rotate(context.Background(), replacement); err == nil {
		t.Fatal("rotation succeeded even though old peer revocation failed")
	}
	status, err := controller.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.PeerPublicKey != oldStatus.PeerPublicKey {
		t.Fatalf("failed rotation left peer %s active instead of %s", status.PeerPublicKey, oldStatus.PeerPublicKey)
	}
	stored, err := LoadRetainedClientConfig(controller.ClientConfigPath)
	if err != nil || string(stored) != string(oldClient) {
		t.Fatalf("failed rotation changed previous client config: err=%v", err)
	}
	if _, err := os.Stat(controller.ClientConfigPath + ".rotation-pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed rotation left pending private key file: %v", err)
	}
	last := commands.calls[len(commands.calls)-1]
	if strings.Join(last, " ") != "set wg0 peer "+newPublic+" remove" {
		t.Fatalf("failed rotation did not revoke new peer: %#v", commands.calls)
	}
}

func TestPeerControllerCanRotateAfterOneTimeDownloadDeletedConfig(t *testing.T) {
	controller, _, oldStatus, _ := newControllerFixture(t)
	if err := os.Remove(controller.ClientConfigPath); err != nil {
		t.Fatal(err)
	}
	status, err := controller.Status()
	if err != nil || status.ConfigAvailable {
		t.Fatalf("status after deletion = %+v, err=%v", status, err)
	}
	replacement, newPublic := replacementConfig(t, status)
	if err := controller.Rotate(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	rotated, err := controller.Status()
	if err != nil || rotated.PeerPublicKey != newPublic || !rotated.ConfigAvailable || rotated.PeerPublicKey == oldStatus.PeerPublicKey {
		t.Fatalf("status after regenerating deleted config = %+v, err=%v", rotated, err)
	}
}

func TestPeerControllerRecoversCommittedStagedConfiguration(t *testing.T) {
	controller, _, status, _ := newControllerFixture(t)
	replacement, newPublic := replacementConfig(t, status)
	client, err := parseClientConfig(string(replacement))
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, _ := base64.StdEncoding.DecodeString(client.PrivateKey)
	newPrivate, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	serverData, err := loadRetainedServerConfig(controller.ServerConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	server, err := parseServerConfig(string(serverData))
	if err != nil {
		t.Fatal(err)
	}
	server.PeerKey = encodeKey(newPrivate.PublicKey().Bytes())
	newServer, err := server.Render()
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWritePrivate(controller.ServerConfigPath, []byte(newServer)); err != nil {
		t.Fatal(err)
	}
	pendingPath := controller.ClientConfigPath + ".rotation-pending"
	if err := writePrivateFile(pendingPath, replacement); err != nil {
		t.Fatal(err)
	}
	if err := controller.RecoverPending(); err != nil {
		t.Fatal(err)
	}
	stored, err := LoadRetainedClientConfig(controller.ClientConfigPath)
	if err != nil || string(stored) != string(replacement) {
		t.Fatalf("recovered config key=%s err=%v", newPublic, err)
	}
	if _, err := os.Stat(pendingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending config was not promoted: %v", err)
	}
}

func TestParsePeerDiagnostics(t *testing.T) {
	peer := "GJkxxRq5V0FhO4TqmN5V8FqZpSE8MgzIvT6m+JkqS1M="
	checked := time.Unix(1_800_000_000, 0)
	got, err := parseLatestHandshake([]byte(peer+"\t1800000000\n"), peer)
	if err != nil || !got.Equal(checked) {
		t.Fatalf("latest handshake = %v, %v; want %v", got, err, checked)
	}
	got, err = parseLatestHandshake([]byte(peer+"\t0\n"), peer)
	if err != nil || !got.IsZero() {
		t.Fatalf("zero latest handshake = %v, %v", got, err)
	}
	if _, err := parseLatestHandshake([]byte(peer+"\tbad\n"), peer); err == nil {
		t.Fatal("invalid handshake timestamp was accepted")
	}
	received, sent, found, err := parsePeerTransfer([]byte(peer+"\t4096\t8192\n"), peer)
	if err != nil || !found || received != 4096 || sent != 8192 {
		t.Fatalf("transfer counters = %d/%d found=%t err=%v", received, sent, found, err)
	}
	if _, _, found, err := parsePeerTransfer([]byte("other-key\t1\t2\n"), peer); err != nil || found {
		t.Fatalf("unmatched peer transfer counters found=%t err=%v", found, err)
	}
	if _, _, _, err := parsePeerTransfer([]byte(peer+"\tbad\t2\n"), peer); err == nil {
		t.Fatal("invalid peer transfer counter was accepted")
	}
}
