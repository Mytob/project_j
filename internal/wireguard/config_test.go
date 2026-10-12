package wireguard

import (
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
)

func keyFill(b byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = b
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestRenderServerAndClientConfigs(t *testing.T) {
	serverKey, peerKey := keyFill(1), keyFill(2)
	server, err := (ServerConfig{PrivateKey: serverKey, Address: netip.MustParsePrefix("10.66.66.1/24"), ListenPort: 51820, PeerKey: peerKey, PeerRoutes: []netip.Prefix{netip.MustParsePrefix("10.66.66.2/32")}}).Render()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(server, "Address = 10.66.66.1/24") || !strings.Contains(server, "AllowedIPs = 10.66.66.2/32") {
		t.Fatalf("unexpected server config: %s", server)
	}
	client, err := (ClientConfig{PrivateKey: peerKey, Address: netip.MustParsePrefix("10.66.66.2/24"), ServerKey: serverKey, Endpoint: "wireguard:51820", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.66.66.1/32")}, Keepalive: 25}).Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Address = 10.66.66.2/24", "Endpoint = wireguard:51820", "AllowedIPs = 10.66.66.1/32", "PersistentKeepalive = 25"} {
		if !strings.Contains(client, expected) {
			t.Errorf("client config missing %q: %s", expected, client)
		}
	}
}

func TestConfigRenderRejectsInvalidKeysAddressesAndEndpoints(t *testing.T) {
	baseServer := ServerConfig{PrivateKey: keyFill(1), Address: netip.MustParsePrefix("10.66.66.1/24"), ListenPort: 51820, PeerKey: keyFill(2), PeerRoutes: []netip.Prefix{netip.MustParsePrefix("10.66.66.2/32")}}
	badServer := baseServer
	badServer.PrivateKey = "short"
	if _, err := badServer.Render(); err == nil {
		t.Fatal("invalid key accepted")
	}
	badServer = baseServer
	badServer.PeerRoutes = []netip.Prefix{netip.MustParsePrefix("10.66.66.2/24")}
	if _, err := badServer.Render(); err == nil {
		t.Fatal("non-canonical peer route accepted")
	}
	baseClient := ClientConfig{PrivateKey: keyFill(2), Address: netip.MustParsePrefix("10.66.66.2/24"), ServerKey: keyFill(1), Endpoint: "wireguard:51820", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.66.66.1/32")}, Keepalive: 25}
	baseClient.Endpoint = "wireguard:99999"
	if _, err := baseClient.Render(); err == nil {
		t.Fatal("invalid endpoint port accepted")
	}
	baseClient.Endpoint = "wireguard:51820"
	baseClient.AllowedIPs = nil
	if _, err := baseClient.Render(); err == nil {
		t.Fatal("empty AllowedIPs accepted")
	}
}
