package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"log"
	"net/netip"
	"os"

	"github.com/Mytob/project_j/internal/wireguard"
)

func main() {
	serverPath := flag.String("server", "", "output path for ephemeral server config")
	peerPath := flag.String("peer", "", "output path for ephemeral peer config")
	endpoint := flag.String("endpoint", "wireguard:51820", "peer endpoint")
	flag.Parse()
	if *serverPath == "" || *peerPath == "" {
		log.Fatal("--server and --peer paths are required")
	}

	serverPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	peerPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	encode := func(value []byte) string { return base64.StdEncoding.EncodeToString(value) }
	serverConfig, err := (wireguard.ServerConfig{PrivateKey: encode(serverPrivate.Bytes()), Address: netip.MustParsePrefix("10.66.66.1/24"), ListenPort: 51820, PeerKey: encode(peerPrivate.PublicKey().Bytes()), PeerRoutes: []netip.Prefix{netip.MustParsePrefix("10.66.66.2/32")}}).Render()
	if err != nil {
		log.Fatal(err)
	}
	peerConfig, err := (wireguard.ClientConfig{PrivateKey: encode(peerPrivate.Bytes()), Address: netip.MustParsePrefix("10.66.66.2/24"), ServerKey: encode(serverPrivate.PublicKey().Bytes()), Endpoint: *endpoint, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.66.66.1/32")}, Keepalive: 25}).Render()
	if err != nil {
		log.Fatal(err)
	}
	for path, content := range map[string]string{*serverPath: serverConfig, *peerPath: peerConfig} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			log.Fatal(err)
		}
	}
}
