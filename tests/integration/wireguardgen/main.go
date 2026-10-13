package main

import (
	"flag"
	"log"
	"net/netip"

	"github.com/Mytob/project_j/internal/wireguard"
)

func main() {
	directory := flag.String("directory", "", "private output directory for the ephemeral peer pair")
	endpoint := flag.String("endpoint", "wireguard:51820", "peer endpoint")
	flag.Parse()
	if *directory == "" {
		log.Fatal("--directory is required")
	}
	_, err := wireguard.EnsureProvisioned(*directory, wireguard.ProvisionOptions{
		Endpoint: *endpoint, ListenPort: 51820,
		ServerAddress: netip.MustParsePrefix("10.66.66.1/24"),
		ClientAddress: netip.MustParsePrefix("10.66.66.2/32"), Keepalive: 25,
	})
	if err != nil {
		log.Fatal(err)
	}
}
