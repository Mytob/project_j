// Package wireguard validates and renders small WireGuard peer configurations.
package wireguard

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type ServerConfig struct {
	PrivateKey string
	Address    netip.Prefix
	ListenPort uint16
	PeerKey    string
	PeerRoutes []netip.Prefix
}

type ClientConfig struct {
	PrivateKey string
	Address    netip.Prefix
	ServerKey  string
	Endpoint   string
	AllowedIPs []netip.Prefix
	Keepalive  uint16
}

func (c ServerConfig) Render() (string, error) {
	if err := ValidateKey(c.PrivateKey); err != nil {
		return "", fmt.Errorf("server private key: %w", err)
	}
	if err := validateAddress(c.Address); err != nil {
		return "", fmt.Errorf("server address: %w", err)
	}
	if c.ListenPort == 0 {
		return "", errors.New("WireGuard listen port must be between 1 and 65535")
	}
	if err := ValidateKey(c.PeerKey); err != nil {
		return "", fmt.Errorf("peer public key: %w", err)
	}
	routes, err := renderPrefixes(c.PeerRoutes)
	if err != nil {
		return "", fmt.Errorf("peer routes: %w", err)
	}
	return fmt.Sprintf("[Interface]\nAddress = %s\nListenPort = %d\nPrivateKey = %s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", c.Address, c.ListenPort, c.PrivateKey, c.PeerKey, routes), nil
}

func (c ClientConfig) Render() (string, error) {
	if err := ValidateKey(c.PrivateKey); err != nil {
		return "", fmt.Errorf("client private key: %w", err)
	}
	if err := validateAddress(c.Address); err != nil {
		return "", fmt.Errorf("client address: %w", err)
	}
	if err := ValidateKey(c.ServerKey); err != nil {
		return "", fmt.Errorf("server public key: %w", err)
	}
	host, port, err := net.SplitHostPort(c.Endpoint)
	if err != nil || strings.TrimSpace(host) == "" {
		return "", errors.New("WireGuard endpoint must be a host and port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("WireGuard endpoint port is invalid")
	}
	routes, err := renderPrefixes(c.AllowedIPs)
	if err != nil {
		return "", fmt.Errorf("allowed routes: %w", err)
	}
	if c.Keepalive == 0 {
		return "", errors.New("persistent keepalive must be between 1 and 65535 seconds")
	}
	return fmt.Sprintf("[Interface]\nAddress = %s\nPrivateKey = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = %d\n", c.Address, c.PrivateKey, c.ServerKey, c.Endpoint, routes, c.Keepalive), nil
}

func ValidateKey(value string) error {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return errors.New("must be a base64-encoded 32-byte WireGuard key")
	}
	return nil
}

func validateAddress(prefix netip.Prefix) error {
	if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" || prefix.Addr().IsUnspecified() {
		return errors.New("must be a valid, non-unspecified IPv4 or IPv6 address prefix")
	}
	return nil
}

func validatePrefix(prefix netip.Prefix) error {
	if err := validateAddress(prefix); err != nil || prefix != prefix.Masked() {
		return errors.New("must be a canonical, non-unspecified IPv4 or IPv6 route prefix")
	}
	return nil
}

func renderPrefixes(prefixes []netip.Prefix) (string, error) {
	if len(prefixes) == 0 {
		return "", errors.New("at least one route is required")
	}
	values := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		if err := validatePrefix(prefix); err != nil {
			return "", err
		}
		values[i] = prefix.String()
	}
	return strings.Join(values, ", "), nil
}
