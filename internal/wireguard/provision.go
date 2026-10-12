package wireguard

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	serverConfigName = "server.conf"
	clientConfigName = "windows.conf"
	maxConfigBytes   = 16 << 10
)

// ProvisionOptions describe the split-tunnel peer pair retained by the VPS.
type ProvisionOptions struct {
	Endpoint      string
	ListenPort    uint16
	ServerAddress netip.Prefix
	ClientAddress netip.Prefix
	Keepalive     uint16
}

// Provisioned contains paths to the persistent server and Windows peer files.
type Provisioned struct {
	ServerPath string
	ClientPath string
}

// EnsureProvisioned creates one server/client keypair in a private directory.
// An existing pair is validated and preserved so restarts and repeat downloads
// do not silently rotate the Windows peer identity.
func EnsureProvisioned(directory string, options ProvisionOptions) (Provisioned, error) {
	if directory == "" {
		return Provisioned{}, errors.New("WireGuard configuration directory is empty")
	}
	paths := Provisioned{ServerPath: filepath.Join(directory, serverConfigName), ClientPath: filepath.Join(directory, clientConfigName)}
	if _, err := os.Lstat(directory); err == nil {
		if err := validateProvisionDirectory(directory); err != nil {
			return Provisioned{}, err
		}
		serverData, err := loadRetainedServerConfig(paths.ServerPath)
		if err != nil {
			return Provisioned{}, fmt.Errorf("load retained server WireGuard configuration: %w", err)
		}
		clientData, err := LoadRetainedClientConfig(paths.ClientPath)
		if err != nil {
			return Provisioned{}, fmt.Errorf("load retained Windows WireGuard configuration: %w", err)
		}
		if err := validatePairContents(serverData, clientData); err != nil {
			return Provisioned{}, fmt.Errorf("validate retained WireGuard peer pair: %w", err)
		}
		return paths, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Provisioned{}, fmt.Errorf("inspect WireGuard configuration directory: %w", err)
	}

	serverPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Provisioned{}, fmt.Errorf("generate server WireGuard key: %w", err)
	}
	clientPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Provisioned{}, fmt.Errorf("generate Windows WireGuard key: %w", err)
	}
	encode := func(value []byte) string { return base64.StdEncoding.EncodeToString(value) }
	serverConfig, err := (ServerConfig{
		PrivateKey: encode(serverPrivate.Bytes()), Address: options.ServerAddress,
		ListenPort: options.ListenPort, PeerKey: encode(clientPrivate.PublicKey().Bytes()),
		PeerRoutes: []netip.Prefix{hostRoute(options.ClientAddress)},
	}).Render()
	if err != nil {
		return Provisioned{}, fmt.Errorf("render server WireGuard configuration: %w", err)
	}
	clientConfig, err := (ClientConfig{
		PrivateKey: encode(clientPrivate.Bytes()), Address: options.ClientAddress,
		ServerKey: encode(serverPrivate.PublicKey().Bytes()), Endpoint: options.Endpoint,
		AllowedIPs: []netip.Prefix{hostRoute(options.ServerAddress)}, Keepalive: options.Keepalive,
	}).Render()
	if err != nil {
		return Provisioned{}, fmt.Errorf("render Windows WireGuard configuration: %w", err)
	}
	if err := validatePairContents([]byte(serverConfig), []byte(clientConfig)); err != nil {
		return Provisioned{}, fmt.Errorf("validate generated WireGuard peer pair: %w", err)
	}

	parent := filepath.Dir(directory)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return Provisioned{}, fmt.Errorf("create WireGuard configuration parent: %w", err)
	}
	temporary, err := os.MkdirTemp(parent, ".wireguard-setup-*")
	if err != nil {
		return Provisioned{}, fmt.Errorf("create temporary WireGuard configuration directory: %w", err)
	}
	defer os.RemoveAll(temporary)
	if err := os.Chmod(temporary, 0o700); err != nil {
		return Provisioned{}, fmt.Errorf("restrict temporary WireGuard directory: %w", err)
	}
	if err := writePrivateFile(filepath.Join(temporary, serverConfigName), []byte(serverConfig)); err != nil {
		return Provisioned{}, fmt.Errorf("write WireGuard server configuration: %w", err)
	}
	if err := writePrivateFile(filepath.Join(temporary, clientConfigName), []byte(clientConfig)); err != nil {
		return Provisioned{}, fmt.Errorf("write Windows WireGuard configuration: %w", err)
	}
	if err := os.Rename(temporary, directory); err != nil {
		// Another process may have provisioned the pair first. Accept that
		// winner only when both protected files validate successfully.
		if _, statErr := os.Lstat(directory); statErr == nil {
			if validateErr := validateProvisionDirectory(directory); validateErr == nil {
				clientData, clientErr := LoadRetainedClientConfig(paths.ClientPath)
				serverData, serverErr := loadRetainedServerConfig(paths.ServerPath)
				if clientErr == nil && serverErr == nil && validatePairContents(serverData, clientData) == nil {
					return paths, nil
				}
			}
		}
		return Provisioned{}, fmt.Errorf("retain WireGuard configuration pair: %w", err)
	}
	return paths, nil
}

func hostRoute(address netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(address.Addr(), address.Addr().BitLen())
}

// LoadRetainedClientConfig reads a small, regular, owner-only Windows config.
func LoadRetainedClientConfig(path string) ([]byte, error) {
	data, err := loadPrivateFile(path, true)
	if err != nil {
		return nil, err
	}
	if _, err := parseClientConfig(string(data)); err != nil {
		return nil, fmt.Errorf("validate Windows WireGuard configuration: %w", err)
	}
	return data, nil
}

func loadRetainedServerConfig(path string) ([]byte, error) {
	data, err := loadPrivateFile(path, false)
	if err != nil {
		return nil, err
	}
	if _, err := parseServerConfig(string(data)); err != nil {
		return nil, fmt.Errorf("validate server WireGuard configuration: %w", err)
	}
	return data, nil
}

func validatePairContents(serverData, clientData []byte) error {
	server, err := parseServerConfig(string(serverData))
	if err != nil {
		return fmt.Errorf("server config: %w", err)
	}
	client, err := parseClientConfig(string(clientData))
	if err != nil {
		return fmt.Errorf("Windows client config: %w", err)
	}
	serverPrivateBytes, _ := base64.StdEncoding.DecodeString(server.PrivateKey)
	clientPrivateBytes, _ := base64.StdEncoding.DecodeString(client.PrivateKey)
	serverPrivate, err := ecdh.X25519().NewPrivateKey(serverPrivateBytes)
	if err != nil {
		return errors.New("invalid server private key")
	}
	clientPrivate, err := ecdh.X25519().NewPrivateKey(clientPrivateBytes)
	if err != nil {
		return errors.New("invalid Windows peer private key")
	}
	if encodeKey(serverPrivate.PublicKey().Bytes()) != client.ServerKey {
		return errors.New("Windows client references a different server key")
	}
	if encodeKey(clientPrivate.PublicKey().Bytes()) != server.PeerKey {
		return errors.New("server references a different Windows peer key")
	}
	if server.Address.Addr().Is4() != client.Address.Addr().Is4() {
		return errors.New("server and Windows peer tunnel addresses use different IP families")
	}
	if !containsPrefix(server.PeerRoutes, hostRoute(client.Address)) {
		return errors.New("server peer routes do not include the Windows tunnel address")
	}
	if !containsPrefix(client.AllowedIPs, hostRoute(server.Address)) {
		return errors.New("Windows peer routes do not include the VPS tunnel address")
	}
	return nil
}

func encodeKey(value []byte) string { return base64.StdEncoding.EncodeToString(value) }

func containsPrefix(prefixes []netip.Prefix, expected netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix == expected {
			return true
		}
	}
	return false
}

func loadPrivateFile(path string, allowGroupRead bool) ([]byte, error) {
	if path == "" {
		return nil, errors.New("WireGuard configuration path is empty")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("WireGuard configuration must be a regular file")
	}
	unsafe := os.FileMode(0o077)
	if allowGroupRead {
		unsafe = 0o037
	}
	if info.Mode().Perm()&unsafe != 0 {
		return nil, errors.New("WireGuard configuration permissions are too broad")
	}
	if info.Size() <= 0 || info.Size() > maxConfigBytes {
		return nil, errors.New("WireGuard configuration size is invalid")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func validateProvisionDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("WireGuard configuration path must be a real directory")
	}
	if info.Mode().Perm()&0o027 != 0 {
		return errors.New("WireGuard configuration directory permissions are too broad")
	}
	return nil
}

func writePrivateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func parseClientConfig(value string) (ClientConfig, error) {
	sections := parseSections(value)
	if len(sections) != 2 || sections[0]["section"] != "Interface" || sections[1]["section"] != "Peer" {
		return ClientConfig{}, errors.New("expected one Interface section followed by one Peer section")
	}
	iface, peer := sections[0], sections[1]
	address, err := netip.ParsePrefix(iface["Address"])
	if err != nil {
		return ClientConfig{}, errors.New("invalid interface address")
	}
	allowed, err := parsePrefixList(peer["AllowedIPs"])
	if err != nil {
		return ClientConfig{}, err
	}
	keepalive, err := strconv.ParseUint(peer["PersistentKeepalive"], 10, 16)
	if err != nil {
		return ClientConfig{}, errors.New("invalid persistent keepalive")
	}
	config := ClientConfig{PrivateKey: iface["PrivateKey"], Address: address, ServerKey: peer["PublicKey"], Endpoint: peer["Endpoint"], AllowedIPs: allowed, Keepalive: uint16(keepalive)}
	rendered, err := config.Render()
	if err != nil {
		return ClientConfig{}, err
	}
	if strings.TrimSpace(value) != strings.TrimSpace(rendered) {
		return ClientConfig{}, errors.New("configuration is not in the supported canonical format")
	}
	return config, nil
}

func parseServerConfig(value string) (ServerConfig, error) {
	sections := parseSections(value)
	if len(sections) != 2 || sections[0]["section"] != "Interface" || sections[1]["section"] != "Peer" {
		return ServerConfig{}, errors.New("expected one Interface section followed by one Peer section")
	}
	iface, peer := sections[0], sections[1]
	address, err := netip.ParsePrefix(iface["Address"])
	if err != nil {
		return ServerConfig{}, errors.New("invalid interface address")
	}
	listenPort, err := strconv.ParseUint(iface["ListenPort"], 10, 16)
	if err != nil {
		return ServerConfig{}, errors.New("invalid listen port")
	}
	routes, err := parsePrefixList(peer["AllowedIPs"])
	if err != nil {
		return ServerConfig{}, err
	}
	config := ServerConfig{PrivateKey: iface["PrivateKey"], Address: address, ListenPort: uint16(listenPort), PeerKey: peer["PublicKey"], PeerRoutes: routes}
	rendered, err := config.Render()
	if err != nil {
		return ServerConfig{}, err
	}
	if strings.TrimSpace(value) != strings.TrimSpace(rendered) {
		return ServerConfig{}, errors.New("configuration is not in the supported canonical format")
	}
	return config, nil
}

func parsePrefixList(value string) ([]netip.Prefix, error) {
	parts := strings.Split(value, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil {
			return nil, errors.New("invalid AllowedIPs prefix")
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func parseSections(value string) []map[string]string {
	sections := []map[string]string{}
	for _, rawLine := range strings.Split(value, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sections = append(sections, map[string]string{"section": strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")})
			continue
		}
		if len(sections) == 0 {
			return nil
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			return nil
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if key == "" || value == "" || sections[len(sections)-1][key] != "" {
			return nil
		}
		sections[len(sections)-1][key] = value
	}
	return sections
}
