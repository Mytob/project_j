package wireguard

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	controlMaxBody = 16 << 10
	controlTimeout = 10 * time.Second
)

// PeerStatus is safe to return to the administrator process: it contains only
// public addresses and keys, never the server private key.
type PeerStatus struct {
	ServerPublicKey   string       `json:"server_public_key"`
	PeerPublicKey     string       `json:"peer_public_key"`
	ServerAddress     netip.Prefix `json:"server_address"`
	ClientAddress     netip.Prefix `json:"client_address"`
	ListenPort        uint16       `json:"listen_port"`
	ConfigAvailable   bool         `json:"config_available"`
	PeerState         string       `json:"peer_state"`
	PeerDetail        string       `json:"peer_detail"`
	PeerLastHandshake *time.Time   `json:"peer_last_handshake,omitempty"`
	PeerRXBytes       uint64       `json:"peer_rx_bytes"`
	PeerTXBytes       uint64       `json:"peer_tx_bytes"`
	JellyfinState     string       `json:"jellyfin_state"`
	JellyfinDetail    string       `json:"jellyfin_detail"`
	JellyfinLatencyMS *uint64      `json:"jellyfin_latency_ms,omitempty"`
}

// ClientConfiguration creates fresh client key material from public tunnel
// metadata. The returned private configuration must be delivered only to the
// privileged WireGuard control service and removed after its one-time download.
func ClientConfiguration(endpoint string, status PeerStatus, keepalive uint16) ([]byte, string, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate Windows peer key: %w", err)
	}
	client := ClientConfig{
		PrivateKey: base64.StdEncoding.EncodeToString(private.Bytes()),
		Address:    status.ClientAddress,
		ServerKey:  status.ServerPublicKey,
		Endpoint:   endpoint,
		AllowedIPs: []netip.Prefix{hostRoute(status.ServerAddress)},
		Keepalive:  keepalive,
	}
	text, err := client.Render()
	if err != nil {
		return nil, "", fmt.Errorf("render Windows peer configuration: %w", err)
	}
	return []byte(text), base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()), nil
}

// WGCommand executes a narrowly-scoped wg command for peer rotation.
type WGCommand interface {
	Run(context.Context, ...string) error
}

type execWGCommand struct{ binary string }

func (w execWGCommand) Run(ctx context.Context, args ...string) error {
	command := exec.CommandContext(ctx, w.binary, args...)
	if _, err := command.CombinedOutput(); err != nil {
		// wg output can include configuration details. Do not return it to callers.
		return fmt.Errorf("WireGuard peer command failed: %w", err)
	}
	return nil
}

// PeerController atomically coordinates the active peer, persistent server
// configuration and one-time client configuration. It never saves a copy of
// the old client private key while rotating.
type PeerController struct {
	ServerConfigPath string
	ClientConfigPath string
	Interface        string
	WGPath           string
	command          WGCommand
	mu               chan struct{}
}

func NewPeerController(serverConfigPath, clientConfigPath, iface, wgPath string) (*PeerController, error) {
	if serverConfigPath == "" || clientConfigPath == "" {
		return nil, errors.New("WireGuard server and client configuration paths are required")
	}
	if iface == "" {
		iface = "wg0"
	}
	if wgPath == "" {
		wgPath = "wg"
	}
	controller := &PeerController{ServerConfigPath: serverConfigPath, ClientConfigPath: clientConfigPath, Interface: iface, WGPath: wgPath, command: execWGCommand{binary: wgPath}, mu: make(chan struct{}, 1)}
	controller.mu <- struct{}{}
	return controller, nil
}

func (p *PeerController) withLock(fn func() error) error {
	<-p.mu
	defer func() { p.mu <- struct{}{} }()
	return fn()
}

func (p *PeerController) Status() (PeerStatus, error) {
	var status PeerStatus
	err := p.withLock(func() error {
		serverData, err := loadRetainedServerConfig(p.ServerConfigPath)
		if err != nil {
			return fmt.Errorf("load active WireGuard server configuration: %w", err)
		}
		server, err := parseServerConfig(string(serverData))
		if err != nil {
			return err
		}
		privateBytes, _ := base64.StdEncoding.DecodeString(server.PrivateKey)
		private, err := ecdh.X25519().NewPrivateKey(privateBytes)
		if err != nil {
			return errors.New("invalid active WireGuard server key")
		}
		if len(server.PeerRoutes) != 1 || server.PeerRoutes[0].Bits() != server.PeerRoutes[0].Addr().BitLen() {
			return errors.New("active WireGuard configuration must contain one Windows peer host route")
		}
		clientAddress := server.PeerRoutes[0].Addr()
		clientBits := clientAddress.BitLen()
		status = PeerStatus{
			ServerPublicKey: encodeKey(private.PublicKey().Bytes()),
			PeerPublicKey:   server.PeerKey,
			ServerAddress:   server.Address,
			ClientAddress:   netip.PrefixFrom(clientAddress, clientBits),
			ListenPort:      server.ListenPort,
			PeerState:       "Unknown",
			PeerDetail:      "WireGuard handshake could not be inspected.",
			JellyfinState:   "Unknown",
			JellyfinDetail:  "Jellyfin reachability could not be inspected from the WireGuard network namespace.",
		}
		lastHandshake, handshakeErr := latestHandshake(p.WGPath, p.Interface, server.PeerKey)
		if handshakeErr == nil && !lastHandshake.IsZero() {
			status.PeerLastHandshake = &lastHandshake
		}
		if received, sent, found, transferErr := peerTransfer(p.WGPath, p.Interface, server.PeerKey); transferErr == nil && found {
			status.PeerRXBytes, status.PeerTXBytes = received, sent
		}
		jellyfinOK, latencyMS, httpStatus := jellyfinReachable(server.PeerRoutes[0].Addr())
		if latencyMS != nil {
			status.JellyfinLatencyMS = latencyMS
		}
		if jellyfinOK {
			status.JellyfinState = "Healthy"
			status.JellyfinDetail = fmt.Sprintf("The Jellyfin endpoint returned HTTP %d in %d ms from the WireGuard network namespace.", httpStatus, *latencyMS)
		} else {
			status.JellyfinState = "Down"
			status.JellyfinDetail = "The Jellyfin HTTP health request failed at the configured Windows peer address on TCP 8096."
		}
		if handshakeErr == nil {
			switch {
			case !lastHandshake.IsZero() && time.Since(lastHandshake) <= 3*time.Minute:
				status.PeerState = "Healthy"
				status.PeerDetail = fmt.Sprintf("Recent WireGuard handshake; received %s and sent %s.", formatBytes(status.PeerRXBytes), formatBytes(status.PeerTXBytes))
			case jellyfinOK:
				status.PeerState = "Degraded"
				status.PeerDetail = fmt.Sprintf("Handshake is older than 3 minutes, but Jellyfin still responds; received %s and sent %s.", formatBytes(status.PeerRXBytes), formatBytes(status.PeerTXBytes))
			default:
				status.PeerState = "Down"
				status.PeerDetail = "No recent WireGuard handshake was recorded and Jellyfin is not reachable."
			}
		}
		if _, err := LoadRetainedClientConfig(p.ClientConfigPath); err == nil {
			status.ConfigAvailable = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("validate pending Windows configuration: %w", err)
		}
		return nil
	})
	return status, err
}

func latestHandshake(wgPath, iface, peerKey string) (time.Time, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, wgPath, "show", iface, "latest-handshakes").Output()
	if err != nil {
		return time.Time{}, err
	}
	return parseLatestHandshake(output, peerKey)
}

func parseLatestHandshake(output []byte, peerKey string) (time.Time, error) {
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != peerKey {
			continue
		}
		seconds, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return time.Time{}, errors.New("invalid WireGuard handshake timestamp")
		}
		if seconds <= 0 {
			return time.Time{}, nil
		}
		return time.Unix(seconds, 0), nil
	}
	return time.Time{}, nil
}

func peerTransfer(wgPath, iface, peerKey string) (uint64, uint64, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, wgPath, "show", iface, "transfer").Output()
	if err != nil {
		return 0, 0, false, err
	}
	return parsePeerTransfer(output, peerKey)
}

func parsePeerTransfer(output []byte, peerKey string) (uint64, uint64, bool, error) {
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != peerKey {
			continue
		}
		received, receiveErr := strconv.ParseUint(fields[1], 10, 64)
		sent, sendErr := strconv.ParseUint(fields[2], 10, 64)
		if receiveErr != nil || sendErr != nil {
			return 0, 0, false, errors.New("invalid WireGuard transfer counters")
		}
		return received, sent, true, nil
	}
	return 0, 0, false, nil
}

func jellyfinReachable(address netip.Addr) (bool, *uint64, int) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(address.String(), "8096"))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://jellyfin/health", nil)
	if err != nil {
		return false, nil, 0
	}
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return false, nil, 0
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	latency := uint64(time.Since(started).Milliseconds())
	return response.StatusCode >= 200 && response.StatusCode < 300, &latency, response.StatusCode
}

func formatBytes(value uint64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	div, exp := uint64(unit), 0
	for n := value / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(value)/float64(div), "KMGTPE"[exp])
}

// RecoverPending resolves a crash during rotation. A staged client config is
// promoted only when its public key is the peer in the active server config.
func (p *PeerController) RecoverPending() error {
	return p.withLock(func() error {
		pendingPath := p.ClientConfigPath + ".rotation-pending"
		clientData, err := LoadRetainedClientConfig(pendingPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect staged WireGuard configuration: %w", err)
		}
		serverData, err := loadRetainedServerConfig(p.ServerConfigPath)
		if err != nil {
			return err
		}
		server, err := parseServerConfig(string(serverData))
		if err != nil {
			return err
		}
		client, err := parseClientConfig(string(clientData))
		if err != nil {
			return err
		}
		privateBytes, _ := base64.StdEncoding.DecodeString(client.PrivateKey)
		private, err := ecdh.X25519().NewPrivateKey(privateBytes)
		if err != nil {
			return errors.New("invalid staged Windows peer key")
		}
		if encodeKey(private.PublicKey().Bytes()) == server.PeerKey && validatePairContents(serverData, clientData) == nil {
			return replaceFile(pendingPath, p.ClientConfigPath)
		}
		if err := os.Remove(pendingPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove abandoned staged Windows configuration: %w", err)
		}
		return nil
	})
}

// Rotate installs the new public peer, persists it, revokes the old peer, and
// publishes the new client config. Any failure rolls live and persistent peer
// state back to the previous key.
func (p *PeerController) Rotate(ctx context.Context, clientData []byte) error {
	if len(clientData) == 0 || len(clientData) > maxConfigBytes {
		return errors.New("Windows peer configuration size is invalid")
	}
	client, err := parseClientConfig(string(clientData))
	if err != nil {
		return fmt.Errorf("validate replacement Windows configuration: %w", err)
	}
	privateBytes, _ := base64.StdEncoding.DecodeString(client.PrivateKey)
	clientPrivate, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return errors.New("invalid replacement Windows key")
	}
	newPeerKey := encodeKey(clientPrivate.PublicKey().Bytes())

	return p.withLock(func() error {
		oldServerData, err := loadRetainedServerConfig(p.ServerConfigPath)
		if err != nil {
			return fmt.Errorf("load active WireGuard server configuration: %w", err)
		}
		oldServer, err := parseServerConfig(string(oldServerData))
		if err != nil {
			return err
		}
		serverPrivateBytes, _ := base64.StdEncoding.DecodeString(oldServer.PrivateKey)
		serverPrivate, err := ecdh.X25519().NewPrivateKey(serverPrivateBytes)
		if err != nil || encodeKey(serverPrivate.PublicKey().Bytes()) != client.ServerKey {
			return errors.New("replacement configuration does not match the active server key")
		}
		if len(oldServer.PeerRoutes) != 1 || oldServer.PeerRoutes[0] != hostRoute(client.Address) || !containsPrefix(client.AllowedIPs, hostRoute(oldServer.Address)) {
			return errors.New("replacement configuration does not match the active single-client tunnel routes")
		}
		if oldServer.PeerKey == newPeerKey {
			return errors.New("replacement Windows peer key must be new")
		}
		newServer := oldServer
		newServer.PeerKey = newPeerKey
		newServerData, err := newServer.Render()
		if err != nil {
			return fmt.Errorf("render replacement server configuration: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(p.ClientConfigPath), 0o750); err != nil {
			return fmt.Errorf("prepare Windows configuration directory: %w", err)
		}
		pendingPath := p.ClientConfigPath + ".rotation-pending"
		_ = os.Remove(pendingPath)
		if err := writePrivateFile(pendingPath, clientData); err != nil {
			return fmt.Errorf("stage replacement Windows configuration: %w", err)
		}
		if err := os.Chown(pendingPath, 0, 65532); err != nil {
			_ = os.Remove(pendingPath)
			return fmt.Errorf("set replacement configuration ownership: %w", err)
		}
		if err := os.Chmod(pendingPath, 0o640); err != nil {
			_ = os.Remove(pendingPath)
			return fmt.Errorf("set replacement configuration permissions: %w", err)
		}
		cleanupPending := func() { _ = os.Remove(pendingPath) }
		clientAddress := oldServer.PeerRoutes[0].String()
		if err := p.command.Run(ctx, "set", p.Interface, "peer", newPeerKey, "allowed-ips", clientAddress); err != nil {
			cleanupPending()
			return err
		}
		rollbackNewPeer := func(cause error) error {
			_ = p.command.Run(context.Background(), "set", p.Interface, "peer", newPeerKey, "remove")
			cleanupPending()
			return cause
		}
		if err := atomicWritePrivate(p.ServerConfigPath, []byte(newServerData)); err != nil {
			return rollbackNewPeer(fmt.Errorf("persist replacement WireGuard peer: %w", err))
		}
		if err := p.command.Run(ctx, "set", p.Interface, "peer", oldServer.PeerKey, "remove"); err != nil {
			rollbackErr := atomicWritePrivate(p.ServerConfigPath, oldServerData)
			_ = p.command.Run(context.Background(), "set", p.Interface, "peer", oldServer.PeerKey, "allowed-ips", clientAddress)
			_ = p.command.Run(context.Background(), "set", p.Interface, "peer", newPeerKey, "remove")
			cleanupPending()
			if rollbackErr != nil {
				return fmt.Errorf("revoke old WireGuard peer failed and server config rollback failed: %w", rollbackErr)
			}
			return fmt.Errorf("revoke old WireGuard peer: %w", err)
		}
		if err := replaceFile(pendingPath, p.ClientConfigPath); err != nil {
			rollbackErr := atomicWritePrivate(p.ServerConfigPath, oldServerData)
			_ = p.command.Run(context.Background(), "set", p.Interface, "peer", oldServer.PeerKey, "allowed-ips", clientAddress)
			_ = p.command.Run(context.Background(), "set", p.Interface, "peer", newPeerKey, "remove")
			cleanupPending()
			if rollbackErr != nil {
				return fmt.Errorf("publish replacement config failed and server config rollback failed: %w", rollbackErr)
			}
			return fmt.Errorf("publish replacement Windows configuration: %w", err)
		}
		return nil
	})
}

func atomicWritePrivate(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".wireguard-server-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return nil
}

func replaceFile(source, destination string) error {
	// Deployment runs on Linux, where rename replaces atomically. Keeping the
	// old file visible until this point prevents a crash from losing the current
	// downloadable configuration during peer rotation.
	return os.Rename(source, destination)
}

// ControlHTTPHandler exposes only peer status and rotation on a private Unix
// socket. The production deployment does not publish this endpoint to TCP.
func ControlHTTPHandler(controller *PeerController) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		status, err := controller.Status()
		if err != nil {
			http.Error(w, "WireGuard status is unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	})
	mux.HandleFunc("POST /rotate", func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, controlMaxBody))
		if err != nil {
			http.Error(w, "Invalid replacement configuration", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), controlTimeout)
		defer cancel()
		if err := controller.Rotate(ctx, data); err != nil {
			http.Error(w, "WireGuard peer rotation failed", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// ListenControl serves the private WireGuard control API on a Unix socket.
func ListenControl(ctx context.Context, socketPath string, controller *PeerController, groupID int) error {
	if socketPath == "" || controller == nil {
		return errors.New("WireGuard control socket and peer controller are required")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o750); err != nil {
		return err
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("WireGuard control path exists and is not a socket")
		}
		if err := os.Remove(socketPath); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen for private WireGuard control requests: %w", err)
	}
	defer func() { listener.Close(); _ = os.Remove(socketPath) }()
	if err := os.Chmod(socketPath, 0o660); err != nil {
		return err
	}
	if groupID >= 0 {
		if err := os.Chown(socketPath, 0, groupID); err != nil {
			return err
		}
	}
	if err := controller.RecoverPending(); err != nil {
		return fmt.Errorf("recover pending WireGuard rotation: %w", err)
	}
	server := &http.Server{Handler: ControlHTTPHandler(controller), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	go func() { <-ctx.Done(); _ = server.Close() }()
	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ControlClient sends administrator actions over the private Unix socket.
type ControlClient struct{ SocketPath string }

func (c ControlClient) request(ctx context.Context, method, path string, body io.Reader, target any) error {
	if c.SocketPath == "" {
		return errors.New("WireGuard control socket is unavailable")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", c.SocketPath)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	request, err := http.NewRequestWithContext(ctx, method, "http://wireguard-control"+path, body)
	if err != nil {
		return err
	}
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/octet-stream")
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("contact private WireGuard control service: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("private WireGuard control service rejected the request")
	}
	if target != nil {
		if err := json.NewDecoder(io.LimitReader(response.Body, controlMaxBody)).Decode(target); err != nil {
			return fmt.Errorf("read WireGuard status: %w", err)
		}
	}
	return nil
}

func (c ControlClient) Status(ctx context.Context) (PeerStatus, error) {
	var status PeerStatus
	err := c.request(ctx, http.MethodGet, "/status", nil, &status)
	return status, err
}

func (c ControlClient) Rotate(ctx context.Context, clientConfig []byte) error {
	return c.request(ctx, http.MethodPost, "/rotate", strings.NewReader(string(clientConfig)), nil)
}

// Endpoint formats the configured public DNS name and WireGuard UDP port.
func Endpoint(domain string, port uint16) string {
	return net.JoinHostPort(strings.TrimSpace(domain), strconv.Itoa(int(port)))
}
