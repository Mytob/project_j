package caddytelemetry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const defaultSecuritySocket = "/run/caddy-security/control.sock"

type SecurityBan struct {
	IP        string    `json:"ip"`
	ExpiresAt time.Time `json:"expires_at"`
}

type SecurityBanSnapshot struct {
	Bans []SecurityBan `json:"bans"`
}

type SecurityControlStatus struct {
	Synced        bool      `json:"synced"`
	LastSync      time.Time `json:"last_sync,omitempty"`
	ActiveBans    int       `json:"active_bans"`
	SocketHealthy bool      `json:"socket_healthy"`
}

type SecurityBlocker struct {
	SocketPath string `json:"socket_path,omitempty"`
	state      *securityBlockState
}

type securityBlockState struct {
	mu              sync.RWMutex
	bans            map[string]time.Time
	blockedRequests map[string]uint64
	listener        net.Listener
	server          *http.Server
	path            string
	refs            int
	lastSync        time.Time
}

var securityStates = struct {
	sync.Mutex
	items map[string]*securityBlockState
}{items: map[string]*securityBlockState{}}

func (SecurityBlocker) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.jp_admin_bans", New: func() caddy.Module { return new(SecurityBlocker) }}
}

func (m *SecurityBlocker) Provision(_ caddy.Context) error {
	path := m.SocketPath
	if path == "" {
		path = defaultSecuritySocket
	}
	state, err := acquireSecurityBlockState(path)
	if err != nil {
		return err
	}
	m.SocketPath = path
	m.state = state
	return nil
}

func (m *SecurityBlocker) Cleanup() error {
	if m.state == nil {
		return nil
	}
	releaseSecurityBlockState(m.state)
	m.state = nil
	return nil
}

func (m *SecurityBlocker) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if m.state == nil {
		return errors.New("administrator ban handler was not provisioned")
	}
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(peer))
	if err == nil && ip.Zone() == "" {
		ip = ip.Unmap()
		if expiresAt, banned := m.state.banned(ip.String(), time.Now()); banned {
			m.state.countBlocked(ip.String())
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, writeErr := io.WriteString(w, "Access Denied\n")
			_ = expiresAt
			return writeErr
		}
	}
	return next.ServeHTTP(w, r)
}

func (m *SecurityBlocker) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	for d.NextBlock(0) {
		switch d.Val() {
		case "socket":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.SocketPath = d.Val()
			if d.NextArg() {
				return d.ArgErr()
			}
		default:
			return d.Errf("unrecognized jp_admin_bans option %q", d.Val())
		}
	}
	return nil
}

func parseSecurityBlocker(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var module SecurityBlocker
	if err := module.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &module, nil
}

func acquireSecurityBlockState(path string) (*securityBlockState, error) {
	securityStates.Lock()
	defer securityStates.Unlock()
	if existing := securityStates.items[path]; existing != nil {
		existing.refs++
		return existing, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create Caddy security control directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("refusing to replace a non-socket Caddy security control path")
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale Caddy security socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect Caddy security socket: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on private Caddy security socket: %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		listener.Close()
		os.Remove(path)
		return nil, fmt.Errorf("protect Caddy security socket: %w", err)
	}
	state := &securityBlockState{bans: map[string]time.Time{}, blockedRequests: map[string]uint64{}, listener: listener, path: path, refs: 1}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/snapshot", state.receiveSnapshot)
	mux.HandleFunc("GET /v1/status", state.readStatus)
	mux.HandleFunc("GET /v1/blocked", state.readBlocked)
	state.server = &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10}
	securityStates.items[path] = state
	go func() {
		if err := state.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// The caller can observe socket failure through its own reconciliation health.
		}
	}()
	return state, nil
}

func releaseSecurityBlockState(state *securityBlockState) {
	securityStates.Lock()
	defer securityStates.Unlock()
	state.refs--
	if state.refs > 0 {
		return
	}
	delete(securityStates.items, state.path)
	_ = state.server.Close()
	_ = state.listener.Close()
	_ = os.Remove(state.path)
}

func (s *securityBlockState) banned(ip string, now time.Time) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiresAt, ok := s.bans[ip]
	if !ok {
		return time.Time{}, false
	}
	if !expiresAt.After(now) {
		delete(s.bans, ip)
		return time.Time{}, false
	}
	return expiresAt, true
}

func (s *securityBlockState) countBlocked(ip string) {
	s.mu.Lock()
	s.blockedRequests[ip]++
	s.mu.Unlock()
}

func (s *securityBlockState) receiveSnapshot(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var snapshot SecurityBanSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		http.Error(w, "Invalid security snapshot", http.StatusBadRequest)
		return
	}
	if err := ensureJSONEOF(decoder); err != nil {
		http.Error(w, "Invalid security snapshot", http.StatusBadRequest)
		return
	}
	if len(snapshot.Bans) > 10000 {
		http.Error(w, "Security snapshot is too large", http.StatusRequestEntityTooLarge)
		return
	}
	now := time.Now().UTC()
	candidate := make(map[string]time.Time, len(snapshot.Bans))
	for _, ban := range snapshot.Bans {
		ip, err := netip.ParseAddr(ban.IP)
		if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ban.ExpiresAt.IsZero() {
			http.Error(w, "Security snapshot contains an invalid ban", http.StatusBadRequest)
			return
		}
		expiresAt := ban.ExpiresAt.UTC()
		if expiresAt.After(now) {
			candidate[ip.Unmap().String()] = expiresAt
		}
	}
	s.mu.Lock()
	s.bans = candidate
	s.lastSync = now
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *securityBlockState) readStatus(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	status := SecurityControlStatus{Synced: !s.lastSync.IsZero(), LastSync: s.lastSync, ActiveBans: len(s.bans), SocketHealthy: true}
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(status)
}

func (s *securityBlockState) readBlocked(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	counts := make(map[string]uint64, len(s.blockedRequests))
	for ip, count := range s.blockedRequests {
		counts[ip] = count
	}
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(counts)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON data")
		}
		return err
	}
	return nil
}

func init() {
	caddy.RegisterModule(SecurityBlocker{})
	httpcaddyfile.RegisterHandlerDirective("jp_admin_bans", parseSecurityBlocker)
	httpcaddyfile.RegisterDirectiveOrder("jp_admin_bans", httpcaddyfile.Before, "reverse_proxy")
}

var (
	_ caddy.Module                = (*SecurityBlocker)(nil)
	_ caddy.Provisioner           = (*SecurityBlocker)(nil)
	_ caddy.CleanerUpper          = (*SecurityBlocker)(nil)
	_ caddyhttp.MiddlewareHandler = (*SecurityBlocker)(nil)
	_ caddyfile.Unmarshaler       = (*SecurityBlocker)(nil)
)
