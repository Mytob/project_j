package caddytelemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestAdminBanHandlerBlocksOnlyBannedExactAddressAndAggregates(t *testing.T) {
	state := &securityBlockState{bans: map[string]time.Time{"203.0.113.10": time.Now().Add(time.Minute), "2001:db8::10": time.Now().Add(time.Minute)}, blockedRequests: map[string]uint64{}}
	module := &SecurityBlocker{state: state}
	next := &securityTestHandler{}
	for _, address := range []string{"203.0.113.10:44000", "[2001:db8::10]:44000"} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.RemoteAddr = address
		if err := module.ServeHTTP(response, request, next); err != nil {
			t.Fatal(err)
		}
		if response.Code != http.StatusForbidden || response.Body.String() != "Access Denied\n" {
			t.Fatalf("banned %s response = %d %q", address, response.Code, response.Body.String())
		}
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "203.0.113.11:44000"
	if err := module.ServeHTTP(response, request, next); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusNoContent || next.calls != 1 {
		t.Fatalf("unbanned address was blocked: response=%d next=%d", response.Code, next.calls)
	}
	if state.blockedRequests["203.0.113.10"] != 1 || state.blockedRequests["2001:db8::10"] != 1 {
		t.Fatalf("blocked traffic was not aggregated per exact address: %+v", state.blockedRequests)
	}
}

func TestAdminBanExpiryIsHonoredWithoutAReconciliation(t *testing.T) {
	state := &securityBlockState{bans: map[string]time.Time{"203.0.113.12": time.Now().Add(-time.Second)}, blockedRequests: map[string]uint64{}}
	module := &SecurityBlocker{state: state}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "203.0.113.12:44000"
	response := httptest.NewRecorder()
	if err := module.ServeHTTP(response, request, &securityTestHandler{}); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusNoContent {
		t.Fatalf("expired ban still blocked request: %d", response.Code)
	}
	if _, stillBanned := state.bans["203.0.113.12"]; stillBanned {
		t.Fatal("expired entry was not discarded")
	}
}

func TestCaddyControlSocketAcceptsSnapshotsAndReportsStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	state, err := acquireSecurityBlockState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSecurityBlockState(state)
	client := &http.Client{Transport: &http.Transport{DialContext: func(_ context.Context, _, _ string) (net.Conn, error) { return net.Dial("unix", path) }}}
	expires := time.Now().Add(2 * time.Minute).UTC()
	body, err := json.Marshal(SecurityBanSnapshot{Bans: []SecurityBan{{IP: "2001:db8::15", ExpiresAt: expires}}})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPut, "http://caddy/v1/snapshot", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("snapshot response = %d", response.StatusCode)
	}
	request, err = http.NewRequest(http.MethodGet, "http://caddy/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var status SecurityControlStatus
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if !status.Synced || status.ActiveBans != 1 || !status.SocketHealthy {
		t.Fatalf("status after sync = %+v", status)
	}
}

type securityTestHandler struct{ calls int }

func (h *securityTestHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) error {
	h.calls++
	w.WriteHeader(http.StatusNoContent)
	return nil
}

var _ caddyhttp.Handler = (*securityTestHandler)(nil)
