package security

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type blockingCaddySnapshotTransport struct {
	mu              sync.Mutex
	startedFirstPut chan struct{}
	releaseFirstPut chan struct{}
	putCount        int
	activeBans      int
	snapshots       []int
}

func (t *blockingCaddySnapshotTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	switch request.URL.Path {
	case "/v1/snapshot":
		var snapshot struct {
			Bans []json.RawMessage `json:"bans"`
		}
		if err := json.NewDecoder(request.Body).Decode(&snapshot); err != nil {
			return nil, err
		}
		t.mu.Lock()
		t.putCount++
		first := t.putCount == 1
		t.mu.Unlock()
		if first {
			close(t.startedFirstPut)
			<-t.releaseFirstPut
		}
		t.mu.Lock()
		t.activeBans = len(snapshot.Bans)
		t.snapshots = append(t.snapshots, len(snapshot.Bans))
		t.mu.Unlock()
		return fakeHTTPResponse(request, http.StatusNoContent, ""), nil
	case "/v1/status":
		t.mu.Lock()
		active := t.activeBans
		t.mu.Unlock()
		body, _ := json.Marshal(map[string]any{"synced": true, "active_bans": active})
		return fakeHTTPResponse(request, http.StatusOK, string(body)), nil
	default:
		return nil, io.ErrUnexpectedEOF
	}
}

func fakeHTTPResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

func TestAdminUnbanCannotBeUndoneByStaleReconciliation(t *testing.T) {
	now := time.Now().UTC()
	manager := newTestManager(t, &now)
	const ip = "203.0.113.44"
	applyFailures(t, manager, Admin, ip, now, 3, "stale-reconcile")

	transport := &blockingCaddySnapshotTransport{
		startedFirstPut: make(chan struct{}),
		releaseFirstPut: make(chan struct{}),
	}
	controller := &Controller{
		Manager: manager,
		Fail2banClient: &Fail2banClient{
			Path:   "test-fail2ban",
			Socket: "",
			run: func(_ context.Context, _ string, args ...string) (string, error) {
				for i := 0; i+2 < len(args); i++ {
					if args[i] == "get" && args[i+2] == "banned" {
						return "['203.0.113.44']", nil
					}
				}
				return "ok", nil
			},
		},
		CaddyHTTP: &http.Client{Transport: transport},
	}

	reconcileDone := make(chan error, 1)
	go func() { reconcileDone <- controller.Reconcile(context.Background()) }()
	<-transport.startedFirstPut

	unbanStarted := make(chan struct{})
	unbanDone := make(chan error, 1)
	go func() {
		close(unbanStarted)
		unbanDone <- controller.CommitUnban(context.Background(), Admin, ip, func() error {
			removed, err := manager.Unban(Admin, ip)
			if err == nil && !removed {
				return errNoActiveBan
			}
			return err
		})
	}()
	<-unbanStarted

	select {
	case err := <-unbanDone:
		t.Fatalf("unban completed while a stale enforcement snapshot was still being applied: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(transport.releaseFirstPut)
	if err := <-reconcileDone; err != nil {
		t.Fatalf("initial reconciliation failed: %v", err)
	}
	if err := <-unbanDone; err != nil {
		t.Fatalf("serialized unban failed: %v", err)
	}

	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.snapshots) != 2 || transport.snapshots[0] != 1 || transport.snapshots[1] != 0 {
		t.Fatalf("Caddy snapshots = %v, want [1 0]", transport.snapshots)
	}
	if transport.activeBans != 0 {
		t.Fatalf("stale reconciliation restored the admin ban: active bans = %d", transport.activeBans)
	}
	if manager.HasBan(Admin, ip) {
		t.Fatal("admin ban remained in persistent manager state after unban")
	}
}
