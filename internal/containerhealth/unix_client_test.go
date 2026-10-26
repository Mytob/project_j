package containerhealth

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixClientReadsOnlyMaintenanceContainerEndpoint(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "maintenance.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/containers" {
			t.Errorf("unexpected maintenance request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[ {"service":"admin","state":"running","health":"healthy","restart_count":2,"checked_at":"2026-10-21T00:00:00Z"} ]`))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	items, err := NewUnixClient(socket).Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Service != "admin" || items[0].RestartCount != 2 {
		t.Fatalf("unexpected maintenance snapshot: %#v", items)
	}
}
