package monitoring

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFeedCombinesFreshHostAndProxyMetricsAndBoundsSubscribers(t *testing.T) {
	proxyPath := filepath.Join(t.TempDir(), "current.json")
	hostServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(HostMetrics{CapturedAt: time.Now().UTC(), CPUPercent: floatValue(25)})
	}))
	defer hostServer.Close()
	writeProxyFixture(t, proxyPath, ProxyMetrics{CapturedAt: time.Now().UTC(), ActiveRequests: 2, AllowedRequests: 12})
	history, err := OpenHistory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	feed, err := NewFeed(hostServer.URL, proxyPath, history, nil)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]uint64, maxSubscribers)
	channels := make([]<-chan LiveData, maxSubscribers)
	for i := range ids {
		ids[i], channels[i], err = feed.Subscribe()
		if err != nil {
			t.Fatal(err)
		}
		defer feed.Unsubscribe(ids[i])
	}
	if _, _, err := feed.Subscribe(); err == nil {
		t.Fatal("subscriber limit was not enforced")
	}
	feed.collect(context.Background())
	current := feed.Current()
	if current.Status != "live" || current.Host == nil || current.Proxy == nil || current.Proxy.ActiveRequests != 2 {
		t.Fatalf("combined live metrics = %+v", current)
	}
	for _, channel := range channels {
		select {
		case update := <-channel:
			if update.Status != "live" {
				t.Fatalf("subscriber received status %q", update.Status)
			}
		default:
			t.Fatal("subscriber was not notified")
		}
	}
}

func TestFeedMarksStaleOrUnavailableSourcesDisconnected(t *testing.T) {
	proxyPath := filepath.Join(t.TempDir(), "missing.json")
	hostServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(HostMetrics{CapturedAt: time.Now().Add(-time.Minute), CPUPercent: floatValue(88)})
	}))
	defer hostServer.Close()
	history, err := OpenHistory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	feed, err := NewFeed(hostServer.URL, proxyPath, history, nil)
	if err != nil {
		t.Fatal(err)
	}
	feed.collect(context.Background())
	if current := feed.Current(); current.Status != "disconnected" || current.Host != nil || current.Proxy != nil {
		t.Fatalf("stale data was presented as live: %+v", current)
	}
}

func TestFeedRejectsPublicMetricsOrigins(t *testing.T) {
	if _, err := NewFeed("http://example.com", filepath.Join(t.TempDir(), "metrics.json"), &History{}, nil); err == nil {
		t.Fatal("public host metrics origin was accepted")
	}
}

func writeProxyFixture(t *testing.T, path string, metrics ProxyMetrics) {
	t.Helper()
	data, err := json.Marshal(metrics)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
