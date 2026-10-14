package monitoring

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHistoryPersistsAndReloadsSamples(t *testing.T) {
	root := filepath.Join(t.TempDir(), "stats")
	history, err := OpenHistory(root)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	if err := history.Append(Snapshot{CapturedAt: at, Host: &HostMetrics{CapturedAt: at, CPUPercent: floatValue(40)}}); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenHistory(root)
	if err != nil {
		t.Fatal(err)
	}
	points := reopened.Range(at.Add(-time.Minute), at.Add(time.Minute), 10)
	if len(points) != 1 || points[0].Host == nil || points[0].Host.CPUPercent == nil || *points[0].Host.CPUPercent != 40 {
		t.Fatalf("reloaded history = %+v", points)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != at.Format("2006-01-02")+".json.gz" {
		t.Fatalf("unexpected atomic snapshot files: %v", entries)
	}
}

func TestHistoryCorruptDaysRecoverAndOldDaysExpire(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	oldDay := now.Add(-HistoryRetention - 48*time.Hour).Format("2006-01-02")
	if err := os.WriteFile(filepath.Join(root, oldDay+".json.gz"), []byte("expired"), 0o600); err != nil {
		t.Fatal(err)
	}
	corruptDay := now.Format("2006-01-02")
	if err := os.WriteFile(filepath.Join(root, corruptDay+".json.gz"), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	history, err := OpenHistory(root)
	if err != nil {
		t.Fatalf("corrupt history prevented startup: %v", err)
	}
	if len(history.Range(now.Add(-HistoryRetention), now.Add(time.Second), 10)) != 0 {
		t.Fatal("corrupt samples should be omitted during recovery")
	}
	if _, err := os.Stat(filepath.Join(root, oldDay+".json.gz")); !os.IsNotExist(err) {
		t.Fatalf("expired history file remains: %v", err)
	}
	if err := history.Append(Snapshot{CapturedAt: now}); err != nil {
		t.Fatalf("healthy history could not be written after corrupt recovery: %v", err)
	}
}

func TestHistoryRangeDownsamplesAndAggregatesCounters(t *testing.T) {
	root := t.TempDir()
	history, err := OpenHistory(root)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	for i, current := range []uint64{100, 110, 130} {
		at := start.Add(time.Duration(i) * time.Minute)
		sample := Snapshot{
			CapturedAt: at,
			Host:       &HostMetrics{CapturedAt: at, CPUPercent: floatValue(float64(10 + 10*i))},
			Proxy:      &ProxyMetrics{CapturedAt: at, AllowedRequests: current, BlockedRequests: uint64(i), HTTPErrorCount: uint64(i / 2), TotalTransferredBytes: current * 100},
		}
		if err := history.Append(sample); err != nil {
			t.Fatal(err)
		}
	}
	points := history.Range(start, start.Add(4*time.Minute), 1)
	if len(points) != 1 {
		t.Fatalf("downsampled point count = %d", len(points))
	}
	point := points[0]
	if point.Host == nil || point.Host.CPUPercent == nil || *point.Host.CPUPercent != 20 {
		t.Fatalf("CPU average = %+v", point.Host)
	}
	if point.Proxy == nil || point.Proxy.AllowedRequests != 30 || point.Proxy.BlockedRequests != 2 || point.Proxy.HTTPErrorCount != 1 || point.Proxy.TotalTransferredBytes != 3000 {
		t.Fatalf("counter deltas = %+v", point.Proxy)
	}
}

func TestHistoryRejectsOutOfOrderAndOversizedSamples(t *testing.T) {
	history, err := OpenHistory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Minute)
	if err := history.Append(Snapshot{CapturedAt: at}); err != nil {
		t.Fatal(err)
	}
	if err := history.Append(Snapshot{CapturedAt: at.Add(-time.Minute)}); err == nil || !strings.Contains(err.Error(), "timestamp order") {
		t.Fatalf("out of order sample error = %v", err)
	}
}

func floatValue(value float64) *float64 { return &value }
