package monitoring

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHistoryPersistsAndReloadsSamples(t *testing.T) {
	root := filepath.Join(t.TempDir(), "stats")
	history, err := OpenHistory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	at := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	if err := history.Append(Snapshot{CapturedAt: at, Host: &HostMetrics{CapturedAt: at, CPUPercent: floatValue(40)}}); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenHistory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	points := reopened.Range(at.Add(-time.Minute), at.Add(time.Minute), 10)
	if len(points) != 1 || points[0].Host == nil || points[0].Host.CPUPercent == nil || *points[0].Host.CPUPercent != 40 {
		t.Fatalf("reloaded history = %+v", points)
	}
	info, err := os.Stat(filepath.Join(root, "statistics.db"))
	if err != nil || info.Size() == 0 {
		t.Fatalf("SQLite statistics database missing or empty: info=%v err=%v", info, err)
	}
}

func TestHistoryRetentionPersistsAndPrunesExpiredRows(t *testing.T) {
	root := t.TempDir()
	history, err := OpenHistory(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Minute)
	old := now.Add(-20 * 24 * time.Hour)
	if err := history.Append(Snapshot{CapturedAt: old}); err != nil {
		t.Fatal(err)
	}
	if err := history.SetRetention(7 * 24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	if history.Retention() != 7*24*time.Hour {
		t.Fatalf("retention = %s", history.Retention())
	}
	if got := history.Range(old.Add(-time.Minute), old.Add(time.Minute), 10); len(got) != 0 {
		t.Fatalf("expired samples were retained: %v", got)
	}
	if err := history.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenHistory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Retention() != 7*24*time.Hour {
		t.Fatalf("persisted retention = %s", reopened.Retention())
	}
}

func TestHistoryPruningDeletesAtMostOneBoundedBatchPerRun(t *testing.T) {
	history, err := OpenHistory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()

	for sample := int64(1); sample <= 2*pruneBatchSize+5; sample++ {
		if _, err := history.db.Exec(`INSERT INTO proxy_samples(captured_at,payload) VALUES(?,?)`, sample, []byte(`{"captured_at":"2026-10-01T00:00:00Z"}`)); err != nil {
			t.Fatalf("insert expired history sample %d: %v", sample, err)
		}
	}
	cutoff := time.Now().UTC()
	if err := history.prune(cutoff); err != nil {
		t.Fatal(err)
	}
	count := func() int64 {
		t.Helper()
		var result int64
		if err := history.db.QueryRow(`SELECT COUNT(*) FROM proxy_samples`).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	if got := count(); got != pruneBatchSize+5 {
		t.Fatalf("rows after one pruning run = %d, want %d", got, pruneBatchSize+5)
	}
	if err := history.prune(cutoff); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 5 {
		t.Fatalf("rows after two pruning runs = %d, want 5", got)
	}
	if err := history.prune(cutoff); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 0 {
		t.Fatalf("rows after final pruning run = %d, want 0", got)
	}
}

func TestHistoryRejectsCorruptDatabase(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "statistics.db"), []byte("not a sqlite database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenHistory(root); err == nil {
		t.Fatal("corrupt statistics database was accepted")
	}
}

func TestValidateHistoryDatabaseIsReadOnlyAndRejectsCorruption(t *testing.T) {
	root := t.TempDir()
	history, err := OpenHistory(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := history.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "statistics.db")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := HistoryDatabaseSchema(path)
	if err != nil || schema != DatabaseSchemaVersion {
		t.Fatalf("history database schema = %d, %v; want %d", schema, err, DatabaseSchemaVersion)
	}
	if err := ValidateHistoryDatabase(path); err != nil {
		t.Fatalf("valid history database rejected: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("read-only history validation changed the database")
	}
	corrupt := filepath.Join(t.TempDir(), "corrupt.db")
	if err := os.WriteFile(corrupt, []byte("not sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateHistoryDatabase(corrupt); err == nil {
		t.Fatal("corrupt SQLite database passed read-only validation")
	}
}

func TestHistoryOnlineBackupIsConsistentAndPrivate(t *testing.T) {
	history, err := OpenHistory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	at := time.Now().UTC().Truncate(time.Minute)
	if err := history.Append(Snapshot{CapturedAt: at, Proxy: &ProxyMetrics{CapturedAt: at, AllowedRequests: 17}}); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "snapshot.db")
	if err := history.BackupTo(destination); err != nil {
		t.Fatalf("online backup: %v", err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("backup permissions = %o", info.Mode().Perm())
	}
	backup, err := OpenHistory(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	points := backup.Range(at.Add(-time.Minute), at.Add(time.Minute), 10)
	if len(points) != 1 || points[0].Proxy == nil || points[0].Proxy.AllowedRequests != 17 {
		t.Fatalf("backup samples = %+v", points)
	}
	if err := history.BackupTo(destination); err == nil {
		t.Fatal("existing backup destination was overwritten")
	}
}

func TestHistoryRangeDownsamplesAndAggregatesCounters(t *testing.T) {
	root := t.TempDir()
	history, err := OpenHistory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
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

func TestAggregateProxyWeightsErrorRateByRequestRate(t *testing.T) {
	at := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	points := []Snapshot{
		{CapturedAt: at, Proxy: &ProxyMetrics{CapturedAt: at, RequestsPerSecond: floatValue(100), ErrorRatePercent: floatValue(1)}},
		{CapturedAt: at.Add(time.Minute), Proxy: &ProxyMetrics{CapturedAt: at.Add(time.Minute), RequestsPerSecond: floatValue(1), ErrorRatePercent: floatValue(100)}},
	}
	got := aggregate(points).Proxy
	if got == nil || got.ErrorRatePercent == nil {
		t.Fatalf("weighted error rate is unavailable: %+v", got)
	}
	want := (100.0*1 + 1.0*100) / 101
	if delta := *got.ErrorRatePercent - want; delta < -0.000001 || delta > 0.000001 {
		t.Fatalf("weighted error rate = %.6f, want %.6f", *got.ErrorRatePercent, want)
	}
}

func TestHistoryRejectsOutOfOrderAndOversizedSamples(t *testing.T) {
	history, err := OpenHistory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	at := time.Date(2026, time.October, 16, 0, 0, 0, 0, time.UTC)
	if err := history.Append(Snapshot{CapturedAt: at}); err != nil {
		t.Fatal(err)
	}
	if err := history.Append(Snapshot{CapturedAt: at.Add(-time.Minute)}); err == nil {
		t.Fatalf("out of order sample error = %v", err)
	}
}

func floatValue(value float64) *float64 { return &value }
