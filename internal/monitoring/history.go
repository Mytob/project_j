package monitoring

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"modernc.org/sqlite"
)

const (
	DefaultHistoryRetention = 30 * 24 * time.Hour
	MaximumHistoryRetention = 180 * 24 * time.Hour
	maxHistoryFile          = 4 << 20
	maxSamplesPerDay        = 1500
	pruneBatchSize          = 1000
	DatabaseSchemaVersion   = 1
)

type ProxyMetrics struct {
	CapturedAt               time.Time `json:"captured_at"`
	ActiveRequests           int64     `json:"active_requests"`
	RequestsPerSecond        *float64  `json:"requests_per_second,omitempty"`
	AllowedRequests          uint64    `json:"allowed_requests"`
	BlockedRequests          uint64    `json:"blocked_requests"`
	HTTPErrorCount           uint64    `json:"http_error_count"`
	ErrorRatePercent         *float64  `json:"error_rate_percent,omitempty"`
	IncomingBytesPerSecond   *uint64   `json:"incoming_bytes_per_second,omitempty"`
	OutgoingBytesPerSecond   *uint64   `json:"outgoing_bytes_per_second,omitempty"`
	TotalTransferredBytes    uint64    `json:"total_transferred_bytes"`
	IncomingTransferredBytes uint64    `json:"incoming_transferred_bytes"`
	OutgoingTransferredBytes uint64    `json:"outgoing_transferred_bytes"`
}

type Snapshot struct {
	CapturedAt time.Time     `json:"captured_at"`
	Host       *HostMetrics  `json:"host,omitempty"`
	Proxy      *ProxyMetrics `json:"proxy,omitempty"`
}

// History stores one-minute samples in a private SQLite database independent
// of replaceable release files.
type History struct {
	mu        sync.RWMutex
	db        *sql.DB
	path      string
	retention time.Duration
	now       func() time.Time
}

func OpenHistory(root string) (*History, error) {
	if root == "" {
		return nil, errors.New("statistics history directory is required")
	}
	path := root
	if filepath.Ext(path) != ".db" {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, fmt.Errorf("create statistics directory: %w", err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return nil, fmt.Errorf("secure statistics directory: %w", err)
		}
		path = filepath.Join(path, "statistics.db")
	} else if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create statistics directory: %w", err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("open statistics database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect statistics database: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("secure statistics database: %w", err)
	}
	history := &History{db: db, path: path, retention: DefaultHistoryRetention, now: time.Now}
	if err := history.initialize(); err != nil {
		db.Close()
		return nil, err
	}
	return history, nil
}

func (h *History) initialize() error {
	if _, err := h.db.Exec(`PRAGMA auto_vacuum=INCREMENTAL`); err != nil {
		return fmt.Errorf("enable incremental database reclamation: %w", err)
	}
	var schema int
	if err := h.db.QueryRow(`PRAGMA user_version`).Scan(&schema); err != nil {
		return fmt.Errorf("read statistics database schema: %w", err)
	}
	if schema > DatabaseSchemaVersion {
		return fmt.Errorf("statistics database schema %d is newer than supported schema %d", schema, DatabaseSchemaVersion)
	}
	statements := []string{`CREATE TABLE IF NOT EXISTS proxy_samples (
		captured_at INTEGER PRIMARY KEY,
		payload BLOB NOT NULL CHECK(length(payload) <= 4194304)
	)`, `CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`, `CREATE INDEX IF NOT EXISTS proxy_samples_captured_at ON proxy_samples(captured_at)`}
	for _, statement := range statements {
		if _, err := h.db.Exec(statement); err != nil {
			return fmt.Errorf("initialize statistics database: %w", err)
		}
	}
	if schema == 0 {
		if _, err := h.db.Exec(`PRAGMA user_version=1`); err != nil {
			return fmt.Errorf("record statistics database schema: %w", err)
		}
	}
	var raw string
	err := h.db.QueryRow(`SELECT value FROM app_settings WHERE key='proxy_retention_days'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := h.db.Exec(`INSERT INTO app_settings(key,value) VALUES('proxy_retention_days','30')`); err != nil {
			return fmt.Errorf("set default proxy statistics retention: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("read proxy statistics retention: %w", err)
	} else {
		days, parseErr := strconv.Atoi(raw)
		retention := time.Duration(days) * 24 * time.Hour
		if parseErr != nil || !validRetention(retention) {
			return errors.New("stored proxy statistics retention is invalid")
		}
		h.retention = retention
	}
	return h.prune(h.now().UTC().Add(-h.retention))
}

func (h *History) Append(sample Snapshot) error {
	if sample.CapturedAt.IsZero() {
		return errors.New("statistics sample timestamp is required")
	}
	sample.CapturedAt = sample.CapturedAt.UTC()
	h.mu.Lock()
	defer h.mu.Unlock()
	var latest int64
	if err := h.db.QueryRow(`SELECT COALESCE(MAX(captured_at),0) FROM proxy_samples`).Scan(&latest); err != nil {
		return fmt.Errorf("read latest statistics timestamp: %w", err)
	}
	if latest > 0 && sample.CapturedAt.UnixNano() < latest {
		return errors.New("statistics samples must be appended in timestamp order")
	}
	if err := h.prune(sample.CapturedAt.Add(-h.retention)); err != nil {
		return err
	}
	var count int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM proxy_samples WHERE captured_at>=? AND captured_at<?`, sample.CapturedAt.UTC().Truncate(24*time.Hour).UnixNano(), sample.CapturedAt.UTC().Truncate(24*time.Hour).Add(24*time.Hour).UnixNano()).Scan(&count); err != nil {
		return err
	}
	if count >= maxSamplesPerDay {
		var exists int
		if err := h.db.QueryRow(`SELECT COUNT(*) FROM proxy_samples WHERE captured_at=?`, sample.CapturedAt.UnixNano()).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return errors.New("statistics sample limit for the day has been reached")
		}
	}
	data, err := json.Marshal(sample)
	if err != nil {
		return err
	}
	if len(data) > maxHistoryFile {
		return errors.New("statistics sample exceeds its storage limit")
	}
	if _, err := h.db.Exec(`INSERT INTO proxy_samples(captured_at,payload) VALUES(?,?) ON CONFLICT(captured_at) DO UPDATE SET payload=excluded.payload`, sample.CapturedAt.UnixNano(), data); err != nil {
		return fmt.Errorf("persist statistics sample: %w", err)
	}
	return nil
}

func (h *History) prune(cutoff time.Time) error {
	result, err := h.db.Exec(`DELETE FROM proxy_samples WHERE captured_at IN (SELECT captured_at FROM proxy_samples WHERE captured_at<? ORDER BY captured_at LIMIT ?)`, cutoff.UnixNano(), pruneBatchSize)
	if err != nil {
		return fmt.Errorf("prune expired statistics: %w", err)
	}
	removed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if removed > 0 {
		if _, err := h.db.Exec(`PRAGMA incremental_vacuum(100)`); err != nil {
			return fmt.Errorf("reclaim expired statistics pages: %w", err)
		}
	}
	return nil
}

func (h *History) LatestAt() (time.Time, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var latest int64
	if err := h.db.QueryRow(`SELECT COALESCE(MAX(captured_at),0) FROM proxy_samples`).Scan(&latest); err != nil || latest == 0 {
		return time.Time{}, false
	}
	return time.Unix(0, latest).UTC(), true
}

func validRetention(value time.Duration) bool {
	for _, days := range []int{7, 14, 30, 60, 90, 180} {
		if value == time.Duration(days)*24*time.Hour {
			return true
		}
	}
	return false
}

func (h *History) Retention() time.Duration { h.mu.RLock(); defer h.mu.RUnlock(); return h.retention }

func (h *History) SetRetention(value time.Duration) error {
	if !validRetention(value) {
		return errors.New("proxy statistics retention must be 7, 14, 30, 60, 90, or 180 days")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	days := int(value / (24 * time.Hour))
	if _, err := h.db.Exec(`INSERT INTO app_settings(key,value) VALUES('proxy_retention_days',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, fmt.Sprint(days)); err != nil {
		return err
	}
	h.retention = value
	return h.prune(h.now().UTC().Add(-value))
}

func (h *History) StorageInfo() (databaseBytes, retainedSamples int64, err error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if err = h.db.QueryRow(`SELECT COUNT(*) FROM proxy_samples`).Scan(&retainedSamples); err != nil {
		return
	}
	var info os.FileInfo
	info, err = os.Stat(h.path)
	if err != nil {
		return
	}
	databaseBytes = info.Size()
	for _, suffix := range []string{"-wal", "-shm"} {
		if sidecar, statErr := os.Stat(h.path + suffix); statErr == nil {
			databaseBytes += sidecar.Size()
		} else if !errors.Is(statErr, os.ErrNotExist) {
			err = statErr
			return
		}
	}
	return
}

func (h *History) Close() error { return h.db.Close() }

// BackupTo uses SQLite's online backup API to create a consistent standalone
// database snapshot without stopping statistics collection.
func (h *History) BackupTo(destination string) error {
	if filepath.Ext(destination) != ".db" {
		return errors.New("statistics backup must use a .db destination")
	}
	absPath, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absPath))
	if err != nil {
		return fmt.Errorf("resolve statistics backup directory: %w", err)
	}
	if parent != filepath.Dir(absPath) {
		return errors.New("statistics backup directory must not be a symbolic link")
	}
	if _, err := os.Lstat(absPath); err == nil {
		return errors.New("statistics backup destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var partial bool
	defer func() {
		if partial {
			_ = os.Remove(absPath)
			_ = os.Remove(absPath + "-wal")
			_ = os.Remove(absPath + "-shm")
		}
	}()
	uri := (&url.URL{Scheme: "file", Path: filepath.ToSlash(absPath)}).String() + "?mode=rwc"
	connection, err := h.db.Conn(context.Background())
	if err != nil {
		return err
	}
	err = connection.Raw(func(raw any) error {
		source, ok := raw.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("SQLite connection does not support online backups")
		}
		backup, err := source.NewBackup(uri)
		if err != nil {
			return err
		}
		var backupErr error
		for {
			more, stepErr := backup.Step(128)
			if stepErr != nil {
				backupErr = stepErr
				break
			}
			if !more {
				break
			}
		}
		return errors.Join(backupErr, backup.Finish())
	})
	connection.Close()
	if err != nil {
		partial = true
		return fmt.Errorf("create online statistics backup: %w", err)
	}
	if err := os.Chmod(absPath, 0o600); err != nil {
		partial = true
		return fmt.Errorf("secure statistics backup: %w", err)
	}
	checkURI := (&url.URL{Scheme: "file", Path: filepath.ToSlash(absPath)}).String() + "?mode=ro"
	check, err := sql.Open("sqlite", checkURI)
	if err != nil {
		partial = true
		return err
	}
	defer check.Close()
	var result string
	if err := check.QueryRow(`PRAGMA integrity_check`).Scan(&result); err != nil || result != "ok" {
		partial = true
		return errors.New("statistics backup failed its SQLite integrity check")
	}
	return nil
}

// Range returns chronologically ordered aggregates bounded by maxPoints.
// Numeric gauges are averaged; cumulative counters use the net change across
// each bucket, including resets.
func (h *History) Range(start, end time.Time, maxPoints int) []Snapshot {
	if maxPoints < 1 || !end.After(start) {
		return []Snapshot{}
	}
	h.mu.RLock()
	rows, err := h.db.QueryContext(context.Background(), `SELECT payload FROM proxy_samples WHERE captured_at>=? AND captured_at<? ORDER BY captured_at`, start.UnixNano(), end.UnixNano())
	if err != nil {
		h.mu.RUnlock()
		return []Snapshot{}
	}
	defer rows.Close()
	samples := make([]Snapshot, 0)
	for rows.Next() {
		var data []byte
		var sample Snapshot
		if rows.Scan(&data) != nil || len(data) > maxHistoryFile || json.Unmarshal(data, &sample) != nil {
			continue
		}
		samples = append(samples, sample)
	}
	h.mu.RUnlock()
	if rows.Err() != nil {
		return []Snapshot{}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].CapturedAt.Before(samples[j].CapturedAt) })
	if len(samples) <= maxPoints {
		return samples
	}
	result := make([]Snapshot, 0, maxPoints)
	for i := 0; i < maxPoints; i++ {
		from := i * len(samples) / maxPoints
		to := (i + 1) * len(samples) / maxPoints
		result = append(result, aggregate(samples[from:to]))
	}
	return result
}

func aggregate(samples []Snapshot) Snapshot {
	if len(samples) == 0 {
		return Snapshot{}
	}
	result := samples[len(samples)-1]
	result.CapturedAt = samples[len(samples)-1].CapturedAt
	result.Host = averageHost(samples)
	result.Proxy = aggregateProxy(samples)
	return result
}

func averageHost(samples []Snapshot) *HostMetrics {
	var result HostMetrics
	result.CapturedAt = samples[len(samples)-1].CapturedAt
	var count int
	for _, sample := range samples {
		if sample.Host == nil {
			continue
		}
		count++
		addHost(&result, sample.Host)
	}
	if count == 0 {
		return nil
	}
	divideHost(&result, uint64(count))
	return &result
}

func addHost(sum *HostMetrics, item *HostMetrics) {
	addFloat(&sum.CPUPercent, item.CPUPercent)
	addUint(&sum.MemoryUsedBytes, item.MemoryUsedBytes)
	addUint(&sum.MemoryTotalBytes, item.MemoryTotalBytes)
	addUint(&sum.MemoryAvailable, item.MemoryAvailable)
	addUint(&sum.SwapUsedBytes, item.SwapUsedBytes)
	addUint(&sum.SwapTotalBytes, item.SwapTotalBytes)
	addUint(&sum.DiskUsedBytes, item.DiskUsedBytes)
	addUint(&sum.DiskFreeBytes, item.DiskFreeBytes)
	addUint(&sum.DiskTotalBytes, item.DiskTotalBytes)
	addUint(&sum.NetworkInBPS, item.NetworkInBPS)
	addUint(&sum.NetworkOutBPS, item.NetworkOutBPS)
	addUint(&sum.UptimeSeconds, item.UptimeSeconds)
	addFloat(&sum.Load1, item.Load1)
	addFloat(&sum.Load5, item.Load5)
	addFloat(&sum.Load15, item.Load15)
}

func divideHost(sum *HostMetrics, count uint64) {
	divideFloat(&sum.CPUPercent, count)
	divideUint(&sum.MemoryUsedBytes, count)
	divideUint(&sum.MemoryTotalBytes, count)
	divideUint(&sum.MemoryAvailable, count)
	divideUint(&sum.SwapUsedBytes, count)
	divideUint(&sum.SwapTotalBytes, count)
	divideUint(&sum.DiskUsedBytes, count)
	divideUint(&sum.DiskFreeBytes, count)
	divideUint(&sum.DiskTotalBytes, count)
	divideUint(&sum.NetworkInBPS, count)
	divideUint(&sum.NetworkOutBPS, count)
	divideUint(&sum.UptimeSeconds, count)
	divideFloat(&sum.Load1, count)
	divideFloat(&sum.Load5, count)
	divideFloat(&sum.Load15, count)
}

func aggregateProxy(samples []Snapshot) *ProxyMetrics {
	result := &ProxyMetrics{CapturedAt: samples[len(samples)-1].CapturedAt}
	var gauges, counters int
	var weightedErrorRate, requestWeight float64
	var previous *ProxyMetrics
	for _, sample := range samples {
		item := sample.Proxy
		if item == nil {
			continue
		}
		gauges++
		result.ActiveRequests += item.ActiveRequests
		addFloat(&result.RequestsPerSecond, item.RequestsPerSecond)
		if item.RequestsPerSecond != nil && item.ErrorRatePercent != nil && *item.RequestsPerSecond > 0 && *item.ErrorRatePercent >= 0 {
			requestWeight += *item.RequestsPerSecond
			weightedErrorRate += *item.RequestsPerSecond * *item.ErrorRatePercent
		}
		addUint(&result.IncomingBytesPerSecond, item.IncomingBytesPerSecond)
		addUint(&result.OutgoingBytesPerSecond, item.OutgoingBytesPerSecond)
		if previous != nil {
			result.AllowedRequests += counterDelta(item.AllowedRequests, previous.AllowedRequests)
			result.BlockedRequests += counterDelta(item.BlockedRequests, previous.BlockedRequests)
			result.HTTPErrorCount += counterDelta(item.HTTPErrorCount, previous.HTTPErrorCount)
			result.TotalTransferredBytes += counterDelta(item.TotalTransferredBytes, previous.TotalTransferredBytes)
		}
		previous = item
		counters++
	}
	if gauges == 0 {
		return nil
	}
	divideFloat(&result.RequestsPerSecond, uint64(gauges))
	if requestWeight > 0 {
		errorRate := weightedErrorRate / requestWeight
		result.ErrorRatePercent = &errorRate
	}
	divideUint(&result.IncomingBytesPerSecond, uint64(gauges))
	divideUint(&result.OutgoingBytesPerSecond, uint64(gauges))
	result.ActiveRequests /= int64(gauges)
	if counters == 0 {
		return nil
	}
	return result
}

func counterDelta(current, previous uint64) uint64 {
	if current < previous {
		return current
	}
	return current - previous
}

func addFloat(sum **float64, value *float64) {
	if value == nil {
		return
	}
	if *sum == nil {
		v := 0.0
		*sum = &v
	}
	**sum += *value
}
func divideFloat(value **float64, divisor uint64) {
	if *value != nil && divisor > 0 {
		**value /= float64(divisor)
	}
}
func addUint(sum **uint64, value *uint64) {
	if value == nil {
		return
	}
	if *sum == nil {
		v := uint64(0)
		*sum = &v
	}
	**sum += *value
}
func divideUint(value **uint64, divisor uint64) {
	if *value != nil && divisor > 0 {
		**value /= divisor
	}
}
