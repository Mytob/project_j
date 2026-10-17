package monitoring

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	HistoryRetention = 90 * 24 * time.Hour
	maxHistoryFile   = 4 << 20
	maxSamplesPerDay = 1500
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

// History stores one-minute samples in compressed, per-day files. Each file
// is replaced atomically, is bounded, and is independent of release contents.
type History struct {
	mu     sync.RWMutex
	root   string
	days   map[string][]Snapshot
	latest time.Time
	now    func() time.Time
}

func OpenHistory(root string) (*History, error) {
	if root == "" {
		return nil, errors.New("statistics history directory is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create statistics history directory: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("secure statistics history directory: %w", err)
	}
	history := &History{root: root, days: make(map[string][]Snapshot), now: time.Now}
	if err := history.load(); err != nil {
		return nil, err
	}
	return history, nil
}

func (h *History) load() error {
	entries, err := os.ReadDir(h.root)
	if err != nil {
		return fmt.Errorf("read statistics history directory: %w", err)
	}
	cutoff := h.now().UTC().Add(-HistoryRetention)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json.gz") {
			continue
		}
		date := strings.TrimSuffix(name, ".json.gz")
		day, parseErr := time.Parse("2006-01-02", date)
		if parseErr != nil {
			continue
		}
		path := filepath.Join(h.root, name)
		if day.Add(24 * time.Hour).Before(cutoff) {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("expire old statistics history: %w", err)
			}
			continue
		}
		info, err := entry.Info()
		if err != nil || info.Size() > maxHistoryFile {
			continue
		}
		samples, err := readHistoryFile(path, day)
		if err != nil {
			// One damaged day is discarded from the in-memory view; healthy days
			// remain available and the next atomic save repairs that day.
			continue
		}
		h.days[date] = samples
		if latest := samples[len(samples)-1].CapturedAt; latest.After(h.latest) {
			h.latest = latest
		}
	}
	return nil
}

func readHistoryFile(path string, day time.Time) ([]Snapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	compressed, err := gzip.NewReader(io.LimitReader(file, maxHistoryFile+1))
	if err != nil {
		return nil, err
	}
	defer compressed.Close()
	data, err := io.ReadAll(io.LimitReader(compressed, maxHistoryFile+1))
	if err != nil || len(data) > maxHistoryFile {
		return nil, errors.New("statistics history is too large or corrupt")
	}
	var samples []Snapshot
	if err := json.Unmarshal(data, &samples); err != nil {
		return nil, err
	}
	if len(samples) > maxSamplesPerDay {
		return nil, errors.New("statistics day exceeds its sample limit")
	}
	start := day.UTC()
	end := start.Add(24 * time.Hour)
	for i, sample := range samples {
		if sample.CapturedAt.IsZero() || sample.CapturedAt.Before(start) || !sample.CapturedAt.Before(end) || (i > 0 && !samples[i-1].CapturedAt.Before(sample.CapturedAt)) {
			return nil, errors.New("statistics samples are out of range or unordered")
		}
	}
	return samples, nil
}

func (h *History) Append(sample Snapshot) error {
	if sample.CapturedAt.IsZero() {
		return errors.New("statistics sample timestamp is required")
	}
	sample.CapturedAt = sample.CapturedAt.UTC()
	date := sample.CapturedAt.Format("2006-01-02")
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.latest.IsZero() && sample.CapturedAt.Before(h.latest) {
		return errors.New("statistics samples must be appended in timestamp order")
	}
	if err := h.expireLocked(sample.CapturedAt.Add(-HistoryRetention)); err != nil {
		return err
	}
	day := append([]Snapshot(nil), h.days[date]...)
	if len(day) > 0 && !day[len(day)-1].CapturedAt.Before(sample.CapturedAt) {
		if day[len(day)-1].CapturedAt.Equal(sample.CapturedAt) {
			day[len(day)-1] = sample
		} else {
			return errors.New("statistics samples must be appended in timestamp order")
		}
	} else {
		if len(day) >= maxSamplesPerDay {
			return errors.New("statistics sample limit for the day has been reached")
		}
		day = append(day, sample)
	}
	if err := writeHistoryFile(h.root, date, day); err != nil {
		return fmt.Errorf("persist statistics history: %w", err)
	}
	h.days[date] = day
	if sample.CapturedAt.After(h.latest) {
		h.latest = sample.CapturedAt
	}
	return nil
}

func (h *History) expireLocked(cutoff time.Time) error {
	for date := range h.days {
		day, err := time.Parse("2006-01-02", date)
		if err != nil || !day.Add(24*time.Hour).Before(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(h.root, date+".json.gz")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("expire old statistics history: %w", err)
		}
		delete(h.days, date)
	}
	return nil
}

func (h *History) LatestAt() (time.Time, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var latest time.Time
	for _, day := range h.days {
		if len(day) > 0 && day[len(day)-1].CapturedAt.After(latest) {
			latest = day[len(day)-1].CapturedAt
		}
	}
	return latest, !latest.IsZero()
}

func writeHistoryFile(root, date string, samples []Snapshot) error {
	data, err := json.Marshal(samples)
	if err != nil {
		return err
	}
	if len(data) > maxHistoryFile {
		return errors.New("statistics history day exceeds its storage limit")
	}
	temp, err := os.CreateTemp(root, ".statistics-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	compressed := gzip.NewWriter(temp)
	if _, err := compressed.Write(data); err != nil {
		compressed.Close()
		temp.Close()
		return err
	}
	if err := compressed.Close(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, filepath.Join(root, date+".json.gz")); err != nil {
		return err
	}
	directory, err := os.Open(root)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// Range returns chronologically ordered aggregates bounded by maxPoints.
// Numeric gauges are averaged; cumulative counters use the net change across
// each bucket, including resets.
func (h *History) Range(start, end time.Time, maxPoints int) []Snapshot {
	if maxPoints < 1 || !end.After(start) {
		return []Snapshot{}
	}
	h.mu.RLock()
	var samples []Snapshot
	for _, day := range h.days {
		for _, sample := range day {
			if !sample.CapturedAt.Before(start) && sample.CapturedAt.Before(end) {
				samples = append(samples, sample)
			}
		}
	}
	h.mu.RUnlock()
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
	var previous *ProxyMetrics
	for _, sample := range samples {
		item := sample.Proxy
		if item == nil {
			continue
		}
		gauges++
		result.ActiveRequests += item.ActiveRequests
		addFloat(&result.RequestsPerSecond, item.RequestsPerSecond)
		addFloat(&result.ErrorRatePercent, item.ErrorRatePercent)
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
	divideFloat(&result.ErrorRatePercent, uint64(gauges))
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
