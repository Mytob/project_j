package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"time"
)

const (
	maxSubscribers = 16
	maxProxyFile   = 64 << 10
)

type LiveData struct {
	Status     string        `json:"status"`
	CapturedAt time.Time     `json:"captured_at,omitempty"`
	Host       *HostMetrics  `json:"host,omitempty"`
	Proxy      *ProxyMetrics `json:"proxy,omitempty"`
}

type Feed struct {
	hostURL   string
	proxyPath string
	history   *History
	client    *http.Client
	logger    *slog.Logger

	mu          sync.RWMutex
	current     LiveData
	subscribers map[uint64]chan LiveData
	nextID      uint64
	lastHistory time.Time
}

func NewFeed(hostURL, proxyPath string, history *History, logger *slog.Logger) (*Feed, error) {
	parsed, err := url.Parse(hostURL)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("host metrics URL must be a private HTTP origin")
	}
	if parsed.Hostname() != "hostmetrics" {
		ip, parseErr := netip.ParseAddr(parsed.Hostname())
		if parseErr != nil || !ip.IsLoopback() {
			return nil, errors.New("host metrics URL must use the private Compose service or a loopback test address")
		}
	}
	if proxyPath == "" || history == nil {
		return nil, errors.New("proxy metrics path and history store are required")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	httpClient := &http.Client{Timeout: 800 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	feed := &Feed{hostURL: hostURL, proxyPath: proxyPath, history: history, client: httpClient, logger: logger, subscribers: make(map[uint64]chan LiveData)}
	if at, ok := history.LatestAt(); ok {
		feed.lastHistory = at.Truncate(time.Minute)
	}
	feed.current.Status = "disconnected"
	return feed, nil
}

func (f *Feed) Start(ctx context.Context) {
	f.collect(ctx)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.collect(ctx)
		}
	}
}

func (f *Feed) collect(ctx context.Context) {
	now := time.Now().UTC()
	snapshot := Snapshot{CapturedAt: now}
	if host, err := f.readHost(ctx); err == nil && fresh(now, host.CapturedAt) {
		snapshot.Host = &host
	}
	if proxy, err := f.readProxy(); err == nil && fresh(now, proxy.CapturedAt) {
		snapshot.Proxy = &proxy
	}
	status := "disconnected"
	switch {
	case snapshot.Host != nil && snapshot.Proxy != nil:
		status = "live"
	case snapshot.Host != nil || snapshot.Proxy != nil:
		status = "partial"
	}
	current := LiveData{Status: status, CapturedAt: now, Host: snapshot.Host, Proxy: snapshot.Proxy}
	f.mu.Lock()
	f.current = current
	minute := now.Truncate(time.Minute)
	if status != "disconnected" && !minute.Equal(f.lastHistory) {
		snapshot.CapturedAt = minute
		if err := f.history.Append(snapshot); err != nil {
			f.logger.Error("persist statistics sample", "error", err)
		} else {
			f.lastHistory = minute
		}
	}
	for _, subscriber := range f.subscribers {
		select {
		case subscriber <- current:
		default:
			select {
			case <-subscriber:
			default:
			}
			select {
			case subscriber <- current:
			default:
			}
		}
	}
	f.mu.Unlock()
}

func fresh(now, captured time.Time) bool {
	if captured.IsZero() {
		return false
	}
	age := now.Sub(captured)
	return age <= 5*time.Second && age >= -5*time.Second
}

func (f *Feed) readHost(ctx context.Context) (HostMetrics, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, f.hostURL+"/metrics", nil)
	if err != nil {
		return HostMetrics{}, err
	}
	response, err := f.client.Do(request)
	if err != nil {
		return HostMetrics{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return HostMetrics{}, fmt.Errorf("host metrics returned status %d", response.StatusCode)
	}
	var host HostMetrics
	if err := json.NewDecoder(io.LimitReader(response.Body, maxProxyFile)).Decode(&host); err != nil {
		return HostMetrics{}, err
	}
	return host, nil
}

func (f *Feed) readProxy() (ProxyMetrics, error) {
	file, err := os.Open(f.proxyPath)
	if err != nil {
		return ProxyMetrics{}, err
	}
	defer file.Close()
	var proxy ProxyMetrics
	if err := json.NewDecoder(io.LimitReader(file, maxProxyFile)).Decode(&proxy); err != nil {
		return ProxyMetrics{}, err
	}
	return proxy, nil
}

func (f *Feed) Current() LiveData {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.current
}

func (f *Feed) HistoryRange(name string, now time.Time) ([]Snapshot, bool) {
	duration, ok := map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour, "90d": 90 * 24 * time.Hour, "180d": MaximumHistoryRetention}[name]
	if !ok {
		return nil, false
	}
	return f.history.Range(now.Add(-duration), now, 900), true
}

func (f *Feed) StorageSettings() (retentionDays int, databaseBytes, retainedSamples int64, err error) {
	retentionDays = int(f.history.Retention() / (24 * time.Hour))
	databaseBytes, retainedSamples, err = f.history.StorageInfo()
	return
}

func (f *Feed) SetRetentionDays(days int) error {
	return f.history.SetRetention(time.Duration(days) * 24 * time.Hour)
}

func (f *Feed) Subscribe() (uint64, <-chan LiveData, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.subscribers) >= maxSubscribers {
		return 0, nil, errors.New("statistics stream capacity reached")
	}
	f.nextID++
	channel := make(chan LiveData, 1)
	f.subscribers[f.nextID] = channel
	return f.nextID, channel, nil
}

func (f *Feed) Unsubscribe(id uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if channel := f.subscribers[id]; channel != nil {
		delete(f.subscribers, id)
		close(channel)
	}
}
