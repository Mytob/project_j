package caddytelemetry

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const defaultSnapshotPath = "/run/proxy-metrics/current.json"

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

type counters struct {
	active   atomic.Int64
	requests atomic.Uint64
	blocked  atomic.Uint64
	errors   atomic.Uint64
	incoming atomic.Uint64
	outgoing atomic.Uint64
	mu       sync.Mutex
	path     string
	lastAt   time.Time
	lastReq  uint64
	lastErr  uint64
	lastIn   uint64
	lastOut  uint64
}

var registry = struct {
	sync.Mutex
	items map[string]*counters
}{items: make(map[string]*counters)}

func forPath(path string) *counters {
	if path == "" {
		path = defaultSnapshotPath
	}
	registry.Lock()
	defer registry.Unlock()
	if current := registry.items[path]; current != nil {
		return current
	}
	current := &counters{path: path}
	registry.items[path] = current
	go current.publishLoop()
	return current
}

func (c *counters) publishLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for at := range ticker.C {
		_ = c.publish(at.UTC()) // Measurement export is best-effort; never block proxy requests.
	}
}

func (c *counters) publish(at time.Time) error {
	requests := c.requests.Load()
	blocked := c.blocked.Load()
	errors := c.errors.Load()
	incoming := c.incoming.Load()
	outgoing := c.outgoing.Load()
	if blocked > requests {
		blocked = requests
	}
	metrics := ProxyMetrics{
		CapturedAt: at, ActiveRequests: c.active.Load(),
		AllowedRequests: requests - blocked, BlockedRequests: blocked,
		HTTPErrorCount: errors, IncomingTransferredBytes: incoming,
		OutgoingTransferredBytes: outgoing,
	}
	if ^uint64(0)-incoming >= outgoing {
		metrics.TotalTransferredBytes = incoming + outgoing
	}
	c.mu.Lock()
	if !c.lastAt.IsZero() {
		seconds := at.Sub(c.lastAt).Seconds()
		if seconds > 0 {
			requestDelta := delta(requests, c.lastReq)
			errorDelta := delta(errors, c.lastErr)
			incomingDelta := delta(incoming, c.lastIn)
			outgoingDelta := delta(outgoing, c.lastOut)
			metrics.RequestsPerSecond = floatPointer(float64(requestDelta) / seconds)
			metrics.IncomingBytesPerSecond = uintPointer(uint64(float64(incomingDelta) / seconds))
			metrics.OutgoingBytesPerSecond = uintPointer(uint64(float64(outgoingDelta) / seconds))
			if requestDelta > 0 {
				metrics.ErrorRatePercent = floatPointer(float64(errorDelta) * 100 / float64(requestDelta))
			}
		}
	}
	c.lastAt, c.lastReq, c.lastErr, c.lastIn, c.lastOut = at, requests, errors, incoming, outgoing
	c.mu.Unlock()

	data, err := json.Marshal(metrics)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(c.path), ".proxy-metrics-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err := temp.Chmod(0o644); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
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
	return os.Rename(temp.Name(), c.path)
}

func delta(current, previous uint64) uint64 {
	if current < previous { // A counter reset starts a fresh rate interval.
		return 0
	}
	return current - previous
}
func floatPointer(value float64) *float64 { return &value }
func uintPointer(value uint64) *uint64    { return &value }

// Recorder wraps only the access hostname's route. Request and response body
// bytes are counted as Read and Write occur, so a long media stream updates
// while it is in flight. No body is buffered.
type Recorder struct {
	Path string `json:"path,omitempty"`
	data *counters
}

func (Recorder) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.jp_proxy_metrics", New: func() caddy.Module { return new(Recorder) }}
}

func (m *Recorder) Provision(caddy.Context) error {
	m.data = forPath(m.Path)
	return nil
}

func (m Recorder) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if m.data == nil {
		return errors.New("proxy metrics handler was not provisioned")
	}
	data := m.data
	data.active.Add(1)
	data.requests.Add(1)
	if r.Body != nil {
		r.Body = &countingReadCloser{ReadCloser: r.Body, count: &data.incoming}
	}
	tracked := &trackedResponseWriter{ResponseWriter: w, incoming: &data.incoming, count: &data.outgoing}
	err := next.ServeHTTP(tracked, r)
	if err == nil {
		if tracked.status >= http.StatusBadRequest {
			data.errors.Add(1)
		}
	} else {
		data.errors.Add(1)
	}
	data.active.Add(-1)
	return err
}

func (m *Recorder) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

type Deny struct {
	Path string `json:"path,omitempty"`
	data *counters
}

func (Deny) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.jp_metrics_deny", New: func() caddy.Module { return new(Deny) }}
}

func (m *Deny) Provision(caddy.Context) error {
	m.data = forPath(m.Path)
	return nil
}

func (m Deny) ServeHTTP(w http.ResponseWriter, _ *http.Request, _ caddyhttp.Handler) error {
	if m.data == nil {
		return errors.New("proxy deny metrics handler was not provisioned")
	}
	m.data.blocked.Add(1)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, err := io.WriteString(w, "Forbidden\n")
	return err
}

func (m *Deny) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

type countingReadCloser struct {
	io.ReadCloser
	count *atomic.Uint64
}

func (r *countingReadCloser) Read(data []byte) (int, error) {
	n, err := r.ReadCloser.Read(data)
	if n > 0 {
		r.count.Add(uint64(n))
	}
	return n, err
}

type trackedResponseWriter struct {
	http.ResponseWriter
	incoming *atomic.Uint64
	count    *atomic.Uint64
	status   int
}

func (w *trackedResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *trackedResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *trackedResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(data)
	if n > 0 {
		w.count.Add(uint64(n))
	}
	return n, err
}

func (w *trackedResponseWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *trackedResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("underlying response writer does not support hijacking")
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	tracked := &countingConn{Conn: conn, incoming: w.incoming, outgoing: w.count}
	pending := rw.Reader.Buffered()
	buffered := make([]byte, pending)
	if pending > 0 {
		if _, err := io.ReadFull(rw.Reader, buffered); err != nil {
			conn.Close()
			return nil, nil, err
		}
	}
	return tracked, bufio.NewReadWriter(bufio.NewReader(io.MultiReader(bytes.NewReader(buffered), tracked)), bufio.NewWriter(tracked)), nil
}

func (w *trackedResponseWriter) Push(target string, options *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, options)
	}
	return http.ErrNotSupported
}

type countingConn struct {
	net.Conn
	incoming *atomic.Uint64
	outgoing *atomic.Uint64
}

func (c *countingConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if n > 0 && c.incoming != nil {
		c.incoming.Add(uint64(n))
	}
	return n, err
}

func (c *countingConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	if n > 0 && c.outgoing != nil {
		c.outgoing.Add(uint64(n))
	}
	return n, err
}

func parseRecorder(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var module Recorder
	if err := module.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &module, nil
}

func parseDeny(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var module Deny
	if err := module.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &module, nil
}

func init() {
	caddy.RegisterModule(Recorder{})
	caddy.RegisterModule(Deny{})
	httpcaddyfile.RegisterHandlerDirective("jp_proxy_metrics", parseRecorder)
	httpcaddyfile.RegisterHandlerDirective("jp_metrics_deny", parseDeny)
	httpcaddyfile.RegisterDirectiveOrder("jp_metrics_deny", httpcaddyfile.Before, "respond")
}

var (
	_ caddy.Module                = (*Recorder)(nil)
	_ caddy.Provisioner           = (*Recorder)(nil)
	_ caddyhttp.MiddlewareHandler = (*Recorder)(nil)
	_ caddyfile.Unmarshaler       = (*Recorder)(nil)
	_ caddy.Module                = (*Deny)(nil)
	_ caddy.Provisioner           = (*Deny)(nil)
	_ caddyhttp.MiddlewareHandler = (*Deny)(nil)
	_ caddyfile.Unmarshaler       = (*Deny)(nil)
)
