package caddytelemetry

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRecorderCountsInFlightStreamingBytesAndErrors(t *testing.T) {
	data := &counters{}
	recorder := Recorder{data: data}
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/stream", strings.NewReader("upload-body"))
	go func() {
		done <- recorder.ServeHTTP(response, request, handlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				return err
			}
			w.WriteHeader(http.StatusPartialContent)
			if _, err := io.WriteString(w, "first chunk"); err != nil {
				return err
			}
			close(entered)
			<-release
			_, err := io.WriteString(w, "second chunk")
			return err
		}))
	}()
	<-entered
	if data.active.Load() != 1 || data.requests.Load() != 1 || data.incoming.Load() != uint64(len("upload-body")) || data.outgoing.Load() != uint64(len("first chunk")) {
		t.Fatalf("in-flight counters active=%d requests=%d in=%d out=%d", data.active.Load(), data.requests.Load(), data.incoming.Load(), data.outgoing.Load())
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if data.active.Load() != 0 || data.errors.Load() != 0 || data.outgoing.Load() != uint64(len("first chunksecond chunk")) {
		t.Fatalf("final counters active=%d errors=%d outgoing=%d", data.active.Load(), data.errors.Load(), data.outgoing.Load())
	}
}

func TestAllowlistDenyCountsOnlyExplicitHTTPDenials(t *testing.T) {
	data := &counters{}
	deny := Deny{data: data}
	response := httptest.NewRecorder()
	if err := deny.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil), nil); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusForbidden || data.blocked.Load() != 1 {
		t.Fatalf("deny response=%d blocked=%d", response.Code, data.blocked.Load())
	}
}

func TestHijackedConnectionCountsWebSocketBytesBothDirections(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	base := &hijackWriter{conn: server}
	incoming := &atomic.Uint64{}
	outgoing := &atomic.Uint64{}
	tracked := &trackedResponseWriter{ResponseWriter: base, incoming: incoming, count: outgoing}
	conn, rw, err := tracked.Hijack()
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("client-frame"))
		writeDone <- err
	}()
	buffer := make([]byte, len("client-frame"))
	if _, err := io.ReadFull(rw.Reader, buffer); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if _, err := rw.Writer.WriteString("proxy-frame"); err != nil {
		t.Fatal(err)
	}
	flushDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(client, make([]byte, len("proxy-frame")))
		flushDone <- err
	}()
	if err := rw.Writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := <-flushDone; err != nil {
		t.Fatal(err)
	}
	if incoming.Load() != uint64(len("client-frame")) || outgoing.Load() != uint64(len("proxy-frame")) {
		t.Fatalf("WebSocket byte counters in=%d out=%d", incoming.Load(), outgoing.Load())
	}
	_ = conn.Close()
}

func TestPublishWritesRateSnapshotAtomicallyAndHandlesCounterReset(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "current.json")
	data := &counters{path: path, lastAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), lastReq: 10, lastErr: 1, lastIn: 100, lastOut: 1000}
	data.requests.Store(15)
	data.blocked.Store(2)
	data.errors.Store(2)
	data.incoming.Store(600)
	data.outgoing.Store(100)
	at := data.lastAt.Add(time.Second)
	if err := data.publish(at); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var metrics ProxyMetrics
	if err := json.Unmarshal(encoded, &metrics); err != nil {
		t.Fatal(err)
	}
	if metrics.AllowedRequests != 13 || metrics.BlockedRequests != 2 || metrics.TotalTransferredBytes != 700 || metrics.RequestsPerSecond == nil || *metrics.RequestsPerSecond != 5 || metrics.IncomingBytesPerSecond == nil || *metrics.IncomingBytesPerSecond != 500 || metrics.OutgoingBytesPerSecond == nil || *metrics.OutgoingBytesPerSecond != 0 {
		t.Fatalf("published metrics = %+v", metrics)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || entries[0].Name() != "current.json" {
		t.Fatalf("snapshot replacement left temporary files: %v, %v", entries, err)
	}
}

type handlerFunc func(http.ResponseWriter, *http.Request) error

func (f handlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error { return f(w, r) }

type hijackWriter struct {
	conn    net.Conn
	headers http.Header
}

func (w *hijackWriter) Header() http.Header {
	if w.headers == nil {
		w.headers = make(http.Header)
	}
	return w.headers
}
func (*hijackWriter) Write(data []byte) (int, error) { return len(data), nil }
func (*hijackWriter) WriteHeader(int)                {}
func (w *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}
