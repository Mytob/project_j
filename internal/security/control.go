package security

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ControlAPI struct {
	Manager  *Manager
	OnChange func(context.Context) error
	OnUnban  func(context.Context, Service, string) error
}

func (a *ControlAPI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/snapshot", a.snapshot)
	mux.HandleFunc("GET /v1/history", a.history)
	mux.HandleFunc("GET /v1/events", a.events)
	mux.HandleFunc("PUT /v1/config", a.updateConfig)
	mux.HandleFunc("POST /v1/unban", a.unban)
	return mux
}

func (a *ControlAPI) snapshot(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, summarySnapshot(a.Manager.Snapshot()))
}

func (a *ControlAPI) history(w http.ResponseWriter, r *http.Request) {
	rows, ok := a.Manager.History(r.URL.Query().Get("range"), r.URL.Query().Get("service"), r.URL.Query().Get("q"))
	if !ok {
		http.Error(w, "Unsupported history filter", http.StatusBadRequest)
		return
	}
	writeJSON(w, rows)
}

func (a *ControlAPI) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Event stream is unavailable", http.StatusInternalServerError)
		return
	}
	id, updates, err := a.Manager.Subscribe()
	if err != nil {
		http.Error(w, "Event stream capacity reached", http.StatusServiceUnavailable)
		return
	}
	defer a.Manager.Unsubscribe(id)
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "retry: 2000\n\n")
	flusher.Flush()
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case snapshot, open := <-updates:
			if !open || writeSSE(w, flusher, snapshot) != nil {
				return
			}
		case <-keepalive.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (a *ControlAPI) updateConfig(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		http.Error(w, "Invalid security configuration", http.StatusBadRequest)
		return
	}
	if err := requireJSONEOF(decoder); err != nil {
		http.Error(w, "Invalid security configuration", http.StatusBadRequest)
		return
	}
	previous := a.Manager.Snapshot().Config
	if err := a.Manager.UpdateConfig(config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if a.OnChange != nil {
		if err := a.OnChange(r.Context()); err != nil {
			rollbackErr := a.Manager.UpdateConfig(previous)
			if rollbackErr != nil {
				http.Error(w, "Configuration application failed and automatic rollback also failed", http.StatusInternalServerError)
				return
			}
			_ = a.OnChange(r.Context())
			http.Error(w, "Configuration could not be applied; the previous settings were restored", http.StatusServiceUnavailable)
			return
		}
	}
	writeJSON(w, summarySnapshot(a.Manager.Snapshot()))
}

func (a *ControlAPI) unban(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request struct {
		Service Service `json:"service"`
		IP      string  `json:"ip"`
	}
	if err := decoder.Decode(&request); err != nil || requireJSONEOF(decoder) != nil {
		http.Error(w, "Invalid unban request", http.StatusBadRequest)
		return
	}
	ip, err := canonicalIP(request.IP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	request.IP = ip
	if !a.Manager.HasBan(request.Service, request.IP) {
		http.Error(w, "No active ban exists for that service and IP", http.StatusNotFound)
		return
	}
	if a.OnUnban != nil {
		if err := a.OnUnban(r.Context(), request.Service, request.IP); err != nil {
			http.Error(w, "The enforcement layer could not remove this ban", http.StatusServiceUnavailable)
			return
		}
	}
	removed, err := a.Manager.Unban(request.Service, request.IP)
	if err != nil {
		if a.OnChange != nil {
			_ = a.OnChange(r.Context())
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !removed {
		http.Error(w, "No active ban exists for that service and IP", http.StatusNotFound)
		return
	}
	writeJSON(w, summarySnapshot(a.Manager.Snapshot()))
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return
	}
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, snapshot Snapshot) error {
	payload, err := json.Marshal(summarySnapshot(snapshot))
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: security\ndata: %s\n\n", payload); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

func summarySnapshot(snapshot Snapshot) Snapshot {
	snapshot.History = nil
	return snapshot
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON data")
		}
		return err
	}
	return nil
}

type Client struct {
	socket string
	http   *http.Client
}

func NewClient(socket string) (*Client, error) {
	if strings.TrimSpace(socket) == "" {
		return nil, errors.New("security control socket path is empty")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	return &Client{socket: socket, http: &http.Client{Transport: transport}}, nil
}

func (c *Client) Snapshot(ctx context.Context) (Snapshot, error) {
	var snapshot Snapshot
	err := c.requestJSON(ctx, http.MethodGet, "/v1/snapshot", nil, &snapshot)
	return snapshot, err
}

func (c *Client) History(ctx context.Context, rangeName, service, query string) ([]HistoryEvent, error) {
	values := url.Values{"range": {rangeName}, "service": {service}, "q": {query}}
	var history []HistoryEvent
	err := c.requestJSON(ctx, http.MethodGet, "/v1/history?"+values.Encode(), nil, &history)
	return history, err
}

func (c *Client) UpdateConfig(ctx context.Context, config Config) (Snapshot, error) {
	var snapshot Snapshot
	err := c.requestJSON(ctx, http.MethodPut, "/v1/config", config, &snapshot)
	return snapshot, err
}

func (c *Client) Unban(ctx context.Context, service Service, ip string) (Snapshot, error) {
	var snapshot Snapshot
	err := c.requestJSON(ctx, http.MethodPost, "/v1/unban", map[string]any{"service": service, "ip": ip}, &snapshot)
	return snapshot, err
}

func (c *Client) Subscribe(ctx context.Context) (<-chan Snapshot, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://security/v1/events", nil)
	if err != nil {
		return nil, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		defer response.Body.Close()
		return nil, fmt.Errorf("security event stream returned status %d", response.StatusCode)
	}
	updates := make(chan Snapshot, 1)
	go func() {
		defer close(updates)
		defer response.Body.Close()
		scanner := bufio.NewScanner(response.Body)
		scanner.Buffer(make([]byte, 4096), 256<<10)
		var data strings.Builder
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				data.WriteString(strings.TrimPrefix(line, "data: "))
				continue
			}
			if line != "" {
				continue
			}
			if data.Len() > 0 {
				var snapshot Snapshot
				if json.Unmarshal([]byte(data.String()), &snapshot) == nil {
					select {
					case updates <- snapshot:
					default:
						select {
						case <-updates:
						default:
						}
						select {
						case updates <- snapshot:
						default:
						}
					}
				}
				data.Reset()
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()
	return updates, nil
}

func (c *Client) requestJSON(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = strings.NewReader(string(encoded))
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://security"+path, body)
	if err != nil {
		return err
	}
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("security service returned %d: %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	if output == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 256<<10)).Decode(output); err != nil {
		return err
	}
	return nil
}
