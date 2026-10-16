package containerhealth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const managedLabel = "jellyfin.proxy.role=application"

// Snapshot contains the deliberately small subset of Docker inspect data that
// the administrator health page needs. Environment, mounts, and other inspect
// fields are never returned by this service.
type Snapshot struct {
	Service      string    `json:"service"`
	State        string    `json:"state"`
	Health       string    `json:"health"`
	RestartCount int       `json:"restart_count"`
	StartedAt    time.Time `json:"started_at,omitempty"`
	CheckedAt    time.Time `json:"checked_at"`
}

type Observer struct {
	socket string
	client *http.Client
	now    func() time.Time
}

func New(socket string) *Observer {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	return &Observer{socket: socket, client: &http.Client{Transport: transport, Timeout: 4 * time.Second}, now: time.Now}
}

func (o *Observer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /containers", o.containers)
	return mux
}

func (o *Observer) containers(w http.ResponseWriter, r *http.Request) {
	items, err := o.Snapshot(r.Context())
	if err != nil {
		http.Error(w, "container health observation is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(items)
}

func (o *Observer) Snapshot(ctx context.Context) ([]Snapshot, error) {
	filters, _ := json.Marshal(map[string][]string{"label": {managedLabel}})
	query := url.Values{"all": {"1"}, "filters": {string(filters)}}
	var containers []containerSummary
	if err := o.get(ctx, "/v1.41/containers/json?"+query.Encode(), &containers); err != nil {
		return nil, err
	}
	if len(containers) > 100 {
		return nil, errors.New("too many managed containers returned")
	}
	result := make([]Snapshot, 0, len(containers))
	for _, item := range containers {
		service := item.Labels["com.docker.compose.service"]
		if service == "" || item.ID == "" || item.Labels["jellyfin.proxy.role"] != "application" {
			continue
		}
		var detail containerInspect
		if err := o.get(ctx, "/v1.41/containers/"+url.PathEscape(item.ID)+"/json", &detail); err != nil {
			return nil, fmt.Errorf("inspect managed container: %w", err)
		}
		if detail.Config.Labels["jellyfin.proxy.role"] != "application" {
			continue
		}
		entry := Snapshot{Service: service, State: detail.State.Status, Health: "none", RestartCount: detail.RestartCount, CheckedAt: o.now().UTC()}
		if detail.State.Health != nil && detail.State.Health.Status != "" {
			entry.Health = detail.State.Health.Status
		}
		if detail.State.StartedAt != "" && detail.State.StartedAt != "0001-01-01T00:00:00Z" {
			entry.StartedAt, _ = time.Parse(time.RFC3339Nano, detail.State.StartedAt)
		}
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Service < result[j].Service })
	return result, nil
}

func (o *Observer) get(ctx context.Context, path string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	response, err := o.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Docker API returned status %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return nil
}

type containerSummary struct {
	ID     string            `json:"Id"`
	Labels map[string]string `json:"Labels"`
}

type containerInspect struct {
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Status    string `json:"Status"`
		StartedAt string `json:"StartedAt"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	RestartCount int `json:"RestartCount"`
}

func StateName(state string) string { return strings.ToLower(strings.TrimSpace(state)) }
