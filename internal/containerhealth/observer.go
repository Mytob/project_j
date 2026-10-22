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
	"strconv"
	"strings"
	"time"
)

const managedLabel = "jellyfin.proxy.role=application"

// The observer uses the lowest Docker API version supported by both this
// client and the daemon. Keeping the client range explicit prevents a newer
// daemon from changing the API contract unexpectedly.
const (
	minimumDockerAPIVersion = "1.41"
	maximumDockerAPIVersion = "1.52"
)

// Snapshot contains the deliberately small subset of Docker inspect data that
// the administrator health page needs. Environment, mounts, and other inspect
// fields are never returned by this service.
type Snapshot struct {
	Service          string    `json:"service"`
	State            string    `json:"state"`
	Health           string    `json:"health"`
	RestartCount     int       `json:"restart_count"`
	Image            string    `json:"image,omitempty"`
	ComponentVersion string    `json:"component_version,omitempty"`
	StartedAt        time.Time `json:"started_at,omitempty"`
	CheckedAt        time.Time `json:"checked_at"`
}

type RuntimeInventory struct {
	UbuntuVersion       string             `json:"ubuntu_version,omitempty"`
	ProxyctlVersion     string             `json:"proxyctl_version,omitempty"`
	DockerEngineVersion string             `json:"docker_engine_version,omitempty"`
	ComposeVersion      string             `json:"compose_version,omitempty"`
	Services            []ServiceInventory `json:"services"`
}

type ServiceInventory struct {
	Service          string `json:"service"`
	Image            string `json:"image"`
	ComponentVersion string `json:"component_version,omitempty"`
}

type Observer struct {
	socket        string
	client        *http.Client
	restartClient *http.Client
	now           func() time.Time
}

func New(socket string) *Observer {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	return &Observer{socket: socket, client: &http.Client{Transport: transport, Timeout: 4 * time.Second}, restartClient: &http.Client{Transport: transport, Timeout: 25 * time.Second}, now: time.Now}
}

// Restart applies one internal recovery action to a fixed Compose service. It
// is intentionally not exposed as an HTTP handler or a generic Docker proxy.
func (o *Observer) Restart(ctx context.Context, service string) error {
	if !recoverableComposeService(service) {
		return errors.New("Docker restart service is not allowlisted")
	}
	apiVersion, err := o.negotiateAPIVersion(ctx)
	if err != nil {
		return err
	}
	filters, _ := json.Marshal(map[string][]string{"label": {managedLabel}})
	query := url.Values{"all": {"1"}, "filters": {string(filters)}}
	var containers []containerSummary
	if err := o.get(ctx, "/v"+apiVersion+"/containers/json?"+query.Encode(), &containers); err != nil {
		return err
	}
	var selected string
	for _, item := range containers {
		if item.Labels["com.docker.compose.service"] != service || item.Labels["jellyfin.proxy.role"] != "application" {
			continue
		}
		if item.ID == "" || selected != "" {
			return errors.New("Docker returned an ambiguous managed service identity")
		}
		selected = item.ID
	}
	if selected == "" {
		return errors.New("managed service container was not found")
	}
	var detail containerInspect
	if err := o.get(ctx, "/v"+apiVersion+"/containers/"+url.PathEscape(selected)+"/json", &detail); err != nil {
		return err
	}
	if detail.Config.Labels["jellyfin.proxy.role"] != "application" || detail.Config.Labels["com.docker.compose.service"] != service {
		return errors.New("managed service identity changed before restart")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/v"+apiVersion+"/containers/"+url.PathEscape(selected)+"/restart?t=10", nil)
	if err != nil {
		return err
	}
	response, err := o.restartClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Docker restart returned status %d", response.StatusCode)
	}
	return nil
}

func recoverableComposeService(service string) bool {
	switch service {
	case "admin", "caddy", "hostmetrics", "securityd", "wireguard":
		return true
	default:
		return false
	}
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
	apiVersion, err := o.negotiateAPIVersion(ctx)
	if err != nil {
		return nil, err
	}
	filters, _ := json.Marshal(map[string][]string{"label": {managedLabel}})
	query := url.Values{"all": {"1"}, "filters": {string(filters)}}
	var containers []containerSummary
	if err := o.get(ctx, "/v"+apiVersion+"/containers/json?"+query.Encode(), &containers); err != nil {
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
		if err := o.get(ctx, "/v"+apiVersion+"/containers/"+url.PathEscape(item.ID)+"/json", &detail); err != nil {
			return nil, fmt.Errorf("inspect managed container: %w", err)
		}
		if detail.Config.Labels["jellyfin.proxy.role"] != "application" {
			continue
		}
		entry := Snapshot{Service: service, State: detail.State.Status, Health: "none", RestartCount: detail.RestartCount, Image: detail.Config.Image, ComponentVersion: detail.Config.Labels["jellyfin.proxy.component-version"], CheckedAt: o.now().UTC()}
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

// Inventory reports only the running Docker Engine version and version labels
// from Jellyfin Proxy managed containers. It never returns arbitrary inspect
// configuration, environment, mounts, or unrelated container data.
func (o *Observer) Inventory(ctx context.Context) (RuntimeInventory, error) {
	snapshots, err := o.Snapshot(ctx)
	if err != nil {
		return RuntimeInventory{}, err
	}
	var daemon dockerVersion
	if err := o.get(ctx, "/version", &daemon); err != nil {
		return RuntimeInventory{}, fmt.Errorf("read Docker Engine version: %w", err)
	}
	if len(daemon.Version) > 64 || strings.TrimSpace(daemon.Version) != daemon.Version {
		return RuntimeInventory{}, errors.New("Docker Engine version metadata is invalid")
	}
	result := RuntimeInventory{DockerEngineVersion: daemon.Version, Services: make([]ServiceInventory, 0, len(snapshots))}
	for _, item := range snapshots {
		if item.Image == "" || len(item.Image) > 256 || strings.ContainsAny(item.Image, "\r\n") || len(item.ComponentVersion) > 128 || strings.ContainsAny(item.ComponentVersion, "\r\n") {
			return RuntimeInventory{}, errors.New("managed container version metadata is invalid")
		}
		result.Services = append(result.Services, ServiceInventory{Service: item.Service, Image: item.Image, ComponentVersion: item.ComponentVersion})
	}
	return result, nil
}

type dockerVersion struct {
	Version       string `json:"Version"`
	APIVersion    string `json:"ApiVersion"`
	MinAPIVersion string `json:"MinAPIVersion"`
}

type apiVersionNumber struct{ major, minor int }

func parseAPIVersion(value string) (apiVersionNumber, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || !decimalDigits(parts[0]) || !decimalDigits(parts[1]) {
		return apiVersionNumber{}, fmt.Errorf("invalid Docker API version %q", value)
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	if majorErr != nil || minorErr != nil || major < 1 || minor < 0 {
		return apiVersionNumber{}, fmt.Errorf("invalid Docker API version %q", value)
	}
	return apiVersionNumber{major: major, minor: minor}, nil
}

func decimalDigits(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func (v apiVersionNumber) less(other apiVersionNumber) bool {
	return v.major < other.major || (v.major == other.major && v.minor < other.minor)
}

func (o *Observer) negotiateAPIVersion(ctx context.Context) (string, error) {
	var daemon dockerVersion
	if err := o.get(ctx, "/version", &daemon); err != nil {
		return "", fmt.Errorf("read Docker API version: %w", err)
	}
	clientMinimum, _ := parseAPIVersion(minimumDockerAPIVersion)
	clientMaximum, _ := parseAPIVersion(maximumDockerAPIVersion)
	daemonMaximum, err := parseAPIVersion(daemon.APIVersion)
	if err != nil {
		return "", err
	}
	selectedMinimum := clientMinimum
	if daemon.MinAPIVersion != "" {
		daemonMinimum, err := parseAPIVersion(daemon.MinAPIVersion)
		if err != nil {
			return "", err
		}
		if selectedMinimum.less(daemonMinimum) {
			selectedMinimum = daemonMinimum
		}
	}
	selectedMaximum := clientMaximum
	if daemonMaximum.less(selectedMaximum) {
		selectedMaximum = daemonMaximum
	}
	if selectedMaximum.less(selectedMinimum) {
		return "", fmt.Errorf("Docker API range %s-%s is not supported by observer range %s-%s", daemon.MinAPIVersion, daemon.APIVersion, minimumDockerAPIVersion, maximumDockerAPIVersion)
	}
	return fmt.Sprintf("%d.%d", selectedMinimum.major, selectedMinimum.minor), nil
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
		Image  string            `json:"Image"`
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
