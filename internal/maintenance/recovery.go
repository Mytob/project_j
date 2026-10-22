package maintenance

import (
	"context"
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

	"github.com/Mytob/project_j/internal/containerhealth"
)

const (
	DefaultRecoveryStatePath = "/var/lib/jellyfin-proxy-maintenance/recovery.json"
	recoveryStateVersion    = 1
	recoveryAttemptLimit    = 5
	recoveryEventLimit      = 100
	recoveryStableWindow    = 10 * time.Minute
	recoveryInitialBackoff  = 15 * time.Second
	recoveryMaximumBackoff  = 5 * time.Minute
)

var recoverableServices = []string{"admin", "caddy", "hostmetrics", "securityd", "wireguard"}

type RecoveryRuntime interface {
	Snapshot(context.Context) ([]containerhealth.Snapshot, error)
	Restart(context.Context, string) error
}

type RecoveryService struct {
	Service        string    `json:"service"`
	State          string    `json:"state"`
	Health         string    `json:"health"`
	Attempts       int       `json:"attempts"`
	NextAttemptAt  time.Time `json:"next_attempt_at,omitempty"`
	HealthySince   time.Time `json:"healthy_since,omitempty"`
	LastAction     string    `json:"last_action,omitempty"`
	LastEventAt    time.Time `json:"last_event_at,omitempty"`
	Stopped        bool      `json:"stopped"`
	Detail         string    `json:"detail,omitempty"`
}

type RecoveryEvent struct {
	At       time.Time `json:"at"`
	Service  string    `json:"service"`
	Action   string    `json:"action"`
	Attempt  int       `json:"attempt"`
	Detail   string    `json:"detail"`
}

type RecoveryStatus struct {
	CheckedAt      time.Time         `json:"checked_at,omitempty"`
	OperationActive bool             `json:"operation_active"`
	Services       []RecoveryService `json:"services"`
	Events         []RecoveryEvent  `json:"events"`
}

type recoveryDocument struct {
	Version   int                         `json:"version"`
	CheckedAt time.Time                   `json:"checked_at,omitempty"`
	Services  map[string]RecoveryService `json:"services"`
	Events    []RecoveryEvent            `json:"events"`
}

// RecoveryController restarts only the five fixed application services when
// Docker reports a stopped or unhealthy container. It never uses Jellyfin
// endpoint reachability as a restart signal.
type RecoveryController struct {
	mu          sync.Mutex
	path        string
	runtime     RecoveryRuntime
	jobs        *JobManager
	now         func() time.Time
	document    recoveryDocument
	loadErr     error
}

func NewRecoveryController(runtime RecoveryRuntime, jobs *JobManager, path string) (*RecoveryController, error) {
	if runtime == nil || jobs == nil || !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return nil, errors.New("service recovery configuration is invalid")
	}
	c := &RecoveryController{runtime: runtime, jobs: jobs, path: filepath.Clean(path), now: time.Now, document: recoveryDocument{Version: recoveryStateVersion, Services: make(map[string]RecoveryService), Events: make([]RecoveryEvent, 0)}}
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *RecoveryController) RunOnce(ctx context.Context) error {
	releaseOperationGate := c.jobs.lockRecovery()
	defer releaseOperationGate()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loadErr != nil {
		return errors.New("service recovery state is unavailable")
	}
	now := c.now().UTC()
	snapshots, err := c.runtime.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("observe managed application services: %w", err)
	}
	observed := make(map[string]containerhealth.Snapshot, len(snapshots))
	for _, snapshot := range snapshots {
		if !allowedRecoveryService(snapshot.Service) {
			continue
		}
		if _, exists := observed[snapshot.Service]; exists {
			return errors.New("container observer returned a duplicate managed service")
		}
		observed[snapshot.Service] = snapshot
	}
	operationActive := c.jobs.HasActiveOperation()
	restartAttempted := false
	for _, service := range recoverableServices {
		state := c.document.Services[service]
		state.Service = service
		snapshot, exists := observed[service]
		if !exists {
			state.State = "missing"
			state.Health = "unknown"
			state.Detail = "managed container was not returned by Docker"
			state.HealthySince = time.Time{}
			c.document.Services[service] = state
			continue
		}
		state.State = safeObservedState(snapshot.State)
		state.Health = safeObservedState(snapshot.Health)
		if containerHealthy(snapshot) {
			state.Detail = ""
			state.Stopped = false
			if state.Attempts > 0 {
				if state.HealthySince.IsZero() {
					state.HealthySince = now
				} else if now.Sub(state.HealthySince) >= recoveryStableWindow {
					state.Attempts = 0
					state.NextAttemptAt = time.Time{}
					state.HealthySince = now
					state.Stopped = false
					state.LastAction = "recovered"
					state.LastEventAt = now
					c.appendEvent(RecoveryEvent{At: now, Service: service, Action: "recovered", Attempt: 0, Detail: "service stayed healthy for ten minutes; retry limit reset"})
				}
			}
			c.document.Services[service] = state
			continue
		}
		if !recoverableFailure(snapshot) {
			state.Detail = "Docker has not reported a stopped or unhealthy service state"
			c.document.Services[service] = state
			continue
		}
		state.HealthySince = time.Time{}
		state.Detail = unhealthyDetail(snapshot)
		if state.State == "restarting" {
			state.Detail = "Docker is already restarting this service"
			c.document.Services[service] = state
			continue
		}
		if operationActive {
			state.Detail = "maintenance operation is stopping or replacing application services"
			c.document.Services[service] = state
			continue
		}
		if state.Attempts >= recoveryAttemptLimit {
			if !state.Stopped {
				state.Stopped = true
				state.NextAttemptAt = time.Time{}
				state.LastAction = "retry_limit_reached"
				state.LastEventAt = now
				c.appendEvent(RecoveryEvent{At: now, Service: service, Action: "retry_limit_reached", Attempt: state.Attempts, Detail: "automatic recovery stopped after five attempts; inspect Health and run proxyctl doctor"})
			}
			c.document.Services[service] = state
			continue
		}
		if !state.NextAttemptAt.IsZero() && now.Before(state.NextAttemptAt) {
			c.document.Services[service] = state
			continue
		}
		if restartAttempted {
			state.Detail = "automatic recovery is handling another service"
			c.document.Services[service] = state
			continue
		}
		restartAttempted = true
		state.Attempts++
		state.NextAttemptAt = now.Add(recoveryBackoff(state.Attempts))
		state.LastAction = "restart_requested"
		state.LastEventAt = now
		c.document.Services[service] = state
		c.appendEvent(RecoveryEvent{At: now, Service: service, Action: "restart_requested", Attempt: state.Attempts, Detail: state.Detail})
		if err := c.persist(); err != nil {
			return fmt.Errorf("persist service recovery attempt before restart: %w", err)
		}
		restartCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		restartErr := c.runtime.Restart(restartCtx, service)
		cancel()
		if restartErr != nil {
			state.LastAction = "restart_failed"
			state.Detail = "Docker could not restart this service; inspect Docker and system logs"
			c.appendEvent(RecoveryEvent{At: c.now().UTC(), Service: service, Action: "restart_failed", Attempt: state.Attempts, Detail: state.Detail})
		} else {
			state.LastAction = "restart_sent"
			state.Detail = "restart requested; health will be checked again"
			c.appendEvent(RecoveryEvent{At: c.now().UTC(), Service: service, Action: "restart_sent", Attempt: state.Attempts, Detail: state.Detail})
		}
		state.LastEventAt = c.now().UTC()
		c.document.Services[service] = state
		if err := c.persist(); err != nil {
			return fmt.Errorf("persist service recovery result: %w", err)
		}
	}
	c.document.CheckedAt = now
	return c.persist()
}

func (c *RecoveryController) Status() RecoveryStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	services := make([]RecoveryService, 0, len(recoverableServices))
	for _, name := range recoverableServices {
		if state, ok := c.document.Services[name]; ok {
			services = append(services, state)
		} else {
			services = append(services, RecoveryService{Service: name, State: "unknown", Health: "unknown", Detail: "no recovery check has completed"})
		}
	}
	events := append([]RecoveryEvent(nil), c.document.Events...)
	sort.Slice(events, func(i, j int) bool { return events[i].At.After(events[j].At) })
	return RecoveryStatus{CheckedAt: c.document.CheckedAt, OperationActive: c.jobs.HasActiveOperation(), Services: services, Events: events}
}

func (c *RecoveryController) load() error {
	directory := filepath.Dir(c.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create service recovery state directory: %w", err)
	}
	dirInfo, err := os.Lstat(directory)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("service recovery state directory is unsafe")
	}
	info, err := os.Lstat(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return c.persist()
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() > 256<<10 {
		return errors.New("service recovery state file is missing or unsafe")
	}
	file, err := os.Open(c.path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(io.LimitReader(file, 256<<10))
	var value recoveryDocument
	decodeErr := decoder.Decode(&value)
	var extra any
	if decodeErr == nil && !errors.Is(decoder.Decode(&extra), io.EOF) {
		decodeErr = errors.New("service recovery state contains trailing data")
	}
	closeErr := file.Close()
	if decodeErr != nil || closeErr != nil || value.Version != recoveryStateVersion || value.Services == nil || len(value.Services) > len(recoverableServices) || len(value.Events) > recoveryEventLimit {
		return errors.New("service recovery state is invalid")
	}
	for name, state := range value.Services {
		if !allowedRecoveryService(name) || state.Service != name || state.Attempts < 0 || state.Attempts > recoveryAttemptLimit || len(state.Detail) > 160 || strings.ContainsAny(state.Detail, "\r\n") {
			return errors.New("service recovery state contains an invalid service record")
		}
	}
	for _, event := range value.Events {
		if event.At.IsZero() || !allowedRecoveryService(event.Service) || len(event.Action) > 32 || len(event.Detail) > 160 || strings.ContainsAny(event.Detail, "\r\n") || event.Attempt < 0 || event.Attempt > recoveryAttemptLimit {
			return errors.New("service recovery history contains an invalid event")
		}
	}
	c.document = value
	return nil
}

func (c *RecoveryController) persist() error {
	data, err := json.Marshal(c.document)
	if err != nil || len(data) > 256<<10 {
		return errors.New("service recovery state exceeds its size limit")
	}
	temp, err := os.CreateTemp(filepath.Dir(c.path), ".recovery-*.tmp")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, c.path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(c.path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (c *RecoveryController) appendEvent(event RecoveryEvent) {
	c.document.Events = append(c.document.Events, event)
	if len(c.document.Events) > recoveryEventLimit {
		c.document.Events = append([]RecoveryEvent(nil), c.document.Events[len(c.document.Events)-recoveryEventLimit:]...)
	}
}

func allowedRecoveryService(value string) bool {
	for _, service := range recoverableServices {
		if value == service {
			return true
		}
	}
	return false
}

func containerHealthy(snapshot containerhealth.Snapshot) bool {
	state := strings.ToLower(strings.TrimSpace(snapshot.State))
	health := strings.ToLower(strings.TrimSpace(snapshot.Health))
	return state == "running" && (health == "healthy" || health == "none" || health == "starting")
}

func recoverableFailure(snapshot containerhealth.Snapshot) bool {
	state := strings.ToLower(strings.TrimSpace(snapshot.State))
	health := strings.ToLower(strings.TrimSpace(snapshot.Health))
	if state == "running" {
		return health == "unhealthy"
	}
	return state == "exited" || state == "dead"
}

func safeObservedState(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "unknown"
	}
	if len(value) > 32 || strings.ContainsAny(value, "\r\n") {
		return "unknown"
	}
	return value
}

func unhealthyDetail(snapshot containerhealth.Snapshot) string {
	if strings.EqualFold(strings.TrimSpace(snapshot.Health), "unhealthy") {
		return "Docker health check reports this service as unhealthy"
	}
	return "Docker reports that this service is not running"
}

func recoveryBackoff(attempt int) time.Duration {
	delay := recoveryInitialBackoff
	for count := 1; count < attempt && delay < recoveryMaximumBackoff; count++ {
		delay *= 2
	}
	if delay > recoveryMaximumBackoff {
		return recoveryMaximumBackoff
	}
	return delay
}
