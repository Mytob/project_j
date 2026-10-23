package security

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const stateSchema = 1

type escalationState struct {
	Level   int       `json:"level"`
	LastBan time.Time `json:"last_ban"`
}

type diskState struct {
	Schema     int                        `json:"schema"`
	Config     Config                     `json:"config"`
	Pending    map[string][]time.Time     `json:"pending"`
	Escalation map[string]escalationState `json:"escalation"`
	Active     map[string]Ban             `json:"active"`
	History    []HistoryEvent             `json:"history"`
	Processed  map[string]time.Time       `json:"processed"`
	Blocked    map[string]uint64          `json:"blocked_requests"`
}

type Manager struct {
	mu             sync.RWMutex
	path           string
	now            func() time.Time
	state          diskState
	health         Health
	subscribers    map[uint64]chan Snapshot
	nextSubscriber uint64
}

const maxSecuritySubscribers = 8

func Open(path string, now func() time.Time) (*Manager, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("security state path is empty")
	}
	if now == nil {
		now = time.Now
	}
	m := &Manager{path: path, now: now, health: Health{Fail2ban: "unknown", SSHJournal: "unknown", Firewall: "unknown", AdminEvents: "unknown", CaddySync: "unknown"}, subscribers: map[uint64]chan Snapshot{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		m.state = newDiskState()
		if err := m.persistLocked(); err != nil {
			return nil, err
		}
		return m, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read security state: %w", err)
	}
	if err := json.Unmarshal(data, &m.state); err != nil {
		return nil, fmt.Errorf("decode security state: %w", err)
	}
	if err := m.normalizeState(); err != nil {
		return nil, err
	}
	if err := m.state.Config.Validate(); err != nil {
		return nil, fmt.Errorf("validate persisted security config: %w", err)
	}
	if m.state.Schema != stateSchema {
		return nil, fmt.Errorf("unsupported security state schema %d", m.state.Schema)
	}
	return m, nil
}

func newDiskState() diskState {
	return diskState{Schema: stateSchema, Config: DefaultConfig(), Pending: map[string][]time.Time{}, Escalation: map[string]escalationState{}, Active: map[string]Ban{}, History: []HistoryEvent{}, Processed: map[string]time.Time{}, Blocked: map[string]uint64{}}
}

func (m *Manager) normalizeState() error {
	if m.state.Schema == 0 {
		m.state.Schema = stateSchema
	}
	if m.state.Pending == nil {
		m.state.Pending = map[string][]time.Time{}
	}
	if m.state.Escalation == nil {
		m.state.Escalation = map[string]escalationState{}
	}
	if m.state.Active == nil {
		m.state.Active = map[string]Ban{}
	}
	if m.state.History == nil {
		m.state.History = []HistoryEvent{}
	}
	if m.state.Processed == nil {
		m.state.Processed = map[string]time.Time{}
	}
	if m.state.Blocked == nil {
		m.state.Blocked = map[string]uint64{}
	}
	return nil
}

func (m *Manager) Apply(event Event) ([]HistoryEvent, error) {
	return m.ApplyBatch([]Event{event})
}

// ApplyBatch serializes a chronological event batch and persists it as one
// transaction. Event IDs make retries after a controller crash idempotent.
func (m *Manager) ApplyBatch(events []Event) ([]HistoryEvent, error) {
	for i := range events {
		if err := events[i].Validate(); err != nil {
			return nil, fmt.Errorf("invalid authentication event: %w", err)
		}
		events[i] = normalizeEvent(events[i])
	}
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].At.Equal(events[j].At) {
			return events[i].ID < events[j].ID
		}
		return events[i].At.Before(events[j].At)
	})
	m.mu.Lock()
	defer m.mu.Unlock()
	before, err := cloneState(m.state)
	if err != nil {
		return nil, err
	}
	created := make([]HistoryEvent, 0, len(events)*2)
	seen := make(map[string]struct{}, len(events))
	for _, event := range events {
		if _, duplicate := seen[event.ID]; duplicate {
			continue
		}
		seen[event.ID] = struct{}{}
		if _, duplicate := m.state.Processed[event.ID]; duplicate {
			continue
		}
		if event.At.After(m.now().UTC().Add(2 * time.Minute)) {
			m.state = before
			return nil, errors.New("authentication event timestamp is too far in the future")
		}
		applied := m.applyLocked(event)
		created = append(created, applied...)
		m.state.History = append(m.state.History, applied...)
		m.state.Processed[event.ID] = event.At
	}
	m.pruneLocked(m.now().UTC())
	if err := m.persistLocked(); err != nil {
		m.state = before
		return nil, err
	}
	m.publishLocked()
	return created, nil
}

func (m *Manager) applyLocked(event Event) []HistoryEvent {
	serviceConfig := m.protection(event.Service)
	identifier := key(event.Service, event.IP)
	created := make([]HistoryEvent, 0, 2)
	if event.Kind == LoginSuccess {
		delete(m.state.Pending, identifier)
		return created
	}
	cutoff := event.At.Add(-serviceConfig.Window)
	pending := m.state.Pending[identifier]
	kept := pending[:0]
	for _, at := range pending {
		if !at.Before(cutoff) && !at.After(event.At) {
			kept = append(kept, at)
		}
	}
	kept = append(kept, event.At)
	m.state.Pending[identifier] = kept
	created = append(created, HistoryEvent{ID: event.ID, At: event.At, Service: event.Service, IP: event.IP, Type: "failure", Details: "Authentication failed", FailedAttempts: len(kept)})
	if len(kept) < serviceConfig.Threshold {
		return created
	}
	if active, exists := m.state.Active[identifier]; exists && active.ExpiresAt.After(event.At) {
		active.FailedAttempts++
		m.state.Active[identifier] = active
		delete(m.state.Pending, identifier)
		return created
	} else if exists {
		delete(m.state.Active, identifier)
	}
	previous := m.state.Escalation[identifier]
	if !previous.LastBan.IsZero() && !event.At.Before(previous.LastBan) && event.At.Sub(previous.LastBan) >= serviceConfig.EscalationReset {
		previous.Level = 0
	}
	level := previous.Level + 1
	if level > len(serviceConfig.BanDurations) {
		level = len(serviceConfig.BanDurations)
	}
	duration := serviceConfig.BanDurations[level-1]
	ban := Ban{Service: event.Service, IP: event.IP, StartedAt: event.At, ExpiresAt: event.At.Add(duration), FailedAttempts: len(kept), Escalation: level}
	m.state.Active[identifier] = ban
	m.state.Escalation[identifier] = escalationState{Level: level, LastBan: event.At}
	delete(m.state.Pending, identifier)
	created = append(created, HistoryEvent{ID: "ban:" + event.ID, At: event.At, Service: event.Service, IP: event.IP, Type: "ban", Details: fmt.Sprintf("Banned for %s", duration), FailedAttempts: ban.FailedAttempts, Escalation: level})
	return created
}

func (m *Manager) Sweep() ([]HistoryEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UTC()
	if !m.sweepNeededLocked(now) {
		return nil, nil
	}
	before, err := cloneState(m.state)
	if err != nil {
		return nil, err
	}
	created := make([]HistoryEvent, 0)
	for identifier, ban := range m.state.Active {
		if !ban.ExpiresAt.After(now) {
			delete(m.state.Active, identifier)
			created = append(created, HistoryEvent{ID: fmt.Sprintf("expired:%s:%d", identifier, ban.ExpiresAt.UnixNano()), At: ban.ExpiresAt, Service: ban.Service, IP: ban.IP, Type: "expired", Details: "Ban expired", FailedAttempts: ban.FailedAttempts, Escalation: ban.Escalation})
		}
	}
	m.state.History = append(m.state.History, created...)
	pruned := m.pruneLocked(now)
	changed := len(created) > 0 || pruned
	if changed {
		if err := m.persistLocked(); err != nil {
			m.state = before
			return nil, err
		}
		m.publishLocked()
	}
	return created, nil
}

func (m *Manager) sweepNeededLocked(now time.Time) bool {
	for _, ban := range m.state.Active {
		if !ban.ExpiresAt.After(now) {
			return true
		}
	}
	historyCutoff := now.Add(-m.state.Config.HistoryRetention)
	for _, event := range m.state.History {
		if event.At.Before(historyCutoff) {
			return true
		}
	}
	processedCutoff := now.Add(-365 * 24 * time.Hour)
	for _, at := range m.state.Processed {
		if at.Before(processedCutoff) {
			return true
		}
	}
	return false
}

func (m *Manager) UpdateConfig(config Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	before, err := cloneState(m.state)
	if err != nil {
		return err
	}
	m.state.Config = cloneConfig(config)
	if err := m.persistLocked(); err != nil {
		m.state = before
		return err
	}
	m.publishLocked()
	return nil
}

func (m *Manager) Unban(service Service, rawIP string) (bool, error) {
	if service != SSH && service != Admin {
		return false, errors.New("service must be ssh or admin")
	}
	ip, err := canonicalIP(rawIP)
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	before, err := cloneState(m.state)
	if err != nil {
		return false, err
	}
	identifier := key(service, ip)
	ban, existed := m.state.Active[identifier]
	delete(m.state.Active, identifier)
	delete(m.state.Pending, identifier)
	if existed {
		at := m.now().UTC()
		m.state.History = append(m.state.History, HistoryEvent{ID: fmt.Sprintf("unban:%s:%d", identifier, at.UnixNano()), At: at, Service: service, IP: ip, Type: "manual_unban", Details: "Manually unbanned", FailedAttempts: ban.FailedAttempts, Escalation: ban.Escalation})
	}
	if err := m.persistLocked(); err != nil {
		m.state = before
		return false, err
	}
	m.publishLocked()
	return existed, nil
}

// IngestBlockedCounts records per-IP aggregate request counts from Caddy.
// Counter resets indicate a Caddy restart and start a new baseline.
func (m *Manager) IngestBlockedCounts(counts map[string]uint64, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	before, err := cloneState(m.state)
	if err != nil {
		return err
	}
	changed := false
	for rawIP, count := range counts {
		ip, err := canonicalIP(rawIP)
		if err != nil {
			continue
		}
		previous := m.state.Blocked[ip]
		if count < previous {
			m.state.Blocked[ip] = count
			changed = true
			continue
		}
		if count == previous {
			continue
		}
		delta := count - previous
		m.state.Blocked[ip] = count
		at = at.UTC()
		m.state.History = append(m.state.History, HistoryEvent{ID: fmt.Sprintf("blocked:%s:%d:%d", ip, at.UnixNano(), count), At: at, Service: Admin, IP: ip, Type: "blocked_requests", Details: fmt.Sprintf("%d requests rejected by the active admin ban", delta), BlockedRequests: delta})
		changed = true
	}
	if !changed {
		return nil
	}
	m.pruneLocked(m.now().UTC())
	if err := m.persistLocked(); err != nil {
		m.state = before
		return err
	}
	m.publishLocked()
	return nil
}

func (m *Manager) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshotLocked()
}

func (m *Manager) HasBan(service Service, rawIP string) bool {
	ip, err := canonicalIP(rawIP)
	if err != nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	ban, ok := m.state.Active[key(service, ip)]
	return ok && ban.ExpiresAt.After(m.now())
}

func (m *Manager) snapshotLocked() Snapshot {
	bans := sortedBans(m.state.Active)
	pending := 0
	for _, failures := range m.state.Pending {
		pending += len(failures)
	}
	history := append([]HistoryEvent(nil), m.state.History...)
	now := m.now().UTC()
	failed, created := 0, 0
	recent := make([]HistoryEvent, 0, len(history))
	for _, event := range history {
		if event.At.Before(now.Add(-24 * time.Hour)) {
			continue
		}
		if event.Type == "failure" {
			failed++
		}
		if event.Type == "ban" {
			created++
		}
		recent = append(recent, event)
	}
	sort.Slice(recent, func(i, j int) bool { return recent[i].At.After(recent[j].At) })
	if len(recent) > 6 {
		recent = recent[:6]
	}
	return Snapshot{Config: cloneConfig(m.state.Config), ActiveBans: bans, History: history, RecentActivity: recent, Failed24h: failed, Bans24h: created, Pending: pending, Health: m.health, CapturedAt: now}
}

func (m *Manager) SetHealth(health Health) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.health = health
	m.publishLocked()
}

func (m *Manager) Subscribe() (uint64, <-chan Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.subscribers) >= maxSecuritySubscribers {
		return 0, nil, errors.New("security event stream capacity reached")
	}
	m.nextSubscriber++
	channel := make(chan Snapshot, 1)
	m.subscribers[m.nextSubscriber] = channel
	channel <- summarySnapshot(m.snapshotLocked())
	return m.nextSubscriber, channel, nil
}

func (m *Manager) Unsubscribe(id uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if channel := m.subscribers[id]; channel != nil {
		delete(m.subscribers, id)
		close(channel)
	}
}

func (m *Manager) publishLocked() {
	snapshot := summarySnapshot(m.snapshotLocked())
	for _, channel := range m.subscribers {
		select {
		case channel <- snapshot:
		default:
			select {
			case <-channel:
			default:
			}
			select {
			case channel <- snapshot:
			default:
			}
		}
	}
}

func (m *Manager) History(rangeName, service, query string) ([]HistoryEvent, bool) {
	durations := map[string]time.Duration{"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}
	duration, ok := durations[rangeName]
	if !ok {
		return nil, false
	}
	if service != "" && service != "all" && service != string(SSH) && service != string(Admin) {
		return nil, false
	}
	query = strings.ToLower(strings.TrimSpace(query))
	m.mu.RLock()
	defer m.mu.RUnlock()
	cutoff := m.now().UTC().Add(-duration)
	result := make([]HistoryEvent, 0)
	for _, event := range m.state.History {
		if event.At.Before(cutoff) || (service != "" && service != "all" && string(event.Service) != service) {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(event.IP+" "+string(event.Service)+" "+event.Type+" "+event.Details), query) {
			continue
		}
		result = append(result, event)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].At.After(result[j].At) })
	return result, true
}

func (m *Manager) protection(service Service) ProtectionConfig {
	if service == SSH {
		return m.state.Config.SSH
	}
	return m.state.Config.Admin
}

func (m *Manager) pruneLocked(now time.Time) bool {
	changed := false
	cutoff := now.Add(-m.state.Config.HistoryRetention)
	history := m.state.History[:0]
	for _, event := range m.state.History {
		if !event.At.Before(cutoff) {
			history = append(history, event)
		} else {
			changed = true
		}
	}
	m.state.History = history
	processedCutoff := now.Add(-365 * 24 * time.Hour)
	for id, at := range m.state.Processed {
		if at.Before(processedCutoff) {
			delete(m.state.Processed, id)
			changed = true
		}
	}
	return changed
}

func cloneState(source diskState) (diskState, error) {
	data, err := json.Marshal(source)
	if err != nil {
		return diskState{}, err
	}
	var clone diskState
	if err := json.Unmarshal(data, &clone); err != nil {
		return diskState{}, err
	}
	return clone, nil
}

func cloneConfig(source Config) Config {
	source.SSH.BanDurations = append([]time.Duration(nil), source.SSH.BanDurations...)
	source.Admin.BanDurations = append([]time.Duration(nil), source.Admin.BanDurations...)
	return source
}

func (m *Manager) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return fmt.Errorf("create security state directory: %w", err)
	}
	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode security state: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(m.path), ".security-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create security state temporary file: %w", err)
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, m.path); err != nil {
		return fmt.Errorf("replace security state: %w", err)
	}
	dir, err := os.Open(filepath.Dir(m.path))
	if err == nil {
		defer dir.Close()
		if err := dir.Sync(); err != nil {
			return err
		}
	}
	return nil
}

func MarshalSnapshot(snapshot Snapshot) ([]byte, error) { return json.Marshal(snapshot) }
