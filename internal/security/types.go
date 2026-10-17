package security

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type Service string

const (
	SSH   Service = "ssh"
	Admin Service = "admin"
)

type EventKind string

const (
	LoginFailure EventKind = "login_failure"
	LoginSuccess EventKind = "login_success"
)

type ProtectionConfig struct {
	Threshold       int             `json:"threshold"`
	Window          time.Duration   `json:"window"`
	BanDurations    []time.Duration `json:"ban_durations"`
	EscalationReset time.Duration   `json:"escalation_reset"`
}

type Config struct {
	SSH              ProtectionConfig `json:"ssh"`
	Admin            ProtectionConfig `json:"admin"`
	HistoryRetention time.Duration    `json:"history_retention"`
}

func DefaultConfig() Config {
	return Config{
		SSH:              ProtectionConfig{Threshold: 3, Window: 10 * time.Minute, BanDurations: []time.Duration{15 * time.Minute, time.Hour, 24 * time.Hour, 7 * 24 * time.Hour}, EscalationReset: 30 * 24 * time.Hour},
		Admin:            ProtectionConfig{Threshold: 3, Window: 10 * time.Minute, BanDurations: []time.Duration{15 * time.Minute, time.Hour, 24 * time.Hour, 7 * 24 * time.Hour}, EscalationReset: 30 * 24 * time.Hour},
		HistoryRetention: 30 * 24 * time.Hour,
	}
}

func (c Config) Validate() error {
	if err := validateProtection("SSH", c.SSH); err != nil {
		return err
	}
	if err := validateProtection("admin", c.Admin); err != nil {
		return err
	}
	if c.HistoryRetention < time.Hour || c.HistoryRetention > 365*24*time.Hour {
		return errors.New("history retention must be between 1 hour and 365 days")
	}
	return nil
}

func validateProtection(name string, c ProtectionConfig) error {
	if c.Threshold < 1 || c.Threshold > 100 {
		return fmt.Errorf("%s failure threshold must be between 1 and 100", name)
	}
	if c.Window < time.Second || c.Window > 7*24*time.Hour {
		return fmt.Errorf("%s detection window must be between 1 second and 7 days", name)
	}
	if len(c.BanDurations) != 4 {
		return fmt.Errorf("%s must define exactly four progressive ban durations", name)
	}
	for i, duration := range c.BanDurations {
		if duration < time.Second || duration > 365*24*time.Hour {
			return fmt.Errorf("%s ban duration %d must be between 1 second and 365 days", name, i+1)
		}
	}
	if c.EscalationReset < time.Hour || c.EscalationReset > 365*24*time.Hour {
		return fmt.Errorf("%s escalation reset must be between 1 hour and 365 days", name)
	}
	return nil
}

type Event struct {
	ID      string    `json:"id"`
	Service Service   `json:"service"`
	Kind    EventKind `json:"kind"`
	IP      string    `json:"ip"`
	At      time.Time `json:"at"`
}

func (e Event) Validate() error {
	if strings.TrimSpace(e.ID) == "" || len(e.ID) > 128 {
		return errors.New("event ID is missing or too long")
	}
	if e.Service != SSH && e.Service != Admin {
		return errors.New("event service must be ssh or admin")
	}
	if e.Kind != LoginFailure && e.Kind != LoginSuccess {
		return errors.New("event kind is invalid")
	}
	if e.At.IsZero() {
		return errors.New("event timestamp is missing")
	}
	ip, err := netip.ParseAddr(e.IP)
	if err != nil || ip.Zone() != "" {
		return errors.New("event IP address is invalid")
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("event IP address cannot be unspecified or multicast")
	}
	return nil
}

func (e Event) normalized() Event {
	if ip, err := netip.ParseAddr(e.IP); err == nil {
		e.IP = ip.Unmap().String()
	}
	e.At = e.At.UTC()
	return e
}

type Ban struct {
	Service        Service   `json:"service"`
	IP             string    `json:"ip"`
	StartedAt      time.Time `json:"started_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	FailedAttempts int       `json:"failed_attempts"`
	Escalation     int       `json:"escalation"`
}

type HistoryEvent struct {
	ID              string    `json:"id"`
	At              time.Time `json:"at"`
	Service         Service   `json:"service"`
	IP              string    `json:"ip"`
	Type            string    `json:"type"`
	Details         string    `json:"details,omitempty"`
	FailedAttempts  int       `json:"failed_attempts,omitempty"`
	Escalation      int       `json:"escalation,omitempty"`
	BlockedRequests uint64    `json:"blocked_requests,omitempty"`
}

type Snapshot struct {
	Config         Config         `json:"config"`
	ActiveBans     []Ban          `json:"active_bans"`
	History        []HistoryEvent `json:"history,omitempty"`
	RecentActivity []HistoryEvent `json:"recent_activity"`
	Failed24h      int            `json:"failed_24h"`
	Bans24h        int            `json:"bans_24h"`
	Pending        int            `json:"pending_failures"`
	Health         Health         `json:"health"`
	CapturedAt     time.Time      `json:"captured_at"`
}

type Health struct {
	Fail2ban    string `json:"fail2ban"`
	SSHJournal  string `json:"ssh_journal"`
	Firewall    string `json:"firewall"`
	AdminEvents string `json:"admin_events"`
	CaddySync   string `json:"caddy_sync"`
	LastError   string `json:"last_error,omitempty"`
}

func normalizeEvent(e Event) Event { return e.normalized() }

func canonicalIP(value string) (string, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return "", errors.New("source must be an exact unicast IP address")
	}
	return ip.Unmap().String(), nil
}

func sortedBans(items map[string]Ban) []Ban {
	result := make([]Ban, 0, len(items))
	for _, item := range items {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].StartedAt.Equal(result[j].StartedAt) {
			if result[i].Service == result[j].Service {
				return result[i].IP < result[j].IP
			}
			return result[i].Service < result[j].Service
		}
		return result[i].StartedAt.After(result[j].StartedAt)
	})
	return result
}

func key(service Service, ip string) string { return string(service) + "|" + ip }
