package security

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newTestManager(t *testing.T, now *time.Time) *Manager {
	t.Helper()
	manager, err := Open(filepath.Join(t.TempDir(), "security-state.json"), func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func authEvent(id string, service Service, kind EventKind, ip string, at time.Time) Event {
	return Event{ID: id, Service: service, Kind: kind, IP: ip, At: at}
}

func applyFailures(t *testing.T, m *Manager, service Service, ip string, at time.Time, count int, prefix string) []HistoryEvent {
	t.Helper()
	events := make([]Event, count)
	for i := range events {
		events[i] = authEvent(fmt.Sprintf("%s-%d", prefix, i), service, LoginFailure, ip, at.Add(time.Duration(i)*time.Second))
	}
	created, err := m.ApplyBatch(events)
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func TestDefaultsValidateAndMatchApprovedPolicy(t *testing.T) {
	config := DefaultConfig()
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, protection := range []ProtectionConfig{config.SSH, config.Admin} {
		if protection.Threshold != 3 || protection.Window != 10*time.Minute || protection.EscalationReset != 30*24*time.Hour {
			t.Fatalf("unexpected protection defaults: %+v", protection)
		}
		want := []time.Duration{15 * time.Minute, time.Hour, 24 * time.Hour, 7 * 24 * time.Hour}
		for i := range want {
			if protection.BanDurations[i] != want[i] {
				t.Fatalf("duration %d = %s, want %s", i+1, protection.BanDurations[i], want[i])
			}
		}
	}
	if config.HistoryRetention != 30*24*time.Hour {
		t.Fatalf("history retention = %s", config.HistoryRetention)
	}
	bad := config
	bad.Admin.Threshold = 0
	if bad.Validate() == nil {
		t.Fatal("accepted an invalid threshold")
	}
}

func TestThresholdWindowAndSuccessResetAreScoped(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	m := newTestManager(t, &now)
	ip := "203.0.113.9"
	if _, err := m.Apply(authEvent("ssh-1", SSH, LoginFailure, ip, now)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(authEvent("admin-1", Admin, LoginFailure, ip, now)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(authEvent("ssh-ok", SSH, LoginSuccess, ip, now.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(authEvent("ssh-2", SSH, LoginFailure, ip, now.Add(2*time.Second))); err != nil {
		t.Fatal(err)
	}
	created, err := m.Apply(authEvent("ssh-3", SSH, LoginFailure, ip, now.Add(3*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 1 || created[0].Type != "failure" {
		t.Fatalf("two failures after scoped success unexpectedly banned: %+v", created)
	}
	created, err = m.Apply(authEvent("admin-2", Admin, LoginFailure, ip, now.Add(4*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 1 {
		t.Fatalf("admin ban fired before third independent failure: %+v", created)
	}
	created, err = m.Apply(authEvent("admin-3", Admin, LoginFailure, ip, now.Add(5*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 2 || created[1].Type != "ban" || created[1].Service != Admin {
		t.Fatalf("expected admin-only ban on third attempt: %+v", created)
	}
	if len(m.Snapshot().ActiveBans) != 1 || m.Snapshot().ActiveBans[0].Service != Admin {
		t.Fatalf("cross-service ban occurred: %+v", m.Snapshot().ActiveBans)
	}
	for _, record := range m.Snapshot().History {
		if record.ID == "ssh-ok" || record.Type == "login_success" {
			t.Fatalf("successful login entered retained event history: %+v", record)
		}
	}
}

func TestFailuresOutsideWindowDoNotCreateBan(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	m := newTestManager(t, &now)
	for i := 0; i < 3; i++ {
		eventAt := now.Add(time.Duration(i) * 11 * time.Minute)
		now = eventAt
		_, err := m.Apply(authEvent(fmt.Sprintf("f-%d", i), Admin, LoginFailure, "2001:db8::7", eventAt))
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := m.Snapshot().ActiveBans; len(got) != 0 {
		t.Fatalf("out-of-window failures banned source: %+v", got)
	}
}

func TestProgressiveBansManualUnbanAndEscalationReset(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	m := newTestManager(t, &now)
	ip := "198.51.100.21"
	want := []time.Duration{15 * time.Minute, time.Hour, 24 * time.Hour, 7 * 24 * time.Hour, 7 * 24 * time.Hour}
	var lastBanAt time.Time
	var nextAttempt time.Time
	for i, duration := range want {
		attemptAt := now
		if i > 0 {
			attemptAt = nextAttempt
		}
		now = attemptAt
		created := applyFailures(t, m, Admin, ip, attemptAt, 3, fmt.Sprintf("cycle-%d", i))
		ban := created[len(created)-1]
		if ban.Type != "ban" || ban.Escalation != min(i+1, 4) {
			t.Fatalf("ban %d = %+v", i+1, ban)
		}
		active := m.Snapshot().ActiveBans[0]
		if got := active.ExpiresAt.Sub(active.StartedAt); got != duration {
			t.Fatalf("ban %d duration = %s, want %s", i+1, got, duration)
		}
		lastBanAt = ban.At
		nextAttempt = active.ExpiresAt.Add(time.Second)
		if i < len(want)-1 {
			if _, err := m.Unban(Admin, ip); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := m.Unban(Admin, ip); err != nil {
		t.Fatal(err)
	}
	now = lastBanAt.Add(30*24*time.Hour + time.Second)
	created := applyFailures(t, m, Admin, ip, now, 3, "after-reset")
	if got := created[len(created)-1].Escalation; got != 1 {
		t.Fatalf("escalation after reset = %d, want 1", got)
	}
}

func TestPersistenceIdempotencyAndOriginalExpiryOnConfigChange(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "security-state.json")
	m, err := Open(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	applyFailures(t, m, SSH, "203.0.113.10", now, 3, "persist")
	ban := m.Snapshot().ActiveBans[0]
	if _, err := m.Apply(authEvent("persist-2", SSH, LoginFailure, ban.IP, now)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(authEvent("persist-2", SSH, LoginFailure, ban.IP, now)); err != nil {
		t.Fatal(err)
	}
	config := m.Snapshot().Config
	config.SSH.BanDurations[0] = 2 * time.Hour
	if err := m.UpdateConfig(config); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	snapshot := reopened.Snapshot()
	if len(snapshot.ActiveBans) != 1 || !snapshot.ActiveBans[0].ExpiresAt.Equal(ban.ExpiresAt) {
		t.Fatalf("restart/config update changed original expiry: %+v", snapshot.ActiveBans)
	}
	if snapshot.Config.SSH.BanDurations[0] != 2*time.Hour {
		t.Fatalf("updated setting was not persisted: %+v", snapshot.Config.SSH)
	}
	if countHistory(snapshot.History, "failure", "persist-2") != 1 {
		t.Fatalf("duplicate event was processed: %+v", snapshot.History)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode = %o, want 600", info.Mode().Perm())
	}
}

func TestIPv4IPv6ExactAddressesAndConcurrentAttempts(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	m := newTestManager(t, &now)
	events := make([]Event, 60)
	for i := range events {
		address := "203.0.113.44"
		if i%2 == 1 {
			address = "2001:db8::44"
		}
		events[i] = authEvent(fmt.Sprintf("parallel-%03d", i), SSH, LoginFailure, address, now)
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(events))
	for _, event := range events {
		wg.Add(1)
		go func(event Event) {
			defer wg.Done()
			_, err := m.Apply(event)
			if err != nil {
				errs <- err
			}
		}(event)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	bans := m.Snapshot().ActiveBans
	if len(bans) != 2 {
		t.Fatalf("expected independent IPv4 and IPv6 bans, got %+v", bans)
	}
	seen := map[string]bool{}
	for _, ban := range bans {
		seen[ban.IP] = true
	}
	if !seen["203.0.113.44"] || !seen["2001:db8::44"] {
		t.Fatalf("wrong addresses were banned: %+v", bans)
	}
	ip, err := canonicalIP("::ffff:203.0.113.44")
	if err != nil || ip != "203.0.113.44" || netip.MustParseAddr(ip).Is6() {
		t.Fatalf("mapped IPv4 was not canonicalized: %q, %v", ip, err)
	}
}

func TestConfigValidationIsTransactionalAndUnbanKeepsEscalation(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "security-state.json")
	m, err := Open(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ip := "192.0.2.101"
	applyFailures(t, m, Admin, ip, now, 3, "admin")
	config := m.Snapshot().Config
	config.Admin.Threshold = 101
	if err := m.UpdateConfig(config); err == nil {
		t.Fatal("accepted invalid config")
	}
	if got := m.Snapshot().Config.Admin.Threshold; got != 3 {
		t.Fatalf("invalid config partially applied: threshold=%d", got)
	}
	removed, err := m.Unban(Admin, ip)
	if err != nil || !removed {
		t.Fatalf("manual unban = %v, %v", removed, err)
	}
	applyFailures(t, m, Admin, ip, now.Add(time.Minute), 3, "admin-again")
	if got := m.Snapshot().ActiveBans[0].Escalation; got != 2 {
		t.Fatalf("manual unban erased escalation, next level=%d", got)
	}
}

func TestSweepExpiresBanAndAppliesHistoryRetentionWithoutDeletingState(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	m := newTestManager(t, &now)
	applyFailures(t, m, SSH, "192.0.2.8", now, 3, "expire")
	ban := m.Snapshot().ActiveBans[0]
	now = ban.ExpiresAt
	if events, err := m.Sweep(); err != nil || len(events) != 1 || events[0].Type != "expired" {
		t.Fatalf("expiration sweep = %+v, %v", events, err)
	}
	if len(m.Snapshot().ActiveBans) != 0 {
		t.Fatal("expired ban remains active")
	}
	config := m.Snapshot().Config
	config.HistoryRetention = time.Hour
	if err := m.UpdateConfig(config); err != nil {
		t.Fatal(err)
	}
	now = ban.StartedAt.Add(30*24*time.Hour + time.Second)
	if _, err := m.Sweep(); err != nil {
		t.Fatal(err)
	}
	if len(m.Snapshot().History) != 0 {
		t.Fatal("expired history was retained beyond configured retention")
	}
	applyFailures(t, m, SSH, "192.0.2.8", now, 3, "escalation-retained")
	if got := m.Snapshot().ActiveBans[0].Escalation; got != 1 {
		t.Fatalf("escalation should reset after configured 30 days, was %d", got)
	}
}

func TestFutureTimestampRollsBackBatch(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	m := newTestManager(t, &now)
	_, err := m.ApplyBatch([]Event{
		authEvent("valid", Admin, LoginFailure, "192.0.2.1", now),
		authEvent("future", Admin, LoginFailure, "192.0.2.1", now.Add(3*time.Minute)),
	})
	if err == nil {
		t.Fatal("accepted future event")
	}
	if len(m.Snapshot().History) != 0 {
		t.Fatal("part of rejected batch was persisted")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatal("unexpected state error")
	}
}

func TestBlockedRequestsArePersistedAsIdempotentAggregates(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "security-state.json")
	m, err := Open(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]uint64{"203.0.113.20": 7}
	if err := m.IngestBlockedCounts(counts, now); err != nil {
		t.Fatal(err)
	}
	if err := m.IngestBlockedCounts(counts, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	snapshot := m.Snapshot()
	if len(snapshot.History) != 1 || snapshot.History[0].Type != "blocked_requests" || snapshot.History[0].BlockedRequests != 7 {
		t.Fatalf("repeated cumulative count created non-idempotent history: %+v", snapshot.History)
	}
	counts["203.0.113.20"] = 10
	if err := m.IngestBlockedCounts(counts, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	history := m.Snapshot().History
	if got := history[len(history)-1].BlockedRequests; got != 3 {
		t.Fatalf("aggregate delta = %d, want 3", got)
	}
	counts["203.0.113.20"] = 1 // Caddy restarted and reset its in-memory counter.
	if err := m.IngestBlockedCounts(counts, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := len(m.Snapshot().History); got != 2 {
		t.Fatalf("counter reset emitted a duplicate blocked event, history entries=%d", got)
	}
	restarted, err := Open(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	counts["203.0.113.20"] = 2
	if err := restarted.IngestBlockedCounts(counts, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := len(restarted.Snapshot().History); got != 3 {
		t.Fatalf("persisted cumulative checkpoint was not restored: history entries=%d", got)
	}
}

func countHistory(history []HistoryEvent, eventType, id string) int {
	count := 0
	for _, event := range history {
		if event.Type == eventType && event.ID == id {
			count++
		}
	}
	return count
}
