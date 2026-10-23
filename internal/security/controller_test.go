package security

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseSSHAuthenticationMessages(t *testing.T) {
	tests := []struct {
		name    string
		message string
		kind    EventKind
		ip      string
		valid   bool
	}{
		{name: "password failure", message: "Failed password for alice from 203.0.113.5 port 44220 ssh2", kind: LoginFailure, ip: "203.0.113.5", valid: true},
		{name: "invalid user failure", message: "Failed publickey for invalid user bad from 2001:db8::5 port 443 ssh2", kind: LoginFailure, ip: "2001:db8::5", valid: true},
		{name: "password success", message: "Accepted password for alice from 203.0.113.6 port 44221 ssh2", kind: LoginSuccess, ip: "203.0.113.6", valid: true},
		{name: "mapped address", message: "Failed keyboard-interactive/pam for alice from ::ffff:203.0.113.7 port 443 ssh2", kind: LoginFailure, ip: "203.0.113.7", valid: true},
		{name: "disconnect is not auth failure", message: "Connection closed by authenticating user alice 203.0.113.8 port 80 [preauth]", valid: false},
		{name: "malformed IP", message: "Failed password for alice from 203.0.113.999 port 22 ssh2", valid: false},
		{name: "unrelated message", message: "Accepted publickey for alice from 203.0.113.9 port 22 ssh2 extra", kind: LoginSuccess, ip: "203.0.113.9", valid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kind, ip, valid := ParseSSHAuthMessage(test.message)
			if valid != test.valid || kind != test.kind || ip != test.ip {
				t.Fatalf("ParseSSHAuthMessage() = %q, %q, %v", kind, ip, valid)
			}
		})
	}
}

func TestSSHJournalMatchArgsCoverLegacyAndSessionProcesses(t *testing.T) {
	want := []string{"_COMM=sshd", "+", "_COMM=sshd-session"}
	if got := sshJournalMatchArgs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SSH journal match arguments = %#v, want %#v", got, want)
	}
}

func TestFail2banCommandsUseSupportedQueriesAndRestoreBanExpiry(t *testing.T) {
	now := time.Date(2026, 10, 17, 14, 0, 0, 0, time.UTC)
	var calls [][]string
	banned := false
	client := &Fail2banClient{Path: "/usr/bin/fail2ban-client", Socket: "/tmp/fail2ban.sock", Now: func() time.Time { return now }}
	client.run = func(_ context.Context, executable string, args ...string) (string, error) {
		if executable != client.Path {
			t.Fatalf("unexpected executable %q", executable)
		}
		calls = append(calls, append([]string(nil), args...))
		withoutSocket := args[2:]
		if len(withoutSocket) == 4 && withoutSocket[0] == "get" && withoutSocket[2] == "banned" {
			if banned {
				return "1", nil
			}
			return "0", nil
		}
		if len(withoutSocket) >= 4 && withoutSocket[0] == "set" && withoutSocket[2] == "banip" {
			banned = true
		}
		return "1", nil
	}
	ban := Ban{Service: SSH, IP: "2001:db8::8", StartedAt: now, ExpiresAt: now.Add(90*time.Second + time.Nanosecond)}
	if err := client.EnsureBan(context.Background(), ban); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"--socket", "/tmp/fail2ban.sock", "get", SSHJail, "banned", ban.IP},
		{"--socket", "/tmp/fail2ban.sock", "set", SSHJail, "bantime", "91"},
		{"--socket", "/tmp/fail2ban.sock", "set", SSHJail, "banip", ban.IP},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("Fail2ban command sequence = %#v, want %#v", calls, want)
	}
	calls = nil
	if err := client.Unban(context.Background(), SSH, ban.IP); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !strings.Contains(strings.Join(calls[1], " "), "set jp-ssh unbanip 2001:db8::8") {
		t.Fatalf("Fail2ban unban command sequence = %#v", calls)
	}
}

func TestFail2banBannedParsesWholeAddressList(t *testing.T) {
	client := &Fail2banClient{Path: "test-fail2ban", Socket: "", run: func(_ context.Context, _ string, args ...string) (string, error) {
		return "['203.0.113.8', '2001:db8::8']", nil
	}}
	addresses, err := client.Banned(context.Background(), SSHJail)
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 2 {
		t.Fatalf("banned-address count = %d, want 2", len(addresses))
	}
	for _, ip := range []string{"203.0.113.8", "2001:db8::8"} {
		if _, ok := addresses[ip]; !ok {
			t.Fatalf("banned-address set omitted %s: %v", ip, addresses)
		}
	}
}

func TestEnsureBansListsEachJailOnceAndRestoresOnlyMissingAddresses(t *testing.T) {
	now := time.Date(2026, 10, 17, 14, 0, 0, 0, time.UTC)
	var calls [][]string
	client := &Fail2banClient{Path: "test-fail2ban", Socket: "/tmp/fail2ban.sock", Now: func() time.Time { return now }}
	client.run = func(_ context.Context, executable string, args ...string) (string, error) {
		if executable != client.Path {
			t.Fatalf("unexpected executable %q", executable)
		}
		calls = append(calls, append([]string(nil), args...))
		withoutSocket := args[2:]
		if len(withoutSocket) == 3 && withoutSocket[0] == "get" && withoutSocket[2] == "banned" {
			if withoutSocket[1] == SSHJail {
				return "['203.0.113.8']", nil
			}
			return "[]", nil
		}
		return "ok", nil
	}
	bans := []Ban{
		{Service: SSH, IP: "203.0.113.8", StartedAt: now, ExpiresAt: now.Add(15 * time.Minute)},
		{Service: Admin, IP: "2001:db8::9", StartedAt: now, ExpiresAt: now.Add(15*time.Minute + time.Nanosecond)},
	}
	if err := client.EnsureBans(context.Background(), bans); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"--socket", "/tmp/fail2ban.sock", "get", SSHJail, "banned"},
		{"--socket", "/tmp/fail2ban.sock", "get", AdminJail, "banned"},
		{"--socket", "/tmp/fail2ban.sock", "set", AdminJail, "bantime", "901"},
		{"--socket", "/tmp/fail2ban.sock", "set", AdminJail, "banip", "2001:db8::9"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("batched Fail2ban commands = %#v, want %#v", calls, want)
	}
}

func TestProcessSSHJournalRecordPersistsCursorAndEvent(t *testing.T) {
	now := time.Date(2026, 10, 17, 14, 0, 0, 0, time.UTC)
	manager := newTestManager(t, &now)
	cursorPath := filepath.Join(t.TempDir(), "ssh.cursor")
	controller := &Controller{Manager: manager, JournalCursor: cursorPath}
	record := sshJournalRecord{Message: "Failed password for alice from 192.0.2.51 port 55000 ssh2", Cursor: "s=abc", Realtime: fmt.Sprint(now.UnixMicro())}
	if err := controller.processSSHJournalRecord(record); err != nil {
		t.Fatal(err)
	}
	if got := manager.Snapshot().History; len(got) != 1 || got[0].Service != SSH || got[0].IP != "192.0.2.51" {
		t.Fatalf("SSH event was not persisted: %+v", got)
	}
	if data, err := os.ReadFile(cursorPath); err != nil || string(data) != record.Cursor {
		t.Fatalf("durable cursor = %q, err=%v", data, err)
	}
	if err := controller.processSSHJournalRecord(record); err != nil {
		t.Fatal(err)
	}
	if got := len(manager.Snapshot().History); got != 1 {
		t.Fatalf("replayed SSH journal event duplicated history: %d", got)
	}
}

func TestProcessSSHJournalRecordRequestsReconcileOnlyWhenBanIsCreated(t *testing.T) {
	now := time.Date(2026, 10, 17, 14, 0, 0, 0, time.UTC)
	manager := newTestManager(t, &now)
	controller := &Controller{Manager: manager, JournalCursor: filepath.Join(t.TempDir(), "ssh.cursor"), reconcileRequests: make(chan struct{}, 1)}
	for i := 0; i < 3; i++ {
		record := sshJournalRecord{
			Message:  "Failed password for alice from 192.0.2.51 port 55000 ssh2",
			Cursor:   fmt.Sprintf("s=auth-%d", i),
			Realtime: fmt.Sprint(now.Add(time.Duration(i) * time.Second).UnixMicro()),
		}
		if err := controller.processSSHJournalRecord(record); err != nil {
			t.Fatal(err)
		}
		if i < 2 && len(controller.reconcileRequests) != 0 {
			t.Fatalf("requested enforcement before the ban threshold on failure %d", i+1)
		}
	}
	if got := len(controller.reconcileRequests); got != 1 {
		t.Fatalf("reconcile requests after ban creation = %d, want 1", got)
	}
}

func TestProcessAdminSpoolRequestsReconcileOnlyWhenBanIsCreated(t *testing.T) {
	now := time.Date(2026, 10, 17, 14, 0, 0, 0, time.UTC)
	manager := newTestManager(t, &now)
	key := []byte("01234567890123456789012345678901")
	controller := &Controller{
		Manager:           manager,
		EventsDir:         filepath.Join(t.TempDir(), "events"),
		EventKey:          key,
		reconcileRequests: make(chan struct{}, 1),
	}
	for i := 0; i < 3; i++ {
		event := authEvent(fmt.Sprintf("admin-%d", i), Admin, LoginFailure, "192.0.2.52", now.Add(time.Duration(i)*time.Second))
		if _, err := AppendEvent(controller.EventsDir, event, key); err != nil {
			t.Fatal(err)
		}
		controller.processAdminSpool()
		if i < 2 && len(controller.reconcileRequests) != 0 {
			t.Fatalf("requested enforcement before the ban threshold on failure %d", i+1)
		}
	}
	if got := len(controller.reconcileRequests); got != 1 {
		t.Fatalf("reconcile requests after ban creation = %d, want 1", got)
	}
}
