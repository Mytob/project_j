package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthenticationEventsAreSignedAndTamperingIsRejected(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	at := time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC)
	event, err := NewEvent(Admin, LoginFailure, "::ffff:203.0.113.8", at)
	if err != nil {
		t.Fatal(err)
	}
	if event.IP != "203.0.113.8" {
		t.Fatalf("mapped IPv4 was not normalized: %s", event.IP)
	}
	signed, err := SignEvent(event, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvent(signed, key); err != nil {
		t.Fatal(err)
	}
	signed.Event.IP = "203.0.113.9"
	if err := VerifyEvent(signed, key); err == nil {
		t.Fatal("accepted forged source address")
	}
	if _, err := SignEvent(event, []byte("short")); err == nil {
		t.Fatal("accepted short authentication-event key")
	}
}

func TestSpoolPersistsAndReadsEventsChronologically(t *testing.T) {
	directory := t.TempDir()
	key := []byte("01234567890123456789012345678901")
	base := time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC)
	later, err := NewEvent(SSH, LoginFailure, "2001:db8::9", base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	earlier, err := NewEvent(SSH, LoginSuccess, "2001:db8::9", base)
	if err != nil {
		t.Fatal(err)
	}
	pathLater, err := AppendEvent(directory, later, key)
	if err != nil {
		t.Fatal(err)
	}
	pathEarlier, err := AppendEvent(directory, earlier, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{pathLater, pathEarlier} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("event file mode = %o", info.Mode().Perm())
		}
	}
	items, rejected, err := ReadSpool(directory, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(rejected) != 0 || len(items) != 2 {
		t.Fatalf("spool results valid=%d rejected=%d err=%v", len(items), len(rejected), err)
	}
	if items[0].Event.ID != earlier.ID || items[1].Event.ID != later.ID {
		t.Fatalf("events are not chronological: %+v", items)
	}
}

func TestSpoolIsolatesMalformedForgedAndSymlinkFiles(t *testing.T) {
	directory := t.TempDir()
	key := []byte("01234567890123456789012345678901")
	at := time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC)
	event, err := NewEvent(Admin, LoginFailure, "192.0.2.1", at)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignEvent(event, key)
	if err != nil {
		t.Fatal(err)
	}
	signed.Event.IP = "192.0.2.2"
	encoded, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	forged := filepath.Join(directory, "20261017T130000.000000000Z-forged.json")
	if err := os.WriteFile(forged, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	malformed := filepath.Join(directory, "20261017T130001.000000000Z-malformed.json")
	if err := os.WriteFile(malformed, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "outside.data")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "20261017T130002.000000000Z-link.json")
	if err := os.Symlink(target, link); err == nil {
		defer os.Remove(link)
	}
	items, rejected, err := ReadSpool(directory, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("accepted invalid spool items: %+v", items)
	}
	wantRejected := 2
	if _, err := os.Lstat(link); err == nil {
		wantRejected++
	}
	if len(rejected) != wantRejected {
		t.Fatalf("rejected %d items, want %d: %+v", len(rejected), wantRejected, rejected)
	}
}

func TestAdminEventWriterHealthIsAuthenticatedAndFresh(t *testing.T) {
	directory := t.TempDir()
	key := []byte("01234567890123456789012345678901")
	now := time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC)
	if err := WriteEventWriterHealth(directory, key, true, now); err != nil {
		t.Fatal(err)
	}
	if err := CheckEventWriterHealth(directory, key, now.Add(20*time.Second), 30*time.Second); err != nil {
		t.Fatalf("fresh signed heartbeat was rejected: %v", err)
	}
	if err := CheckEventWriterHealth(directory, key, now.Add(31*time.Second), 30*time.Second); err == nil {
		t.Fatal("accepted stale heartbeat")
	}
	if err := WriteEventWriterHealth(directory, key, false, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := CheckEventWriterHealth(directory, key, now.Add(time.Second), 30*time.Second); err == nil {
		t.Fatal("accepted degraded event writer")
	}
	data, err := os.ReadFile(filepath.Join(directory, eventWriterHealthFile))
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-2] ^= 1
	if err := os.WriteFile(filepath.Join(directory, eventWriterHealthFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckEventWriterHealth(directory, key, now.Add(time.Second), 30*time.Second); err == nil {
		t.Fatal("accepted a forged heartbeat")
	}
	info, err := os.Stat(filepath.Join(directory, eventWriterHealthFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("heartbeat file mode = %o, want 640", info.Mode().Perm())
	}
}
