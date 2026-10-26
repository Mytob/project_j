package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxEventBytes = 16 << 10

type SignedEvent struct {
	Event Event  `json:"event"`
	MAC   string `json:"mac"`
}

func NewEvent(service Service, kind EventKind, ip string, at time.Time) (Event, error) {
	canonical, err := canonicalIP(ip)
	if err != nil {
		return Event{}, err
	}
	randomID := make([]byte, 16)
	if _, err := rand.Read(randomID); err != nil {
		return Event{}, fmt.Errorf("generate security event ID: %w", err)
	}
	return Event{ID: hex.EncodeToString(randomID), Service: service, Kind: kind, IP: canonical, At: at.UTC()}, nil
}

func SignEvent(event Event, key []byte) (SignedEvent, error) {
	if len(key) < 32 {
		return SignedEvent{}, errors.New("security event key must contain at least 32 bytes")
	}
	if err := event.Validate(); err != nil {
		return SignedEvent{}, err
	}
	event = normalizeEvent(event)
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, eventCanonical(event))
	return SignedEvent{Event: event, MAC: hex.EncodeToString(mac.Sum(nil))}, nil
}

func VerifyEvent(signed SignedEvent, key []byte) error {
	if len(key) < 32 {
		return errors.New("security event key must contain at least 32 bytes")
	}
	if err := signed.Event.Validate(); err != nil {
		return err
	}
	received, err := hex.DecodeString(signed.MAC)
	if err != nil || len(received) != sha256.Size {
		return errors.New("security event signature is malformed")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, eventCanonical(normalizeEvent(signed.Event)))
	if !hmac.Equal(received, mac.Sum(nil)) {
		return errors.New("security event signature is invalid")
	}
	return nil
}

func eventCanonical(event Event) string {
	return strings.Join([]string{event.ID, string(event.Service), string(event.Kind), event.IP, event.At.UTC().Format(time.RFC3339Nano)}, "\n")
}

// AppendEvent creates an immutable one-event spool file. The file is synced
// before success is returned, so an authentication decision is recoverable
// even if the admin or security controller stops immediately afterward.
func AppendEvent(directory string, event Event, key []byte) (string, error) {
	signed, err := SignEvent(event, key)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create security event directory: %w", err)
	}
	data, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	name := signed.Event.At.Format("20060102T150405.000000000Z") + "-" + signed.Event.ID + ".json"
	path := filepath.Join(directory, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return "", fmt.Errorf("create security event: %w", err)
	}
	if err := file.Chmod(0o640); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("protect security event: %w", err)
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("write security event: %w", err)
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close security event: %w", closeErr)
	}
	if dir, openErr := os.Open(directory); openErr == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return path, nil
}

type SpoolItem struct {
	Path  string
	Event Event
}

type RejectedEvent struct {
	Path string
	Err  error
}

// ReadSpool validates all immutable files and returns them in timestamp order.
// Rejected items are reported separately so one malformed file cannot hold up
// unrelated authentication events.
func ReadSpool(directory string, key []byte) ([]SpoolItem, []RejectedEvent, error) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return []SpoolItem{}, []RejectedEvent{}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	items := make([]SpoolItem, 0, len(entries))
	rejected := make([]RejectedEvent, 0)
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			rejected = append(rejected, RejectedEvent{Path: path, Err: err})
			continue
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxEventBytes {
			rejected = append(rejected, RejectedEvent{Path: path, Err: errors.New("event file is not a small regular file")})
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			rejected = append(rejected, RejectedEvent{Path: path, Err: err})
			continue
		}
		var signed SignedEvent
		if err := json.Unmarshal(data, &signed); err != nil {
			rejected = append(rejected, RejectedEvent{Path: path, Err: err})
			continue
		}
		if err := VerifyEvent(signed, key); err != nil {
			rejected = append(rejected, RejectedEvent{Path: path, Err: err})
			continue
		}
		items = append(items, SpoolItem{Path: path, Event: normalizeEvent(signed.Event)})
	}
	return items, rejected, nil
}

func (m *Manager) Processed(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.state.Processed[id]
	return ok
}
