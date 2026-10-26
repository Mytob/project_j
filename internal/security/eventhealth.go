package security

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const eventWriterHealthFile = "admin-writer.health"

// EventWriterHealthFilename identifies the volatile liveness marker beside
// signed security events. Fresh-host recovery deliberately does not restore it.
const EventWriterHealthFilename = eventWriterHealthFile

type eventWriterHealth struct {
	At      time.Time `json:"at"`
	Healthy bool      `json:"healthy"`
	MAC     string    `json:"mac"`
}

// WriteEventWriterHealth atomically publishes an authenticated liveness marker
// beside the admin authentication spool so the security controller can detect
// failures even while no administrator is logging in.
func WriteEventWriterHealth(directory string, key []byte, healthy bool, at time.Time) error {
	if strings.TrimSpace(directory) == "" || len(key) < 32 {
		return errors.New("event writer health requires a directory and 256-bit key")
	}
	marker := eventWriterHealth{At: at.UTC(), Healthy: healthy}
	if marker.At.IsZero() {
		return errors.New("event writer health timestamp is required")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, eventWriterHealthCanonical(marker))
	marker.MAC = hex.EncodeToString(mac.Sum(nil))
	data, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create event writer health directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".admin-writer-health-*.tmp")
	if err != nil {
		return fmt.Errorf("create event writer health marker: %w", err)
	}
	name := temporary.Name()
	defer os.Remove(name)
	// The shared spool is group-readable by the security controller. The marker
	// contains no secret; its HMAC prevents spoofing while 0640 lets the
	// controller verify that the admin event writer is alive.
	if err := temporary.Chmod(0o640); err != nil {
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
	if err := os.Rename(name, filepath.Join(directory, eventWriterHealthFile)); err != nil {
		return fmt.Errorf("publish event writer health marker: %w", err)
	}
	dir, err := os.Open(directory)
	if err == nil {
		defer dir.Close()
		if err := dir.Sync(); err != nil {
			return err
		}
	}
	return nil
}

// CheckEventWriterHealth verifies the signed marker and ensures it is recent.
func CheckEventWriterHealth(directory string, key []byte, now time.Time, maxAge time.Duration) error {
	if strings.TrimSpace(directory) == "" || len(key) < 32 || maxAge <= 0 {
		return errors.New("event writer health check is not configured")
	}
	path := filepath.Join(directory, eventWriterHealthFile)
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("read administrator event writer heartbeat: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 1024 {
		return errors.New("administrator event writer heartbeat is not a small regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read administrator event writer heartbeat: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var marker eventWriterHealth
	if err := decoder.Decode(&marker); err != nil {
		return fmt.Errorf("decode administrator event writer heartbeat: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("administrator event writer heartbeat contains trailing data")
	}
	if err := verifyEventWriterHealth(marker, key); err != nil {
		return err
	}
	if marker.At.After(now.Add(2 * time.Minute)) {
		return errors.New("administrator event writer heartbeat timestamp is in the future")
	}
	if now.Sub(marker.At) > maxAge {
		return errors.New("administrator event writer heartbeat is stale")
	}
	if !marker.Healthy {
		return errors.New("administrator authentication event writer reported a failure")
	}
	return nil
}

func verifyEventWriterHealth(marker eventWriterHealth, key []byte) error {
	if len(key) < 32 || marker.At.IsZero() {
		return errors.New("administrator event writer heartbeat is malformed")
	}
	received, err := hex.DecodeString(marker.MAC)
	if err != nil || len(received) != sha256.Size {
		return errors.New("administrator event writer heartbeat signature is malformed")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, eventWriterHealthCanonical(marker))
	if !hmac.Equal(received, mac.Sum(nil)) {
		return errors.New("administrator event writer heartbeat signature is invalid")
	}
	return nil
}

func eventWriterHealthCanonical(marker eventWriterHealth) string {
	state := "degraded"
	if marker.Healthy {
		state = "healthy"
	}
	return marker.At.UTC().Format(time.RFC3339Nano) + "\n" + state
}

// StartEventWriterHealth publishes immediately and then refreshes every ten
// seconds. The callback reflects the actual event writer, not just this loop.
func StartEventWriterHealth(ctx context.Context, directory string, key []byte, healthy func() bool, onError func(error)) {
	keyCopy := append([]byte(nil), key...)
	go func() {
		defer clear(keyCopy)
		write := func() {
			if err := WriteEventWriterHealth(directory, keyCopy, healthy != nil && healthy(), time.Now().UTC()); err != nil && onError != nil {
				onError(err)
			}
		}
		write()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				write()
			}
		}
	}()
}
