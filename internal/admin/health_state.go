package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	maxHealthStateBytes = 256 << 10
	maxHealthEvents     = 500
	healthEventLifetime = 90 * 24 * time.Hour
)

type healthRecord struct {
	State         string     `json:"state"`
	LastCheckedAt time.Time  `json:"last_checked_at"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastFailureAt *time.Time `json:"last_failure_at,omitempty"`
}

type healthEvent struct {
	At     time.Time `json:"at"`
	Name   string    `json:"name"`
	From   string    `json:"from,omitempty"`
	To     string    `json:"to"`
	Detail string    `json:"detail"`
}

type healthStateFile struct {
	Version    int                     `json:"version"`
	Components map[string]healthRecord `json:"components"`
	Events     []healthEvent           `json:"events"`
}

func (s *Server) loadHealthState(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		s.healthRecords = make(map[string]healthRecord)
		s.healthEvents = nil
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect health state: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxHealthStateBytes {
		return errors.New("health state file is unsafe or too large")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open health state: %w", err)
	}
	defer file.Close()
	var data healthStateFile
	decoder := json.NewDecoder(io.LimitReader(file, maxHealthStateBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&data); err != nil {
		return fmt.Errorf("decode health state: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("health state contains trailing data")
	}
	if data.Version != 1 || len(data.Events) > maxHealthEvents {
		return errors.New("health state has an unsupported version or event count")
	}
	if data.Components == nil {
		data.Components = make(map[string]healthRecord)
	}
	s.healthRecords = data.Components
	s.healthEvents = data.Events
	return nil
}

func (s *Server) recordHealth(items []componentStatus, now time.Time) []componentStatus {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	if s.healthRecords == nil {
		s.healthRecords = make(map[string]healthRecord)
	}
	cutoff := now.Add(-healthEventLifetime)
	retained := s.healthEvents[:0]
	for _, event := range s.healthEvents {
		if !event.At.Before(cutoff) {
			retained = append(retained, event)
		}
	}
	s.healthEvents = retained
	for i := range items {
		item := &items[i]
		old, exists := s.healthRecords[item.Name]
		record := old
		record.State = item.State
		record.LastCheckedAt = now
		switch item.State {
		case "Healthy":
			checkedAt := now
			record.LastSuccessAt = &checkedAt
		case "Down", "Degraded":
			checkedAt := now
			record.LastFailureAt = &checkedAt
		}
		if exists && old.State != item.State {
			s.healthEvents = append(s.healthEvents, healthEvent{At: now, Name: item.Name, From: old.State, To: item.State, Detail: item.Detail})
		}
		s.healthRecords[item.Name] = record
		item.CheckedAt = record.LastCheckedAt
		item.LastSuccessAt = record.LastSuccessAt
		item.LastFailureAt = record.LastFailureAt
	}
	if excess := len(s.healthEvents) - maxHealthEvents; excess > 0 {
		s.healthEvents = append([]healthEvent(nil), s.healthEvents[excess:]...)
	}
	if s.healthStatePath != "" {
		if err := s.saveHealthStateLocked(); err != nil {
			s.logger.Error("persist health history", "error", err)
		}
	}
	return items
}

func (s *Server) recentHealthEvents() []healthEvent {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	start := len(s.healthEvents) - 20
	if start < 0 {
		start = 0
	}
	return append([]healthEvent{}, s.healthEvents[start:]...)
}

func (s *Server) saveHealthStateLocked() error {
	data, err := json.Marshal(healthStateFile{Version: 1, Components: s.healthRecords, Events: s.healthEvents})
	if err != nil {
		return err
	}
	if len(data) > maxHealthStateBytes {
		return errors.New("health state exceeds its storage bound")
	}
	directory := filepath.Dir(s.healthStatePath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create health state directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".health-state-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, s.healthStatePath); err != nil {
		return fmt.Errorf("replace health state: %w", err)
	}
	return nil
}
