package admin

import (
	"errors"
	"fmt"
	"sync"

	"github.com/Mytob/project_j/internal/whitelist"
)

var (
	ErrDuplicateWhitelistEntry = errors.New("whitelist entry already exists")
	ErrWhitelistEntryNotFound  = errors.New("whitelist entry does not exist")
)

type whitelistStore interface {
	Load() ([]string, error)
	Save([]string) error
}

type policyApplier interface {
	Apply([]string) error
}

// WhitelistManager serializes file changes and live Caddy activation. Its
// mutex spans the whole change so concurrent requests cannot race a rollback.
type WhitelistManager struct {
	mu      sync.Mutex
	store   whitelistStore
	applier policyApplier
	entries []string
	ready   bool
}

func NewWhitelistManager(store whitelistStore, applier policyApplier) *WhitelistManager {
	return &WhitelistManager{store: store, applier: applier}
}

// Initialize loads the persisted list and installs it into Caddy before the
// admin server begins accepting requests. Missing persistence is deny-all.
func (m *WhitelistManager) Initialize() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries, err := m.store.Load()
	if err != nil {
		return fmt.Errorf("load whitelist: %w", err)
	}
	canonical, err := whitelist.Validate(entries)
	if err != nil {
		return fmt.Errorf("validate whitelist: %w", err)
	}
	values := whitelist.Strings(canonical)
	if err := m.applier.Apply(values); err != nil {
		return fmt.Errorf("activate persisted whitelist: %w", err)
	}
	m.entries = values
	m.ready = true
	return nil
}

func (m *WhitelistManager) List() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ready {
		return nil, errors.New("whitelist manager is not initialized")
	}
	return append([]string(nil), m.entries...), nil
}

func (m *WhitelistManager) Add(value string) error {
	parsed, err := whitelist.Validate([]string{value})
	if err != nil {
		return err
	}
	entry := parsed[0].String()
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ready {
		return errors.New("whitelist manager is not initialized")
	}
	nextInput := append(append([]string(nil), m.entries...), entry)
	next, err := whitelist.Validate(nextInput)
	if err != nil {
		return err
	}
	values := whitelist.Strings(next)
	if len(values) == len(m.entries) {
		return ErrDuplicateWhitelistEntry
	}
	return m.commit(values)
}

func (m *WhitelistManager) Remove(value string) error {
	parsed, err := whitelist.Validate([]string{value})
	if err != nil {
		return err
	}
	entry := parsed[0].String()
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ready {
		return errors.New("whitelist manager is not initialized")
	}
	next := make([]string, 0, len(m.entries))
	found := false
	for _, current := range m.entries {
		if current == entry {
			found = true
			continue
		}
		next = append(next, current)
	}
	if !found {
		return ErrWhitelistEntryNotFound
	}
	return m.commit(next)
}

func (m *WhitelistManager) commit(next []string) error {
	previous := append([]string(nil), m.entries...)
	if err := m.store.Save(next); err != nil {
		return fmt.Errorf("save whitelist: %w", err)
	}
	if err := m.applier.Apply(next); err != nil {
		if rollbackErr := m.store.Save(previous); rollbackErr != nil {
			return fmt.Errorf("activate whitelist: %v; restore persisted whitelist: %w", err, rollbackErr)
		}
		return fmt.Errorf("activate whitelist: %w", err)
	}
	m.entries = append([]string(nil), next...)
	return nil
}
