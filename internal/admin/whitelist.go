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
	entries []whitelist.Entry
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
	entries, err := m.loadEntries()
	if err != nil {
		return fmt.Errorf("load whitelist: %w", err)
	}
	canonical, err := whitelist.ValidateEntries(entries)
	if err != nil {
		return fmt.Errorf("validate whitelist: %w", err)
	}
	values := whitelist.Addresses(canonical)
	if err := m.applier.Apply(values); err != nil {
		return fmt.Errorf("activate persisted whitelist: %w", err)
	}
	m.entries = canonical
	m.ready = true
	return nil
}

func (m *WhitelistManager) List() ([]string, error) {
	entries, err := m.ListEntries()
	if err != nil {
		return nil, err
	}
	return whitelist.Addresses(entries), nil
}

func (m *WhitelistManager) ListEntries() ([]whitelist.Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ready {
		return nil, errors.New("whitelist manager is not initialized")
	}
	return append([]whitelist.Entry(nil), m.entries...), nil
}

func (m *WhitelistManager) Add(value string, names ...string) error {
	name := ""
	if len(names) > 0 {
		name = names[0]
	}
	parsed, err := whitelist.ValidateEntries([]whitelist.Entry{{Address: value, Name: name}})
	if err != nil {
		return err
	}
	entry := parsed[0]
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ready {
		return errors.New("whitelist manager is not initialized")
	}
	nextInput := append(append([]whitelist.Entry(nil), m.entries...), entry)
	next, err := whitelist.ValidateEntries(nextInput)
	if err != nil {
		return err
	}
	if len(next) == len(m.entries) {
		return ErrDuplicateWhitelistEntry
	}
	return m.commit(next)
}

func (m *WhitelistManager) SetName(value, name string) error {
	parsed, err := whitelist.ValidateEntries([]whitelist.Entry{{Address: value, Name: name}})
	if err != nil {
		return err
	}
	entry := parsed[0]
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ready {
		return errors.New("whitelist manager is not initialized")
	}
	next := append([]whitelist.Entry(nil), m.entries...)
	found := false
	for i := range next {
		if next[i].Address == entry.Address {
			if next[i].Name == entry.Name {
				return nil
			}
			next[i].Name = entry.Name
			found = true
			break
		}
	}
	if !found {
		return ErrWhitelistEntryNotFound
	}
	if err := m.saveEntries(next); err != nil {
		return fmt.Errorf("save whitelist: %w", err)
	}
	m.entries = next
	return nil
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
	next := make([]whitelist.Entry, 0, len(m.entries))
	found := false
	for _, current := range m.entries {
		if current.Address == entry {
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

func (m *WhitelistManager) commit(next []whitelist.Entry) error {
	previous := append([]whitelist.Entry(nil), m.entries...)
	addresses := whitelist.Addresses(next)
	if err := m.saveEntries(next); err != nil {
		return fmt.Errorf("save whitelist: %w", err)
	}
	if err := m.applier.Apply(addresses); err != nil {
		if rollbackErr := m.saveEntries(previous); rollbackErr != nil {
			return fmt.Errorf("activate whitelist: %v; restore persisted whitelist: %w", err, rollbackErr)
		}
		return fmt.Errorf("activate whitelist: %w", err)
	}
	m.entries = append([]whitelist.Entry(nil), next...)
	return nil
}

type namedWhitelistStore interface {
	LoadEntries() ([]whitelist.Entry, error)
	SaveEntries([]whitelist.Entry) error
}

func (m *WhitelistManager) loadEntries() ([]whitelist.Entry, error) {
	if store, ok := m.store.(namedWhitelistStore); ok {
		return store.LoadEntries()
	}
	addresses, err := m.store.Load()
	if err != nil {
		return nil, err
	}
	entries := make([]whitelist.Entry, len(addresses))
	for i, address := range addresses {
		entries[i] = whitelist.Entry{Address: address}
	}
	return entries, nil
}

func (m *WhitelistManager) saveEntries(entries []whitelist.Entry) error {
	if store, ok := m.store.(namedWhitelistStore); ok {
		return store.SaveEntries(entries)
	}
	return m.store.Save(whitelist.Addresses(entries))
}
