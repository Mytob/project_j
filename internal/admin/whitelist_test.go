package admin

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/Mytob/project_j/internal/whitelist"
)

type memoryWhitelistStore struct {
	entries      []string
	namedEntries []whitelist.Entry
	fail         bool
}

func (s *memoryWhitelistStore) Load() ([]string, error) {
	return append([]string(nil), s.entries...), nil
}
func (s *memoryWhitelistStore) Save(entries []string) error {
	if s.fail {
		return errors.New("simulated disk failure")
	}
	s.entries = append([]string(nil), entries...)
	s.namedEntries = make([]whitelist.Entry, len(entries))
	for i, address := range entries {
		s.namedEntries[i] = whitelist.Entry{Address: address}
	}
	return nil
}
func (s *memoryWhitelistStore) LoadEntries() ([]whitelist.Entry, error) {
	if s.namedEntries != nil {
		return append([]whitelist.Entry(nil), s.namedEntries...), nil
	}
	entries := make([]whitelist.Entry, len(s.entries))
	for i, address := range s.entries {
		entries[i] = whitelist.Entry{Address: address}
	}
	return entries, nil
}
func (s *memoryWhitelistStore) SaveEntries(entries []whitelist.Entry) error {
	if s.fail {
		return errors.New("simulated disk failure")
	}
	s.namedEntries = append([]whitelist.Entry(nil), entries...)
	s.entries = whitelist.Addresses(entries)
	return nil
}

type recordingPolicy struct {
	mu      sync.Mutex
	applied [][]string
	failOn  map[string]bool
}

func (p *recordingPolicy) Apply(entries []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	copyEntries := append([]string(nil), entries...)
	if p.failOn != nil && p.failOn[fmt.Sprint(copyEntries)] {
		return errors.New("simulated Caddy failure")
	}
	p.applied = append(p.applied, copyEntries)
	return nil
}

func newManager(store *memoryWhitelistStore, applier *recordingPolicy) *WhitelistManager {
	manager := NewWhitelistManager(store, applier)
	if err := manager.Initialize(); err != nil {
		panic(err)
	}
	return manager
}

func TestWhitelistManagerInitializeAddRemoveAndDuplicate(t *testing.T) {
	store := &memoryWhitelistStore{entries: []string{"192.0.2.1"}}
	applier := &recordingPolicy{}
	manager := newManager(store, applier)
	if got, _ := manager.List(); !reflect.DeepEqual(got, []string{"192.0.2.1/32"}) {
		t.Fatalf("initial list = %v", got)
	}
	if err := manager.Add("192.0.2.1/32"); !errors.Is(err, ErrDuplicateWhitelistEntry) {
		t.Fatalf("duplicate add error = %v", err)
	}
	if err := manager.Add("2001:db8::/64"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Remove("192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Remove("192.0.2.1"); !errors.Is(err, ErrWhitelistEntryNotFound) {
		t.Fatalf("missing remove error = %v", err)
	}
	want := []string{"2001:db8::/64"}
	got, _ := manager.List()
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(store.entries, want) {
		t.Fatalf("state = %v, persisted = %v, want %v", got, store.entries, want)
	}
}

func TestWhitelistManagerPersistsFriendlyNameWithoutChangingPolicy(t *testing.T) {
	store := &memoryWhitelistStore{}
	applier := &recordingPolicy{}
	manager := newManager(store, applier)
	if err := manager.Add("203.0.113.24", "Home phone"); err != nil {
		t.Fatal(err)
	}
	want := []whitelist.Entry{{Address: "203.0.113.24/32", Name: "Home phone"}}
	got, err := manager.ListEntries()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("named entries = %#v, %v; want %#v", got, err, want)
	}
	if !reflect.DeepEqual(store.namedEntries, want) {
		t.Fatalf("persisted named entries = %#v, want %#v", store.namedEntries, want)
	}
	if len(applier.applied) != 2 || len(applier.applied[0]) != 0 || !reflect.DeepEqual(applier.applied[1], []string{"203.0.113.24/32"}) {
		t.Fatalf("applied policies = %#v, want deny-all then only the address", applier.applied)
	}
	if err := manager.SetName("203.0.113.24", "Living room TV"); err != nil {
		t.Fatal(err)
	}
	want[0].Name = "Living room TV"
	if err := manager.SetName("203.0.113.24", strings.Repeat("x", whitelist.MaxEntryNameRunes+1)); !errors.Is(err, whitelist.ErrInvalidEntryName) {
		t.Fatalf("invalid name error = %v", err)
	}
	reopened := newManager(store, &recordingPolicy{})
	got, err = reopened.ListEntries()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("reloaded named entries = %#v, %v; want %#v", got, err, want)
	}
}

func TestWhitelistManagerActivationFailurePreservesPreviousState(t *testing.T) {
	old := []string{"192.0.2.1/32"}
	next := []string{"192.0.2.1/32", "192.0.2.2/32"}
	store := &memoryWhitelistStore{entries: old}
	applier := &recordingPolicy{failOn: map[string]bool{fmt.Sprint(next): true}}
	manager := newManager(store, applier)
	if err := manager.Add("192.0.2.2"); err == nil {
		t.Fatal("activation failure was reported as success")
	}
	got, _ := manager.List()
	if !reflect.DeepEqual(got, old) || !reflect.DeepEqual(store.entries, old) {
		t.Fatalf("failed activation changed state: memory=%v store=%v", got, store.entries)
	}
	if len(applier.applied) != 1 {
		t.Fatalf("Caddy accepted calls = %d, want only initialization", len(applier.applied))
	}
}

func TestWhitelistManagerPersistenceFailureDoesNotChangeActivePolicy(t *testing.T) {
	old := []string{"192.0.2.1/32"}
	store := &memoryWhitelistStore{entries: old, fail: true}
	applier := &recordingPolicy{}
	manager := newManager(store, applier)
	if err := manager.Add("192.0.2.2"); err == nil {
		t.Fatal("persistence failure was reported as success")
	}
	got, _ := manager.List()
	if !reflect.DeepEqual(got, old) || !reflect.DeepEqual(store.entries, old) {
		t.Fatalf("failed persistence changed state: memory=%v store=%v", got, store.entries)
	}
	wantCalls := [][]string{old}
	if !reflect.DeepEqual(applier.applied, wantCalls) {
		t.Fatalf("live policy history = %v, want %v", applier.applied, wantCalls)
	}
}

func TestWhitelistManagerSerializesConcurrentChanges(t *testing.T) {
	store := &memoryWhitelistStore{}
	applier := &recordingPolicy{}
	manager := newManager(store, applier)
	const total = 32
	var wg sync.WaitGroup
	for i := 1; i <= total; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := manager.Add(fmt.Sprintf("192.0.2.%d", i)); err != nil {
				t.Errorf("add %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	got, err := manager.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != total || !reflect.DeepEqual(got, store.entries) {
		t.Fatalf("concurrent state has %d entries, persisted has %d", len(got), len(store.entries))
	}
}
