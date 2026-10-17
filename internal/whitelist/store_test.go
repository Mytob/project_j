package whitelist

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStoreLoadSaveAndMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "whitelist.json")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}

	entries, err := store.Load()
	if err != nil || len(entries) != 0 {
		t.Fatalf("Load() missing file = %v, %v; want empty list and nil", entries, err)
	}
	if err := store.Save([]string{"192.0.2.3/24", "2001:db8::1"}); err != nil {
		t.Fatal(err)
	}
	entries, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.0/24", "2001:db8::1/128"}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("Load() = %v, want %v", entries, want)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %o, want 600", info.Mode().Perm())
	}
}

func TestStoreMigratesAddressOnlyWhitelistAndPreservesNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.json")
	legacy := `{"version":1,"entries":["192.0.2.1"]}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := store.LoadEntries()
	if err != nil {
		t.Fatal(err)
	}
	wantLegacy := []Entry{{Address: "192.0.2.1/32"}}
	if !reflect.DeepEqual(entries, wantLegacy) {
		t.Fatalf("legacy entries = %#v, want %#v", entries, wantLegacy)
	}
	want := []Entry{{Address: "192.0.2.1/32", Name: "Home phone"}, {Address: "2001:db8::1/128", Name: "Travel laptop"}}
	if err := store.SaveEntries(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.LoadEntries()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("named entries = %#v, want %#v", got, want)
	}
	addresses, err := store.Load()
	if err != nil || !reflect.DeepEqual(addresses, []string{"192.0.2.1/32", "2001:db8::1/128"}) {
		t.Fatalf("policy addresses = %v, %v", addresses, err)
	}
}

func TestStoreRejectsCorruptOrUnsupportedFiles(t *testing.T) {
	for name, content := range map[string]string{
		"invalid json":    "{",
		"unknown version": `{"version":3,"entries":[]}`,
		"unknown field":   `{"version":1,"entries":[],"extra":true}`,
		"invalid entry":   `{"version":1,"entries":["not-an-ip"]}`,
		"trailing data":   `{"version":1,"entries":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "whitelist.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			store, err := NewStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(); err == nil {
				t.Fatal("Load() unexpectedly accepted invalid file")
			}
		})
	}
}

func TestStoreInvalidSavePreservesLastValidData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.json")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save([]string{"192.0.2.4"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save([]string{"bad.example"}); err == nil {
		t.Fatal("Save() accepted invalid input")
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.4/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load() = %v, want preserved %v", got, want)
	}
}
