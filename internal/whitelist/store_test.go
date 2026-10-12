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

func TestStoreRejectsCorruptOrUnsupportedFiles(t *testing.T) {
	for name, content := range map[string]string{
		"invalid json":    "{",
		"unknown version": `{"version":2,"entries":[]}`,
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
