package auth

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Mytob/project_j/internal/totp"
)

func testTOTPStore(t *testing.T) (*TOTPStore, string, []byte) {
	t.Helper()
	root := t.TempDir()
	keyPath := filepath.Join(root, "config", "totp.key")
	if err := CreateTOTPKey(keyPath); err != nil {
		t.Fatal(err)
	}
	key, err := LoadTOTPKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "data", "totp-state.json")
	store, err := InitializeTOTPStore(statePath, key)
	if err != nil {
		t.Fatal(err)
	}
	return store, statePath, key
}

func TestTOTPStoreInitialPendingAbandonedAndRestart(t *testing.T) {
	store, statePath, key := testTOTPStore(t)
	if store.Status() != TOTPUnconfigured {
		t.Fatalf("initial status = %q", store.Status())
	}
	secret, err := store.BeginEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := append([]byte(nil), secret...)
	defer clear(plaintext)
	if store.Status() != TOTPPending {
		t.Fatal("enrollment did not remain pending")
	}
	pending, err := store.PendingSecret()
	if err != nil || !bytes.Equal(secret, pending) {
		t.Fatalf("pending secret readback: equal=%v err=%v", bytes.Equal(secret, pending), err)
	}
	clear(secret)
	clear(pending)

	contents, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(contents, plaintext) {
		t.Fatal("TOTP state contains plaintext secret")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(statePath)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("TOTP state permissions = %v, %v", info, err)
		}
	}

	store, err = NewTOTPStore(statePath, key)
	if err != nil {
		t.Fatal(err)
	}
	if store.Status() != TOTPPending {
		t.Fatal("pending enrollment did not survive reopening the store")
	}
	if err := store.ConfirmEnrollment("000000", time.Unix(59, 0)); !errors.Is(err, ErrInvalidTOTPCode) {
		t.Fatalf("incorrect code error = %v", err)
	}
	if store.Status() != TOTPPending {
		t.Fatal("incorrect code changed pending enrollment")
	}
	if err := store.CancelEnrollment(); err != nil {
		t.Fatal(err)
	}
	store, err = NewTOTPStore(statePath, key)
	if err != nil {
		t.Fatal(err)
	}
	if store.Status() != TOTPUnconfigured {
		t.Fatal("cancelled enrollment did not persist as unconfigured")
	}
}

func TestTOTPStoreActivationAndReplaySurviveRestart(t *testing.T) {
	store, statePath, key := testTOTPStore(t)
	secret, err := store.BeginEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_010, 0)
	confirmation, err := totp.Code(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	clear(secret)
	if err := store.ConfirmEnrollment(confirmation, now); err != nil {
		t.Fatal(err)
	}
	if store.Status() != TOTPEnabled {
		t.Fatal("successful enrollment did not activate TOTP")
	}
	if _, err := store.PendingSecret(); !errors.Is(err, ErrNoTOTPEnrollment) {
		t.Fatalf("active state exposed a pending secret: %v", err)
	}
	if _, err := store.BeginEnrollment(); !errors.Is(err, ErrTOTPAlreadyEnabled) {
		t.Fatalf("second enrollment error = %v", err)
	}

	store, err = NewTOTPStore(statePath, key)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := store.Verify(confirmation, now)
	if err != nil || accepted {
		t.Fatalf("activation code replay after restart accepted=%v err=%v", accepted, err)
	}

	secret, err = store.decrypt(store.file.Secret, "active")
	if err != nil {
		t.Fatal(err)
	}
	nextTime := now.Add(totp.Period)
	nextCode, err := totp.Code(secret, nextTime)
	clear(secret)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err = store.Verify(nextCode, nextTime)
	if err != nil || !accepted {
		t.Fatalf("next-step code accepted=%v err=%v", accepted, err)
	}
	store, err = NewTOTPStore(statePath, key)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err = store.Verify(nextCode, nextTime)
	if err != nil || accepted {
		t.Fatalf("last accepted code replay after restart accepted=%v err=%v", accepted, err)
	}
}

func TestTOTPStoreSerializesConcurrentCodeConsumption(t *testing.T) {
	store, _, _ := testTOTPStore(t)
	secret, err := store.BeginEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_010, 0)
	confirmation, _ := totp.Code(secret, now)
	clear(secret)
	if err := store.ConfirmEnrollment(confirmation, now); err != nil {
		t.Fatal(err)
	}
	secret, err = store.decrypt(store.file.Secret, "active")
	if err != nil {
		t.Fatal(err)
	}
	nextTime := now.Add(totp.Period)
	code, _ := totp.Code(secret, nextTime)
	clear(secret)
	const attempts = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			accepted, err := store.Verify(code, nextTime)
			if err != nil {
				t.Errorf("concurrent verification: %v", err)
			}
			if accepted {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("successful concurrent verifications = %d, want 1", successes)
	}
}

func TestTOTPStoreFailsClosedOnMissingKeyCorruptionAndBadPermissions(t *testing.T) {
	store, statePath, key := testTOTPStore(t)
	secret, err := store.BeginEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	clear(secret)
	contents, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	contents[len(contents)/2] ^= 1
	if err := os.WriteFile(statePath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewTOTPStore(statePath, key); err == nil {
		t.Fatal("corrupted TOTP state was loaded")
	}
	if _, err := NewTOTPStore(filepath.Join(t.TempDir(), "missing.json"), []byte("short")); err == nil {
		t.Fatal("invalid/missing key was accepted")
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(statePath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := NewTOTPStore(statePath, key); err == nil {
			t.Fatal("broadly readable TOTP state was loaded")
		}
	}
}

func TestTOTPStoreWriteFailureDoesNotPartiallyTransition(t *testing.T) {
	root := t.TempDir()
	key := bytes.Repeat([]byte{3}, totpKeySize)
	parent := filepath.Join(root, "blocked")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(parent, "state.json")
	store, err := InitializeTOTPStore(statePath, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(parent, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginEnrollment(); err == nil {
		t.Fatal("enrollment succeeded with an unusable state path")
	}
	if store.Status() != TOTPUnconfigured {
		t.Fatal("failed enrollment modified in-memory authentication state")
	}
}

func TestTOTPStoreFailsClosedWhenStateFileIsMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-state.json")
	if _, err := NewTOTPStore(path, bytes.Repeat([]byte{4}, totpKeySize)); err == nil {
		t.Fatal("missing persistent TOTP state was treated as unconfigured")
	}
}

func TestTOTPKeyCreationAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "totp.key")
	if err := CreateTOTPKey(path); err != nil {
		t.Fatal(err)
	}
	key, err := LoadTOTPKey(path)
	if err != nil || len(key) != totpKeySize {
		t.Fatalf("loaded key length=%d err=%v", len(key), err)
	}
	if err := CreateTOTPKey(path); err == nil {
		t.Fatal("key creation replaced an existing key")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadTOTPKey(path); err == nil {
			t.Fatal("world-readable key was loaded")
		}
	}
}
