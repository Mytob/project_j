package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPasswordHashAndVerify(t *testing.T) {
	password := "correct horse battery"
	first, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("hashes should use independent salts")
	}
	if err := ValidatePasswordHash(first); err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(first, password) {
		t.Fatal("correct password rejected")
	}
	if VerifyPassword(first, "incorrect password") {
		t.Fatal("incorrect password accepted")
	}
}

func TestPasswordHashRejectsInvalidInputs(t *testing.T) {
	for _, password := range []string{"short", strings.Repeat("x", maximumBytes+1)} {
		if _, err := HashPassword(password); err == nil {
			t.Fatalf("HashPassword(%d bytes) succeeded", len(password))
		}
	}
	for _, encoded := range []string{"", "pbkdf2-sha256$1$bad$bad", "pbkdf2-sha256$600000$YQ$YQ", "other$600000$YWFhYWFhYWFhYWFhYWFhYQ$YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"} {
		if ValidatePasswordHash(encoded) == nil {
			t.Errorf("ValidatePasswordHash accepted %q", encoded)
		}
		if VerifyPassword(encoded, "password") {
			t.Errorf("VerifyPassword accepted %q", encoded)
		}
	}
}

func TestCredentialPersistenceAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "admin.json")
	password := "an adequately long password"
	if err := SaveCredential(path, password); err != nil {
		t.Fatal(err)
	}
	credential, err := LoadCredential(path)
	if err != nil {
		t.Fatal(err)
	}
	if !credential.Verify(password) || credential.Verify("not the password") {
		t.Fatal("credential verification mismatch")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("credential mode = %o, want 600", info.Mode().Perm())
		}
	}
	if err := os.WriteFile(path, []byte(`{"version":99,"password_hash":"bad"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredential(path); err == nil {
		t.Fatal("invalid credential file loaded")
	}
	if err := SaveCredential(path, "tiny"); err == nil {
		t.Fatal("invalid password save succeeded")
	}
}

func TestCredentialReplacementPersistsBeforeActivating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "admin-credential.json")
	if err := SaveCredential(path, "old administrator password"); err != nil {
		t.Fatal(err)
	}
	credential, err := LoadCredential(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := credential.ReplacePassword(path, "new administrator password"); err != nil {
		t.Fatal(err)
	}
	if credential.Verify("old administrator password") || !credential.Verify("new administrator password") {
		t.Fatal("in-memory credential was not replaced")
	}
	restarted, err := LoadCredential(path)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Verify("old administrator password") || !restarted.Verify("new administrator password") {
		t.Fatal("replacement was not persisted")
	}
	if err := credential.ReplacePassword(t.TempDir(), "another valid administrator password"); err == nil {
		t.Fatal("replacement unexpectedly succeeded when parent directory could not be written")
	}
	if !credential.Verify("new administrator password") {
		t.Fatal("failed replacement changed the active credential")
	}
}

func TestLoadCredentialRejectsTrailingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.json")
	hash, err := HashPassword("adequate credential password")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(credentialFile{Version: credentialVersion, PasswordHash: hash})
	if err := os.WriteFile(path, append(b, []byte(` {}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredential(path); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
}

func TestSessionsCSRFExpiryAndRevoke(t *testing.T) {
	s := NewSessions(time.Minute)
	now := time.Now()
	s.now = func() time.Time { return now }
	id, csrf, err := s.Create(true)
	if err != nil {
		t.Fatal(err)
	}
	gotCSRF, authenticated, ok := s.State(id)
	if !ok || !authenticated || gotCSRF != csrf {
		t.Fatal("created authenticated session not found")
	}
	if !s.CheckCSRF(id, csrf) || s.CheckCSRF(id, "wrong") {
		t.Fatal("CSRF validation mismatch")
	}
	now = now.Add(time.Minute)
	if _, _, ok := s.State(id); ok {
		t.Fatal("expired session remained valid")
	}
	id, _, err = s.Create(false)
	if err != nil {
		t.Fatal(err)
	}
	s.Revoke(id)
	if _, _, ok := s.State(id); ok {
		t.Fatal("revoked session remained valid")
	}
}

func TestLoginLimiterCooldownAndSuccessReset(t *testing.T) {
	l := NewLoginLimiter(2, time.Minute)
	now := time.Now()
	l.now = func() time.Time { return now }
	if allowed, _ := l.Allow(); !allowed {
		t.Fatal("initial attempt blocked")
	}
	l.Failed()
	l.Failed()
	if allowed, wait := l.Allow(); allowed || wait != time.Minute {
		t.Fatalf("locked result = %v, %v", allowed, wait)
	}
	now = now.Add(time.Minute)
	if allowed, _ := l.Allow(); !allowed {
		t.Fatal("attempt stayed blocked after cooldown")
	}
	l.Failed()
	l.Succeeded()
	if allowed, _ := l.Allow(); !allowed {
		t.Fatal("success did not reset failures")
	}
}
