package auth

import (
	"testing"
	"time"
)

func TestRecentPasswordVerificationIsAuthenticatedAndExpires(t *testing.T) {
	sessions := NewSessions(time.Hour)
	now := time.Unix(1_700_000_000, 0)
	sessions.now = func() time.Time { return now }
	anonymous, _, err := sessions.Create(false)
	if err != nil {
		t.Fatal(err)
	}
	if sessions.GrantRecentPasswordVerification(anonymous, time.Minute) || sessions.HasRecentPasswordVerification(anonymous) {
		t.Fatal("anonymous session received a password verification grant")
	}
	authenticated, _, err := sessions.Create(true)
	if err != nil {
		t.Fatal(err)
	}
	if !sessions.GrantRecentPasswordVerification(authenticated, 5*time.Minute) || !sessions.HasRecentPasswordVerification(authenticated) {
		t.Fatal("authenticated session did not receive recent password grant")
	}
	now = now.Add(5 * time.Minute)
	if sessions.HasRecentPasswordVerification(authenticated) {
		t.Fatal("expired password verification grant remained active")
	}
	now = now.Add(time.Hour)
	if sessions.GrantRecentPasswordVerification(authenticated, time.Minute) {
		t.Fatal("expired session received a password verification grant")
	}
}
