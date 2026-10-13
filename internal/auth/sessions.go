package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

const DefaultSessionLifetime = 12 * time.Hour

type session struct {
	csrf                string
	expires             time.Time
	authenticated       bool
	reauthenticationEnd time.Time
}

// Sessions keeps opaque session IDs and CSRF secrets in process memory. A
// process restart invalidates all sessions by design.
type Sessions struct {
	mu       sync.Mutex
	items    map[string]session
	lifetime time.Duration
	now      func() time.Time
}

func NewSessions(lifetime time.Duration) *Sessions {
	if lifetime <= 0 {
		lifetime = DefaultSessionLifetime
	}
	return &Sessions{items: make(map[string]session), lifetime: lifetime, now: time.Now}
}

func (s *Sessions) Create(authenticated bool) (id, csrf string, err error) {
	id, err = randomToken()
	if err != nil {
		return "", "", err
	}
	csrf, err = randomToken()
	if err != nil {
		return "", "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for existingID, item := range s.items {
		if !now.Before(item.expires) {
			delete(s.items, existingID)
		}
	}
	s.items[id] = session{csrf: csrf, expires: now.Add(s.lifetime), authenticated: authenticated}
	return id, csrf, nil
}

func (s *Sessions) State(id string) (csrf string, authenticated, ok bool) {
	if id == "" {
		return "", false, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, exists := s.items[id]
	if !exists {
		return "", false, false
	}
	if !s.now().Before(item.expires) {
		delete(s.items, id)
		return "", false, false
	}
	return item.csrf, item.authenticated, true
}

func (s *Sessions) CheckCSRF(id, token string) bool {
	csrf, _, ok := s.State(id)
	return ok && len(csrf) == len(token) && subtle.ConstantTimeCompare([]byte(csrf), []byte(token)) == 1
}

func (s *Sessions) Revoke(id string) {
	s.mu.Lock()
	delete(s.items, id)
	s.mu.Unlock()
}

// RevokeAll invalidates every outstanding session atomically.
func (s *Sessions) RevokeAll() {
	s.mu.Lock()
	clear(s.items)
	s.mu.Unlock()
}

// GrantRecentPasswordVerification allows a session to reveal a pending TOTP
// setup secret for a short time after the password has been checked.
func (s *Sessions) GrantRecentPasswordVerification(id string, lifetime time.Duration) bool {
	if id == "" || lifetime <= 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	now := s.now()
	if !ok || !item.authenticated || !now.Before(item.expires) {
		delete(s.items, id)
		return false
	}
	item.reauthenticationEnd = now.Add(lifetime)
	s.items[id] = item
	return true
}

// HasRecentPasswordVerification checks the short-lived TOTP setup grant.
func (s *Sessions) HasRecentPasswordVerification(id string) bool {
	if id == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	now := s.now()
	if !ok || !item.authenticated || !now.Before(item.expires) {
		delete(s.items, id)
		return false
	}
	return now.Before(item.reauthenticationEnd)
}

func randomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
