package auth

import (
	"sync"
	"time"
)

const (
	defaultLoginFailures = 5
	defaultLoginCooldown = time.Minute
)

// LoginLimiter applies a small process-wide delay after repeated failures.
// The single-account admin service has no trusted client-IP proxy requirement.
type LoginLimiter struct {
	mu         sync.Mutex
	limit      int
	cooldown   time.Duration
	failures   int
	lockedTill time.Time
	now        func() time.Time
}

func NewLoginLimiter(limit int, cooldown time.Duration) *LoginLimiter {
	if limit <= 0 {
		limit = defaultLoginFailures
	}
	if cooldown <= 0 {
		cooldown = defaultLoginCooldown
	}
	return &LoginLimiter{limit: limit, cooldown: cooldown, now: time.Now}
}

func (l *LoginLimiter) Allow() (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Before(l.lockedTill) {
		return false, l.lockedTill.Sub(now)
	}
	if !l.lockedTill.IsZero() {
		l.failures = 0
		l.lockedTill = time.Time{}
	}
	return true, 0
}

func (l *LoginLimiter) Failed() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures++
	if l.failures >= l.limit {
		l.lockedTill = l.now().Add(l.cooldown)
	}
}

func (l *LoginLimiter) Succeeded() {
	l.mu.Lock()
	l.failures = 0
	l.lockedTill = time.Time{}
	l.mu.Unlock()
}
