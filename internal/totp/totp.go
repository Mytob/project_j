// Package totp implements the RFC 6238 six-digit SHA-1 authenticator format.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	Digits              = 6
	Period              = 30 * time.Second
	SecretLength        = 20
	minimumSecretLength = 16
	maximumSecretLength = 64
	maximumSkewSteps    = 2
)

var (
	ErrInvalidSecret = errors.New("TOTP secret must be between 16 and 64 bytes")
	ErrInvalidSkew   = errors.New("TOTP clock skew must be between 0 and 2 steps")
)

// GenerateSecret returns a cryptographically random 160-bit secret. Callers
// should encode it for display and protect it as credential material.
func GenerateSecret() ([]byte, error) {
	secret := make([]byte, SecretLength)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate TOTP secret: %w", err)
	}
	return secret, nil
}

// Code returns the six-digit TOTP value for secret at the supplied time.
func Code(secret []byte, at time.Time) (string, error) {
	if err := validateSecret(secret); err != nil {
		return "", err
	}
	counter, err := counterAt(at)
	if err != nil {
		return "", err
	}
	return codeAtCounter(secret, counter), nil
}

// Verifier binds replay tracking to one secret. A successfully used time step
// can never be accepted again, including by simultaneous requests.
type Verifier struct {
	mu       sync.Mutex
	secret   []byte
	skew     int64
	lastStep int64
	used     bool
}

// NewVerifier creates a replay-protecting verifier. allowedSkewSteps is
// deliberately bounded; one step (30 seconds) is the usual deployment value.
func NewVerifier(secret []byte, allowedSkewSteps int) (*Verifier, error) {
	if err := validateSecret(secret); err != nil {
		return nil, err
	}
	if allowedSkewSteps < 0 || allowedSkewSteps > maximumSkewSteps {
		return nil, ErrInvalidSkew
	}
	return &Verifier{secret: append([]byte(nil), secret...), skew: int64(allowedSkewSteps)}, nil
}

// Verify accepts a current or permitted adjacent time-step code once. The
// lock covers comparison and state update so concurrent submissions cannot
// both consume the same code.
func (v *Verifier) Verify(code string, at time.Time) bool {
	if len(code) != Digits {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	current, err := counterAt(at)
	if err != nil {
		return false
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	matched := int64(-1)
	for step := current - v.skew; step <= current+v.skew; step++ {
		if step < 0 {
			continue
		}
		expected := codeAtCounter(v.secret, step)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 && (!v.used || step > v.lastStep) {
			matched = step
		}
	}
	if matched < 0 {
		return false
	}
	v.lastStep = matched
	v.used = true
	return true
}

func validateSecret(secret []byte) error {
	if len(secret) < minimumSecretLength || len(secret) > maximumSecretLength {
		return ErrInvalidSecret
	}
	return nil
}

func counterAt(at time.Time) (int64, error) {
	seconds := at.Unix()
	if seconds < 0 {
		return 0, errors.New("TOTP time precedes Unix epoch")
	}
	return seconds / int64(Period/time.Second), nil
}

func codeAtCounter(secret []byte, counter int64) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(message[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	binaryCode := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	value := binaryCode % 1_000_000
	return fmt.Sprintf("%0*d", Digits, value)
}
