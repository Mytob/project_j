package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	passwordAlgorithm  = "pbkdf2-sha256"
	passwordIterations = 600_000
	minIterations      = 600_000
	maxIterations      = 2_000_000
	passwordSaltBytes  = 16
	passwordHashBytes  = 32
	minimumRunes       = 12
	maximumBytes       = 1024
)

// HashPassword derives a salted PBKDF2-HMAC-SHA256 credential. Passwords must
// contain at least 12 Unicode code points and no more than 1024 UTF-8 bytes.
func HashPassword(password string) (string, error) {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < minimumRunes || len(password) > maximumBytes {
		return "", fmt.Errorf("password must contain at least %d characters and be at most %d bytes", minimumRunes, maximumBytes)
	}
	salt := make([]byte, passwordSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	derived, err := pbkdf2.Key(sha256.New, password, salt, passwordIterations, passwordHashBytes)
	if err != nil {
		return "", fmt.Errorf("derive password hash: %w", err)
	}
	return strings.Join([]string{
		passwordAlgorithm,
		strconv.Itoa(passwordIterations),
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(derived),
	}, "$"), nil
}

// ValidatePasswordHash checks the serialized credential format and resource
// bounds before a hash can be used for verification.
func ValidatePasswordHash(encoded string) error {
	_, _, _, _, err := parsePasswordHash(encoded)
	return err
}

// VerifyPassword compares a password to a serialized hash in constant time.
func VerifyPassword(encoded, password string) bool {
	iterations, salt, expected, ok, err := parsePasswordHash(encoded)
	if !ok || err != nil {
		return false
	}
	derived, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(expected))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(derived, expected) == 1
}

func parsePasswordHash(encoded string) (int, []byte, []byte, bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != passwordAlgorithm {
		return 0, nil, nil, false, fmt.Errorf("unsupported password hash format")
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < minIterations || iterations > maxIterations {
		return 0, nil, nil, false, fmt.Errorf("password hash iteration count is invalid")
	}
	salt, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(salt) != passwordSaltBytes {
		return 0, nil, nil, false, fmt.Errorf("password hash salt is invalid")
	}
	derived, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(derived) != passwordHashBytes {
		return 0, nil, nil, false, fmt.Errorf("password hash output is invalid")
	}
	return iterations, salt, derived, true, nil
}
