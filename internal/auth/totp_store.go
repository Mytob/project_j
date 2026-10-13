package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/Mytob/project_j/internal/totp"
)

const (
	totpKeySize     = 32
	totpStateFormat = 1
	totpSkewSteps   = 1
)

type TOTPStatus string

const (
	TOTPUnconfigured TOTPStatus = "unconfigured"
	TOTPPending      TOTPStatus = "pending"
	TOTPEnabled      TOTPStatus = "enabled"
	TOTPRecovery     TOTPStatus = "recovery_required"
)

var (
	ErrTOTPEnrollmentPending = errors.New("TOTP enrollment is already pending")
	ErrTOTPAlreadyEnabled    = errors.New("TOTP is already enabled")
	ErrNoTOTPEnrollment      = errors.New("no TOTP enrollment is pending")
	ErrInvalidTOTPCode       = errors.New("TOTP code was not accepted")
	ErrTOTPNotEnabled        = errors.New("TOTP is not enabled")
)

type totpStateFile struct {
	Version           int        `json:"version"`
	Status            TOTPStatus `json:"status"`
	RequireEnrollment bool       `json:"require_enrollment,omitempty"`
	Secret            []byte     `json:"secret,omitempty"`
	PendingSecret     []byte     `json:"pending_secret,omitempty"`
	LastAcceptedStep  int64      `json:"last_accepted_step,omitempty"`
	HasAcceptedStep   bool       `json:"has_accepted_step,omitempty"`
}

// TOTPStore stores the authenticator secret encrypted with a separate
// installation key. Its mutex serializes state transitions and replay updates.
type TOTPStore struct {
	mu   sync.Mutex
	path string
	key  []byte
	file totpStateFile
}

// CreateTOTPKey creates an independent 256-bit key file without replacing an
// existing key. Installers should set its ownership for the admin container
// and mount it read-only.
func CreateTOTPKey(path string) error {
	if path == "" {
		return errors.New("TOTP key path is empty")
	}
	key := make([]byte, totpKeySize)
	defer clear(key)
	if _, err := rand.Read(key); err != nil {
		return errors.New("generate TOTP storage key")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create TOTP key directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create TOTP key file: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(key); err != nil {
		return errors.New("write TOTP key file")
	}
	if err := file.Sync(); err != nil {
		return errors.New("sync TOTP key file")
	}
	if err := file.Close(); err != nil {
		return errors.New("close TOTP key file")
	}
	remove = false
	return nil
}

// LoadTOTPKey validates and loads the independent storage key. The key file
// may be owner-only or readable by the dedicated admin group, but never by
// other users or writable by its group.
func LoadTOTPKey(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("TOTP key path is empty")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect TOTP key file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("TOTP key must be a regular file")
	}
	if runtime.GOOS != "windows" {
		mode := info.Mode().Perm()
		if mode&^os.FileMode(0o640) != 0 || mode&0o027 != 0 || mode&0o440 == 0 {
			return nil, errors.New("TOTP key file permissions are too broad or unreadable")
		}
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read TOTP key file")
	}
	if len(key) != totpKeySize {
		return nil, errors.New("TOTP key file has an invalid length")
	}
	return key, nil
}

// InitializeTOTPStore creates the versioned unconfigured marker during a fresh
// install or an explicit v1.0 migration. It never replaces an existing file.
func InitializeTOTPStore(path string, key []byte) (*TOTPStore, error) {
	if path == "" {
		return nil, errors.New("TOTP state path is empty")
	}
	if len(key) != totpKeySize {
		return nil, errors.New("TOTP storage key has an invalid length")
	}
	if _, err := os.Lstat(path); err == nil {
		return nil, errors.New("TOTP state file already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect TOTP state before initialization: %w", err)
	}
	store := &TOTPStore{path: path, key: append([]byte(nil), key...), file: totpStateFile{Version: totpStateFormat, Status: TOTPUnconfigured}}
	if err := store.writeState(store.file, true); err != nil {
		return nil, err
	}
	return store, nil
}

// NewTOTPStore opens the persistent authenticator state. A missing, malformed,
// unreadable, or unauthentic state fails closed.
func NewTOTPStore(path string, key []byte) (*TOTPStore, error) {
	if path == "" {
		return nil, errors.New("TOTP state path is empty")
	}
	if len(key) != totpKeySize {
		return nil, errors.New("TOTP storage key has an invalid length")
	}
	store := &TOTPStore{path: path, key: append([]byte(nil), key...), file: totpStateFile{Version: totpStateFormat, Status: TOTPUnconfigured}}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *TOTPStore) Status() TOTPStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.Status
}

// RequiresEnrollment reports whether a root recovery operation requires the
// next password-authenticated session to complete a new enrollment first.
func (s *TOTPStore) RequiresEnrollment() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.Status == TOTPRecovery || (s.file.Status == TOTPPending && s.file.RequireEnrollment)
}

// BeginEnrollment creates and persists a pending secret. It is not active
// until ConfirmEnrollment accepts a code for it.
func (s *TOTPStore) BeginEnrollment() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	requireEnrollment := false
	switch s.file.Status {
	case TOTPEnabled:
		return nil, ErrTOTPAlreadyEnabled
	case TOTPPending:
		return nil, ErrTOTPEnrollmentPending
	case TOTPUnconfigured:
	case TOTPRecovery:
		requireEnrollment = true
	default:
		return nil, errors.New("TOTP state is invalid")
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		return nil, errors.New("generate pending TOTP secret")
	}
	ciphertext, err := s.encrypt(secret, "pending")
	if err != nil {
		clear(secret)
		return nil, err
	}
	candidate := totpStateFile{Version: totpStateFormat, Status: TOTPPending, PendingSecret: ciphertext, RequireEnrollment: requireEnrollment}
	if err := s.persist(candidate); err != nil {
		clear(secret)
		return nil, err
	}
	s.file = candidate
	return secret, nil
}

// PendingSecret returns a copy of an incomplete enrollment secret for the
// enrollment UI. Callers must first verify the administrator's password.
func (s *TOTPStore) PendingSecret() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file.Status != TOTPPending {
		return nil, ErrNoTOTPEnrollment
	}
	return s.decrypt(s.file.PendingSecret, "pending")
}

// ConfirmEnrollment atomically activates a pending secret and consumes the
// confirming code so it cannot be reused after a restart.
func (s *TOTPStore) ConfirmEnrollment(code string, atTime time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file.Status != TOTPPending {
		return ErrNoTOTPEnrollment
	}
	secret, err := s.decrypt(s.file.PendingSecret, "pending")
	if err != nil {
		return err
	}
	defer clear(secret)
	verifier, err := totp.NewVerifier(secret, totpSkewSteps)
	if err != nil {
		return errors.New("pending TOTP secret is invalid")
	}
	if !verifier.Verify(code, atTime) {
		return ErrInvalidTOTPCode
	}
	lastStep, hasStep := verifier.LastAcceptedStep()
	encrypted, err := s.encrypt(secret, "active")
	if err != nil {
		return err
	}
	candidate := totpStateFile{Version: totpStateFormat, Status: TOTPEnabled, Secret: encrypted, LastAcceptedStep: lastStep, HasAcceptedStep: hasStep}
	if err := s.persist(candidate); err != nil {
		return err
	}
	s.file = candidate
	return nil
}

// CancelEnrollment removes a pending secret and returns to the unconfigured
// state. Established TOTP cannot be disabled through this method.
func (s *TOTPStore) CancelEnrollment() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file.Status != TOTPPending {
		return ErrNoTOTPEnrollment
	}
	status := TOTPUnconfigured
	if s.file.RequireEnrollment {
		status = TOTPRecovery
	}
	candidate := totpStateFile{Version: totpStateFormat, Status: status}
	if err := s.persist(candidate); err != nil {
		return err
	}
	s.file = candidate
	return nil
}

// RequireFreshEnrollment invalidates every current/pending factor and marks
// TOTP mandatory for the next admin session. This is reserved for root CLI
// recovery; it is never exposed through an HTTP handler.
func (s *TOTPStore) RequireFreshEnrollment() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file.Status == TOTPRecovery {
		return nil
	}
	candidate := totpStateFile{Version: totpStateFormat, Status: TOTPRecovery}
	if err := s.persist(candidate); err != nil {
		return err
	}
	s.file = candidate
	return nil
}

// Disable clears any TOTP credential and returns to the optional, unconfigured
// state. Only the privileged local CLI calls this operation.
func (s *TOTPStore) Disable() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file.Status == TOTPUnconfigured {
		return nil
	}
	candidate := totpStateFile{Version: totpStateFormat, Status: TOTPUnconfigured}
	if err := s.persist(candidate); err != nil {
		return err
	}
	s.file = candidate
	return nil
}

// Verify checks one active TOTP code and persists the replay checkpoint before
// reporting success. A write failure therefore denies the authentication.
func (s *TOTPStore) Verify(code string, atTime time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file.Status != TOTPEnabled {
		return false, ErrTOTPNotEnabled
	}
	secret, err := s.decrypt(s.file.Secret, "active")
	if err != nil {
		return false, err
	}
	defer clear(secret)
	verifier, err := totp.NewVerifierWithLastStep(secret, totpSkewSteps, s.file.LastAcceptedStep, s.file.HasAcceptedStep)
	if err != nil {
		return false, errors.New("stored TOTP replay state is invalid")
	}
	if !verifier.Verify(code, atTime) {
		return false, nil
	}
	step, hasStep := verifier.LastAcceptedStep()
	candidate := s.file
	candidate.LastAcceptedStep = step
	candidate.HasAcceptedStep = hasStep
	if err := s.persist(candidate); err != nil {
		return false, err
	}
	s.file = candidate
	return true, nil
}

func (s *TOTPStore) load() error {
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("TOTP state file is missing")
	}
	if err != nil {
		return fmt.Errorf("inspect TOTP state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("TOTP state must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return errors.New("TOTP state file permissions must be 600")
	}
	file, err := os.Open(s.path)
	if err != nil {
		return fmt.Errorf("open TOTP state: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 16<<10))
	decoder.DisallowUnknownFields()
	var state totpStateFile
	if err := decoder.Decode(&state); err != nil {
		return errors.New("decode TOTP state")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("TOTP state contains trailing data")
	}
	if err := s.validate(state); err != nil {
		return err
	}
	s.file = state
	return nil
}

func (s *TOTPStore) validate(state totpStateFile) error {
	if state.Version != totpStateFormat {
		return errors.New("unsupported TOTP state version")
	}
	switch state.Status {
	case TOTPUnconfigured:
		if state.RequireEnrollment || len(state.Secret) != 0 || len(state.PendingSecret) != 0 || state.HasAcceptedStep || state.LastAcceptedStep != 0 {
			return errors.New("unconfigured TOTP state contains credentials")
		}
	case TOTPRecovery:
		if state.RequireEnrollment || len(state.Secret) != 0 || len(state.PendingSecret) != 0 || state.HasAcceptedStep || state.LastAcceptedStep != 0 {
			return errors.New("recovery-required TOTP state contains credentials")
		}
	case TOTPPending:
		if len(state.Secret) != 0 || len(state.PendingSecret) == 0 || state.HasAcceptedStep || state.LastAcceptedStep != 0 {
			return errors.New("pending TOTP state is invalid")
		}
		secret, err := s.decrypt(state.PendingSecret, "pending")
		if err != nil {
			return errors.New("pending TOTP secret cannot be verified")
		}
		clear(secret)
	case TOTPEnabled:
		if state.RequireEnrollment || len(state.Secret) == 0 || len(state.PendingSecret) != 0 || !state.HasAcceptedStep || state.LastAcceptedStep < 0 {
			return errors.New("enabled TOTP state is invalid")
		}
		secret, err := s.decrypt(state.Secret, "active")
		if err != nil {
			return errors.New("active TOTP secret cannot be verified")
		}
		if len(secret) < 16 || len(secret) > 64 {
			clear(secret)
			return errors.New("active TOTP secret has an invalid length")
		}
		clear(secret)
	default:
		return errors.New("TOTP state has an invalid status")
	}
	return nil
}

func (s *TOTPStore) persist(state totpStateFile) error {
	return s.writeState(state, false)
}

func (s *TOTPStore) writeState(state totpStateFile, initial bool) error {
	data, err := json.Marshal(state)
	if err != nil {
		return errors.New("encode TOTP state")
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create TOTP state directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".totp-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary TOTP state: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return errors.New("restrict temporary TOTP state permissions")
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return errors.New("write TOTP state")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return errors.New("sync TOTP state")
	}
	if err := tmp.Close(); err != nil {
		return errors.New("close TOTP state")
	}
	if initial {
		if err := os.Link(tmpPath, s.path); err != nil {
			return fmt.Errorf("create initial TOTP state: %w", err)
		}
	} else if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replace TOTP state: %w", err)
	}
	if directory, err := os.Open(dir); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func (s *TOTPStore) encrypt(secret []byte, purpose string) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, errors.New("initialize TOTP state encryption")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("initialize TOTP state encryption")
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("generate TOTP state nonce")
	}
	return aead.Seal(nonce, nonce, secret, []byte("jellyfin-proxy/totp/"+purpose+"/v1")), nil
}

func (s *TOTPStore) decrypt(ciphertext []byte, purpose string) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, errors.New("initialize TOTP state encryption")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("stored TOTP secret is invalid")
	}
	nonce, sealed := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	secret, err := aead.Open(nil, nonce, sealed, []byte("jellyfin-proxy/totp/"+purpose+"/v1"))
	if err != nil {
		return nil, errors.New("stored TOTP secret cannot be verified")
	}
	return secret, nil
}
