package totp

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

func TestRFC6238SHA1ReferenceVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1_111_111_109, "081804"},
		{1_111_111_111, "050471"},
		{1_234_567_890, "005924"},
		{2_000_000_000, "279037"},
		{20_000_000_000, "353130"},
	}
	for _, tc := range cases {
		got, err := Code(secret, time.Unix(tc.unix, 0))
		if err != nil {
			t.Fatalf("Code at %d: %v", tc.unix, err)
		}
		if got != tc.want {
			t.Errorf("Code at %d = %s, want %s", tc.unix, got, tc.want)
		}
	}
}

func TestCodeAndTimeStepBoundaries(t *testing.T) {
	secret := []byte("12345678901234567890")
	first, err := Code(secret, time.Unix(29, 999_999_999))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Code(secret, time.Unix(30, 0))
	if err != nil {
		t.Fatal(err)
	}
	if first != "755224" || second != "287082" {
		t.Fatalf("codes around step boundary = %s, %s", first, second)
	}
}

func TestVerifierAcceptsCodeOnceAndRejectsInvalidCodes(t *testing.T) {
	secret := []byte("12345678901234567890")
	verifier, err := NewVerifier(secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(59, 0)
	valid, _ := Code(secret, now)
	if !verifier.Verify(valid, now) {
		t.Fatal("valid code rejected")
	}
	if verifier.Verify(valid, now) {
		t.Fatal("replayed code accepted")
	}
	for _, invalid := range []string{"", "28708", "2870820", "28x082", " 87082", "999999"} {
		if verifier.Verify(invalid, now.Add(30*time.Second)) {
			t.Errorf("invalid code %q accepted", invalid)
		}
	}
}

func TestVerifierClockSkewIsBounded(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(90, 0)
	previous, _ := Code(secret, now.Add(-Period))
	verifier, err := NewVerifier(secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !verifier.Verify(previous, now) {
		t.Fatal("previous-step code outside tolerance was rejected")
	}

	tooOldVerifier, _ := NewVerifier(secret, 1)
	tooOld, _ := Code(secret, now.Add(-2*Period))
	if tooOldVerifier.Verify(tooOld, now) {
		t.Fatal("code two steps behind was accepted")
	}

	futureVerifier, _ := NewVerifier(secret, 1)
	future, _ := Code(secret, now.Add(2*Period))
	if futureVerifier.Verify(future, now) {
		t.Fatal("code two steps ahead was accepted")
	}
}

func TestVerifierRejectsOlderStepAfterClockRollback(t *testing.T) {
	secret := []byte("12345678901234567890")
	verifier, err := NewVerifier(secret, 2)
	if err != nil {
		t.Fatal(err)
	}
	later := time.Unix(120, 0)
	code, _ := Code(secret, later)
	if !verifier.Verify(code, later) {
		t.Fatal("valid later-step code rejected")
	}
	earlier := time.Unix(90, 0)
	oldCode, _ := Code(secret, earlier)
	if verifier.Verify(oldCode, earlier) {
		t.Fatal("clock rollback allowed an older step")
	}
}

func TestConcurrentVerificationConsumesCodeOnlyOnce(t *testing.T) {
	secret := []byte("12345678901234567890")
	verifier, err := NewVerifier(secret, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_010, 0)
	code, _ := Code(secret, now)
	const attempts = 48
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if verifier.Verify(code, now) {
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

func TestSecretValidationAndDefensiveCopy(t *testing.T) {
	for _, secret := range [][]byte{nil, bytes.Repeat([]byte{1}, 15), bytes.Repeat([]byte{1}, 65)} {
		if _, err := Code(secret, time.Unix(59, 0)); err == nil {
			t.Errorf("Code accepted secret of length %d", len(secret))
		}
		if _, err := NewVerifier(secret, 1); err == nil {
			t.Errorf("NewVerifier accepted secret of length %d", len(secret))
		}
	}
	secret := bytes.Repeat([]byte{7}, SecretLength)
	verifier, err := NewVerifier(secret, 0)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_010, 0)
	code, _ := Code(secret, at)
	for i := range secret {
		secret[i] = 0
	}
	if !verifier.Verify(code, at) {
		t.Fatal("caller mutation changed verifier secret")
	}
}

func TestSecretGeneration(t *testing.T) {
	first, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != SecretLength || len(second) != SecretLength {
		t.Fatalf("secret lengths = %d and %d, want %d", len(first), len(second), SecretLength)
	}
}

func TestVerifierConfigurationAndPreEpochTime(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, skew := range []int{-1, maximumSkewSteps + 1} {
		if _, err := NewVerifier(secret, skew); err == nil {
			t.Errorf("NewVerifier accepted skew %d", skew)
		}
	}
	if _, err := Code(secret, time.Unix(-1, 0)); err == nil {
		t.Fatal("Code accepted time before Unix epoch")
	}
	verifier, _ := NewVerifier(secret, 0)
	if verifier.Verify("287082", time.Unix(-1, 0)) {
		t.Fatal("Verify accepted time before Unix epoch")
	}
}
