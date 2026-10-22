//go:build linux

package deployment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func newTestSSHKey(t *testing.T) string {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey)))
}

func TestSSHAdministratorConfigIsUserScopedAndCanDisableRoot(t *testing.T) {
	config := SSHAdministratorConfig{Username: "jpadmin", Authentication: SSHAuthenticationKey}
	base := string(sshAdministratorConfig(config, false))
	for _, expected := range []string{
		sshAdminMarker,
		"Match User jpadmin",
		"PasswordAuthentication no",
		"KbdInteractiveAuthentication no",
		"PubkeyAuthentication yes",
		"Match all",
	} {
		if !strings.Contains(base, expected) {
			t.Errorf("base policy does not contain %q", expected)
		}
	}
	if strings.Contains(base, "PermitRootLogin") {
		t.Fatal("base policy unexpectedly changes root login")
	}

	rootDisabled := string(sshAdministratorConfig(config, true))
	if !strings.HasPrefix(rootDisabled, base) || !strings.Contains(rootDisabled, "Match User root\n    PermitRootLogin no\nMatch all\n") {
		t.Fatalf("root restriction is not an explicit addition to the administrator policy:\n%s", rootDisabled)
	}
	if !sshAdministratorRootDisabled(config, []byte(rootDisabled)) || sshAdministratorRootDisabled(config, []byte(base)) {
		t.Fatal("retry root-policy detection did not preserve the existing root restriction")
	}
}

func TestParseSSHAdministratorKey(t *testing.T) {
	keyText := newTestSSHKey(t)
	config := SSHAdministratorConfig{Authentication: SSHAuthenticationKey, PublicKey: keyText}
	key, err := parseSSHAdministratorKey(config)
	if err != nil || key == nil {
		t.Fatalf("valid key rejected: key=%v err=%v", key, err)
	}

	for name, invalid := range map[string]string{
		"malformed":              "ssh-ed25519 not-base64",
		"authorized_keys option": `command="echo unsafe" ` + keyText,
		"multiple keys":          keyText + "\n" + newTestSSHKey(t),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseSSHAdministratorKey(SSHAdministratorConfig{Authentication: SSHAuthenticationKey, PublicKey: invalid}); err == nil {
				t.Fatal("invalid SSH key accepted")
			}
		})
	}
}

func TestInstallSSHAdministratorKeyAddsKeyOnceAndRejectsSymlink(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	change := &SSHAdministratorChange{uid: os.Geteuid(), gid: os.Getegid()}
	key := newTestSSHKey(t)
	if err := installSSHAdministratorKey(home, change, key); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(change.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(change.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("authorized_keys mode = %o, want 600", info.Mode().Perm())
	}
	if !authorizedKeyPresent(first, mustParseTestKey(t, key)) {
		t.Fatal("installed key is not present")
	}

	secondChange := &SSHAdministratorChange{uid: os.Geteuid(), gid: os.Getegid()}
	if err := installSSHAdministratorKey(home, secondChange, key); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(secondChange.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || secondChange.keyChanged {
		t.Fatal("retry duplicated or rewrote the already installed public key")
	}

	symlinkHome := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(symlinkHome, 0o700); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(symlinkHome, ".ssh")); err != nil {
		t.Fatal(err)
	}
	if err := installSSHAdministratorKey(symlinkHome, &SSHAdministratorChange{uid: os.Geteuid(), gid: os.Getegid()}, key); err == nil {
		t.Fatal("symlinked .ssh directory accepted")
	}
}

func mustParseTestKey(t *testing.T, text string) ssh.PublicKey {
	t.Helper()
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestAuthorizedKeyPresentScansAllKeys(t *testing.T) {
	first := newTestSSHKey(t)
	second := newTestSSHKey(t)
	data := []byte(first + "\n" + second + "\n")
	if !authorizedKeyPresent(data, mustParseTestKey(t, second)) {
		t.Fatal("did not find key after the first authorized key")
	}
	if authorizedKeyPresent(data, mustParseTestKey(t, newTestSSHKey(t))) {
		t.Fatal("reported a key that is not authorized")
	}
}

type sshPasswordInputRecorder struct {
	input []byte
	args  []string
}

func (r *sshPasswordInputRecorder) Run(context.Context, string, ...string) (string, error) {
	return "", errors.New("unexpected command")
}

func (r *sshPasswordInputRecorder) RunInput(_ context.Context, command string, input []byte, args ...string) (string, error) {
	if command != "chpasswd" {
		return "", errors.New("unexpected password command")
	}
	r.input = append([]byte(nil), input...)
	r.args = append([]string(nil), args...)
	return "", nil
}

func TestSetSSHAdministratorPasswordUsesStdin(t *testing.T) {
	const password = "correct-horse-battery"
	recorder := &sshPasswordInputRecorder{}
	if err := setSSHAdministratorPassword(context.Background(), SSHAdministratorConfig{Username: "jpadmin", Password: password}, recorder); err != nil {
		t.Fatal(err)
	}
	if string(recorder.input) != "jpadmin:"+password+"\n" {
		t.Fatalf("password input = %q", recorder.input)
	}
	for _, argument := range recorder.args {
		if strings.Contains(argument, password) {
			t.Fatal("SSH password was passed in the process argument list")
		}
	}
}

type sshPolicyTestRunner struct {
	reloadCalls int
	failReloads int
}

func (r *sshPolicyTestRunner) Run(_ context.Context, executable string, args ...string) (string, error) {
	if executable == "/usr/sbin/sshd" {
		if len(args) > 0 && args[0] == "-t" {
			return "", nil
		}
		settings := "passwordauthentication yes\npubkeyauthentication no\nkbdinteractiveauthentication no\npermitrootlogin yes\n"
		if len(args) > 0 && strings.Contains(args[len(args)-1], "user=root,") {
			settings = strings.Replace(settings, "permitrootlogin yes", "permitrootlogin no", 1)
		}
		return settings, nil
	}
	if executable == "systemctl" && len(args) == 2 && args[0] == "reload" && args[1] == "ssh.service" {
		r.reloadCalls++
		if r.reloadCalls <= r.failReloads {
			return "", errors.New("simulated reload failure")
		}
		return "", nil
	}
	return "", errors.New("unexpected command")
}

func TestFailedRootSSHRestrictionPreservesEarlierRollbackState(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("test writes root-owned SSH policy files")
	}
	config := SSHAdministratorConfig{Username: "jpadmin", Authentication: SSHAuthenticationPassword, Password: "correct-horse-battery"}
	path := filepath.Join(t.TempDir(), "sshd.conf")
	basePolicy := sshAdministratorConfig(config, false)
	if err := os.WriteFile(path, basePolicy, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &sshPolicyTestRunner{failReloads: 1}
	change := &SSHAdministratorChange{
		username:             config.Username,
		dropInPath:           path,
		previousConfig:       []byte("pre-install policy"),
		previousConfigExists: true,
		configChanged:        true,
	}
	if err := DisableRootSSHLogin(context.Background(), change, config, runner); err == nil {
		t.Fatal("simulated SSH reload failure was ignored")
	}
	if !change.configChanged {
		t.Fatal("failed root restriction erased the earlier administrator config change")
	}
	if change.rootLoginDisabled {
		t.Fatal("failed root restriction was recorded as successful")
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, basePolicy) {
		t.Fatalf("failed root restriction did not restore the verified administrator policy: %v", err)
	}
	if err := RollbackSSHAdministrator(context.Background(), change, runner); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(path)
	if err != nil || string(restored) != "pre-install policy" {
		t.Fatalf("outer rollback did not restore the pre-install state: %q (%v)", restored, err)
	}
}
