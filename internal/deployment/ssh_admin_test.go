package deployment

import (
	"strings"
	"testing"
)

func TestValidateSSHAdministratorConfig(t *testing.T) {
	tests := []struct {
		name   string
		config SSHAdministratorConfig
		valid  bool
	}{
		{name: "password authentication", config: SSHAdministratorConfig{Username: "jpadmin", Authentication: SSHAuthenticationPassword, Password: "correct-horse-battery"}, valid: true},
		{name: "key authentication", config: SSHAdministratorConfig{Username: "_media-admin", Authentication: SSHAuthenticationKey, Password: "correct-horse-battery", PublicKey: "ssh-ed25519 AAAA test"}, valid: true},
		{name: "root account", config: SSHAdministratorConfig{Username: "root", Authentication: SSHAuthenticationPassword, Password: "correct-horse-battery"}},
		{name: "invalid account characters", config: SSHAdministratorConfig{Username: "jpadmin;id", Authentication: SSHAuthenticationPassword, Password: "correct-horse-battery"}},
		{name: "trailing hyphen", config: SSHAdministratorConfig{Username: "jpadmin-", Authentication: SSHAuthenticationPassword, Password: "correct-horse-battery"}},
		{name: "short password", config: SSHAdministratorConfig{Username: "jpadmin", Authentication: SSHAuthenticationPassword, Password: "short"}},
		{name: "password delimiter", config: SSHAdministratorConfig{Username: "jpadmin", Authentication: SSHAuthenticationPassword, Password: "valid-enough:bad"}},
		{name: "key required", config: SSHAdministratorConfig{Username: "jpadmin", Authentication: SSHAuthenticationKey, Password: "correct-horse-battery"}},
		{name: "key is single line", config: SSHAdministratorConfig{Username: "jpadmin", Authentication: SSHAuthenticationKey, Password: "correct-horse-battery", PublicKey: "ssh-ed25519 AAAA\nssh-ed25519 BBBB"}},
		{name: "unknown authentication", config: SSHAdministratorConfig{Username: "jpadmin", Authentication: "keyboard", Password: "correct-horse-battery"}},
		{name: "password mode rejects public key", config: SSHAdministratorConfig{Username: "jpadmin", Authentication: SSHAuthenticationPassword, Password: "correct-horse-battery", PublicKey: "ssh-ed25519 AAAA"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateSSHAdministratorConfig(test.config)
			if test.valid && err != nil {
				t.Fatalf("expected valid config, got %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("expected invalid config")
			}
		})
	}
}

func TestSSHAdministratorLoginPromptKeepsExistingSession(t *testing.T) {
	prompt := SSHAdministratorLoginPrompt(SSHAdministratorConfig{Username: "jpadmin", Authentication: SSHAuthenticationKey})
	for _, expected := range []string{"separate SSH session", "jpadmin", "matching private key", "sudo", "Keep the current installer session open"} {
		if !strings.Contains(prompt, expected) {
			t.Errorf("prompt %q does not include %q", prompt, expected)
		}
	}
}
