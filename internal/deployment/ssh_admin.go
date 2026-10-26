package deployment

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type SSHAuthentication string

const (
	SSHAuthenticationPassword SSHAuthentication = "password"
	SSHAuthenticationKey      SSHAuthentication = "public-key"
)

// SSHAdministratorConfig describes a dedicated non-root sudo account created
// during a fresh installation. Its password is also the account's sudo
// password when public-key SSH authentication is selected.
type SSHAdministratorConfig struct {
	Username       string
	Authentication SSHAuthentication
	Password       string
	PublicKey      string
}

var sshAdministratorName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func ValidateSSHAdministratorConfig(config SSHAdministratorConfig) error {
	if config.Username == "root" || !sshAdministratorName.MatchString(config.Username) || strings.HasSuffix(config.Username, "-") {
		return errors.New("SSH administrator username must be a valid, unused Linux account name")
	}
	if len(config.Password) < 12 || strings.ContainsAny(config.Password, "\x00\r\n:") {
		return errors.New("SSH administrator password must be at least 12 characters and cannot contain a colon or line break")
	}
	switch config.Authentication {
	case SSHAuthenticationPassword:
		if config.PublicKey != "" {
			return errors.New("a public key is only valid with public-key authentication")
		}
	case SSHAuthenticationKey:
		key := strings.TrimSpace(config.PublicKey)
		if key == "" || strings.ContainsAny(key, "\x00\r\n") {
			return errors.New("a single-line SSH public key is required")
		}
	default:
		return errors.New("SSH authentication must be password or public-key")
	}
	return nil
}

// SSHAdministratorLoginPrompt describes the exact second-session check the
// installer requires before it can disable root SSH login.
func SSHAdministratorLoginPrompt(config SSHAdministratorConfig) string {
	method := "password"
	if config.Authentication == SSHAuthenticationKey {
		method = "the matching private key"
	}
	return fmt.Sprintf("Open a separate SSH session to this server as %s using %s. Confirm that login works and that sudo requests this account's password. Keep the current installer session open.", config.Username, method)
}
