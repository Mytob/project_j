//go:build linux

package deployment

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
)

const (
	sshAdminConfigPath = "/etc/ssh/sshd_config.d/99-jellyfin-proxy-admin.conf"
	sshAdminMarker     = "# Managed by Jellyfin Proxy proxyctl"
	sshAdminComment    = "Jellyfin Proxy SSH administrator"
)

type InputCommandRunner interface {
	RunInput(context.Context, string, []byte, ...string) (string, error)
}

func (ExecRunner) RunInput(ctx context.Context, executable string, input []byte, args ...string) (string, error) {
	command := exec.CommandContext(ctx, executable, args...)
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s %s: %w: %s", executable, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

type SSHAdministratorChange struct {
	username             string
	dropInPath           string
	previousConfig       []byte
	previousConfigExists bool
	configChanged        bool
	userCreated          bool
	keyPath              string
	previousKey          []byte
	previousKeyMode      os.FileMode
	previousKeyExists    bool
	previousKeyUID       int
	previousKeyGID       int
	keyChanged           bool
	sshDirPath           string
	sshDirCreated        bool
	uid                  int
	gid                  int
	rootLoginDisabled    bool
}

// ConfigureSSHAdministrator creates (or resumes a product-owned) dedicated
// non-root sudo account, scopes its selected SSH method to that account, and
// leaves the current root SSH policy unchanged. The caller must verify a
// second login before calling DisableRootSSHLogin.
func ConfigureSSHAdministrator(ctx context.Context, config SSHAdministratorConfig, runner CommandRunner) (_ *SSHAdministratorChange, resultErr error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("SSH administrator setup requires root")
	}
	if err := ValidateSSHAdministratorConfig(config); err != nil {
		return nil, err
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	if _, err := parseSSHAdministratorKey(config); err != nil {
		return nil, err
	}
	if err := validateSSHConfigDirectory(filepath.Dir(sshAdminConfigPath)); err != nil {
		return nil, err
	}
	change := &SSHAdministratorChange{username: config.Username, dropInPath: sshAdminConfigPath}
	change.previousConfig, change.previousConfigExists, resultErr = readOwnedSSHConfig(sshAdminConfigPath)
	if resultErr != nil {
		return nil, resultErr
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, rollbackSSHAdministrator(ctx, change, runner))
		}
	}()

	if _, err := runner.Run(ctx, "/usr/sbin/sshd", "-t"); err != nil {
		return nil, fmt.Errorf("existing SSH configuration is invalid; no changes were made: %w", err)
	}
	account, exists, err := lookupSSHAccount(ctx, config.Username, runner)
	if err != nil {
		return nil, err
	}
	if exists {
		if account.comment != sshAdminComment {
			return nil, fmt.Errorf("SSH account %q already exists and is not managed by Jellyfin Proxy", config.Username)
		}
		if change.previousConfigExists && !bytes.Equal(change.previousConfig, sshAdministratorConfig(config, false)) && !bytes.Equal(change.previousConfig, sshAdministratorConfig(config, true)) {
			return nil, errors.New("a product-owned SSH account exists with a different configuration; use the existing login or remove it manually before retrying")
		}
		change.uid, change.gid = account.uid, account.gid
		if !change.previousConfigExists {
			// A power loss between useradd and publishing the managed sshd
			// drop-in leaves a marked, product-owned account. Complete that
			// partial setup on retry; root access is still untouched.
			if err := setSSHAdministratorPassword(ctx, config, runner); err != nil {
				return nil, err
			}
		} else {
			change.rootLoginDisabled = sshAdministratorRootDisabled(config, change.previousConfig)
		}
	} else {
		if _, err := runner.Run(ctx, "useradd", "--create-home", "--user-group", "--groups", "sudo", "--shell", "/bin/bash", "--comment", sshAdminComment, config.Username); err != nil {
			return nil, fmt.Errorf("create SSH administrator account: %w", err)
		}
		change.userCreated = true
		if err := setSSHAdministratorPassword(ctx, config, runner); err != nil {
			return nil, err
		}
		account, exists, err = lookupSSHAccount(ctx, config.Username, runner)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, errors.New("SSH administrator account was not visible after creation")
		}
		change.uid, change.gid = account.uid, account.gid
	}
	if _, err := runner.Run(ctx, "usermod", "-aG", "sudo", config.Username); err != nil {
		return nil, fmt.Errorf("grant the SSH administrator sudo group membership: %w", err)
	}
	if config.Authentication == SSHAuthenticationKey {
		if err := installSSHAdministratorKey(account.home, change, config.PublicKey); err != nil {
			return nil, err
		}
	}

	content := sshAdministratorConfig(config, change.rootLoginDisabled)
	if !change.previousConfigExists || !bytes.Equal(change.previousConfig, content) {
		if err := atomicReplace(change.dropInPath, content, 0o644); err != nil {
			return nil, fmt.Errorf("write managed SSH administrator policy: %w", err)
		}
		change.configChanged = true
		if err := os.Chown(change.dropInPath, 0, 0); err != nil {
			return nil, fmt.Errorf("secure managed SSH administrator policy: %w", err)
		}
	}
	if err := verifySSHAdministratorConfig(ctx, config, runner, change.rootLoginDisabled); err != nil {
		return nil, err
	}
	if change.configChanged {
		if _, err := runner.Run(ctx, "systemctl", "reload", "ssh.service"); err != nil {
			return nil, fmt.Errorf("reload SSH with the verified administrator policy: %w", err)
		}
	}
	return change, nil
}

func setSSHAdministratorPassword(ctx context.Context, config SSHAdministratorConfig, runner CommandRunner) error {
	inputRunner, ok := runner.(InputCommandRunner)
	if !ok {
		return errors.New("SSH account password input is unavailable")
	}
	if _, err := inputRunner.RunInput(ctx, "chpasswd", []byte(config.Username+":"+config.Password+"\n")); err != nil {
		return fmt.Errorf("set SSH administrator password: %w", err)
	}
	return nil
}

// DisableRootSSHLogin applies only after the caller has confirmed a separate
// login and sudo check for the configured administrator account.
func DisableRootSSHLogin(ctx context.Context, change *SSHAdministratorChange, config SSHAdministratorConfig, runner CommandRunner) error {
	if os.Geteuid() != 0 {
		return errors.New("changing root SSH access requires root")
	}
	if change == nil || change.username != config.Username || !change.configChanged && !change.previousConfigExists {
		return errors.New("verified SSH administrator setup is required before disabling root SSH login")
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	old, err := os.ReadFile(change.dropInPath)
	if err != nil || !bytes.Contains(old, []byte(sshAdminMarker)) {
		return errors.New("managed SSH administrator policy is unavailable")
	}
	expectedOld := sshAdministratorConfig(config, change.rootLoginDisabled)
	if !bytes.Equal(old, expectedOld) {
		return errors.New("managed SSH administrator policy changed after verification; inspect it before changing root login")
	}
	if change.rootLoginDisabled {
		return verifySSHAdministratorConfig(ctx, config, runner, true)
	}
	previouslyChanged := change.configChanged
	updated := sshAdministratorConfig(config, true)
	if err := atomicReplace(change.dropInPath, updated, 0o644); err != nil {
		return fmt.Errorf("write root SSH restriction: %w", err)
	}
	change.configChanged = true
	if err := os.Chown(change.dropInPath, 0, 0); err != nil {
		restoreErr := restoreSSHConfig(change.dropInPath, old)
		change.configChanged = previouslyChanged
		return errors.Join(fmt.Errorf("secure root SSH restriction: %w", err), restoreErr)
	}
	if err := verifySSHAdministratorConfig(ctx, config, runner, true); err != nil {
		restoreErr := restoreSSHConfig(change.dropInPath, old)
		change.configChanged = previouslyChanged
		return errors.Join(err, restoreErr)
	}
	if _, err := runner.Run(ctx, "systemctl", "reload", "ssh.service"); err != nil {
		restoreErr := restoreSSHConfig(change.dropInPath, old)
		change.configChanged = previouslyChanged
		_, reloadErr := runner.Run(context.Background(), "systemctl", "reload", "ssh.service")
		return errors.Join(fmt.Errorf("reload SSH after root-login restriction; previous policy restored: %w", err), restoreErr, reloadErr)
	}
	change.rootLoginDisabled = true
	return nil
}

func restoreSSHConfig(path string, data []byte) error {
	if err := atomicReplace(path, data, 0o644); err != nil {
		return fmt.Errorf("restore SSH policy: %w", err)
	}
	if err := os.Chown(path, 0, 0); err != nil {
		return fmt.Errorf("restore SSH policy ownership: %w", err)
	}
	return nil
}

// RollbackSSHAdministrator restores only the managed drop-in and files created
// for a new account. It never removes an account that existed before this run.
func RollbackSSHAdministrator(ctx context.Context, change *SSHAdministratorChange, runner CommandRunner) error {
	if runner == nil {
		runner = ExecRunner{}
	}
	return rollbackSSHAdministrator(ctx, change, runner)
}

func rollbackSSHAdministrator(ctx context.Context, change *SSHAdministratorChange, runner CommandRunner) error {
	if change == nil {
		return nil
	}
	var failures []error
	if change.dropInPath != "" && change.configChanged {
		if change.previousConfigExists {
			if err := atomicReplace(change.dropInPath, change.previousConfig, 0o644); err != nil {
				failures = append(failures, fmt.Errorf("restore previous SSH administrator policy: %w", err))
			} else if err := os.Chown(change.dropInPath, 0, 0); err != nil {
				failures = append(failures, fmt.Errorf("restore SSH policy ownership: %w", err))
			}
		} else if err := os.Remove(change.dropInPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, fmt.Errorf("remove incomplete SSH administrator policy: %w", err))
		}
		if _, err := runner.Run(ctx, "systemctl", "reload", "ssh.service"); err != nil {
			failures = append(failures, fmt.Errorf("reload previous SSH policy: %w", err))
		}
	}
	if change.keyChanged {
		if change.previousKeyExists {
			if err := atomicReplace(change.keyPath, change.previousKey, change.previousKeyMode.Perm()); err != nil {
				failures = append(failures, fmt.Errorf("restore previous authorized keys: %w", err))
			} else if err := os.Chown(change.keyPath, change.previousKeyUID, change.previousKeyGID); err != nil {
				failures = append(failures, fmt.Errorf("restore authorized keys ownership: %w", err))
			}
		} else if err := os.Remove(change.keyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, fmt.Errorf("remove newly created authorized keys: %w", err))
		}
	}
	if change.sshDirCreated {
		if err := os.Remove(change.sshDirPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, fmt.Errorf("remove newly created SSH key directory: %w", err))
		}
	}
	if change.userCreated {
		if _, err := runner.Run(ctx, "userdel", "--remove", change.username); err != nil {
			failures = append(failures, fmt.Errorf("remove the unverified SSH administrator account: %w", err))
		}
	}
	return errors.Join(failures...)
}

type sshAccount struct {
	uid     int
	gid     int
	comment string
	home    string
}

func lookupSSHAccount(ctx context.Context, username string, runner CommandRunner) (sshAccount, bool, error) {
	output, err := runner.Run(ctx, "getent", "passwd", username)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 {
			return sshAccount{}, false, nil
		}
		return sshAccount{}, false, fmt.Errorf("inspect SSH account %q: %w", username, err)
	}
	fields := strings.Split(strings.TrimSpace(output), ":")
	if len(fields) != 7 || fields[0] != username {
		return sshAccount{}, false, errors.New("system account lookup returned malformed data")
	}
	uid, uidErr := strconv.Atoi(fields[2])
	gid, gidErr := strconv.Atoi(fields[3])
	if uidErr != nil || gidErr != nil || uid < 1000 || fields[5] == "" || !filepath.IsAbs(fields[5]) {
		return sshAccount{}, false, errors.New("SSH administrator must be a regular non-root local account with an absolute home directory")
	}
	return sshAccount{uid: uid, gid: gid, comment: fields[4], home: fields[5]}, true, nil
}

func validateSSHConfigDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("OpenSSH configuration drop-in directory is missing or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("OpenSSH configuration drop-in directory must be root-owned")
	}
	return nil
}

func readOwnedSSHConfig(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, false, errors.New("managed SSH configuration path is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil, false, errors.New("managed SSH configuration must be root-owned")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	if !bytes.Contains(data, []byte(sshAdminMarker)) {
		return nil, false, errors.New("SSH configuration drop-in already exists and is not managed by Jellyfin Proxy")
	}
	return data, true, nil
}

func parseSSHAdministratorKey(config SSHAdministratorConfig) (ssh.PublicKey, error) {
	if config.Authentication != SSHAuthenticationKey {
		return nil, nil
	}
	key, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(config.PublicKey))
	if err != nil || key == nil || len(options) != 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("SSH public key is invalid; enter exactly one key without authorized_keys options")
	}
	_ = comment
	return key, nil
}

func sshAdministratorConfig(config SSHAdministratorConfig, disableRoot bool) []byte {
	password, publicKey := "no", "no"
	if config.Authentication == SSHAuthenticationPassword {
		password = "yes"
	} else {
		publicKey = "yes"
	}
	content := fmt.Sprintf("%s\nMatch User %s\n    PasswordAuthentication %s\n    KbdInteractiveAuthentication no\n    PubkeyAuthentication %s\nMatch all\n", sshAdminMarker, config.Username, password, publicKey)
	if disableRoot {
		content += "\nMatch User root\n    PermitRootLogin no\nMatch all\n"
	}
	return []byte(content)
}

func sshAdministratorRootDisabled(config SSHAdministratorConfig, existing []byte) bool {
	return bytes.Equal(existing, sshAdministratorConfig(config, true))
}

func verifySSHAdministratorConfig(ctx context.Context, config SSHAdministratorConfig, runner CommandRunner, rootDisabled bool) error {
	if _, err := runner.Run(ctx, "/usr/sbin/sshd", "-t"); err != nil {
		return fmt.Errorf("OpenSSH rejected the staged administrator policy: %w", err)
	}
	output, err := runner.Run(ctx, "/usr/sbin/sshd", "-T", "-C", "user="+config.Username+",host=localhost,addr=127.0.0.1")
	if err != nil {
		return fmt.Errorf("inspect effective SSH administrator policy: %w", err)
	}
	settings := sshSettings(output)
	wantPassword := config.Authentication == SSHAuthenticationPassword
	wantKey := config.Authentication == SSHAuthenticationKey
	if settings["passwordauthentication"] != yesNo(wantPassword) || settings["pubkeyauthentication"] != yesNo(wantKey) || settings["kbdinteractiveauthentication"] != "no" {
		return errors.New("effective SSH settings do not match the selected administrator authentication method")
	}
	if rootDisabled {
		rootOutput, err := runner.Run(ctx, "/usr/sbin/sshd", "-T", "-C", "user=root,host=localhost,addr=127.0.0.1")
		if err != nil || sshSettings(rootOutput)["permitrootlogin"] != "no" {
			return errors.New("effective SSH policy does not disable root login")
		}
	}
	return nil
}

func sshSettings(output string) map[string]string {
	settings := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			settings[strings.ToLower(fields[0])] = strings.ToLower(fields[1])
		}
	}
	return settings
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func installSSHAdministratorKey(home string, change *SSHAdministratorChange, input string) error {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(input))
	if err != nil || key == nil {
		return errors.New("SSH public key could not be parsed")
	}
	homeInfo, err := os.Lstat(home)
	if err != nil || !homeInfo.IsDir() || homeInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("SSH administrator home is missing or unsafe")
	}
	homeStat, ok := homeInfo.Sys().(*syscall.Stat_t)
	if !ok || int(homeStat.Uid) != change.uid || homeInfo.Mode().Perm()&0o022 != 0 {
		return errors.New("SSH administrator home must be owned by the account and not writable by others")
	}
	sshDir := filepath.Join(home, ".ssh")
	change.sshDirPath = sshDir
	if err := os.Mkdir(sshDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create SSH key directory: %w", err)
	} else if err == nil {
		change.sshDirCreated = true
		if err := os.Chown(sshDir, change.uid, change.gid); err != nil {
			return fmt.Errorf("set SSH key directory owner: %w", err)
		}
	}
	sshInfo, err := os.Lstat(sshDir)
	if err != nil || !sshInfo.IsDir() || sshInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("SSH key directory is unsafe")
	}
	sshStat, ok := sshInfo.Sys().(*syscall.Stat_t)
	if !ok || int(sshStat.Uid) != change.uid || sshInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("existing SSH key directory must be owned by the SSH administrator and private")
	}
	path := filepath.Join(sshDir, "authorized_keys")
	change.keyPath = path
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("authorized_keys is unsafe")
		}
		change.previousKey, err = os.ReadFile(path)
		if err != nil {
			return err
		}
		change.previousKeyMode = info.Mode()
		change.previousKeyExists = true
		keyStat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("authorized_keys ownership cannot be verified")
		}
		change.previousKeyUID, change.previousKeyGID = int(keyStat.Uid), int(keyStat.Gid)
		if change.previousKeyUID != change.uid || change.previousKeyGID != change.gid || info.Mode().Perm()&0o077 != 0 {
			return errors.New("existing authorized_keys must be administrator-owned and private")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	canonical := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	if !authorizedKeyPresent(change.previousKey, key) {
		updated := append([]byte(nil), change.previousKey...)
		if len(updated) > 0 && updated[len(updated)-1] != '\n' {
			updated = append(updated, '\n')
		}
		updated = append(updated, canonical...)
		updated = append(updated, '\n')
		if err := atomicReplace(path, updated, 0o600); err != nil {
			return fmt.Errorf("write SSH authorized key: %w", err)
		}
		change.keyChanged = true
		if err := os.Chown(path, change.uid, change.gid); err != nil {
			return fmt.Errorf("set authorized key owner: %w", err)
		}
	}
	return nil
}

func authorizedKeyPresent(data []byte, wanted ssh.PublicKey) bool {
	for len(bytes.TrimSpace(data)) > 0 {
		key, _, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return false
		}
		if bytes.Equal(key.Marshal(), wanted.Marshal()) {
			return true
		}
		data = rest
	}
	return false
}
