package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"charm.land/huh/v2"
	"github.com/Mytob/project_j/internal/deployment"
	"github.com/Mytob/project_j/internal/whitelist"
)

type installSettings struct {
	domain            string
	allowed           string
	password          string
	confirm           string
	sshUsername       string
	sshAuthentication string
	sshPassword       string
	sshConfirm        string
	sshPublicKey      string
	disableRootSSH    bool
	port              string
	backupSchedule    string
	backupRetention   string
	approved          bool
}

// runInstallWizard gathers and reviews all values consumed by first install.
// Huh uses its full-screen keyboard UI in a terminal and accessible prompts in
// pipes or TERM=dumb environments.
func runInstallWizard(input io.Reader, output io.Writer) (installSettings, error) {
	return runInstallWizardWithPreflight(input, output, deployment.InstallResourceReport{})
}

func runInstallWizardWithPreflight(input io.Reader, output io.Writer, preflight deployment.InstallResourceReport) (installSettings, error) {
	settings := installSettings{sshAuthentication: string(deployment.SSHAuthenticationPassword)}
	accessible := os.Getenv("TERM") == "dumb"
	if file, ok := input.(*os.File); !ok {
		accessible = true
	} else if info, err := file.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		accessible = true
	}
	domain := huh.NewInput().
		Title("Base domain").
		Description("DNS must point the base, admin and access names to this server.").
		Placeholder("example.com").
		Validate(func(value string) error { _, err := deployment.ValidateDomain(value); return err }).
		Value(&settings.domain)
	allowed := huh.NewInput().
		Title("Administrator IP allowlist").
		Description("Enter comma-separated IP addresses or CIDR ranges. This prevents locking yourself out of the admin site.").
		Placeholder("203.0.113.10/32, 2001:db8::10/128").
		Validate(validateAllowlistInput).
		Value(&settings.allowed)
	password := huh.NewInput().
		Title("Initial administrator password").
		Description("Use at least 12 characters. The value is masked while typed.").
		EchoMode(huh.EchoModePassword).
		Validate(func(value string) error {
			if len(value) < 12 {
				return errors.New("administrator password must contain at least 12 characters")
			}
			return nil
		}).
		Value(&settings.password)
	confirmation := huh.NewInput().
		Title("Confirm administrator password").
		EchoMode(huh.EchoModePassword).
		Validate(func(value string) error {
			if value != settings.password {
				return errors.New("passwords do not match")
			}
			return nil
		}).
		Value(&settings.confirm)
	sshUsername := huh.NewInput().
		Title("Dedicated SSH administrator username").
		Description("Choose an unused non-root Linux account name. The account will be added to sudo.").
		Placeholder("jpadmin").
		Validate(func(value string) error {
			return deployment.ValidateSSHAdministratorConfig(deployment.SSHAdministratorConfig{Username: strings.TrimSpace(value), Authentication: deployment.SSHAuthenticationPassword, Password: "temporary-validation-password"})
		}).
		Value(&settings.sshUsername)
	sshAuthentication := huh.NewInput().
		Title("SSH authentication method").
		Description("Enter password or public-key. The administrator password is used for sudo in either mode.").
		Placeholder("public-key").
		Validate(validateSSHAuthenticationInput).
		Value(&settings.sshAuthentication)
	sshPassword := huh.NewInput().
		Title("SSH administrator and sudo password").
		Description("Use at least 12 characters. The value is masked; for public-key SSH it remains the sudo password.").
		EchoMode(huh.EchoModePassword).
		Validate(validateSSHAdministratorPassword).
		Value(&settings.sshPassword)
	sshConfirmation := huh.NewInput().
		Title("Confirm SSH administrator password").
		EchoMode(huh.EchoModePassword).
		Validate(func(value string) error {
			if value != settings.sshPassword {
				return errors.New("SSH administrator passwords do not match")
			}
			return nil
		}).
		Value(&settings.sshConfirm)
	sshPublicKey := huh.NewInput().
		Title("SSH public key").
		Description("Required for public-key authentication; leave blank when password authentication is selected.").
		Validate(func(value string) error {
			if strings.TrimSpace(settings.sshAuthentication) == string(deployment.SSHAuthenticationKey) && strings.TrimSpace(value) == "" {
				return errors.New("enter one SSH public key")
			}
			if strings.ContainsAny(value, "\x00\r\n") {
				return errors.New("enter exactly one single-line SSH public key")
			}
			return nil
		}).
		Value(&settings.sshPublicKey)
	disableRootSSH := huh.NewConfirm().
		Title("Disable SSH login for root after verification?").
		Description("The installer will keep this SSH session open and require a successful second login as the new administrator before applying this change.").
		Affirmative("Disable after verification").
		Negative("Keep current root policy").
		Value(&settings.disableRootSSH)
	port := huh.NewInput().
		Title("Public WireGuard UDP port").
		Description("The default is 51820. The VPS provider firewall must allow this UDP port.").
		Value(&settings.port).
		Placeholder("51820").
		Validate(validateWireGuardPort)
	schedule := huh.NewInput().
		Title("Automatic backup schedule").
		Description("Choose daily or weekly. Backups are written to /var/backups/jellyfin-proxy.").
		Placeholder("daily").
		Validate(validateBackupSchedule).
		Value(&settings.backupSchedule)
	retention := huh.NewInput().
		Title("Backup retention in days").
		Description("Choose 7, 14, or 30 days. Expired backups are removed automatically.").
		Placeholder("30").
		Validate(validateBackupRetention).
		Value(&settings.backupRetention)
	first := huh.NewGroup(domain, allowed).
		Title("Network configuration").
		Description(preflight.Summary() + " Set the public domain and administrator addresses. Existing host firewall rules are preserved.")
	second := huh.NewGroup(password, confirmation, sshUsername, sshAuthentication, sshPassword, sshConfirmation, sshPublicKey, disableRootSSH, port, schedule, retention).
		Title("Administrator, SSH and tunnel").
		Description("Secrets are masked. SSH authentication is scoped to the dedicated account. Use Tab or Enter to continue and Shift+Tab to go back.")
	review := huh.NewConfirm().
		Title("Review and apply").
		DescriptionFunc(func() string {
			ips := strings.TrimSpace(settings.allowed)
			if ips == "" {
				ips = "None (default deny; admin sign-in will be blocked until an address is added)"
			}
			portValue := strings.TrimSpace(settings.port)
			if portValue == "" {
				portValue = "51820"
			}
			backupSchedule := strings.ToLower(strings.TrimSpace(settings.backupSchedule))
			if backupSchedule == "" {
				backupSchedule = "daily"
			}
			backupRetention := strings.TrimSpace(settings.backupRetention)
			if backupRetention == "" {
				backupRetention = "30"
			}
			sshAuth := strings.TrimSpace(settings.sshAuthentication)
			if sshAuth == "" {
				sshAuth = string(deployment.SSHAuthenticationPassword)
			}
			rootPolicy := "keep current root SSH policy"
			if settings.disableRootSSH {
				rootPolicy = "disable root only after a successful second-session login and sudo check"
			}
			return fmt.Sprintf("Base domain: %s\nAdmin IP ranges: %s\nSSH administrator: %s (%s)\nRoot SSH: %s\nWireGuard UDP port: %s\nAutomatic backups: %s · keep %s days\n%s", strings.TrimSpace(settings.domain), ips, strings.TrimSpace(settings.sshUsername), sshAuth, rootPolicy, portValue, backupSchedule, backupRetention, preflight.Summary())
		}, nil).
		Affirmative("Install").
		Negative("Cancel").
		Value(&settings.approved)
	third := huh.NewGroup(review).
		Title("Final review").
		Description("Confirm only after checking the values above. Use Shift+Tab to return and edit them.")
	form := huh.NewForm(first, second, third).
		WithAccessible(accessible).
		WithInput(input).
		WithOutput(output).
		WithShowHelp(true).
		WithShowErrors(true)
	if err := form.Run(); err != nil {
		return installSettings{}, fmt.Errorf("installer configuration: %w", err)
	}
	if !settings.approved {
		return installSettings{}, errors.New("installation cancelled before any deployment files were written")
	}
	domainValue, err := deployment.ValidateDomain(settings.domain)
	if err != nil {
		return installSettings{}, err
	}
	settings.domain = domainValue
	if strings.TrimSpace(settings.allowed) != "" {
		prefixes, err := whitelist.Validate(splitAddressList(settings.allowed))
		if err != nil {
			return installSettings{}, err
		}
		canonical := make([]string, len(prefixes))
		for i, prefix := range prefixes {
			canonical[i] = prefix.String()
		}
		settings.allowed = strings.Join(canonical, ",")
	}
	if err := validateWireGuardPort(settings.port); err != nil {
		return installSettings{}, err
	}
	if err := validateBackupSchedule(settings.backupSchedule); err != nil {
		return installSettings{}, err
	}
	if err := validateBackupRetention(settings.backupRetention); err != nil {
		return installSettings{}, err
	}
	settings.sshUsername = strings.TrimSpace(settings.sshUsername)
	settings.sshAuthentication = strings.TrimSpace(settings.sshAuthentication)
	settings.sshPublicKey = strings.TrimSpace(settings.sshPublicKey)
	sshConfig := deployment.SSHAdministratorConfig{Username: settings.sshUsername, Authentication: deployment.SSHAuthentication(settings.sshAuthentication), Password: settings.sshPassword, PublicKey: settings.sshPublicKey}
	if err := deployment.ValidateSSHAdministratorConfig(sshConfig); err != nil {
		return installSettings{}, err
	}
	if strings.TrimSpace(settings.backupSchedule) == "" {
		settings.backupSchedule = "daily"
	}
	if strings.TrimSpace(settings.backupRetention) == "" {
		settings.backupRetention = "30"
	}
	return settings, nil
}

func validateAllowlistInput(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	_, err := whitelist.Validate(splitAddressList(value))
	return err
}

func validateSHA256Input(value string) error {
	value = strings.TrimSpace(value)
	if len(value) != 64 {
		return errors.New("checksum must contain exactly 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return errors.New("checksum must contain exactly 64 hexadecimal characters")
	}
	return nil
}

func splitAddressList(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func validateWireGuardPort(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	port, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil || port == 0 {
		return errors.New("WireGuard UDP port must be between 1 and 65535")
	}
	return nil
}

func validateBackupSchedule(value string) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "daily" || value == "weekly" {
		return nil
	}
	return errors.New("backup schedule must be daily or weekly")
}

func validateBackupRetention(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || value == "7" || value == "14" || value == "30" {
		return nil
	}
	return errors.New("backup retention must be 7, 14, or 30 days")
}

func validateSSHAuthenticationInput(value string) error {
	if value != string(deployment.SSHAuthenticationPassword) && value != string(deployment.SSHAuthenticationKey) {
		return errors.New("enter password or public-key")
	}
	return nil
}

func validateSSHAdministratorPassword(value string) error {
	if len(value) < 12 || strings.ContainsAny(value, "\x00\r\n:") {
		return errors.New("SSH administrator password must be at least 12 characters and cannot contain a colon or line break")
	}
	return nil
}

func runTextForm(input io.Reader, output io.Writer, title, description string, value *string, validate func(string) error, secret bool) error {
	field := huh.NewInput().Title(title).Description(description).Value(value).Validate(validate)
	if secret {
		field.EchoMode(huh.EchoModePassword)
	}
	form := huh.NewForm(huh.NewGroup(field)).WithAccessible(isAccessibleTerminal(input)).WithInput(input).WithOutput(output).WithShowHelp(true).WithShowErrors(true)
	return form.Run()
}

func runApprovalForm(input io.Reader, output io.Writer, title, description string) (bool, error) {
	approved := false
	field := huh.NewConfirm().Title(title).Description(description).Affirmative("Continue").Negative("Cancel").Value(&approved)
	form := huh.NewForm(huh.NewGroup(field)).WithAccessible(isAccessibleTerminal(input)).WithInput(input).WithOutput(output).WithShowHelp(true).WithShowErrors(true)
	if err := form.Run(); err != nil {
		return false, err
	}
	return approved, nil
}

func runInitialPasswordForm(input io.Reader, output io.Writer) (string, error) {
	var password, confirmation string
	first := huh.NewInput().Title("Initial administrator password").Description("Use at least 12 characters. The value is masked while typed.").EchoMode(huh.EchoModePassword).Validate(func(value string) error {
		if len(value) < 12 {
			return errors.New("administrator password must contain at least 12 characters")
		}
		return nil
	}).Value(&password)
	second := huh.NewInput().Title("Confirm administrator password").EchoMode(huh.EchoModePassword).Validate(func(value string) error {
		if value != password {
			return errors.New("passwords do not match")
		}
		return nil
	}).Value(&confirmation)
	form := huh.NewForm(huh.NewGroup(first, second).Title("Administrator credentials")).WithAccessible(isAccessibleTerminal(input)).WithInput(input).WithOutput(output).WithShowHelp(true).WithShowErrors(true)
	if err := form.Run(); err != nil {
		return "", err
	}
	confirmation = ""
	return password, nil
}

func isAccessibleTerminal(input io.Reader) bool {
	if os.Getenv("TERM") == "dumb" {
		return true
	}
	file, ok := input.(*os.File)
	if !ok {
		return true
	}
	info, err := file.Stat()
	return err != nil || info.Mode()&os.ModeCharDevice == 0
}

func parseAllowedIPs(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	values := splitAddressList(value)
	prefixes, err := whitelist.Validate(values)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		if prefix.Addr().IsValid() {
			result = append(result, netip.PrefixFrom(prefix.Addr(), prefix.Bits()).String())
		}
	}
	return result, nil
}
