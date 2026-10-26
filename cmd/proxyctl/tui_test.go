package main

import "testing"

func TestInstallerInputValidation(t *testing.T) {
	tests := []struct {
		name    string
		check   func(string) error
		value   string
		wantErr bool
	}{
		{name: "empty optional allowlist", check: validateAllowlistInput, value: ""},
		{name: "valid IPv4 and IPv6 CIDR", check: validateAllowlistInput, value: "203.0.113.4/32, 2001:db8::4/128"},
		{name: "invalid allowlist", check: validateAllowlistInput, value: "all", wantErr: true},
		{name: "default UDP port", check: validateWireGuardPort, value: ""},
		{name: "valid UDP port", check: validateWireGuardPort, value: "51820"},
		{name: "zero UDP port", check: validateWireGuardPort, value: "0", wantErr: true},
		{name: "oversized UDP port", check: validateWireGuardPort, value: "65536", wantErr: true},
		{name: "valid independent checksum", check: validateSHA256Input, value: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{name: "invalid checksum", check: validateSHA256Input, value: "abc", wantErr: true},
		{name: "default backup schedule", check: validateBackupSchedule, value: ""},
		{name: "weekly backup schedule", check: validateBackupSchedule, value: "weekly"},
		{name: "invalid backup schedule", check: validateBackupSchedule, value: "monthly", wantErr: true},
		{name: "default backup retention", check: validateBackupRetention, value: ""},
		{name: "14 day backup retention", check: validateBackupRetention, value: "14"},
		{name: "invalid backup retention", check: validateBackupRetention, value: "90", wantErr: true},
		{name: "password SSH authentication", check: validateSSHAuthenticationInput, value: "password"},
		{name: "key SSH authentication", check: validateSSHAuthenticationInput, value: "public-key"},
		{name: "invalid SSH authentication", check: validateSSHAuthenticationInput, value: "root", wantErr: true},
		{name: "valid SSH sudo password", check: validateSSHAdministratorPassword, value: "correct-horse-battery"},
		{name: "short SSH sudo password", check: validateSSHAdministratorPassword, value: "short", wantErr: true},
		{name: "SSH password delimiter", check: validateSSHAdministratorPassword, value: "correct-horse:bad", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.check(test.value)
			if (err != nil) != test.wantErr {
				t.Fatalf("validation error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
