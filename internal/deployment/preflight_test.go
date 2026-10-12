package deployment

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestValidateHost(t *testing.T) {
	tests := []struct {
		name    string
		facts   HostFacts
		wantErr bool
	}{
		{name: "supported root host", facts: HostFacts{OSID: "ubuntu", VersionID: "26.04", Codename: "resolute", Arch: "x86_64", EffectiveUID: 0}},
		{name: "not root", facts: HostFacts{OSID: "ubuntu", VersionID: "26.04", Codename: "resolute", Arch: "x86_64", EffectiveUID: 1000}, wantErr: true},
		{name: "wrong release", facts: HostFacts{OSID: "ubuntu", VersionID: "24.04", Codename: "noble", Arch: "x86_64", EffectiveUID: 0}, wantErr: true},
		{name: "wrong architecture", facts: HostFacts{OSID: "ubuntu", VersionID: "26.04", Codename: "resolute", Arch: "aarch64", EffectiveUID: 0}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateHost(test.facts)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateHost() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestValidateDomain(t *testing.T) {
	for _, value := range []string{"example.com", "MEDIA.Example.co.uk.", "xn--bcher-kva.example"} {
		if got, err := ValidateDomain(value); err != nil || got == "" {
			t.Errorf("ValidateDomain(%q) = %q, %v", value, got, err)
		}
	}
	for _, value := range []string{"", "localhost", "127.0.0.1", "https://example.com", "-bad.example", "bad_.example", "bad..example"} {
		if _, err := ValidateDomain(value); err == nil {
			t.Errorf("ValidateDomain(%q) unexpectedly succeeded", value)
		}
	}
}

func TestCheckDNSRequiresAllHostnames(t *testing.T) {
	lookups := map[string][]net.IP{
		"example.com":        {net.ParseIP("203.0.113.10")},
		"admin.example.com":  {net.ParseIP("203.0.113.10")},
		"access.example.com": {net.ParseIP("2001:db8::10")},
	}
	got, err := CheckDNS(context.Background(), "example.com", func(_ context.Context, host string) ([]net.IP, error) { return lookups[host], nil })
	if err != nil || len(got) != 3 {
		t.Fatalf("CheckDNS() = %v, %v", got, err)
	}
	_, err = CheckDNS(context.Background(), "example.com", func(_ context.Context, host string) ([]net.IP, error) {
		if host == "access.example.com" {
			return nil, nil
		}
		return lookups[host], nil
	})
	if err == nil {
		t.Fatal("CheckDNS accepted a hostname without addresses")
	}
	_, err = CheckDNS(context.Background(), "example.com", func(_ context.Context, host string) ([]net.IP, error) {
		if host == "admin.example.com" {
			return nil, errors.New("not found")
		}
		return lookups[host], nil
	})
	if err == nil {
		t.Fatal("CheckDNS accepted a failed DNS lookup")
	}
}
