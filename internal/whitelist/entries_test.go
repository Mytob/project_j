package whitelist

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestParseEntryNormalizesAddressesAndNetworks(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"192.0.2.8", "192.0.2.8/32"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"192.0.2.129/24", "192.0.2.0/24"},
		{"2001:db8:1::1234/64", "2001:db8:1::/64"},
		{"  198.51.100.1/32  ", "198.51.100.1/32"},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := ParseEntry(test.input)
			if err != nil {
				t.Fatalf("ParseEntry() error = %v", err)
			}
			if got.String() != test.want {
				t.Fatalf("ParseEntry() = %s, want %s", got, test.want)
			}
		})
	}
}

func TestParseEntryRejectsInvalidAndAmbiguousValues(t *testing.T) {
	for _, input := range []string{
		"", " ", "example.com", "192.0.2.1/33", "2001:db8::/129", "192.0.2.1/",
		"::ffff:192.0.2.1", "::ffff:192.0.2.0/120", "fe80::1%eth0", "0.0.0.0/0x",
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseEntry(input); err == nil {
				t.Fatalf("ParseEntry(%q) unexpectedly succeeded", input)
			}
		})
	}
}

func TestValidateDeduplicatesAndSorts(t *testing.T) {
	got, err := Validate([]string{"2001:db8::1", "192.0.2.9/24", "192.0.2.0/24", "198.51.100.2"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.0/24", "198.51.100.2/32", "2001:db8::1/128"}
	if !reflect.DeepEqual(Strings(got), want) {
		t.Fatalf("Validate() = %v, want %v", Strings(got), want)
	}
}

func TestContainsCIDRBoundaries(t *testing.T) {
	entries, err := Validate([]string{"192.0.2.8/29", "2001:db8::/126"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		addr string
		want bool
	}{
		{"192.0.2.8", true},
		{"192.0.2.15", true},
		{"192.0.2.7", false},
		{"192.0.2.16", false},
		{"2001:db8::", true},
		{"2001:db8::3", true},
		{"2001:db8::4", false},
		{"2001:db7::ffff", false},
	}
	for _, test := range tests {
		t.Run(test.addr, func(t *testing.T) {
			addr := netip.MustParseAddr(test.addr)
			if got := Contains(entries, addr); got != test.want {
				t.Fatalf("Contains(%s) = %v, want %v", addr, got, test.want)
			}
		})
	}
}

func TestContainsFailsClosedForInvalidOrUnspecifiedPeer(t *testing.T) {
	entries, err := Validate([]string{"0.0.0.0/0", "::/0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []netip.Addr{{}, netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("::"), netip.MustParseAddr("::ffff:192.0.2.1")} {
		if Contains(entries, addr) {
			t.Fatalf("Contains(%s) unexpectedly allowed", addr)
		}
	}
}

func TestRenderCaddyPolicyDefaultsToDeny(t *testing.T) {
	empty := RenderCaddyPolicy(nil)
	if !strings.Contains(empty, `respond "Forbidden" 403`) {
		t.Fatalf("empty policy does not deny: %q", empty)
	}
	if strings.Contains(empty, "remote_ip") || strings.Contains(empty, "reverse_proxy") {
		t.Fatalf("empty policy has an allow route: %q", empty)
	}

	entries, err := Validate([]string{"192.0.2.0/24", "2001:db8::/64"})
	if err != nil {
		t.Fatal(err)
	}
	policy := RenderCaddyPolicy(entries)
	if !strings.Contains(policy, "@whitelisted remote_ip 192.0.2.0/24 2001:db8::/64") {
		t.Fatalf("policy has unexpected matcher: %q", policy)
	}
	if !strings.Contains(policy, "reverse_proxy 10.66.66.2:8096") || !strings.Contains(policy, `respond "Forbidden" 403`) {
		t.Fatalf("policy is missing proxy or deny handler: %q", policy)
	}
	invalid := RenderCaddyPolicy([]netip.Prefix{{}})
	if strings.Contains(invalid, "reverse_proxy") || !strings.Contains(invalid, `respond "Forbidden" 403`) {
		t.Fatalf("invalid policy did not fail closed: %q", invalid)
	}
}
