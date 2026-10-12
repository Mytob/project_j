package deployment

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// HostFacts are the small set of host properties required by the installer.
type HostFacts struct {
	OSID         string
	VersionID    string
	Codename     string
	Arch         string
	EffectiveUID int
}

// ValidateHost rejects hosts outside the frozen production target before any
// installation files or services are changed.
func ValidateHost(f HostFacts) error {
	if !strings.EqualFold(f.OSID, "ubuntu") || f.VersionID != "26.04" {
		return fmt.Errorf("unsupported operating system: require Ubuntu 26.04 LTS (found %s %s)", f.OSID, f.VersionID)
	}
	if f.Arch != "x86_64" && f.Arch != "amd64" {
		return fmt.Errorf("unsupported architecture %q: require x86_64", f.Arch)
	}
	if f.EffectiveUID != 0 {
		return errors.New("installation requires root; run proxyctl with sudo")
	}
	if !codenamePattern.MatchString(f.Codename) {
		return errors.New("Ubuntu release codename is missing or invalid")
	}
	return nil
}

var (
	domainLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	codenamePattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
)

// ValidateDomain accepts a public DNS base domain, excluding IP literals,
// single-label names, and syntax that could be interpreted as a URL or shell.
func ValidateDomain(value string) (string, error) {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if len(domain) == 0 || len(domain) > 253 || strings.ContainsAny(domain, "/:@[]\\ \t\r\n") {
		return "", errors.New("enter a public base domain such as example.com")
	}
	if net.ParseIP(domain) != nil {
		return "", errors.New("enter a DNS domain, not an IP address")
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return "", errors.New("base domain must contain at least two DNS labels")
	}
	for _, label := range labels {
		if !domainLabelPattern.MatchString(label) {
			return "", fmt.Errorf("invalid DNS label %q in base domain", label)
		}
	}
	return domain, nil
}

type LookupIPFunc func(context.Context, string) ([]net.IP, error)

// CheckDNS verifies that all three public hostnames currently resolve. The
// caller must show the addresses and ask the operator to confirm they point to
// this VPS, because discovering a server's public/NAT address is environment
// specific and must not be guessed.
func CheckDNS(ctx context.Context, domain string, lookup LookupIPFunc) (map[string][]net.IP, error) {
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	results := make(map[string][]net.IP, 3)
	for _, host := range []string{domain, "admin." + domain, "access." + domain} {
		addresses, err := lookup(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("DNS lookup for %s failed: %w", host, err)
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("DNS lookup for %s returned no addresses", host)
		}
		results[host] = addresses
	}
	return results, nil
}
