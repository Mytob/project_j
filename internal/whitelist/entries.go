// Package whitelist parses, validates, persists, and renders the Jellyfin
// access allowlist. Empty allowlists intentionally match no client.
package whitelist

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

var ErrInvalidEntry = errors.New("invalid whitelist entry")

// ParseEntry accepts one IPv4 address, IPv6 address, or CIDR prefix.
// Addresses are represented as host prefixes and networks are masked.
func ParseEntry(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, fmt.Errorf("%w: entry is empty", ErrInvalidEntry)
	}

	if addr, err := netip.ParseAddr(value); err == nil {
		if addr.Is4In6() || addr.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("%w: mapped or zone-scoped address %q is not supported", ErrInvalidEntry, value)
		}
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}

	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.IsValid() {
		return netip.Prefix{}, fmt.Errorf("%w: %q", ErrInvalidEntry, value)
	}
	addr := prefix.Addr()
	if addr.Is4In6() || addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("%w: mapped or zone-scoped network %q is not supported", ErrInvalidEntry, value)
	}
	return prefix.Masked(), nil
}

// Validate parses entries, removes duplicates, and sorts them into a stable
// representation suitable for persistence and Caddy configuration.
func Validate(values []string) ([]netip.Prefix, error) {
	seen := make(map[netip.Prefix]struct{}, len(values))
	entries := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := ParseEntry(value)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		entries = append(entries, prefix)
	}

	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Addr().Is4() != b.Addr().Is4() {
			return a.Addr().Is4()
		}
		if cmp := a.Addr().Compare(b.Addr()); cmp != 0 {
			return cmp < 0
		}
		return a.Bits() < b.Bits()
	})
	return entries, nil
}

// Contains reports whether addr is allowed by any prefix. Invalid and
// unspecified peer addresses are denied.
func Contains(entries []netip.Prefix, addr netip.Addr) bool {
	if !addr.IsValid() || addr.IsUnspecified() || addr.Is4In6() || addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	for _, entry := range entries {
		if entry.IsValid() && entry.Contains(addr) {
			return true
		}
	}
	return false
}

// RenderCaddyPolicy returns a Caddyfile route snippet. An empty list renders
// only a 403 handler, preserving default-deny behaviour.
func RenderCaddyPolicy(entries []netip.Prefix) string {
	if len(entries) == 0 {
		return "handle {\n\trespond \"Forbidden\" 403\n}\n"
	}

	values := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsValid() || entry != entry.Masked() {
			return "handle {\n\trespond \"Forbidden\" 403\n}\n"
		}
		values = append(values, entry.String())
	}
	return "@whitelisted remote_ip " + strings.Join(values, " ") + "\n" +
		"handle @whitelisted {\n\treverse_proxy jellyfin-mock:8096\n}\n" +
		"handle {\n\trespond \"Forbidden\" 403\n}\n"
}

// Strings converts a validated prefix list into its canonical text format.
func Strings(entries []netip.Prefix) []string {
	result := make([]string, len(entries))
	for i, entry := range entries {
		result[i] = entry.String()
	}
	return result
}
