// Package netguard holds network-boundary validation helpers shared across
// packages (config validation, the SIEM forwarder, the tamper-alarm webhook
// notifier) without dragging their owners' dependencies along.
//
// It must stay a leaf package importing only the standard library — that is
// what lets internal/config validate webhook URLs without transitively
// depending on the audit and persistence layers (RD-1255; enforced by
// internal/archtest).
package netguard

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// blockedCIDRs are the IP ranges that must never be used as a webhook
// destination. netip.Prefix.Contains matches within one address family only,
// which avoids the string-prefix pitfall where "172.0.0.1" or "10.io" could
// bypass or trip a HasPrefix check.
//
// Note: netip does NOT match IPv4-mapped IPv6 addresses (::ffff:a.b.c.d)
// against IPv4 prefixes — parseIPHost Unmap()s them to IPv4 first, so the
// IPv4 ranges below cover those forms too.
var blockedCIDRs = func() []netip.Prefix {
	ranges := []string{
		"127.0.0.0/8",    // IPv4 loopback
		"::1/128",        // IPv6 loopback
		"169.254.0.0/16", // Link-local / cloud instance metadata (AWS, GCP, Azure)
		"fe80::/10",      // IPv6 link-local
		"10.0.0.0/8",     // RFC-1918 private
		"172.16.0.0/12",  // RFC-1918 private (Docker bridge lives here)
		"192.168.0.0/16", // RFC-1918 private
		"100.64.0.0/10",  // CGNAT / Tailscale (shared address space)
		"fc00::/7",       // IPv6 ULA — private, the v6 analogue of RFC-1918
	}
	prefixes := make([]netip.Prefix, 0, len(ranges))
	for _, r := range ranges {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			panic(fmt.Sprintf("netguard: invalid blockedCIDR %q: %v", r, err))
		}
		prefixes = append(prefixes, p)
	}
	return prefixes
}()

// normalizeHost lowercases the host and strips one trailing dot: DNS names
// are case-insensitive and may be root-qualified, so name-based checks would
// otherwise be bypassed with "LOCALHOST" or "localhost.".
func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// isLocalhostName reports whether a normalized host names loopback:
// "localhost" itself or any *.localhost subdomain (RFC 6761 — resolvers
// answer loopback for those too).
func isLocalhostName(host string) bool {
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// parseIPHost parses an IP-literal host for range checking. It tolerates an
// RFC 6874 zone suffix (fe80::1%en0 — which net.ParseIP would reject) and
// strips it, and Unmap()s IPv4-mapped IPv6 so the IPv4 ranges apply.
func parseIPHost(host string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.WithZone("").Unmap(), true
}

// ValidateWebhookURL checks that a webhook URL (SIEM forwarder, audit tamper
// alarm) is safe to use in production. It rejects non-HTTPS schemes and
// private/loopback destinations to prevent Server-Side Request Forgery
// (SSRF). See ValidateWebhookURLForEnv for the env-aware variant used in
// non-prod where HTTP-on-localhost is acceptable for development.
//
// IP range checks parse the host with net/netip and match against CIDR
// prefixes instead of using strings.HasPrefix, avoiding the pitfalls
// documented in localhost_security_test.go (e.g. "10.io" tripping a prefix
// check, or "172.0.0.1" bypassing the Docker range).
//
// Note: if the host is a domain name (not a bare IP literal), DNS-resolved
// addresses are not checked here — that would require a network call at
// startup. The https requirement and redirect-blocking on the client provide
// additional defence for hostname-based URLs.
func ValidateWebhookURL(rawURL string) error {
	return ValidateWebhookURLForEnv(rawURL, false)
}

// ValidateWebhookURLForEnv runs the SSRF guard with an optional relaxation
// for non-production environments (RD-950).
//
// In strict mode (allowInsecure=false) — the production default — the URL
// must use HTTPS and the host must not resolve to a loopback / RFC-1918 /
// link-local / CGNAT / IPv6-ULA address. This is the only safe configuration
// for a system that POSTs audit data from inside the VPC to an
// operator-supplied destination.
//
// In relaxed mode (allowInsecure=true) HTTP is also accepted, but ONLY when
// the host is a loopback or private-network destination — e.g. an httptest
// server on 127.0.0.1, or a SIEM collector reachable over the Docker bridge
// during local development. Public HTTP destinations are still rejected so
// audit batches never traverse the public internet in cleartext.
func ValidateWebhookURLForEnv(rawURL string, allowInsecure bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid SIEM webhook URL: %w", err)
	}

	switch u.Scheme {
	case "https":
		// Always allowed; fall through to the host check below.
	case "http":
		if !allowInsecure {
			return fmt.Errorf("SIEM_WEBHOOK_URL must use https in production, got %q", u.Scheme)
		}
		// Allow HTTP only when the destination is loopback or a private
		// network. Cleartext POST to a public host is still rejected so a
		// misconfigured dev box can't leak audit data to the internet.
		if err := requireLoopbackOrPrivate(u.Hostname()); err != nil {
			return fmt.Errorf("SIEM_WEBHOOK_URL: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("SIEM_WEBHOOK_URL scheme must be http or https, got %q", u.Scheme)
	}

	host := normalizeHost(u.Hostname())

	// localhost by name — any case, optionally root-qualified, including
	// RFC 6761 *.localhost subdomains — aliases loopback; block it.
	if isLocalhostName(host) {
		return fmt.Errorf("SIEM_WEBHOOK_URL must not target a loopback address")
	}

	// If the host is an IP literal, run proper CIDR checks.
	if ip, ok := parseIPHost(host); ok {
		for _, blocked := range blockedCIDRs {
			if blocked.Contains(ip) {
				return fmt.Errorf("SIEM_WEBHOOK_URL targets a blocked IP range (%s is in %s)", ip, blocked)
			}
		}
	} else if strings.ContainsAny(host, ":%") {
		// Looks like an IP literal (hostnames contain neither ':' nor '%')
		// but does not parse — fail closed rather than treat it as a
		// hostname and skip the range checks.
		return fmt.Errorf("SIEM_WEBHOOK_URL host %q is not a valid IP literal", host)
	}

	return nil
}

// requireLoopbackOrPrivate enforces that an HTTP destination is loopback or
// on a private network. Used by ValidateWebhookURLForEnv when running in the
// relaxed mode — cleartext traffic is acceptable on the local box / VPC, but
// not over the public internet.
func requireLoopbackOrPrivate(host string) error {
	host = normalizeHost(host)
	if isLocalhostName(host) {
		return nil
	}
	ip, ok := parseIPHost(host)
	if !ok {
		// Domain name — cannot prove private at validation time without DNS,
		// and we don't want cleartext POSTs to "evil.com". Reject.
		return fmt.Errorf("http scheme is only allowed for loopback or private destinations, got hostname %q", host)
	}
	if ip.IsLoopback() {
		return nil
	}
	for _, private := range allowedHTTPCIDRs {
		if private.Contains(ip) {
			return nil
		}
	}
	return fmt.Errorf("http scheme is only allowed for loopback or private destinations, got %s", ip)
}

// allowedHTTPCIDRs lists private/loopback IP ranges that may use http://
// when ValidateWebhookURLForEnv is called in relaxed mode (non-production).
// Mirrors the operator-network ranges in server.localhostOnlyMiddleware so
// the two trust boundaries share a single definition of "this is on our
// network, cleartext is acceptable".
var allowedHTTPCIDRs = func() []netip.Prefix {
	ranges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"fc00::/7", // IPv6 ULA
	}
	prefixes := make([]netip.Prefix, 0, len(ranges))
	for _, r := range ranges {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			panic(fmt.Sprintf("netguard: invalid allowedHTTPCIDR %q: %v", r, err))
		}
		prefixes = append(prefixes, p)
	}
	return prefixes
}()
