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
	"net"
	"net/url"
)

// blockedCIDRs are the IP ranges that must never be used as a webhook
// destination. Using net.ParseCIDR + subnet.Contains avoids the string-prefix
// pitfall where "172.0.0.1" or "10.io" could bypass or trip a HasPrefix check.
//
// Note: do NOT include IPv4-mapped IPv6 ranges like ::ffff:0:0/96 here.
// Go's net.IPNet.Contains normalises them to IPv4 by taking the last 4 bytes
// of the mask, which turns a /96 IPv6 mask into a /0 IPv4 mask and would
// match every IPv4 address.
var blockedCIDRs = func() []*net.IPNet {
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
	nets := make([]*net.IPNet, 0, len(ranges))
	for _, r := range ranges {
		_, cidr, err := net.ParseCIDR(r)
		if err != nil {
			panic(fmt.Sprintf("netguard: invalid blockedCIDR %q: %v", r, err))
		}
		nets = append(nets, cidr)
	}
	return nets
}()

// ValidateWebhookURL checks that a webhook URL (SIEM forwarder, audit tamper
// alarm) is safe to use in production. It rejects non-HTTPS schemes and
// private/loopback destinations to prevent Server-Side Request Forgery
// (SSRF). See ValidateWebhookURLForEnv for the env-aware variant used in
// non-prod where HTTP-on-localhost is acceptable for development.
//
// IP range checks use net.ParseCIDR + subnet.Contains instead of
// strings.HasPrefix to avoid the pitfalls documented in
// localhost_security_test.go (e.g. "10.io" tripping a prefix check,
// or "172.0.0.1" bypassing the Docker range).
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
// link-local / CGNAT / IPv6-ULA address. This is the only safe configuration for a
// system that POSTs audit data from inside the VPC to an operator-supplied
// destination.
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

	host := u.Hostname()

	// "localhost" is a hostname alias for loopback; block it by name.
	if host == "localhost" {
		return fmt.Errorf("SIEM_WEBHOOK_URL must not target a loopback address")
	}

	// If the host is an IP literal, run proper CIDR checks.
	if ip := net.ParseIP(host); ip != nil {
		for _, blocked := range blockedCIDRs {
			if blocked.Contains(ip) {
				return fmt.Errorf("SIEM_WEBHOOK_URL targets a blocked IP range (%s is in %s)", ip, blocked)
			}
		}
	}

	return nil
}

// requireLoopbackOrPrivate enforces that an HTTP destination is loopback or
// on a private network. Used by ValidateWebhookURLForEnv when running in the
// relaxed mode — cleartext traffic is acceptable on the local box / VPC, but
// not over the public internet.
func requireLoopbackOrPrivate(host string) error {
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
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
var allowedHTTPCIDRs = func() []*net.IPNet {
	ranges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"fc00::/7", // IPv6 ULA
	}
	nets := make([]*net.IPNet, 0, len(ranges))
	for _, r := range ranges {
		_, cidr, err := net.ParseCIDR(r)
		if err != nil {
			panic(fmt.Sprintf("netguard: invalid allowedHTTPCIDR %q: %v", r, err))
		}
		nets = append(nets, cidr)
	}
	return nets
}()
