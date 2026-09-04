package netguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// CheckResolvedAddr reports whether a resolved destination address may be
// dialed in strict mode. It is the single rule set behind both halves of the
// SSRF guard: ValidateWebhookURLForEnv applies it to IP-literal hosts at
// configuration time, and GuardedDialer applies it to every resolved address
// at dial time. Keeping one function means the two cannot drift.
//
// Zones are stripped and IPv4-mapped IPv6 addresses are unmapped first, so
// fe80::1%en0 and ::ffff:10.0.0.1 are classified as the addresses they
// actually reach.
func CheckResolvedAddr(addr netip.Addr) error {
	addr = addr.WithZone("").Unmap()

	// An address we cannot classify must be refused, not allowed through.
	if !addr.IsValid() {
		return fmt.Errorf("destination address is not a valid IP")
	}
	// 0.0.0.0 and :: mean "this host"/all-interfaces when dialed on many
	// stacks — a loopback-class destination.
	if addr.IsUnspecified() {
		return fmt.Errorf("destination %s is the unspecified address", addr)
	}
	for _, blocked := range blockedCIDRs {
		if blocked.Contains(addr) {
			return fmt.Errorf("destination %s is in blocked IP range %s", addr, blocked)
		}
	}
	return nil
}

// GuardedDialer returns a dialer that refuses outbound connections to
// loopback / RFC-1918 / link-local / CGNAT / IPv6-ULA / unspecified addresses
// when allowPrivate is false.
//
// The check lives in net.Dialer.Control, which the runtime calls once per
// candidate address *after* DNS resolution and *before* connect. That is what
// makes this resistant to DNS rebinding: URL validation can only inspect a
// hostname, whereas this sees the address the kernel is about to connect to.
// Re-resolving the name ourselves would reintroduce the very race we are
// closing, so we deliberately do not.
//
// When allowPrivate is true no dial restriction is installed, matching
// ValidateWebhookURLForEnv's relaxed (non-production) mode where local
// collectors and httptest servers are legitimate destinations.
//
// The returned dialer is owned by the caller; tests may set Resolver on it.
func GuardedDialer(allowPrivate bool) *net.Dialer {
	d := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	if !allowPrivate {
		d.Control = guardDialControl
	}
	return d
}

// guardDialControl is the net.Dialer.Control hook. address is always a
// resolved "ip:port" at this point; anything we cannot parse is refused.
func guardDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("blocked outbound dial: cannot parse destination %q", address)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("blocked outbound dial: destination %q is not a resolved IP", host)
	}
	if err := CheckResolvedAddr(addr); err != nil {
		return fmt.Errorf("blocked outbound dial: %w", err)
	}
	return nil
}

// GuardedDialContext is GuardedDialer's DialContext, for wiring straight into
// an http.Transport.
func GuardedDialContext(allowPrivate bool) func(ctx context.Context, network, address string) (net.Conn, error) {
	return GuardedDialer(allowPrivate).DialContext
}

// GuardedTransport clones http.DefaultTransport (keeping its proxy, timeout
// and HTTP/2 settings) and installs the dial-time SSRF guard. Use this for any
// client that POSTs to an operator-supplied destination.
//
// Limitation: the guard inspects the address being dialled. When an egress
// proxy is configured (HTTP_PROXY/HTTPS_PROXY, inherited from
// ProxyFromEnvironment), that address is the proxy's, and the proxy — not this
// process — chooses the final destination. Proxy support is kept because
// egress-proxied deployments need it, so operators relying on one must apply
// destination policy at the proxy as well.
func GuardedTransport(allowPrivate bool) *http.Transport {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// DefaultTransport has been replaced with something else; build a
		// plain transport rather than panicking in a constructor.
		return &http.Transport{DialContext: GuardedDialContext(allowPrivate)}
	}
	t := base.Clone()
	t.DialContext = GuardedDialContext(allowPrivate)
	return t
}
