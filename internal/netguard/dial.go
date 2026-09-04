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
	return CheckResolvedAddrForEnv(addr, false)
}

// CheckResolvedAddrForEnv is CheckResolvedAddr with the same relaxation
// ValidateWebhookURLForEnv applies: when allowPrivate is true (non-production)
// loopback and private/CGNAT/ULA destinations are permitted, because httptest
// servers and local or VPC-side SIEM collectors legitimately live there.
//
// What relaxed mode does NOT permit is link-local — which carries the cloud
// instance-metadata endpoint — or the unspecified address. Relaxing those
// would let a public-looking hostname that resolves or rebinds to
// 169.254.169.254 be dialed in development, even though the equivalent
// literal URL is rejected by relaxed URL validation (RD-1266 review). The two
// halves of the guard must agree in BOTH modes, not just in strict.
func CheckResolvedAddrForEnv(addr netip.Addr, allowPrivate bool) error {
	addr = addr.WithZone("").Unmap()

	// An address we cannot classify must be refused, not allowed through.
	if !addr.IsValid() {
		return fmt.Errorf("destination address is not a valid IP")
	}
	// 0.0.0.0 and :: mean "this host"/all-interfaces when dialed on many
	// stacks — a loopback-class destination. Blocked in every mode.
	if addr.IsUnspecified() {
		return fmt.Errorf("destination %s is the unspecified address", addr)
	}
	for _, blocked := range alwaysBlockedCIDRs {
		if blocked.Contains(addr) {
			return fmt.Errorf("destination %s is in blocked IP range %s", addr, blocked)
		}
	}
	if allowPrivate {
		return nil
	}
	for _, blocked := range strictBlockedCIDRs {
		if blocked.Contains(addr) {
			return fmt.Errorf("destination %s is in blocked IP range %s", addr, blocked)
		}
	}
	return nil
}

// GuardedDialer returns a dialer that refuses outbound connections to blocked
// destinations, classified by CheckResolvedAddrForEnv.
//
// The check lives in net.Dialer.Control, which the runtime calls once per
// candidate address *after* DNS resolution and *before* connect. That is what
// makes this resistant to DNS rebinding: URL validation can only inspect a
// hostname, whereas this sees the address the kernel is about to connect to.
// Re-resolving the name ourselves would reintroduce the very race we are
// closing, so we deliberately do not.
//
// The hook is installed in BOTH modes. allowPrivate widens what is acceptable
// (loopback and private networks, for httptest servers and local collectors)
// but never removes the guard: link-local — the cloud metadata endpoint — and
// the unspecified address stay blocked in development too.
//
// The returned dialer is owned by the caller; tests may set Resolver on it.
func GuardedDialer(allowPrivate bool) *net.Dialer {
	return &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   guardDialControl(allowPrivate),
	}
}

// guardDialControl builds the net.Dialer.Control hook for a mode. address is
// always a resolved "ip:port" at this point; anything we cannot parse is
// refused.
func guardDialControl(allowPrivate bool) func(string, string, syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("blocked outbound dial: cannot parse destination %q", address)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("blocked outbound dial: destination %q is not a resolved IP", host)
		}
		if err := CheckResolvedAddrForEnv(addr, allowPrivate); err != nil {
			return fmt.Errorf("blocked outbound dial: %w", err)
		}
		return nil
	}
}

// GuardedDialContext is GuardedDialer's DialContext, for wiring straight into
// an http.Transport.
func GuardedDialContext(allowPrivate bool) func(ctx context.Context, network, address string) (net.Conn, error) {
	return GuardedDialer(allowPrivate).DialContext
}

// GuardedTransport clones http.DefaultTransport (keeping its timeout and
// HTTP/2 settings) and installs the dial-time SSRF guard. Use this for any
// client that POSTs to an operator-supplied destination.
//
// Proxying is explicitly DISABLED on the returned transport, and that is a
// security decision rather than an oversight. The guard classifies the address
// being dialled; with a proxy in play that address is the proxy's, and the
// proxy — not this process — resolves and reaches the real destination. So a
// proxied request would (a) get no destination checking at all, silently
// making the guarantee vacuous, and (b) be refused anyway in strict mode
// whenever the proxy itself sits on a private address, which is the normal
// shape of an in-network egress proxy. Inheriting ProxyFromEnvironment here
// therefore buys a footgun in both directions.
//
// These two clients (SIEM forwarder, audit tamper notifier) previously picked
// up proxy support only implicitly, by using http.DefaultTransport; no
// deployment in this repo configures HTTP_PROXY/HTTPS_PROXY for them. Note
// internal/nodehttp keeps ProxyFromEnvironment for reaching the upstream node
// — a different trust boundary, unaffected by this.
//
// If egress-proxied webhook delivery is ever required, it needs a deliberate
// design (destination policy enforced at the proxy) rather than an ambient
// environment variable; the failure mode meanwhile is a loud connection
// error, not a quiet hole.
func GuardedTransport(allowPrivate bool) *http.Transport {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// DefaultTransport has been replaced with something else; build a
		// plain transport rather than panicking in a constructor.
		return &http.Transport{DialContext: GuardedDialContext(allowPrivate)}
	}
	t := base.Clone()
	t.DialContext = GuardedDialContext(allowPrivate)
	t.Proxy = nil
	return t
}
