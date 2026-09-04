package netguard

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckResolvedAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr string // "" = allowed
	}{
		{"public IPv4 allowed", "93.184.216.34", ""},
		{"public IPv6 allowed", "2606:2800:220:1:248:1893:25c8:1946", ""},

		{"IPv4 loopback", "127.0.0.1", "blocked IP range"},
		{"IPv4 loopback high", "127.255.255.254", "blocked IP range"},
		{"IPv6 loopback", "::1", "blocked IP range"},
		{"RFC-1918 10/8", "10.0.0.1", "blocked IP range"},
		{"RFC-1918 172.16/12", "172.16.0.1", "blocked IP range"},
		{"RFC-1918 192.168/16", "192.168.1.1", "blocked IP range"},
		{"cloud metadata", "169.254.169.254", "blocked IP range"},
		{"IPv6 link-local", "fe80::1", "blocked IP range"},
		{"IPv6 ULA", "fc00::1", "blocked IP range"},
		{"CGNAT", "100.64.0.1", "blocked IP range"},

		// IPv4-mapped IPv6 must be unmapped before range matching, or the
		// IPv4 ranges silently stop applying to ::ffff:a.b.c.d forms.
		{"IPv4-mapped loopback", "::ffff:127.0.0.1", "blocked IP range"},
		{"IPv4-mapped RFC-1918", "::ffff:10.0.0.1", "blocked IP range"},

		{"IPv4 unspecified", "0.0.0.0", "unspecified"},
		{"IPv6 unspecified", "::", "unspecified"},
		{"IPv4-mapped unspecified", "::ffff:0.0.0.0", "unspecified"},

		// Zoned link-local: the zone must be stripped, not make the check skip.
		{"zoned link-local", "fe80::1%en0", "blocked IP range"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(tt.addr)
			if err != nil {
				t.Fatalf("ParseAddr(%q): %v", tt.addr, err)
			}
			err = CheckResolvedAddr(addr)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckResolvedAddr(%s) = %v, want nil", tt.addr, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("CheckResolvedAddr(%s) = nil, want error containing %q", tt.addr, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("CheckResolvedAddr(%s) = %q, want substring %q", tt.addr, err, tt.wantErr)
			}
		})
	}
}

// TestCheckResolvedAddr_InvalidFailsClosed pins the fail-closed direction: an
// address we cannot classify must be refused, never allowed through.
func TestCheckResolvedAddr_InvalidFailsClosed(t *testing.T) {
	if err := CheckResolvedAddr(netip.Addr{}); err == nil {
		t.Fatal("CheckResolvedAddr(zero Addr) = nil, want error — an unclassifiable address must fail closed")
	}
}

// TestGuardedDial_RefusesLoopbackLiteral is the core dial-time property: even
// when the destination passed URL validation (here bypassed entirely), a
// connection to a blocked address is refused before connect. This is the
// effect a DNS rebind would produce — validation saw a name, the dial resolved
// to loopback.
func TestGuardedDial_RefusesLoopbackLiteral(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Transport: GuardedTransport(false), Timeout: 5 * time.Second}
	resp, err := client.Get(srv.URL) //nolint:bodyclose // err path asserted below
	if err == nil {
		resp.Body.Close()
		t.Fatal("request to loopback succeeded, want refusal at dial time")
	}
	if !strings.Contains(err.Error(), "blocked outbound dial") {
		t.Fatalf("error = %q, want it to name the dial guard", err)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hits = %d, want 0 — the connection must never be established", got)
	}
}

// TestGuardedDial_AllowsLoopbackWhenRelaxed keeps parity with
// ValidateWebhookURLForEnv's relaxed mode: local collectors and httptest
// servers must still work in development.
func TestGuardedDial_AllowsLoopbackWhenRelaxed(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Transport: GuardedTransport(true), Timeout: 5 * time.Second}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("relaxed dial to loopback failed: %v", err)
	}
	resp.Body.Close()
	if got := hits.Load(); got != 1 {
		t.Fatalf("server hits = %d, want 1", got)
	}
}

// TestGuardedDial_HostnameResolvingToLoopbackIsRefused exercises the actual
// rebinding shape: a public-looking hostname that DNS answers with a blocked
// address. The guard sits in Dialer.Control, which runs per resolved address
// after resolution and before connect, so the name never gets a chance to
// matter.
func TestGuardedDial_HostnameResolvingToLoopbackIsRefused(t *testing.T) {
	dnsAddr := startFakeDNS(t, netip.MustParseAddr("127.0.0.1"))

	d := GuardedDialer(false)
	d.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", dnsAddr)
		},
	}

	_, err := d.DialContext(context.Background(), "tcp", "totally-legit.example.com:80")
	if err == nil {
		t.Fatal("dial to a hostname resolving to 127.0.0.1 succeeded, want refusal")
	}
	if !strings.Contains(err.Error(), "blocked outbound dial") {
		t.Fatalf("error = %q, want it to name the dial guard", err)
	}
	if !strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("error = %q, want it to name the resolved address", err)
	}
}

// startFakeDNS runs a minimal in-process UDP DNS responder that answers every
// A query with answerA and every other qtype with an empty NOERROR. Returns
// its host:port. Avoids depending on real DNS in tests.
func startFakeDNS(t *testing.T, answerA netip.Addr) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, peer, err := pc.ReadFrom(buf)
			if err != nil {
				return // closed by cleanup
			}
			resp, ok := buildDNSResponse(buf[:n], answerA)
			if !ok {
				continue
			}
			_, _ = pc.WriteTo(resp, peer)
		}
	}()

	return pc.LocalAddr().String()
}

// buildDNSResponse assembles a response for a single-question query: the
// question is echoed back, and an A question additionally gets one answer
// record pointing at answerA.
func buildDNSResponse(query []byte, answerA netip.Addr) ([]byte, bool) {
	const headerLen = 12
	if len(query) < headerLen {
		return nil, false
	}
	// Walk the QNAME labels to find where the question's type/class sit.
	i := headerLen
	for i < len(query) {
		l := int(query[i])
		if l == 0 {
			i++
			break
		}
		if l >= 0xC0 { // compression pointer: not expected in a query
			return nil, false
		}
		i += l + 1
	}
	if i+4 > len(query) {
		return nil, false
	}
	qtype := binary.BigEndian.Uint16(query[i : i+2])
	questionEnd := i + 4

	resp := make([]byte, 0, questionEnd+16)
	resp = append(resp, query[:headerLen]...)
	binary.BigEndian.PutUint16(resp[2:4], 0x8180) // response, no error
	binary.BigEndian.PutUint16(resp[4:6], 1)      // QDCOUNT

	const typeA = 1
	if qtype != typeA {
		binary.BigEndian.PutUint16(resp[6:8], 0) // ANCOUNT: empty NOERROR
		return append(resp, query[headerLen:questionEnd]...), true
	}

	binary.BigEndian.PutUint16(resp[6:8], 1) // ANCOUNT
	resp = append(resp, query[headerLen:questionEnd]...)

	v4 := answerA.As4()
	answer := []byte{
		0xC0, 0x0C, // NAME: pointer to the question's name
		0x00, typeA, // TYPE A
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x00, 0x3C, // TTL 60
		0x00, 0x04, // RDLENGTH
		v4[0], v4[1], v4[2], v4[3],
	}
	return append(resp, answer...), true
}
