package netguard

import (
	"net/netip"
	"regexp"
	"strings"
	"testing"
)

// envVarToken matches a SCREAMING_SNAKE_CASE identifier — the shape of an
// environment-variable name. netguard is shared by three callers, so a
// configuration setting appearing in a message here is by definition the
// wrong one for at least two of them (RD-1277). Matching the shape rather
// than a fixed list means a NEW setting name leaking in also trips this.
var envVarToken = regexp.MustCompile(`\b[A-Z][A-Z0-9]*(_[A-Z0-9]+)+\b`)

// bareReasonCases exercises every distinct reason branch reachable through
// URL validation. wantFragment is the message shape callers prefix; asserting
// it here is what makes the caller-side tests in internal/config and
// internal/audit meaningful — they check ownership of the prefix, this checks
// the leaf stays bare.
var bareReasonCases = []struct {
	name          string
	url           string
	allowInsecure bool
	wantFragment  string
}{
	{"unparseable URL", "://bad-url", false, "invalid webhook URL:"},
	{"non-http scheme", "file:///etc/passwd", false, "scheme must be http or https, got"},
	{"http in production", "http://siem.example.com/ingest", false, "must use https in production, got"},
	{"empty host", "https:///ingest", false, "must include a host"},
	{"localhost by name", "https://localhost/ingest", false, "must not target a loopback address"},
	{"blocked IP range", "https://127.0.0.1/ingest", false, "is in blocked IP range"},
	{"unspecified address", "https://0.0.0.0/ingest", false, "is the unspecified address"},
	{"IP-ish host that fails to parse", "https://a%25b/ingest", false, "is not a valid IP literal"},
	{"relaxed http to public host", "http://siem.example.com/ingest", true, "http scheme is only allowed for loopback or private destinations"},
}

// TestBareReasonsNameNoConfigurationSetting is the leaf half of the RD-1277
// contract: netguard owns the reason, the caller owns the identifier. Before
// RD-1277 this package named SIEM_WEBHOOK_URL itself, which produced
// "AUDIT_TAMPER_WEBHOOK_URL: SIEM_WEBHOOK_URL must use https" on the tamper
// path — a message that sends the operator to the wrong setting.
func TestBareReasonsNameNoConfigurationSetting(t *testing.T) {
	for _, tc := range bareReasonCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateWebhookURLForEnv(tc.url, tc.allowInsecure)
			if err == nil {
				t.Fatalf("ValidateWebhookURLForEnv(%q, %v) = nil, want an error for branch %q",
					tc.url, tc.allowInsecure, tc.wantFragment)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.wantFragment) {
				t.Errorf("error = %q, want fragment %q (branch moved or message reworded)", msg, tc.wantFragment)
			}
			if leaked := envVarToken.FindString(msg); leaked != "" {
				t.Errorf("error = %q names configuration setting %q; netguard errors must be bare reasons "+
					"— the caller owns the identifier (RD-1277)", msg, leaked)
			}
		})
	}
}

// TestCheckResolvedAddrErrorsNameNoConfigurationSetting covers the dial-time
// half of the shared rule set, including the not-a-valid-IP branch that URL
// validation cannot reach (parseIPHost only returns addresses that parsed).
func TestCheckResolvedAddrErrorsNameNoConfigurationSetting(t *testing.T) {
	cases := []struct {
		name         string
		addr         netip.Addr
		allowPrivate bool
		wantFragment string
	}{
		{"zero Addr", netip.Addr{}, false, "not a valid IP"},
		{"unspecified", netip.MustParseAddr("0.0.0.0"), true, "is the unspecified address"},
		{"always-blocked link-local", netip.MustParseAddr("169.254.169.254"), true, "is in blocked IP range"},
		{"strict-blocked loopback", netip.MustParseAddr("127.0.0.1"), false, "is in blocked IP range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckResolvedAddrForEnv(tc.addr, tc.allowPrivate)
			if err == nil {
				t.Fatalf("CheckResolvedAddrForEnv(%v, %v) = nil, want an error", tc.addr, tc.allowPrivate)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.wantFragment) {
				t.Errorf("error = %q, want fragment %q", msg, tc.wantFragment)
			}
			if leaked := envVarToken.FindString(msg); leaked != "" {
				t.Errorf("error = %q names configuration setting %q; must be a bare reason (RD-1277)", msg, leaked)
			}
		})
	}
}
