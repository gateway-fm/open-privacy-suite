package netguard

import (
	"strings"
	"testing"
)

func TestValidateWebhookURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		// Valid
		{"valid https URL", "https://siem.example.com/ingest", false},
		{"172.32.x allowed - outside private range", "https://172.32.0.1/ingest", false},

		// Scheme
		{"http rejected", "http://siem.example.com/ingest", true},
		{"invalid URL rejected", "://bad-url", true},

		// Loopback
		{"localhost rejected", "https://localhost/ingest", true},
		{"127.0.0.1 rejected", "https://127.0.0.1/ingest", true},
		{"127.255.255.255 rejected - whole /8 blocked", "https://127.255.255.255/ingest", true},

		// IPv6 loopback
		{"[::1] rejected - IPv6 loopback", "https://[::1]/ingest", true},

		// Link-local / cloud metadata
		{"169.254.169.254 rejected - AWS metadata", "https://169.254.169.254/latest/meta-data/", true},
		{"169.254.0.1 rejected - link-local range start", "https://169.254.0.1/ingest", true},

		// IPv6 link-local
		{"[fe80::1] rejected - IPv6 link-local", "https://[fe80::1]/ingest", true},

		// IPv6 ULA — private (fc00::/7); the relaxed-mode list already
		// classifies it as private, so strict mode must block it too.
		{"[fc00::1] rejected - IPv6 ULA", "https://[fc00::1]/ingest", true},
		{"[fdff::1] rejected - IPv6 ULA range end", "https://[fdff::1]/ingest", true},

		// IPv6 zone literals (RFC 6874, %25-escaped in URLs) — a zone must
		// not push the address off the bare-IP check into the hostname path.
		{"[fe80::1%25en0] rejected - zoned IPv6 link-local", "https://[fe80::1%25en0]/ingest", true},
		{"[fc00::1%25en0] rejected - zoned IPv6 ULA", "https://[fc00::1%25en0]/ingest", true},

		// IPv4-mapped IPv6 — the v4 ranges must apply to ::ffff: forms.
		{"[::ffff:127.0.0.1] rejected - IPv4-mapped loopback", "https://[::ffff:127.0.0.1]/ingest", true},

		// IP-ish hosts that don't parse must fail closed, not pass as
		// "hostname" (hostnames contain neither ':' nor '%').
		{"bracketed IP garbage rejected", "https://[fe80::zz%25en0]/ingest", true},
		{"bare-percent host rejected", "https://a%25b/ingest", true},
		{"unbracketed :: rejected - parses as host \":\"", "https://::/ingest", true},

		// Unspecified addresses mean "this host"/all-interfaces on many
		// stacks — a loopback-class destination when dialed.
		{"0.0.0.0 rejected - IPv4 unspecified", "https://0.0.0.0/ingest", true},
		{"[::] rejected - IPv6 unspecified", "https://[::]/ingest", true},
		{"[::ffff:0.0.0.0] rejected - mapped unspecified", "https://[::ffff:0.0.0.0]/ingest", true},

		// A URL without a host classifies as nothing — require one.
		{"empty host rejected", "https:///ingest", true},
		{"port-only host rejected", "https://:8080/ingest", true},

		// localhost by any other spelling: DNS names are case-insensitive,
		// a trailing dot is the DNS root, and *.localhost subdomains resolve
		// to loopback per RFC 6761.
		{"LOCALHOST rejected - case-insensitive", "https://LOCALHOST/ingest", true},
		{"localhost. rejected - root-qualified", "https://localhost./ingest", true},
		{"LoCaLhOsT rejected - mixed case", "https://LoCaLhOsT/ingest", true},
		{"foo.localhost rejected - RFC 6761 subdomain", "https://foo.localhost/ingest", true},
		{"foo.LOCALHOST. rejected - subdomain, mixed case, root-qualified", "https://foo.LOCALHOST./ingest", true},

		// RFC-1918 private ranges - correct CIDR boundaries, not string prefix
		{"10.0.0.1 rejected", "https://10.0.0.1/ingest", true},
		{"10.255.255.255 rejected - end of /8", "https://10.255.255.255/ingest", true},
		{"192.168.1.1 rejected", "https://192.168.1.1/ingest", true},
		{"172.16.0.1 rejected - start of Docker /12", "https://172.16.0.1/ingest", true},
		{"172.31.255.255 rejected - end of Docker /12", "https://172.31.255.255/ingest", true},

		// CGNAT / Tailscale (RFC-6598 shared address space)
		{"100.64.0.1 rejected - CGNAT/Tailscale start", "https://100.64.0.1/ingest", true},

		// Pitfall: string-prefix matching would wrongly block/allow these
		{"172.0.0.1 allowed - outside 172.16/12 (HasPrefix pitfall)", "https://172.0.0.1/ingest", false},
		{"172.15.255.255 allowed - just below 172.16/12", "https://172.15.255.255/ingest", false},

		// Domain names that look like IPs are NOT blocked (host is not a bare IP)
		// This documents the known limitation: DNS resolution is not performed at validation time.
		{"10.io domain allowed - not a bare IP", "https://10.io/ingest", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWebhookURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateWebhookURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

// TestValidateWebhookURLForEnv covers the env-aware variant added for RD-950.
// In production (allowInsecure=false) the behaviour is identical to
// ValidateWebhookURL — see TestValidateWebhookURL above. The cases below
// document the non-prod relaxation: HTTP is accepted but only when the host
// is loopback or RFC-1918, never for public destinations.
func TestValidateWebhookURLForEnv(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		allowInsecure bool
		wantErr       bool
		wantErrSubstr string // optional: substring to assert in the error message
	}{
		// Non-prod: HTTP on loopback/private is OK, mirrors how local
		// docker-compose dev points the SIEM at an httptest stub.
		{"non-prod http loopback allowed", "http://127.0.0.1:9000/ingest", true, false, ""},
		{"non-prod http localhost allowed", "http://localhost:9000/ingest", true, false, ""},
		{"non-prod http RFC-1918 allowed", "http://10.1.2.3/ingest", true, false, ""},
		{"non-prod http Docker bridge allowed", "http://172.18.0.5/ingest", true, false, ""},
		{"non-prod https public still allowed", "https://siem.example.com/ingest", true, false, ""},

		// Non-prod: HTTP on a public destination MUST still be rejected.
		// We don't ever want audit batches in cleartext over the public
		// internet, even from a dev box.
		{"non-prod http public rejected", "http://siem.example.com/ingest", true, true, "loopback or private"},
		{"non-prod http public IP rejected", "http://8.8.8.8/ingest", true, true, "loopback or private"},

		// Non-prod: cloud-metadata IP is still rejected — link-local is
		// neither loopback nor private and is the canonical SSRF target.
		{"non-prod http 169.254.169.254 rejected (AWS metadata)", "http://169.254.169.254/latest/meta-data/", true, true, "loopback or private"},

		// Prod: every loopback / private / link-local rejection from
		// TestValidateWebhookURL must still apply. A representative sample
		// here keeps the contract explicit; the exhaustive list lives above.
		{"prod http rejected", "http://siem.example.com/ingest", false, true, "https"},
		{"prod localhost rejected", "https://localhost/ingest", false, true, "loopback"},
		{"prod 127.0.0.1 rejected", "https://127.0.0.1/ingest", false, true, "blocked IP range"},
		{"prod 10.0.0.1 rejected", "https://10.0.0.1/ingest", false, true, "blocked IP range"},
		{"prod 192.168.1.1 rejected", "https://192.168.1.1/ingest", false, true, "blocked IP range"},
		{"prod 172.16.0.1 rejected", "https://172.16.0.1/ingest", false, true, "blocked IP range"},
		{"prod 169.254.169.254 rejected (AWS metadata)", "https://169.254.169.254/latest/meta-data/", false, true, "blocked IP range"},
		{"prod [::1] rejected (IPv6 loopback)", "https://[::1]/ingest", false, true, "blocked IP range"},
		{"prod [fe80::1] rejected (IPv6 link-local)", "https://[fe80::1]/ingest", false, true, "blocked IP range"},
		{"prod [fc00::1] rejected (IPv6 ULA)", "https://[fc00::1]/ingest", false, true, "blocked IP range"},
		{"prod [fe80::1%25en0] rejected (zoned link-local)", "https://[fe80::1%25en0]/ingest", false, true, "blocked IP range"},
		{"prod [fc00::1%25en0] rejected (zoned ULA)", "https://[fc00::1%25en0]/ingest", false, true, "blocked IP range"},
		{"prod bare-percent host rejected fail-closed", "https://a%25b/ingest", false, true, "not a valid IP literal"},
		{"prod unbracketed :: rejected fail-closed", "https://::/ingest", false, true, "not a valid IP literal"},
		{"prod 0.0.0.0 rejected (unspecified)", "https://0.0.0.0/ingest", false, true, "unspecified"},
		{"prod [::] rejected (unspecified)", "https://[::]/ingest", false, true, "unspecified"},
		{"prod empty host rejected", "https:///ingest", false, true, "host"},
		{"prod port-only host rejected", "https://:8080/ingest", false, true, "host"},

		// Unspecified is neither loopback nor private — relaxed mode must
		// reject it on both schemes.
		{"non-prod https [::] rejected (unspecified)", "https://[::]/ingest", true, true, "unspecified"},
		{"non-prod http 0.0.0.0 rejected (not loopback/private)", "http://0.0.0.0:9000/ingest", true, true, "loopback or private"},
		{"non-prod http [::] rejected (not loopback/private)", "http://[::]:9000/ingest", true, true, "loopback or private"},
		{"non-prod http empty host rejected", "http:///ingest", true, true, "loopback or private"},
		{"prod LOCALHOST rejected", "https://LOCALHOST/ingest", false, true, "loopback"},
		{"prod localhost. rejected", "https://localhost./ingest", false, true, "loopback"},
		{"prod foo.localhost rejected", "https://foo.localhost/ingest", false, true, "loopback"},

		// The zone/name normalizations apply in relaxed mode too: https to a
		// zoned private range is still range-blocked, http to a zoned
		// link-local is still not private, and localhost spellings are
		// loopback (so relaxed http accepts them).
		{"non-prod https zoned ULA still rejected", "https://[fc00::1%25en0]/ingest", true, true, "blocked IP range"},
		{"non-prod http zoned link-local rejected", "http://[fe80::1%25en0]/ingest", true, true, "loopback or private"},
		{"non-prod http zoned loopback allowed", "http://[::1%25lo0]:9000/ingest", true, false, ""},
		{"non-prod http LOCALHOST allowed as loopback", "http://LOCALHOST:9000/ingest", true, false, ""},
		{"non-prod http localhost. allowed as loopback", "http://localhost.:9000/ingest", true, false, ""},
		{"non-prod http foo.localhost allowed as loopback", "http://foo.localhost:9000/ingest", true, false, ""},
		{"prod public https allowed", "https://siem.example.com/ingest", false, false, ""},

		// Garbage schemes are rejected in both modes — we only know what
		// to do with http/https.
		{"non-prod file scheme rejected", "file:///etc/passwd", true, true, "scheme"},
		{"prod gopher scheme rejected", "gopher://siem.example.com/", false, true, "https"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWebhookURLForEnv(tt.url, tt.allowInsecure)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateWebhookURLForEnv(%q, allowInsecure=%v) error = %v, wantErr %v",
					tt.url, tt.allowInsecure, err, tt.wantErr)
			}
			if tt.wantErr && tt.wantErrSubstr != "" && !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Errorf("ValidateWebhookURLForEnv(%q, allowInsecure=%v) error = %v, want substring %q",
					tt.url, tt.allowInsecure, err, tt.wantErrSubstr)
			}
		})
	}
}
