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
