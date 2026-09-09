package config

import (
	"strings"
	"testing"
)

// strictWebhookReasonBranches lists every netguard reason branch reachable
// through config validation. Config always calls the strict variant, so the
// relaxed-mode branch ("http scheme is only allowed for loopback or private
// destinations") is unreachable here by construction and is covered in
// internal/netguard instead.
var strictWebhookReasonBranches = []struct {
	name string
	url  string
}{
	{"unparseable URL", "://bad-url"},
	{"non-http scheme", "file:///etc/passwd"},
	{"http in production", "http://siem.example.com/ingest"},
	{"empty host", "https:///ingest"},
	{"localhost by name", "https://localhost/ingest"},
	{"blocked IP range", "https://127.0.0.1/ingest"},
	{"unspecified address", "https://0.0.0.0/ingest"},
	{"IP-ish host that fails to parse", "https://a%25b/ingest"},
}

func productionConfigForWebhookTest() *Config {
	return &Config{
		Environment:      "production",
		JWTSecret:        "secret",
		JWTRefreshSecret: "refresh-secret",
		VerifierID:       "did:test:verifier",
		AdminAPIToken:    "admin-token",
		NodeURL:          "https://node.example.com",
		BaseURL:          "https://api.example.com",
	}
}

// TestWebhookValidationErrorNamesOwningSetting is the caller half of the
// RD-1277 contract. netguard returns a bare reason and each caller prefixes
// the setting it owns; config owns two settings validated by the same
// function, so a shared-package identifier would necessarily be wrong for one
// of them. Every reason branch is checked on both settings: the message must
// lead with its own env var and must not mention the other, so neither a leaf
// that reintroduces a setting name nor a caller that drops its prefix can
// pass.
func TestWebhookValidationErrorNamesOwningSetting(t *testing.T) {
	const (
		siemVar   = "SIEM_WEBHOOK_URL"
		tamperVar = "AUDIT_TAMPER_WEBHOOK_URL"
		validURL  = "https://siem.example.com/ingest"
	)

	settings := []struct {
		name    string
		own     string
		other   string
		apply   func(c *Config, url string)
		comment string
	}{
		{
			name:  siemVar,
			own:   siemVar,
			other: tamperVar,
			apply: func(c *Config, url string) { c.SIEMWebhookURL = url },
		},
		{
			name:  tamperVar,
			own:   tamperVar,
			other: siemVar,
			// A valid SIEM URL is set so validation reaches the tamper check;
			// that also proves a passing SIEM check contributes no identifier.
			apply: func(c *Config, url string) {
				c.SIEMWebhookURL = validURL
				c.AuditTamperWebhookURL = url
			},
		},
	}

	for _, setting := range settings {
		t.Run(setting.name, func(t *testing.T) {
			for _, branch := range strictWebhookReasonBranches {
				t.Run(branch.name, func(t *testing.T) {
					c := productionConfigForWebhookTest()
					setting.apply(c, branch.url)

					err := c.Validate()
					if err == nil {
						t.Fatalf("Validate() = nil for %s = %q, want a rejection", setting.name, branch.url)
					}
					msg := err.Error()
					if !strings.HasPrefix(msg, setting.own+": ") {
						t.Errorf("Validate() = %q, want it to lead with %q: the operator must be sent to the "+
							"setting that is actually misconfigured (RD-1277)", msg, setting.own+": ")
					}
					if strings.Contains(msg, setting.other) {
						t.Errorf("Validate() = %q names %q while validating %s — the shared guard must not "+
							"attribute the failure to the other setting (RD-1277)", msg, setting.other, setting.name)
					}
				})
			}
		})
	}
}

// TestWebhookValidationAcceptsValidURLs guards the other direction: the
// ownership assertions above are only meaningful if a good URL on either
// setting passes, so a future change that rejects everything cannot satisfy
// both tests at once.
func TestWebhookValidationAcceptsValidURLs(t *testing.T) {
	t.Setenv("AUDIT_DATABASE_URL", "")

	c := productionConfigForWebhookTest()
	c.SIEMWebhookURL = "https://siem.example.com/ingest"
	c.AuditTamperWebhookURL = "https://alerts.example.com/tamper"

	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for valid https webhook URLs", err)
	}
}
