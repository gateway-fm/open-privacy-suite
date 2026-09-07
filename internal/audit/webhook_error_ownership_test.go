package audit

import (
	"strings"
	"testing"
	"time"
)

// The env-var names internal/config owns. internal/audit is handed an
// already-resolved URL and owns no setting, so neither may appear in a
// message produced here — a forwarder built from a YAML file or an admin API
// call would be pointed at an env var that was never involved (RD-1277).
const (
	siemEnvVar   = "SIEM_WEBHOOK_URL"
	tamperEnvVar = "AUDIT_TAMPER_WEBHOOK_URL"
)

// auditStrictReasonBranches lists the netguard reason branches reachable
// through the audit-side callers in strict mode. The relaxed-mode branch is
// reachable only through the SIEM forwarder (AllowInsecure) and is exercised
// separately below; the tamper notifier is strict in every deployment.
var auditStrictReasonBranches = []struct {
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

// assertNamesDestinationNotEnvVar checks the audit-side half of the RD-1277
// contract: the message identifies which destination failed, and names
// neither of the settings internal/config owns.
func assertNamesDestinationNotEnvVar(t *testing.T, err error, wantPrefix string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got nil error, want a rejection prefixed %q", wantPrefix)
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, wantPrefix) {
		t.Errorf("error = %q, want it to lead with %q so the operator can tell which destination failed", msg, wantPrefix)
	}
	for _, envVar := range []string{siemEnvVar, tamperEnvVar} {
		if strings.Contains(msg, envVar) {
			t.Errorf("error = %q names %q, but internal/audit owns no configuration setting — it receives an "+
				"already-resolved URL, which may not have come from that env var at all (RD-1277)", msg, envVar)
		}
	}
}

// TestSIEMForwarderConstructorErrorNamesDestination covers the startup
// validation in NewSIEMForwarder.
func TestSIEMForwarderConstructorErrorNamesDestination(t *testing.T) {
	for _, branch := range auditStrictReasonBranches {
		t.Run(branch.name, func(t *testing.T) {
			_, err := NewSIEMForwarder(SIEMConfig{WebhookURL: branch.url})
			assertNamesDestinationNotEnvVar(t, err, "siem webhook url: ")
		})
	}

	t.Run("relaxed http to public host", func(t *testing.T) {
		_, err := NewSIEMForwarder(SIEMConfig{WebhookURL: "http://siem.example.com/ingest", AllowInsecure: true})
		assertNamesDestinationNotEnvVar(t, err, "siem webhook url: ")
	})
}

// TestSIEMForwarderSendErrorNamesDestination covers the defence-in-depth
// re-validation in send(). It is reached by constructing a forwarder by hand
// — exactly the case that check exists for, since the constructor would have
// rejected this URL.
func TestSIEMForwarderSendErrorNamesDestination(t *testing.T) {
	events := []SIEMEvent{{Timestamp: time.Unix(0, 0), EventType: "test", Action: "test", Outcome: "success"}}

	for _, branch := range auditStrictReasonBranches {
		t.Run(branch.name, func(t *testing.T) {
			s := &SIEMForwarder{cfg: SIEMConfig{WebhookURL: branch.url}}
			assertNamesDestinationNotEnvVar(t, s.send(events), "SIEM webhook URL failed SSRF guard: ")
		})
	}
}

// TestWebhookNotifierErrorNamesDestination covers the audit tamper notifier.
// This is the path RD-1277 was reported from: before the fix the shared guard
// named SIEM_WEBHOOK_URL, so a misconfigured tamper webhook produced
// "audit tamper webhook url: SIEM_WEBHOOK_URL must use https in production".
func TestWebhookNotifierErrorNamesDestination(t *testing.T) {
	for _, branch := range auditStrictReasonBranches {
		t.Run(branch.name, func(t *testing.T) {
			_, err := NewWebhookNotifier(branch.url)
			assertNamesDestinationNotEnvVar(t, err, "audit tamper webhook url: ")
		})
	}
}

// TestWebhookOwnershipAssertionsAcceptValidURLs keeps the assertions above
// honest: they would also hold for a guard that rejected everything, so the
// accepting path has to be pinned too.
func TestWebhookOwnershipAssertionsAcceptValidURLs(t *testing.T) {
	if _, err := NewSIEMForwarder(SIEMConfig{WebhookURL: "https://siem.example.com/ingest"}); err != nil {
		t.Errorf("NewSIEMForwarder(valid https) = %v, want nil", err)
	}
	if _, err := NewWebhookNotifier("https://alerts.example.com/tamper"); err != nil {
		t.Errorf("NewWebhookNotifier(valid https) = %v, want nil", err)
	}
}
