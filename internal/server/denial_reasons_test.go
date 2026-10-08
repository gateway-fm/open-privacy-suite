package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestWireReason_ClosedAllowlist is the core RD-1137 Part A security test: the
// wire layer must only expose caller-own-fact reason codes and must collapse
// every oracle-sensitive (and every unknown/future) code to the generic value.
// A failure here means the verbose channel leaks cross-org/existence state.
//
// Every Reason* constant in denial_reasons.go MUST appear in exactly one of the
// two buckets below. Go can't enumerate consts by reflection, so when you add a
// new Reason*, add it here too — the test then forces a conscious safe-vs-
// collapse classification (mirrors wireReason's closed-allowlist intent).
func TestWireReason_ClosedAllowlist(t *testing.T) {
	// Safe to expose: facts about the caller's OWN request they could infer.
	safe := []string{
		ReasonAuthRequired,
		ReasonMethodNotAllowed, // safe only while RBAC denials stay a uniform 404 (see TestWireReason_MethodNotAllowedInvariant note)
		ReasonSenderNotLinked,
		ReasonInvalidRequestShape,
		ReasonStateOverrideNotAllowed, // the caller sent the override themselves
		ReasonRateLimited,
		ReasonConcurrencyLimited,
		ReasonUpstreamError,
	}
	// Must collapse: oracle-sensitive (cross-org reachability / existence) or
	// not-yet-reviewed-for-exposure.
	collapsed := []string{
		ReasonCrossOrg,
		ReasonTracingUnavailable,
		ReasonTraceDepthExceeded,
		ReasonDeployClaimRequired,
		ReasonComplianceBlocked,
		ReasonInternalError,
	}

	for _, code := range safe {
		assert.Equalf(t, code, wireReason(code), "safe code %q must pass through unchanged", code)
	}
	for _, code := range collapsed {
		assert.Equalf(t, ReasonWireGenericDenied, wireReason(code), "code %q must collapse to the generic value", code)
	}

	// Fail-safe: unknown / future codes and empty must collapse, never pass.
	assert.Equal(t, ReasonWireGenericDenied, wireReason("some_future_reason"))
	assert.Equal(t, ReasonWireGenericDenied, wireReason(""))

	// The load-bearing invariant, stated directly: the three cross-org
	// reachability codes must NEVER survive to the wire.
	for _, oracle := range []string{ReasonCrossOrg, ReasonTracingUnavailable, ReasonTraceDepthExceeded} {
		assert.NotEqualf(t, oracle, wireReason(oracle), "cross-org oracle code %q leaked to the wire", oracle)
	}
}
