package server

// Curated denial-reason codes (RD-1137).
//
// These are STABLE, tenant-facing identifiers for why a request was denied.
// They are written to access_logs.denial_reason (always, for the org-scoped
// admin Access Logs panel — RD-1137 Part B) and, for opt-in verbose callers,
// returned on the wire (RD-1137 Part A).
//
// Rules:
//   - Stable: external automations may switch on these once Part A ships, so
//     treat the string values as an API contract — add, don't rename.
//   - Tenant-safe: a code may only describe a fact about the caller's OWN
//     request. Codes that could reveal another tenant's state are marked
//     ORACLE-SENSITIVE below; the wire path (Part A) collapses those to a
//     single generic value. The access-log column always stores the precise
//     code (the admin view is already org-scoped, so it's safe there).
//   - Never derived from raw internal/DB error text.
const (
	// ReasonAuthRequired: no/invalid token on a method that requires auth.
	ReasonAuthRequired = "auth_required"
	// ReasonMethodNotAllowed: the caller's group(s) don't permit this method
	// or contract (RBAC entry-point deny).
	ReasonMethodNotAllowed = "method_not_allowed"
	// ReasonMethodPolicyDenied: RBAC permitted the call, but the target
	// contract's per-record method access policy (RD-1206) denied this caller
	// for the requested record. ORACLE-SENSITIVE — whether a record exists / who
	// its stakeholders are is another tenant's state; NOT on the wire allowlist,
	// so it collapses to the generic value (and the JSON-RPC deny body is a fixed
	// opaque error regardless). Stored precisely in the access log (org-scoped).
	ReasonMethodPolicyDenied = "method_policy_denied"
	// ReasonSenderNotLinked: a user-supplied `from` is not one of the caller's
	// linked EOAs. A fact about the caller's own request — safe to surface.
	ReasonSenderNotLinked = "sender_not_linked"
	// ReasonInvalidRequestShape: malformed params the proxy validates before
	// tracing (bad block tag, non-hex to/from, etc.).
	ReasonInvalidRequestShape = "invalid_request_shape"
	// ReasonCrossOrg: a traced call touched a contract owned by another org or
	// an unregistered (private-by-default) address. ORACLE-SENSITIVE — reveals
	// that some address is/ isn't registered elsewhere; the wire path collapses
	// it (Part A). Stored precisely in the log for the org-scoped admin view.
	ReasonCrossOrg = "cross_org"
	// ReasonTraceDepthExceeded: the trace exceeded max depth, so same-org could
	// not be proven; failed closed.
	ReasonTraceDepthExceeded = "trace_depth_exceeded"
	// ReasonTracingUnavailable: the upstream tracer errored / returned nil, so
	// the request failed closed.
	ReasonTracingUnavailable = "tracing_unavailable"
	// ReasonDeployClaimRequired: a debug_trace* / runtime-create path that
	// requires the deploy (or admin) claim.
	ReasonDeployClaimRequired = "deploy_claim_required"
	// ReasonComplianceBlocked: a travel-rule / sanctions check blocked the tx.
	ReasonComplianceBlocked = "compliance_blocked"
	// ReasonRateLimited: request- or daily-rate limit hit (429).
	ReasonRateLimited = "rate_limited"
	// ReasonConcurrencyLimited: per-user in-flight concurrency cap hit (429).
	ReasonConcurrencyLimited = "concurrency_limited"
	// ReasonUpstreamError: the upstream node was unreachable / returned a
	// transport error (502).
	ReasonUpstreamError = "upstream_error"
	// ReasonInternalError: an internal failure (500) — generic by construction.
	ReasonInternalError = "internal_error"

	// ReasonWireGenericDenied is the single value oracle-sensitive (and any
	// unrecognized) reason codes collapse to on the wire (RD-1137 Part A). It
	// carries no tenant state — it only tells the caller "denied."
	ReasonWireGenericDenied = "access_denied"
)

// wireReason maps a curated denial-reason code to the value safe to return to
// an opt-in verbose caller ON THE WIRE (RD-1137 Part A). It is a CLOSED
// ALLOWLIST: only codes that describe a fact about the caller's OWN request —
// which they could already infer — pass through; EVERYTHING else, including
// any code added in the future and any unknown value, collapses to
// ReasonWireGenericDenied (fail-safe).
//
// Collapsed on purpose (do NOT add to the allowlist without a security review):
//   - cross_org, tracing_unavailable, trace_depth_exceeded: the trace runs
//     AFTER the entry-point access check on the top-level target, then walks
//     internal frames the caller can steer via calldata. Distinguishing these
//     on the wire turns the verbose channel into a cross-org reachability /
//     existence oracle (the exact RD-915/RD-934 class). They stay precise in
//     the access-log column (org-scoped admin view), generic on the wire.
//   - deploy_claim_required, compliance_blocked, internal_error: not currently
//     exposed; collapsed conservatively until individually reviewed.
//
// The access-log row always stores the precise code; only this wire path
// collapses.
func wireReason(code string) string {
	switch code {
	case ReasonAuthRequired,
		ReasonMethodNotAllowed, // safe only while RBAC denials stay a uniform 404 (see TestWireReason… / RBAC deny site)
		ReasonSenderNotLinked,
		ReasonInvalidRequestShape,
		ReasonRateLimited,
		ReasonConcurrencyLimited,
		ReasonUpstreamError:
		return code
	default:
		return ReasonWireGenericDenied
	}
}
