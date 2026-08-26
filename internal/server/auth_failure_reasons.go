package server

// Curated auth-session failure codes (RD-1242).
//
// A wallet callback and the browser that started the login are DIFFERENT HTTP
// clients. The wallet reads its rejection from the callback response; the
// browser only ever sees GET /api/v1/auth/session/{id}/status. Before RD-1242 a
// rejected proof left the session pending, so the browser polled until its own
// budget ran out and then reported a timeout that never happened - actively
// misdiagnosing the failure.
//
// These codes are what the session carries so the browser can be told the
// truth. They follow the same rules as the RPC denial reasons in
// denial_reasons.go:
//   - Stable: treat the string values as an API contract - add, don't rename.
//   - Never derived from raw internal error text.
//   - Only codes describing the caller's OWN request pass to the wire; codes
//     that describe a property of an identity, or internal state, collapse.
//
// The threat model differs from denial_reasons.go in one way that matters: the
// status endpoint is polled with nothing but a session ID, and that ID is
// rendered on screen inside the login QR code. Someone who photographs the QR
// can poll the legitimate user's session without ever proving anything, so the
// wire set is kept narrower than "whatever the wallet was told".
const (
	// AuthFailVerification: the JWZ proof did not verify. An outcome of the
	// caller's own submission, not a property of any account.
	AuthFailVerification = "verification_failed"

	// AuthFailHumanityRequired: a ProofOfHumanity credential is required and
	// was absent. Passed through deliberately - the whole point of this state
	// is to route the user to the verification flow, the login page has a
	// dedicated step for it, and the wallet is already told the same thing
	// (with a verify URL) today. It does reveal that the identity lacks the
	// credential, which is accepted as the cost of the feature working.
	AuthFailHumanityRequired = "humanity_required"

	// AuthFailInvalidRequest: the callback body was unreadable or carried no
	// JWZ token. A fact about the caller's own request.
	AuthFailInvalidRequest = "invalid_request"

	// AuthFailAccountBanned: the DID resolved to a banned account.
	// ORACLE-SENSITIVE - this is a property of an identity, not of the request,
	// and the codebase deliberately does not surface ban state elsewhere (see
	// the onboard-by-DID handler). The wallet that submitted a valid proof is
	// still told directly in its own response; the pollable session collapses
	// it so a third party holding only a photographed QR cannot learn it.
	AuthFailAccountBanned = "account_banned"

	// AuthFailInternalError: persistence or token issuance failed. Collapsed -
	// an anonymous poller has no business distinguishing our internal faults,
	// and the operator log carries the detail.
	AuthFailInternalError = "internal_error"

	// AuthFailNetworkUnsupported: the wallet's iden3 identity network is not
	// configured on this deployment (RD-1241). ORACLE-SENSITIVE and therefore
	// NOT on the wire allowlist below: unlike humanity_required, this describes
	// someone else's wallet rather than the poller's own request, and the
	// session ID is readable straight off the on-screen QR. The wallet that
	// actually submitted the proof is still told precisely, and operators get
	// the exact code in the log and the session listing. Passing it through to
	// the poller would help the user in front of the browser, so it is a
	// reasonable future change - but a deliberate one, not a merge artifact.
	AuthFailNetworkUnsupported = "network_not_supported"

	// AuthFailWireGeneric is the single value that oracle-sensitive and
	// unrecognised codes collapse to on the wire. It carries no state beyond
	// "this attempt failed".
	AuthFailWireGeneric = "authentication_failed"
)

// wireAuthFailureReason maps a curated failure code to the value safe to return
// from the session-status endpoint. It is a CLOSED ALLOWLIST: only codes that
// describe the caller's own request or drive a user-facing recovery flow pass
// through; everything else, including any code added later and any unknown or
// raw-error value, collapses to AuthFailWireGeneric (fail-safe).
//
// Do NOT widen the allowlist without a security review. The precise code is
// still available to operators via the session listing and the server log.
func wireAuthFailureReason(code string) string {
	switch code {
	case AuthFailVerification,
		AuthFailHumanityRequired,
		AuthFailInvalidRequest:
		return code
	default:
		return AuthFailWireGeneric
	}
}

// authFailReasonForVerification maps the wire-response class chosen by
// respondVerificationError (RD-1241) onto this file's curated codes, so the
// session records the same outcome the wallet was told and the two cannot
// drift. Anything unrecognised lands on AuthFailVerification, which is the
// accurate description of "the proof did not verify" and is itself allowlisted.
func authFailReasonForVerification(class verificationErrorClass) string {
	switch class {
	case verificationHumanityRequired:
		return AuthFailHumanityRequired
	case verificationNetworkUnsupported:
		return AuthFailNetworkUnsupported
	default:
		return AuthFailVerification
	}
}
