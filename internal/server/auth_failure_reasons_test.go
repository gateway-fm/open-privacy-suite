package server

import "testing"

// RD-1242: wireAuthFailureReason is a CLOSED allowlist. The session-status
// endpoint is polled by an unauthenticated client that presents only a session
// ID, so anything not explicitly cleared must collapse. Mirrors
// TestWireReason_ClosedAllowlist for RPC denials (RD-1137).
func TestWireAuthFailureReason_ClosedAllowlist(t *testing.T) {
	tests := []struct {
		name string
		code string
		want string
	}{
		// Passed through: facts about the caller's own request/proof.
		{"verification failure", AuthFailVerification, AuthFailVerification},
		{"humanity credential required", AuthFailHumanityRequired, AuthFailHumanityRequired},
		{"malformed callback", AuthFailInvalidRequest, AuthFailInvalidRequest},
		// RD-1251: the supported-network set is already public via
		// GET /api/v1/auth/providers, so collapsing this protected nothing.
		{"unsupported network", AuthFailNetworkUnsupported, AuthFailNetworkUnsupported},

		// Collapsed: properties of an identity, or internal state.
		{"ban state must not leak", AuthFailAccountBanned, AuthFailWireGeneric},
		{"internal error must not leak", AuthFailInternalError, AuthFailWireGeneric},

		// Anything unrecognised collapses (fail-safe for future additions).
		{"unknown code", "some_future_code", AuthFailWireGeneric},
		{"empty code", "", AuthFailWireGeneric},
		{"raw error text", "dial tcp 10.0.0.5:8545: connect: connection refused", AuthFailWireGeneric},
		{"leaky verifier detail", "issuer did:iden3:privado:main:2Sc not in allowlist", AuthFailWireGeneric},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wireAuthFailureReason(tt.code); got != tt.want {
				t.Errorf("wireAuthFailureReason(%q) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

// The allowlist must never echo text it was not given from the curated set:
// every output has to be one of the known constants.
func TestWireAuthFailureReason_OutputIsAlwaysCurated(t *testing.T) {
	allowed := map[string]bool{
		AuthFailVerification:       true,
		AuthFailHumanityRequired:   true,
		AuthFailInvalidRequest:     true,
		AuthFailNetworkUnsupported: true,
		AuthFailWireGeneric:        true,
	}

	inputs := []string{
		AuthFailVerification, AuthFailHumanityRequired, AuthFailInvalidRequest,
		AuthFailNetworkUnsupported, AuthFailAccountBanned, AuthFailInternalError,
		"", "arbitrary", "RPC https://internal.host/rpc unreachable",
		"../../etc/passwd", "<script>alert(1)</script>",
	}

	for _, in := range inputs {
		got := wireAuthFailureReason(in)
		if !allowed[got] {
			t.Errorf("wireAuthFailureReason(%q) = %q, which is not a curated reason", in, got)
		}
	}
}

// RD-1251: admitting network_not_supported rests on the code being a bare
// classification. The wallet's own response names the network (it is the
// caller's own, already known to it); the pollable session must not, because
// its ID is readable off the on-screen QR.
//
// The expectation is written out as a literal on purpose. Every other
// assertion in this file derives from the constant, so all of them would move
// with it if someone appended or substituted an identifier; only pinning the
// exact published string catches that. It doubles as the API contract - this
// value is documented in SessionStatusResponse and the operator reason table.
func TestAuthFailNetworkUnsupported_CarriesNoNetworkName(t *testing.T) {
	const wantWire = "network_not_supported"

	if got := wireAuthFailureReason(AuthFailNetworkUnsupported); got != wantWire {
		t.Errorf("wire reason = %q, want exactly %q.\n"+
			"Anything else means a network identifier reached the pollable session, "+
			"or the documented contract changed. The poller must learn only that the "+
			"wallet's network is outside the (already public) supported set.", got, wantWire)
	}
}

// authFailReasonForVerification is what decides which code lands on the
// session, so the wallet response and the polled session cannot disagree. It
// had no coverage before RD-1251.
func TestAuthFailReasonForVerification(t *testing.T) {
	tests := []struct {
		name  string
		class verificationErrorClass
		want  string
	}{
		{"humanity", verificationHumanityRequired, AuthFailHumanityRequired},
		{"unsupported network", verificationNetworkUnsupported, AuthFailNetworkUnsupported},
		{"generic verification failure", verificationFailed, AuthFailVerification},
		// Fail-safe: an unrecognised class must land on a truthful, allowlisted
		// code rather than an empty string or a leaked value.
		{"unknown class", verificationErrorClass("something_new"), AuthFailVerification},
		{"empty class", verificationErrorClass(""), AuthFailVerification},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := authFailReasonForVerification(tt.class)
			if got != tt.want {
				t.Errorf("authFailReasonForVerification(%q) = %q, want %q", tt.class, got, tt.want)
			}
			// Whatever it returns must survive the allowlist unchanged or
			// collapse deliberately — never be an unrecognised string.
			if wire := wireAuthFailureReason(got); wire != got && wire != AuthFailWireGeneric {
				t.Errorf("code %q maps to unexpected wire value %q", got, wire)
			}
		})
	}
}
