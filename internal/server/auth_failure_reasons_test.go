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
		AuthFailVerification:     true,
		AuthFailHumanityRequired: true,
		AuthFailInvalidRequest:   true,
		AuthFailWireGeneric:      true,
	}

	inputs := []string{
		AuthFailVerification, AuthFailHumanityRequired, AuthFailInvalidRequest,
		AuthFailAccountBanned, AuthFailInternalError,
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
