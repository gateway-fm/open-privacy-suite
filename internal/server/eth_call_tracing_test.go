package server

import (
	"context"
	"testing"
	"time"

	"privacy-proxy/internal/rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-915 unit tests for validateEthCallWithTracing.
//
// Same setup pattern as debug_trace_test.go (a tracer pointed at an
// unreachable URL — tests assert behavior at gates that fire before the
// HTTP call, or on the upstream-error path).
//
// The integration tests that actually drive the trace-and-decide path
// (cross-org deny, multi-hop, proxy-flip, STATICCALL/DELEGATECALL semantics,
// depth limit, reverted subcalls, EOA target, precompile/shared-infra) live
// in eth_call_tracing_integration_test.go.

func setupEthCallProc(t *testing.T) (*JSONRPCProcessor, *testServerRBAC) {
	t.Helper()
	proc, ts := setupProcessorWithTracing(t)
	proc.SetEthCallTracing(true, 5*time.Second)
	return proc, ts
}

func TestEthCallTracing_DisabledKnobBypasses(t *testing.T) {
	proc, _ := setupProcessorWithTracing(t)
	proc.SetEthCallTracing(false, 5*time.Second)
	req := &ProcessRequest{
		UserID: "did:privado:any",
		Method: "eth_call",
		Params: []any{map[string]any{"to": "0x1111111111111111111111111111111111111111"}},
	}
	require.Nil(t, proc.validateEthCallWithTracing(context.Background(), req, "0x1111111111111111111111111111111111111111"),
		"knob disabled → must skip tracing without touching DB or upstream")
}

func TestEthCallTracing_WrongMethodBypasses(t *testing.T) {
	proc, _ := setupEthCallProc(t)
	req := &ProcessRequest{
		UserID: "did:privado:any",
		Method: "eth_getBalance",
		Params: []any{"0x1111111111111111111111111111111111111111", "latest"},
	}
	require.Nil(t, proc.validateEthCallWithTracing(context.Background(), req, "0x1111111111111111111111111111111111111111"),
		"non-eth_call non-eth_estimateGas method must early-return")
}

// H10 (security audit follow-up to RD-915): eth_estimateGas runs the
// EVM the same way eth_call does and therefore shares the same
// cross-org composability leak shape. The gate must fire for it too.
// This pins the post-fix behavior: a malformed eth_estimateGas to/
// from must reach the validator and return 400 (rather than silently
// being bypassed at the method check). When this test starts to fail
// it almost certainly means someone narrowed validateEthCallWithTracing
// back to eth_call only — re-read the H10 comment in the validator
// before changing the gate.
func TestEthEstimateGasTracing_InvalidFromReturns400(t *testing.T) {
	proc, _ := setupEthCallProc(t)
	req := &ProcessRequest{
		UserID: "did:privado:any",
		Method: "eth_estimateGas",
		Params: []any{map[string]any{
			"to":   "0x2222222222222222222222222222222222222222",
			"from": "0xnope",
		}},
	}
	err := proc.validateEthCallWithTracing(context.Background(), req, "0x2222222222222222222222222222222222222222")
	require.NotNil(t, err, "eth_estimateGas must go through the tracing gate")
	assert.Equal(t, 400, err.StatusCode)
	assert.Contains(t, err.Message, "invalid request shape")
}

func TestEthCreateAccessListTracing_InvalidFromReturns400(t *testing.T) {
	proc, _ := setupEthCallProc(t)
	req := &ProcessRequest{
		UserID: "did:privado:any",
		Method: "eth_createAccessList",
		Params: []any{map[string]any{
			"to":   "0x2222222222222222222222222222222222222222",
			"from": "0xnope",
		}},
	}
	err := proc.validateEthCallWithTracing(context.Background(), req, "0x2222222222222222222222222222222222222222")
	require.NotNil(t, err, "eth_createAccessList must go through the live tracing gate")
	assert.Equal(t, 400, err.StatusCode)
	assert.Contains(t, err.Message, "invalid request shape")
}

func TestEthCallTracing_EmptyTargetBypasses(t *testing.T) {
	proc, _ := setupEthCallProc(t)
	req := &ProcessRequest{
		UserID: "did:privado:any",
		Method: "eth_call",
		Params: []any{map[string]any{}},
	}
	require.Nil(t, proc.validateEthCallWithTracing(context.Background(), req, ""),
		"empty target — RBAC entry-point check would have already rejected if required")
}

func TestEthCallTracing_InvalidToReturns400(t *testing.T) {
	proc, _ := setupEthCallProc(t)
	req := &ProcessRequest{
		UserID: "did:privado:any",
		Method: "eth_call",
		Params: []any{map[string]any{"to": "not-a-hex-address"}},
	}
	err := proc.validateEthCallWithTracing(context.Background(), req, "not-a-hex-address")
	require.NotNil(t, err)
	assert.Equal(t, 400, err.StatusCode)
	assert.Contains(t, err.Message, "invalid request shape")
}

func TestEthCallTracing_InvalidFromReturns400(t *testing.T) {
	proc, _ := setupEthCallProc(t)
	req := &ProcessRequest{
		UserID: "did:privado:any",
		Method: "eth_call",
		Params: []any{map[string]any{
			"to":   "0x2222222222222222222222222222222222222222",
			"from": "0xnope",
		}},
	}
	err := proc.validateEthCallWithTracing(context.Background(), req, "0x2222222222222222222222222222222222222222")
	require.NotNil(t, err)
	assert.Equal(t, 400, err.StatusCode)
	assert.Contains(t, err.Message, "invalid request shape")
}

func TestEthCallTracing_UnknownUserDenied(t *testing.T) {
	proc, _ := setupEthCallProc(t)
	req := &ProcessRequest{
		UserID: "did:privado:nonexistent",
		Method: "eth_call",
		Params: []any{map[string]any{"to": "0x2222222222222222222222222222222222222222"}},
	}
	err := proc.validateEthCallWithTracing(context.Background(), req, "0x2222222222222222222222222222222222222222")
	require.NotNil(t, err)
	assert.Equal(t, 403, err.StatusCode)
	assert.Contains(t, err.Message, "tracing temporarily unavailable")
}

func TestEthCallTracing_FromSpoofRejected(t *testing.T) {
	proc, ts := setupEthCallProc(t)
	ctx := context.Background()
	did := createOrgGroupUserMembership(t, ctx, ts.db, []rbac.Claim{rbac.ClaimAdmin})

	// User owns 0xaaaa…; supplies 0xbbbb… — must be rejected, not silently rebound.
	require.NoError(t, ts.db.SystemLinkEthAddress(ctx,
		did, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))

	req := &ProcessRequest{
		UserID: did,
		Method: "eth_call",
		Params: []any{map[string]any{
			"to":   "0x2222222222222222222222222222222222222222",
			"from": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		}},
	}
	err := proc.validateEthCallWithTracing(ctx, req, "0x2222222222222222222222222222222222222222")
	require.NotNil(t, err)
	assert.Equal(t, 400, err.StatusCode)
	assert.Contains(t, err.Message, "invalid request shape")
}

func TestEthCallTracing_RuntimeOverrideTakesEffect(t *testing.T) {
	// Verifies that the super-admin runtime override actually wins over
	// the env-installed value at the next validator call. With the
	// processor's tracer pointed at 127.0.0.1:1 (unreachable), an
	// enabled validator deny-403s any reachable user; a disabled one
	// returns nil and the call would forward. We assert the gate
	// flips on Override.
	proc, ts := setupEthCallProc(t)
	ctx := context.Background()
	did := createOrgGroupUserMembership(t, ctx, ts.db, []rbac.Claim{rbac.ClaimAdmin})

	req := &ProcessRequest{
		UserID: did,
		Method: "eth_call",
		Params: []any{map[string]any{"to": "0x2222222222222222222222222222222222222222"}},
	}

	// On (from setup) → upstream-unreachable path returns ethCallDenyTracerError.
	err1 := proc.validateEthCallWithTracing(ctx, req, "0x2222222222222222222222222222222222222222")
	require.NotNil(t, err1)
	assert.Equal(t, ethCallDenyTracerError, err1.Message)

	// Off via runtime override → validator bypasses entirely, returns nil.
	proc.SetEthCallTracingRuntimeOverride(false, "test", "ops drill")
	require.Nil(t, proc.validateEthCallWithTracing(ctx, req, "0x2222222222222222222222222222222222222222"),
		"runtime override OFF must bypass the validator on the very next call")

	// Re-enable.
	proc.SetEthCallTracingRuntimeOverride(true, "test", "drill complete")
	err3 := proc.validateEthCallWithTracing(ctx, req, "0x2222222222222222222222222222222222222222")
	require.NotNil(t, err3, "runtime override ON re-arms the validator")
}

func TestEthCallTracing_UpstreamErrorDeniedClosed(t *testing.T) {
	// Tracer points at 127.0.0.1:1 — connect refused → upstream error path.
	// Must produce a 403 with the generic tracer-error message (no %v leak).
	proc, ts := setupEthCallProc(t)
	ctx := context.Background()
	did := createOrgGroupUserMembership(t, ctx, ts.db, []rbac.Claim{rbac.ClaimAdmin})

	req := &ProcessRequest{
		UserID: did,
		Method: "eth_call",
		Params: []any{map[string]any{
			"to": "0x2222222222222222222222222222222222222222",
		}},
	}
	err := proc.validateEthCallWithTracing(ctx, req, "0x2222222222222222222222222222222222222222")
	require.NotNil(t, err)
	assert.Equal(t, 403, err.StatusCode)
	assert.Contains(t, err.Message, "tracing temporarily unavailable")
	// Must not echo upstream details — the message ends with the canonical phrase.
	assert.NotContains(t, err.Message, "127.0.0.1")
	assert.NotContains(t, err.Message, "connect")
}
