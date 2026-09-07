package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-915 F1 — alias bypass fix.
//
// Pre-fix, validateEthCallWithTracing literally checked `req.Method !=
// "eth_call"`. Chain-specific aliases (e.g. linea_call → eth_call,
// configured via EXTRA_RPC_NAMESPACES_FILE) bypassed tracing entirely
// even though RBAC saw them as eth_call via ResolveMethodAlias. These
// tests pin that aliased methods now go through tracing.

// withMethodAlias temporarily registers an alias and restores the prior
// state in t.Cleanup. Required because MethodAliases is package-global.
func withMethodAlias(t *testing.T, method, target string) {
	t.Helper()
	t.Cleanup(rbac.SnapshotMethodRegistriesForTest())
	rbac.MethodAliases[method] = target
}

func TestEthCallTracing_AliasedMethodIsTraced(t *testing.T) {
	addrA := fixedAddr(0xaa)
	addrB := fixedAddr(0xbb)

	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: addrA,
		Calls: []traceFrame{{Type: "CALL", From: addrA, To: addrB}},
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)

	ctx := context.Background()
	did, _ := callerSameOrg(t, ctx, ts, addrA)
	registerForeignOrgContract(t, ctx, ts, addrB)

	withMethodAlias(t, "linea_call", "eth_call")

	req := &ProcessRequest{
		UserID: did,
		Method: "linea_call",
		Params: []any{map[string]any{"to": addrA, "data": "0x"}},
	}
	err := proc.validateEthCallWithTracing(ctx, req, addrA)
	require.NotNil(t, err,
		"a chain-specific alias of eth_call (linea_call) must go through tracing — pre-F1 this bypassed and the cross-org call leaked")
	assert.Equal(t, http.StatusForbidden, err.StatusCode)
	assert.Equal(t, ethCallDenyCrossOrg, err.Message)
}

func TestEthCallTracing_UnrelatedMethodStillBypasses(t *testing.T) {
	// Even with an alias registered for some method, an unaliased
	// method that happens to share a prefix must still bypass.
	addrA := fixedAddr(0xaa)
	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: addrA,
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)

	ctx := context.Background()
	did, _ := callerSameOrg(t, ctx, ts, addrA)

	withMethodAlias(t, "linea_call", "eth_call")

	req := &ProcessRequest{
		UserID: did,
		Method: "linea_estimateGas", // not aliased to eth_call
		Params: []any{map[string]any{"to": addrA}},
	}
	require.Nil(t, proc.validateEthCallWithTracing(ctx, req, addrA),
		"only methods that resolve to eth_call go through this gate; other aliases are out of scope")
}

func TestEthCallTracing_WildcardPassthroughBypasses(t *testing.T) {
	// Per RD-911, a method that matches ONLY a wildcard (no explicit
	// alias) passes through verbatim and opts out of RBAC + redaction.
	// Tracing must also not fire — opting into wildcards is opting
	// into operator-managed scope.
	addrA := fixedAddr(0xaa)
	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: addrA,
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)
	ctx := context.Background()
	did, _ := callerSameOrg(t, ctx, ts, addrA)

	// No alias registered — name happens to resemble a wildcard match.
	req := &ProcessRequest{
		UserID: did,
		Method: "linea_someBespokeMethod",
		Params: []any{map[string]any{"to": addrA}},
	}
	require.Nil(t, proc.validateEthCallWithTracing(ctx, req, addrA))
}

// setupProcessorWithMockTracer is in eth_call_tracing_integration_test.go;
// fixedAddr, traceFrame, scriptedTracerServer, callerSameOrg etc are also
// shared from that file.

// Strings used above must match (compile-time sanity to keep the file
// self-contained when refactors split tests across packages).
var _ = strings.ToLower
var _ = time.Second
