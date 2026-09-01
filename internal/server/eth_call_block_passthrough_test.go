package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/tracer"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-915 F2 — block-tag passthrough.
//
// The eth_call validation trace must run at the same block as the
// forwarded call; otherwise a proxy contract that has been flipped
// between block N and "latest" lets an attacker exfil historical
// cross-org state (trace at "latest" allows, real call at block N
// returns foreign-org payload). These tests prove the block param
// from params[1] actually reaches the upstream debug_traceCall.

// capturingTracerServer is a single-shot scripted server that records
// the raw JSON-RPC request it received. The test then asserts on the
// second positional param (the block tag).
type capturingTracerServer struct {
	srv      *httptest.Server
	mu       sync.Mutex
	requests []map[string]any
}

func newCapturingTracer(t *testing.T) *capturingTracerServer {
	t.Helper()
	c := &capturingTracerServer{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		c.mu.Lock()
		c.requests = append(c.requests, req)
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		// Return a trivial successful trace (no internal calls).
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"type": "CALL",
				"from": fixedAddr(0xee),
				"to":   fixedAddr(0xaa),
			},
		})
	}))
	t.Cleanup(c.srv.Close)
	return c
}

// blockParam returns the second positional param of the i-th captured request.
func (c *capturingTracerServer) blockParam(i int) any {
	c.mu.Lock()
	defer c.mu.Unlock()
	params := c.requests[i]["params"].([]any)
	return params[1]
}

func setupProcessorWithCapturingTracer(t *testing.T, srv *httptest.Server) (*JSONRPCProcessor, *testServerRBAC) {
	t.Helper()
	ts := setupTestServerForRBAC(t)
	rt := tracer.NewRuntimeTracer(tracer.RuntimeTracerConfig{
		NodeURL: srv.URL,
		Enabled: true,
		Timeout: 5 * time.Second,
	})
	t.Cleanup(rt.Stop)
	tv := rbac.NewTraceValidator(ts.db)
	proc := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:     ts.rbacAccessCtrl,
		RateLimiter:        &noopRateLimiter{},
		AccessLogger:       ts.db,
		RuntimeTracer:      rt,
		TraceValidator:     tv,
		CircuitBreaker:     NewCircuitBreaker(),
		ConcurrencyLimiter: NewConcurrencyLimiter(50, 0),
		EthCallTracing:     &EthCallTracingConfig{Enabled: true, Timeout: 5 * time.Second},
	})
	return proc, ts
}

func TestEthCallTracing_DefaultBlockParamIsLatest(t *testing.T) {
	cap := newCapturingTracer(t)
	proc, ts := setupProcessorWithCapturingTracer(t, cap.srv)

	ctx := context.Background()
	addrA := fixedAddr(0xaa)
	did, _ := callerSameOrg(t, ctx, ts, addrA)

	// No params[1] supplied — must default to "latest".
	req := &ProcessRequest{
		UserID: did,
		Method: "eth_call",
		Params: []any{map[string]any{"to": addrA, "data": "0x"}},
	}
	require.Nil(t, proc.validateEthCallWithTracing(ctx, req, addrA))
	require.Len(t, cap.requests, 1)
	assert.Equal(t, "latest", cap.blockParam(0),
		"omitted block param must default to 'latest'")
}

func TestEthCallTracing_StringBlockParamReachesUpstream(t *testing.T) {
	cap := newCapturingTracer(t)
	proc, ts := setupProcessorWithCapturingTracer(t, cap.srv)

	ctx := context.Background()
	addrA := fixedAddr(0xaa)
	did, _ := callerSameOrg(t, ctx, ts, addrA)

	req := &ProcessRequest{
		UserID: did,
		Method: "eth_call",
		Params: []any{
			map[string]any{"to": addrA, "data": "0x"},
			"0x1234abcd",
		},
	}
	require.Nil(t, proc.validateEthCallWithTracing(ctx, req, addrA))
	require.Len(t, cap.requests, 1)
	assert.Equal(t, "0x1234abcd", cap.blockParam(0),
		"historical block hex must be forwarded — trace and call must run at the same block")
}

func TestEthCallTracing_EIP1898ObjectReachesUpstream(t *testing.T) {
	cap := newCapturingTracer(t)
	proc, ts := setupProcessorWithCapturingTracer(t, cap.srv)

	ctx := context.Background()
	addrA := fixedAddr(0xaa)
	did, _ := callerSameOrg(t, ctx, ts, addrA)

	obj := map[string]any{"blockNumber": "0xabc123"}
	req := &ProcessRequest{
		UserID: did,
		Method: "eth_call",
		Params: []any{
			map[string]any{"to": addrA, "data": "0x"},
			obj,
		},
	}
	require.Nil(t, proc.validateEthCallWithTracing(ctx, req, addrA))
	require.Len(t, cap.requests, 1)
	got := cap.blockParam(0).(map[string]any)
	assert.Equal(t, "0xabc123", got["blockNumber"],
		"EIP-1898 object must pass through verbatim")
}

func TestEthCallTracing_MalformedBlockParamRejected(t *testing.T) {
	cap := newCapturingTracer(t)
	proc, ts := setupProcessorWithCapturingTracer(t, cap.srv)

	ctx := context.Background()
	addrA := fixedAddr(0xaa)
	did, _ := callerSameOrg(t, ctx, ts, addrA)

	req := &ProcessRequest{
		UserID: did,
		Method: "eth_call",
		Params: []any{
			map[string]any{"to": addrA, "data": "0x"},
			float64(42), // numbers aren't a valid block param shape
		},
	}
	err := proc.validateEthCallWithTracing(ctx, req, addrA)
	require.NotNil(t, err)
	assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	assert.Equal(t, ethCallDenyInvalidRequest, err.Message)
	// And — crucially — no upstream trace was issued. A malformed
	// request must not burn an upstream connection or a concurrency
	// slot, same rule as IsHexAddress.
	assert.Len(t, cap.requests, 0,
		"malformed block param must short-circuit before the upstream trace")
}

// Convenience to keep the file self-contained.
var _ = strings.ToLower
