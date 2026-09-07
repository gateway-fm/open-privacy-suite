package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"
	"privacy-proxy/internal/tracer"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-915 integration tests for validateEthCallWithTracing.
//
// The pre-existing eth_call_tracing_test.go covers the 8 gates that fire
// before any actual trace runs (knob disabled, wrong method, invalid input,
// upstream-unreachable, etc.). This file covers the path through the trace
// itself: a controllable httptest server returns crafted callTracer JSON,
// and the assertions are on the wrapper's allow/deny decision given that
// trace shape.
//
// Why httptest rather than mocking RuntimeTracer: the field is a concrete
// *tracer.RuntimeTracer (not an interface) and refactoring to inject a fake
// would expand PR #205's surface. The HTTP boundary is the existing seam.

// traceFrame mirrors callFrame in the geth callTracer output. Exported only
// for test fixtures — the production parser uses an internal type.
type traceFrame struct {
	Type  string       `json:"type"`
	From  string       `json:"from"`
	To    string       `json:"to,omitempty"`
	Error string       `json:"error,omitempty"`
	Calls []traceFrame `json:"calls,omitempty"`
}

// nodeReply is the JSON-RPC envelope the proxy expects from the upstream node.
type nodeReply struct {
	JSONRPC string     `json:"jsonrpc"`
	ID      int        `json:"id"`
	Result  traceFrame `json:"result"`
}

// scriptedTracerServer hands out trace responses in sequence, one per request.
// Used for the proxy-flip test where the same (from,to,data,value) must yield
// different trace results across two calls (cache MUST be bypassed).
type scriptedTracerServer struct {
	t        *testing.T
	srv      *httptest.Server
	frames   []traceFrame
	delay    time.Duration
	hits     atomic.Int64
	cursor   atomic.Int64
	overflow atomic.Bool // set when more requests arrive than fixtures
}

func newScriptedTracer(t *testing.T, frames ...traceFrame) *scriptedTracerServer {
	t.Helper()
	s := &scriptedTracerServer{t: t, frames: frames}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if s.delay > 0 {
			time.Sleep(s.delay)
		}
		s.hits.Add(1)
		idx := int(s.cursor.Add(1) - 1)
		if idx >= len(s.frames) {
			s.overflow.Store(true)
			idx = len(s.frames) - 1
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(nodeReply{
			JSONRPC: "2.0",
			ID:      1,
			Result:  s.frames[idx],
		})
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// setupProcessorWithMockTracer wires a JSONRPCProcessor to a scripted tracer
// HTTP endpoint. Distinct from setupProcessorWithTracing (which points at
// 127.0.0.1:1) so the trace path actually executes.
func setupProcessorWithMockTracer(t *testing.T, scripted *scriptedTracerServer) (*JSONRPCProcessor, *testServerRBAC) {
	t.Helper()
	ts := setupTestServerForRBAC(t)

	rt := tracer.NewRuntimeTracer(tracer.RuntimeTracerConfig{
		NodeURL: scripted.srv.URL,
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
		CircuitBreaker:     middleware.NewCircuitBreaker(),
		ConcurrencyLimiter: middleware.NewConcurrencyLimiter(50, 0),
		EthCallTracing:     &EthCallTracingConfig{Enabled: true, Timeout: 5 * time.Second},
	})
	return proc, ts
}

// fixedAddr returns a 20-byte lowercase address with the supplied byte
// repeated. Used to give each test contract a stable, distinguishable address.
func fixedAddr(b byte) string {
	return "0x" + strings.Repeat(fmt.Sprintf("%02x", b), 20)
}

// registerForeignOrgContract creates an org and registers a single contract
// address to it. Returns the new orgID. The caller can then build a user
// attached to a different org to test cross-org denial. Distinct name from
// the explorer_api_test.go helper to avoid the package-level collision.
func registerForeignOrgContract(t *testing.T, ctx context.Context, ts *testServerRBAC, addr string) (orgID string) {
	t.Helper()
	orgID = uuid.New().String()
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{
		ID:   orgID,
		Slug: "owner-" + orgID[:8],
		Name: "Owner Org",
	}))
	require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{
		ID:      uuid.New().String(),
		OrgID:   orgID,
		Address: strings.ToLower(addr),
		Name:    "C-" + addr[2:6],
	}))
	return orgID
}

// callerSameOrg makes a user attached to the same org as the contract at
// `contractAddr`. Use when the test needs the entry-point to be same-org.
func callerSameOrg(t *testing.T, ctx context.Context, ts *testServerRBAC, contractAddr string) (did, orgID string) {
	t.Helper()
	orgID = registerForeignOrgContract(t, ctx, ts, contractAddr)
	groupID := uuid.New().String()
	userID := uuid.New().String()
	did = "did:privado:caller-" + uuid.New().String()
	insertGroupRawSQL(t, ctx, ts.db, groupID, orgID,
		"caller-grp-"+groupID[:8], "Caller Grp", "caller-grp-"+groupID[:8])
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        groupID,
		Claims:         []rbac.Claim{rbac.ClaimAdmin},
		AllowedMethods: []string{},
	}))
	require.NoError(t, ts.db.CreateUser(ctx, &rbac.User{ID: userID, ExternalID: did}))
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: userID, GroupID: groupID,
		Source: rbac.MembershipSourceAdmin,
	}))
	return did, orgID
}

// ethCallReq is a small constructor for the request type the processor expects.
func ethCallReq(did, to string) *ProcessRequest {
	return &ProcessRequest{
		UserID: did,
		Method: "eth_call",
		Params: []any{map[string]any{"to": to, "data": "0x"}},
	}
}

// =============================================================================
// #1 — Same-org allow / cross-org deny (the actual security goal)
// =============================================================================

func TestEthCallTracing_AllowsSameOrgTrace(t *testing.T) {
	addrA := fixedAddr(0xaa)
	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: addrA,
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)

	ctx := context.Background()
	did, _ := callerSameOrg(t, ctx, ts, addrA)

	err := proc.validateEthCallWithTracing(ctx, ethCallReq(did, addrA), addrA)
	require.Nil(t, err, "trace touching only same-org targets must be allowed")
	assert.Equal(t, int64(1), scripted.hits.Load(), "trace should have been performed exactly once")
}

func TestEthCallTracing_DeniesCrossOrgInternalCall(t *testing.T) {
	addrA := fixedAddr(0xaa) // same-org wrapper
	addrB := fixedAddr(0xbb) // foreign-org

	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: addrA,
		Calls: []traceFrame{
			{Type: "CALL", From: addrA, To: addrB},
		},
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)

	ctx := context.Background()
	did, _ := callerSameOrg(t, ctx, ts, addrA)
	registerForeignOrgContract(t, ctx, ts, addrB) // distinct org

	err := proc.validateEthCallWithTracing(ctx, ethCallReq(did, addrA), addrA)
	require.NotNil(t, err, "trace touching a foreign-org address must deny")
	assert.Equal(t, http.StatusForbidden, err.StatusCode)
	assert.Equal(t, ethCallDenyCrossOrg, err.Message,
		"deny message must be the canonical cross-org constant (no detail leak)")
	// Must NOT echo the denied address into the response body.
	assert.NotContains(t, err.Message, strings.TrimPrefix(addrB, "0x"))
}

func TestEthCallTracing_PinnedOrgDeniesOtherMembershipOrg(t *testing.T) {
	addrA := fixedAddr(0xaa)
	addrB := fixedAddr(0xbb)
	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: addrA,
		Calls: []traceFrame{{Type: "STATICCALL", From: addrA, To: addrB}},
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)

	ctx := context.Background()
	did, callerOrg := callerSameOrg(t, ctx, ts, addrA)
	otherOrg := registerForeignOrgContract(t, ctx, ts, addrB)
	user, err := ts.db.GetUserByExternalID(ctx, did)
	require.NoError(t, err)
	require.NotNil(t, user)
	otherGroupID := uuid.New().String()
	insertGroupRawSQL(t, ctx, ts.db, otherGroupID, otherOrg,
		"other-grp-"+otherGroupID[:8], "Other Grp", "other-grp-"+otherGroupID[:8])
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: user.ID, GroupID: otherGroupID,
		Source: rbac.MembershipSourceAdmin,
	}))

	traceErr := proc.validateEthCallWithTracingInOrg(ctx, ethCallReq(did, addrA), addrA, callerOrg)
	require.NotNil(t, traceErr, "dry-run validation must stay in the administrator's path org")
	assert.Equal(t, http.StatusForbidden, traceErr.StatusCode)
	assert.Equal(t, ethCallDenyCrossOrg, traceErr.Message)
}

// =============================================================================
// #2, #9 — Multi-hop A→B→C-foreign and self-recursion
// =============================================================================

func TestEthCallTracing_DeniesMultiHopCrossOrg(t *testing.T) {
	addrA := fixedAddr(0xaa)
	addrB := fixedAddr(0xbb) // also same-org (legitimate intermediary)
	addrC := fixedAddr(0xcc) // foreign-org, two hops deep

	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: addrA,
		Calls: []traceFrame{{
			Type: "CALL", From: addrA, To: addrB,
			Calls: []traceFrame{{
				Type: "CALL", From: addrB, To: addrC,
			}},
		}},
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)

	ctx := context.Background()
	did, callerOrg := callerSameOrg(t, ctx, ts, addrA)
	// addrB belongs to caller's org (legitimate intermediary)
	require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{
		ID:      uuid.New().String(),
		OrgID:   callerOrg,
		Address: strings.ToLower(addrB),
		Name:    "B-intermediary",
	}))
	// addrC is foreign
	registerForeignOrgContract(t, ctx, ts, addrC)

	err := proc.validateEthCallWithTracing(ctx, ethCallReq(did, addrA), addrA)
	require.NotNil(t, err, "depth-2 cross-org call must be denied")
	assert.Equal(t, http.StatusForbidden, err.StatusCode)
	assert.Equal(t, ethCallDenyCrossOrg, err.Message)
}

func TestEthCallTracing_DeniesSelfRecursionCrossOrg(t *testing.T) {
	// A → A → B-foreign. The self-edge should not confuse the validator;
	// the foreign B at depth 2 must still be detected.
	addrA := fixedAddr(0xaa)
	addrB := fixedAddr(0xbb)

	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: addrA,
		Calls: []traceFrame{{
			Type: "CALL", From: addrA, To: addrA,
			Calls: []traceFrame{{
				Type: "CALL", From: addrA, To: addrB,
			}},
		}},
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)

	ctx := context.Background()
	did, _ := callerSameOrg(t, ctx, ts, addrA)
	registerForeignOrgContract(t, ctx, ts, addrB)

	err := proc.validateEthCallWithTracing(ctx, ethCallReq(did, addrA), addrA)
	require.NotNil(t, err, "self-recursion masking a deeper foreign-org call must be denied")
	assert.Equal(t, ethCallDenyCrossOrg, err.Message)
}

// =============================================================================
// #3 — EIP-1967 proxy implementation flip; cache MUST be bypassed
// =============================================================================

// TestEthCallTracing_ProxyImplementationFlip simulates a proxy contract whose
// implementation slot is rewritten between two eth_call invocations. The two
// invocations have IDENTICAL (from,to,data,value), so a cache-keyed validator
// would reuse the first decision and miss the cross-org flip.
func TestEthCallTracing_ProxyImplementationFlip(t *testing.T) {
	proxyAddr := fixedAddr(0xaa)   // same-org proxy entry
	implOK := fixedAddr(0xa1)      // same-org implementation v1
	implForeign := fixedAddr(0xbb) // post-flip implementation, foreign-org

	// Pre-flip trace: proxy DELEGATECALLs into same-org impl v1 → allow.
	preFlip := traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: proxyAddr,
		Calls: []traceFrame{{
			Type: "DELEGATECALL", From: proxyAddr, To: implOK,
		}},
	}
	// Post-flip trace: proxy now DELEGATECALLs into foreign-org impl → deny.
	postFlip := traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: proxyAddr,
		Calls: []traceFrame{{
			Type: "DELEGATECALL", From: proxyAddr, To: implForeign,
		}},
	}
	scripted := newScriptedTracer(t, preFlip, postFlip)

	proc, ts := setupProcessorWithMockTracer(t, scripted)
	ctx := context.Background()
	did, callerOrg := callerSameOrg(t, ctx, ts, proxyAddr)
	// implOK same-org
	require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{
		ID:      uuid.New().String(),
		OrgID:   callerOrg,
		Address: strings.ToLower(implOK),
		Name:    "impl-v1",
	}))
	// implForeign foreign-org
	registerForeignOrgContract(t, ctx, ts, implForeign)

	// First call — pre-flip — should allow.
	err1 := proc.validateEthCallWithTracing(ctx, ethCallReq(did, proxyAddr), proxyAddr)
	require.Nil(t, err1, "pre-flip trace (same-org impl) must be allowed")

	// Second call — same (from,to,data,value), but post-flip — must deny.
	// If a cache was consulted, it would reuse the first allow.
	err2 := proc.validateEthCallWithTracing(ctx, ethCallReq(did, proxyAddr), proxyAddr)
	require.NotNil(t, err2,
		"post-flip trace (foreign-org impl) must deny — cache bypass is the entire point of TraceTransactionUncached")
	assert.Equal(t, ethCallDenyCrossOrg, err2.Message)

	assert.Equal(t, int64(2), scripted.hits.Load(),
		"two distinct upstream traces must occur; one would mean cache leaked")
	assert.False(t, scripted.overflow.Load(),
		"more than 2 trace requests means the wrapper retried unexpectedly")
}

// =============================================================================
// #4 — STATICCALL and DELEGATECALL semantics
// =============================================================================

func TestEthCallTracing_DeniesCrossOrgStaticcall(t *testing.T) {
	addrA := fixedAddr(0xaa)
	addrB := fixedAddr(0xbb)

	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: addrA,
		Calls: []traceFrame{{
			Type: "STATICCALL", From: addrA, To: addrB,
		}},
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)

	ctx := context.Background()
	did, _ := callerSameOrg(t, ctx, ts, addrA)
	registerForeignOrgContract(t, ctx, ts, addrB)

	err := proc.validateEthCallWithTracing(ctx, ethCallReq(did, addrA), addrA)
	require.NotNil(t, err, "STATICCALL into a foreign-org contract leaks state and must be denied")
	assert.Equal(t, ethCallDenyCrossOrg, err.Message)
}

func TestEthCallTracing_DeniesCrossOrgDelegatecall(t *testing.T) {
	// DELEGATECALL executes the foreign code in the caller's storage —
	// from a privacy standpoint, the foreign contract's bytecode is
	// loaded and observed, so cross-org DELEGATECALL must deny.
	addrA := fixedAddr(0xaa)
	addrB := fixedAddr(0xbb)

	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: addrA,
		Calls: []traceFrame{{
			Type: "DELEGATECALL", From: addrA, To: addrB,
		}},
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)

	ctx := context.Background()
	did, _ := callerSameOrg(t, ctx, ts, addrA)
	registerForeignOrgContract(t, ctx, ts, addrB)

	err := proc.validateEthCallWithTracing(ctx, ethCallReq(did, addrA), addrA)
	require.NotNil(t, err, "DELEGATECALL into a foreign-org contract must be denied (code is observed)")
	assert.Equal(t, ethCallDenyCrossOrg, err.Message)
}

// =============================================================================
// #6 — Trace-depth-exceeded translates to the distinct deny message
// =============================================================================

func TestEthCallTracing_DepthExceededReturnsDistinctMessage(t *testing.T) {
	// Build a frame chain deeper than maxTraceDepth (256). The validator
	// recurses one level per nested frame; >256 must produce the distinct
	// ethCallDenyDepthExceeded message rather than the generic tracer error.
	const overDepth = 260

	innermost := traceFrame{Type: "CALL", From: fixedAddr(0xaa), To: fixedAddr(0xaa)}
	cursor := &innermost
	for i := 0; i < overDepth; i++ {
		wrapped := traceFrame{
			Type: "CALL", From: fixedAddr(0xaa), To: fixedAddr(0xaa),
			Calls: []traceFrame{*cursor},
		}
		cursor = &wrapped
	}

	scripted := newScriptedTracer(t, *cursor)
	proc, ts := setupProcessorWithMockTracer(t, scripted)
	ctx := context.Background()
	addrA := fixedAddr(0xaa)
	did, _ := callerSameOrg(t, ctx, ts, addrA)

	err := proc.validateEthCallWithTracing(ctx, ethCallReq(did, addrA), addrA)
	require.NotNil(t, err, "over-deep trace must deny")
	assert.Equal(t, http.StatusForbidden, err.StatusCode)
	assert.Equal(t, ethCallDenyDepthExceeded, err.Message,
		"depth-overflow must surface the dedicated message, not the generic tracer-error one")
}

// =============================================================================
// #7 — Reverted internal call to a foreign-org contract still denies
// =============================================================================

// The geth callTracer returns reverted subcalls in the trace with an `error`
// field on the frame. ValidateTrace does not consult frame.Error, so a
// reverted CALL into a foreign-org contract is still in CallTargets and is
// still denied. This is the right posture — even probing reverted state is
// a leak — but the wiring needs to be pinned by a test so a future
// "optimization" doesn't quietly drop reverted frames.
func TestEthCallTracing_RevertedSubcallToForeignOrgStillDenies(t *testing.T) {
	addrA := fixedAddr(0xaa)
	addrB := fixedAddr(0xbb)

	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: addrA,
		Calls: []traceFrame{{
			Type:  "CALL",
			From:  addrA,
			To:    addrB,
			Error: "execution reverted",
		}},
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)

	ctx := context.Background()
	did, _ := callerSameOrg(t, ctx, ts, addrA)
	registerForeignOrgContract(t, ctx, ts, addrB)

	err := proc.validateEthCallWithTracing(ctx, ethCallReq(did, addrA), addrA)
	require.NotNil(t, err,
		"reverted subcalls to foreign-org contracts must still deny — probe-via-revert is a leak")
	assert.Equal(t, ethCallDenyCrossOrg, err.Message)
}

// =============================================================================
// #8 — eth_call to an EOA target: pin current behavior
// =============================================================================

// EOAs have no Contract registry row, so IsAddressOwnedByOrg / GetContractOwnerOrgID
// return empty for every org. ValidateTrace then falls through to Rule 2e
// (unregistered → deny). This test pins that behavior so any future change
// to the Rule 2e default is intentional.
//
// If the product decision flips to "EOAs are public", swap this to assert
// allow and add a SharedInfrastructure carve-out or a HasCode short-circuit.
func TestEthCallTracing_EOATargetDeniedAsUnregistered(t *testing.T) {
	addrA := fixedAddr(0xaa)
	eoaAddr := fixedAddr(0xee)

	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: addrA, To: eoaAddr,
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)

	ctx := context.Background()
	did, _ := callerSameOrg(t, ctx, ts, addrA)

	err := proc.validateEthCallWithTracing(ctx, ethCallReq(did, eoaAddr), eoaAddr)
	require.NotNil(t, err,
		"current Rule 2e — unregistered addresses (incl. EOAs) deny by default; revisit if product flips this")
	assert.Equal(t, ethCallDenyCrossOrg, err.Message)
}

// =============================================================================
// Precompile + shared-infrastructure subcalls — must allow
// =============================================================================

func TestEthCallTracing_AllowsPrecompileSubcall(t *testing.T) {
	addrA := fixedAddr(0xaa)
	const ecRecover = "0x0000000000000000000000000000000000000001"

	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: addrA,
		Calls: []traceFrame{{
			Type: "STATICCALL", From: addrA, To: ecRecover,
		}},
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)
	ctx := context.Background()
	did, _ := callerSameOrg(t, ctx, ts, addrA)

	err := proc.validateEthCallWithTracing(ctx, ethCallReq(did, addrA), addrA)
	require.Nil(t, err, "trace touching ecrecover precompile must be allowed")
}

func TestEthCallTracing_AllowsSharedInfrastructureSubcall(t *testing.T) {
	addrA := fixedAddr(0xaa)
	sharedAddr := fixedAddr(0x99) // registered as shared infrastructure

	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: addrA,
		Calls: []traceFrame{{
			Type: "CALL", From: addrA, To: sharedAddr,
		}},
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)
	ctx := context.Background()
	did, _ := callerSameOrg(t, ctx, ts, addrA)

	require.NoError(t, ts.db.CreateSharedInfrastructure(ctx, &rbac.SharedInfrastructure{
		Address: strings.ToLower(sharedAddr),
		Name:    "Test Shared",
	}))

	err := proc.validateEthCallWithTracing(ctx, ethCallReq(did, addrA), addrA)
	require.Nil(t, err, "trace touching shared-infrastructure address must be allowed")
}

// =============================================================================
// RD-1053 — intra-org contract-grant scoping (end-to-end through the processor)
// =============================================================================

// callerSameOrgWithGroup is callerSameOrg but also returns the caller's group
// and the contract ID of the entry contract, so a test can attach contract
// grants — required to exercise the RD-1053 grant set, which is resolved from
// real EffectivePermissions (contract_grants) rather than passed in.
func callerSameOrgWithGroup(t *testing.T, ctx context.Context, ts *testServerRBAC, entryAddr string) (did, orgID, groupID, entryContractID string) {
	t.Helper()
	orgID = uuid.New().String()
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{
		ID:   orgID,
		Slug: "owner-" + orgID[:8],
		Name: "Owner Org",
	}))
	entryContractID = uuid.New().String()
	require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{
		ID:      entryContractID,
		OrgID:   orgID,
		Address: strings.ToLower(entryAddr),
		Name:    "entry",
	}))
	groupID = uuid.New().String()
	userID := uuid.New().String()
	did = "did:privado:caller-" + uuid.New().String()
	insertGroupRawSQL(t, ctx, ts.db, groupID, orgID,
		"caller-grp-"+groupID[:8], "Caller Grp", "caller-grp-"+groupID[:8])
	// No admin claim here: a plain member, so ContractAccess is exactly the
	// set of contracts the group has explicit grants for. That makes the
	// granted-vs-ungranted distinction meaningful for the test.
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        groupID,
		Claims:         []rbac.Claim{},
		AllowedMethods: []string{},
	}))
	require.NoError(t, ts.db.CreateUser(ctx, &rbac.User{ID: userID, ExternalID: did}))
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: userID, GroupID: groupID,
		Source: rbac.MembershipSourceAdmin,
	}))
	return did, orgID, groupID, entryContractID
}

// addSameOrgContract registers a contract to an existing org and returns its
// contract ID (so the caller can optionally grant it).
func addSameOrgContract(t *testing.T, ctx context.Context, ts *testServerRBAC, orgID, addr, name string) (contractID string) {
	t.Helper()
	contractID = uuid.New().String()
	require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{
		ID:      contractID,
		OrgID:   orgID,
		Address: strings.ToLower(addr),
		Name:    name,
	}))
	return contractID
}

// The gap RD-1053 closes: addrB is registered to the SAME org as the caller,
// but the caller's group has no grant for it. Reached as the direct `to` it
// would be denied by the grant-aware entry-point CheckAccess; reached through
// an internal CALL it slips past because the tracer historically gated on org
// ownership alone. With the knob OFF (default) it is still allowed — org
// ownership is the boundary — which this test pins as the unchanged baseline.
func TestEthCallTracing_IntraOrgScoping_Off_AllowsUngrantedSameOrg(t *testing.T) {
	addrA := fixedAddr(0xaa)
	addrB := fixedAddr(0xbb)
	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: addrA,
		Calls: []traceFrame{{Type: "CALL", From: addrA, To: addrB}},
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)
	// knob defaults OFF; assert that explicitly via the snapshot.
	require.False(t, proc.IntraOrgGrantTracingSnapshot().Enabled)

	ctx := context.Background()
	did, orgID, _, _ := callerSameOrgWithGroup(t, ctx, ts, addrA)
	addSameOrgContract(t, ctx, ts, orgID, addrB, "B-ungranted")

	err := proc.validateEthCallWithTracing(ctx, ethCallReq(did, addrA), addrA)
	require.Nil(t, err, "knob OFF: same-org internal frame allowed on org ownership alone (baseline)")
}

// Same setup, knob ON: the ungranted same-org internal frame is now denied.
func TestEthCallTracing_IntraOrgScoping_On_DeniesUngrantedSameOrg(t *testing.T) {
	addrA := fixedAddr(0xaa)
	addrB := fixedAddr(0xbb)
	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: addrA,
		Calls: []traceFrame{{Type: "CALL", From: addrA, To: addrB}},
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)
	proc.SetIntraOrgGrantTracing(true)

	ctx := context.Background()
	did, orgID, _, _ := callerSameOrgWithGroup(t, ctx, ts, addrA)
	addSameOrgContract(t, ctx, ts, orgID, addrB, "B-ungranted")

	err := proc.validateEthCallWithTracing(ctx, ethCallReq(did, addrA), addrA)
	require.NotNil(t, err, "knob ON: same-org internal frame with no grant must deny")
	assert.Equal(t, http.StatusForbidden, err.StatusCode)
	assert.Equal(t, ethCallDenyCrossOrg, err.Message, "deny body stays opaque (no detail leak)")
	assert.NotContains(t, err.Message, strings.TrimPrefix(addrB, "0x"))
}

// Knob ON, but the caller's group HAS a grant for addrB → allowed. Proves the
// grant set is resolved from real EffectivePermissions, and that the entry
// target addrA (no grant, injected as the already-authorized top-level `to`)
// does not false-deny.
func TestEthCallTracing_IntraOrgScoping_On_AllowsGrantedSameOrg(t *testing.T) {
	addrA := fixedAddr(0xaa)
	addrB := fixedAddr(0xbb)
	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: addrA,
		Calls: []traceFrame{{Type: "CALL", From: addrA, To: addrB}},
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)
	proc.SetIntraOrgGrantTracing(true)

	ctx := context.Background()
	did, orgID, groupID, _ := callerSameOrgWithGroup(t, ctx, ts, addrA)
	bContractID := addSameOrgContract(t, ctx, ts, orgID, addrB, "B-granted")
	require.NoError(t, ts.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: bContractID,
		GroupID:    groupID,
	}))

	err := proc.validateEthCallWithTracing(ctx, ethCallReq(did, addrA), addrA)
	require.Nil(t, err, "knob ON: granted same-org internal frame must be allowed")
}

// Knob ON must not weaken cross-org isolation: a foreign-org internal frame is
// still denied, classified as cross-org (not intra-org).
func TestEthCallTracing_IntraOrgScoping_On_StillDeniesCrossOrg(t *testing.T) {
	addrA := fixedAddr(0xaa)
	addrB := fixedAddr(0xbb)
	scripted := newScriptedTracer(t, traceFrame{
		Type: "CALL", From: fixedAddr(0xee), To: addrA,
		Calls: []traceFrame{{Type: "CALL", From: addrA, To: addrB}},
	})
	proc, ts := setupProcessorWithMockTracer(t, scripted)
	proc.SetIntraOrgGrantTracing(true)

	ctx := context.Background()
	did, _, _, _ := callerSameOrgWithGroup(t, ctx, ts, addrA)
	registerForeignOrgContract(t, ctx, ts, addrB) // different org

	err := proc.validateEthCallWithTracing(ctx, ethCallReq(did, addrA), addrA)
	require.NotNil(t, err, "knob ON must still deny cross-org frames")
	assert.Equal(t, ethCallDenyCrossOrg, err.Message)
}
