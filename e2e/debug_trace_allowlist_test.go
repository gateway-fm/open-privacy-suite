//go:build mockauth

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"privacy-proxy/internal/rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rpcErrorString extracts the proxy's HTTP-level error string from a JSON body.
// RBAC denials are returned as {"error": "<message>"} with the matching HTTP
// status (not a nested JSON-RPC {code,message} object), so callers assert on
// the top-level string.
func rpcErrorString(t *testing.T, body []byte) string {
	t.Helper()
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed), "response: %s", string(body))
	if e, ok := parsed["error"].(string); ok {
		return e
	}
	return ""
}

// traceRPCCallRaw keeps successive requests outside the trace rate window.
// Setup and ordinary RPC requests use the same per-user counter.
func traceRPCCallRaw(t *testing.T, serverURL, orgID, token, method string, params []any) (int, []byte) {
	t.Helper()
	time.Sleep(time.Second + 10*time.Millisecond)
	return jsonRPCCallRaw(t, serverURL, orgID, token, method, params)
}

// RD-1121: debug_trace* must be gated by the group method allowlist exactly
// like every other named RPC method. Historically processDebugTrace checked
// ONLY the deploy/admin claim and skipped the allowlist, so an operator who
// curated allowed_methods to exclude tracing was silently ignored for any
// group that had the deploy claim.
//
// These tests drive the full HTTP stack (real proxy server + real Anvil trace,
// via the shared create2 env) so the allowlist gate, the opaque-denial wire
// shape, and the cross-org ValidateTrace content gate are all exercised on the
// real Process path — not a unit stub.

// traceCallParams builds a debug_traceCall param tuple targeting addr.
func traceCallParams(from, to string) []any {
	return []any{
		map[string]any{
			"from": from,
			"to":   to,
			"data": "0x",
		},
		"latest",
	}
}

// TestDebugTrace_DeployClaimButMethodNotAllowlisted_Denied is the core RD-1121
// regression at the HTTP layer: a group WITH the deploy claim but WITHOUT
// debug_traceCall in allowed_methods must be denied. Pre-fix the deploy claim
// alone granted tracing.
func TestDebugTrace_DeployClaimButMethodNotAllowlisted_Denied(t *testing.T) {
	env := setupCreate2Env(t)
	defer env.cleanup()

	// did:test: prefix so the mockauth dev-admin auto-grant is skipped — the
	// user's ONLY membership is the group we configure (deploy claim, trace NOT
	// allowlisted). Otherwise mock login adds an org-admin "*" group that would
	// itself allowlist trace.
	userDID := "did:test:rd1121_deploy_no_trace"

	// Deploy claim, but the allowlist deliberately OMITS debug_traceCall.
	createOrgWithUser(t, env.srv.DB(), "rd1121-a", "rd1121-a-grp", userDID,
		[]rbac.Claim{rbac.ClaimDeploy},
		[]string{"eth_call", "eth_blockNumber", "eth_chainId"},
		anvilAccount0,
	)

	token := getJWTTokenForCreate2(t, env.serverURL, userDID)

	// did:test: users skip the dev-admin auto-grant, so they belong to exactly
	// one org and the bare "/" endpoint (empty orgID) resolves unambiguously.
	status, body := jsonRPCCallRaw(t, env.serverURL, "", token, "debug_traceCall",
		traceCallParams(anvilAccount0, anvilAccount1))

	// Denied: the deploy claim does NOT bypass the method allowlist anymore.
	// Opaque "method not found" / 404 deny (uniform with every other RBAC denial).
	assert.Equal(t, http.StatusNotFound, status, "body: %s", string(body))
	assert.Equal(t, "method not found", rpcErrorString(t, body))
}

// TestDebugTrace_AllowlistedWithoutDeployClaim_Reaches traces a granted
// contract on Anvil and asserts a successful callTracer result.
func TestDebugTrace_AllowlistedWithoutDeployClaim_Reaches(t *testing.T) {
	env := setupCreate2Env(t)
	defer env.cleanup()

	// did:test: prefix — skip the dev-admin auto-grant so this user's only
	// grant is the group we configure (trace allowlisted, no deploy claim).
	userDID := "did:test:rd1121_trace_no_deploy"

	// No operational claims, but debug_traceCall IS allowlisted.
	orgID := createOrgWithUser(t, env.srv.DB(), "rd1121-b", "rd1121-b-grp", userDID,
		[]rbac.Claim{},
		[]string{"debug_traceCall", "eth_call", "eth_blockNumber", "eth_chainId"},
		anvilAccount0,
	)
	// A same-org contract granted to the caller's (only) group.
	granted := "0xc0ffee00000000000000000000000000000000b1"
	registerContract(t, env.srv.DB(), orgID, granted, "GrantedTarget")

	token := getJWTTokenForCreate2(t, env.serverURL, userDID)

	status, body := jsonRPCCallRaw(t, env.serverURL, "", token, "debug_traceCall",
		traceCallParams(anvilAccount0, granted))

	// Passed the allowlist gate AND the access gate: the trace ran and returned.
	require.Equal(t, http.StatusOK, status,
		"allowlisted trace of a granted contract must succeed without the deploy claim; body: %s", string(body))
	var out struct {
		Result map[string]any `json:"result"`
	}
	require.NoError(t, json.Unmarshal(body, &out))
	assert.NotEmpty(t, out.Result, "the trace must return a call frame; body: %s", string(body))
}

// TestDebugTrace_CrossOrgTargetDenied checks the organization boundary
// and includes a successful trace in the caller's organization.
func TestDebugTrace_CrossOrgTargetDenied(t *testing.T) {
	env := setupCreate2Env(t)
	defer env.cleanup()

	// did:test: prefix — skip the dev-admin auto-grant so the tracer's grants are
	// exactly the org-b group we configure (otherwise the org-admin "*" group
	// would resolve a different org and defeat the cross-org isolation we test).
	tracerDID := "did:test:rd1121_xorg_tracer" // org-b, allowlists trace

	// org-a owns a contract. We register it directly to org-a (no deploy needed;
	// the cross-org denial keys off DB ownership of the traced address). Use a
	// stable, lowercased address.
	orgAID := createOrgWithUser(t, env.srv.DB(), "rd1121-xa", "rd1121-xa-grp",
		"did:test:rd1121_xorg_owner",
		[]rbac.Claim{rbac.ClaimDeploy},
		[]string{"eth_call", "eth_blockNumber", "eth_chainId"},
		"",
	)
	orgAContract := "0xc0ffee0000000000000000000000000000000001"
	registerContract(t, env.srv.DB(), orgAID, orgAContract, "OrgAContract")

	// org-b: trace is allowlisted, but org-b does NOT own org-a's contract.
	orgBID := createOrgWithUser(t, env.srv.DB(), "rd1121-xb", "rd1121-xb-grp", tracerDID,
		[]rbac.Claim{},
		[]string{"debug_traceCall", "eth_call", "eth_blockNumber", "eth_chainId"},
		anvilAccount1,
	)
	// A contract in org-b's OWN org, granted to the tracer (positive control).
	orgBContract := "0xc0ffee00000000000000000000000000000000b2"
	registerContract(t, env.srv.DB(), orgBID, orgBContract, "OrgBContract")

	tracerToken := getJWTTokenForCreate2(t, env.serverURL, tracerDID)

	// org-b tries to debug_traceCall INTO org-a's registered contract: denied,
	// and no trace data comes back.
	status, body := traceRPCCallRaw(t, env.serverURL, "", tracerToken, "debug_traceCall",
		traceCallParams(anvilAccount1, orgAContract))
	require.GreaterOrEqual(t, status, 400, "cross-org trace must be denied; body: %s", string(body))
	assert.NotContains(t, string(body), `"result"`, "a denied cross-org trace must return no trace; body: %s", string(body))

	// Positive control: the same user, same allowlist, traces its OWN org's
	// contract successfully — so the denial above is target-specific (cross-
	// org), not a blanket allowlist deny.
	status, body = traceRPCCallRaw(t, env.serverURL, "", tracerToken, "debug_traceCall",
		traceCallParams(anvilAccount1, orgBContract))
	require.Equal(t, http.StatusOK, status,
		"the same user must be able to trace its own org's contract; body: %s", string(body))
}
