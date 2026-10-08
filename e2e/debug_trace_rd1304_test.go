//go:build mockauth

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1304 checks the supported call-tree format and scoped access through a
// real proxy server and Anvil. The fixture includes ordinary storage slots
// so the storage-read and trace response contracts can be checked together.
const rd1304StorageBytecode = "0x6080604052602a5f55625ec2e76001553480156019575f5ffd5b5061031e806100275f395ff3fe608060405234801561000f575f5ffd5b506004361061004a575f3560e01c80630dbe671f1461004e57806360fe47b11461006c5780636d4ce63c14610088578063acefafae146100a6575b5f5ffd5b6100566100d6565b6040516100639190610191565b60405180910390f35b610086600480360381019061008191906101d8565b6100db565b005b610090610132565b60405161009d9190610191565b60405180910390f35b6100c060048036038101906100bb919061025d565b610159565b6040516100cd9190610191565b60405180910390f35b5f5481565b805f819055503373ffffffffffffffffffffffffffffffffffffffff167fbdd4be579984a3856cd1022b131de0a9912cd0f746e727f0d0a56ef44cab8cc2826040516101279190610191565b60405180910390a250565b5f5f60015411610142575f610145565b60015b60ff165f5461015491906102b5565b905090565b5f8173ffffffffffffffffffffffffffffffffffffffff16319050919050565b5f819050919050565b61018b81610179565b82525050565b5f6020820190506101a45f830184610182565b92915050565b5f5ffd5b6101b781610179565b81146101c1575f5ffd5b50565b5f813590506101d2816101ae565b92915050565b5f602082840312156101ed576101ec6101aa565b5b5f6101fa848285016101c4565b91505092915050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f61022c82610203565b9050919050565b61023c81610222565b8114610246575f5ffd5b50565b5f8135905061025781610233565b92915050565b5f60208284031215610272576102716101aa565b5b5f61027f84828501610249565b91505092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6102bf82610179565b91506102ca83610179565b92508282019050808211156102e2576102e1610288565b5b9291505056fea26469706673582212209ef3e4f11a664a869fdb4ce3cf25e9c8a27aa06abd41c8746c2d2392966ded0064736f6c634300081c0033"

const (
	rd1304StorageMarker = "5ec2e7" // slot-1 value, as it appears in any storage dump
	rd1304GetSel        = "0x6d4ce63c"
	rd1304SetCall       = "0x60fe47b10000000000000000000000000000000000000000000000000000000000000005"
)

// addUserToOrg adds a second user (own group, given claims/methods, linked
// address) to an existing org, so a same-org non-participant can be modelled.
func addUserToOrg(t *testing.T, database *db.DB, orgID, groupSlug, userDID string, claims []rbac.Claim, methods []string, ethAddress string) {
	t.Helper()
	ctx := context.Background()
	groupID := uuid.New().String()
	require.NoError(t, database.CreateGroup(ctx, &rbac.Group{ID: groupID, OrgID: orgID, Slug: groupSlug, Name: groupSlug, Depth: 0, Path: groupSlug}))
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{ID: uuid.New().String(), GroupID: groupID, AllowedMethods: methods, Claims: claims}))
	user := &rbac.User{ID: uuid.New().String(), ExternalID: userDID, KYC: true, Metadata: map[string]any{}}
	require.NoError(t, database.CreateUser(ctx, user))
	require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.New().String(), UserID: user.ID, GroupID: groupID, Source: rbac.MembershipSourceAdmin}))
	if ethAddress != "" {
		require.NoError(t, database.SystemLinkEthAddress(ctx, userDID, ethAddress))
	}
}

// deployStorage deploys S through the proxy as the given user and returns its
// address. Deploying through the proxy registers S to the user's org and
// auto-grants the deployer (without the admin claim).
func deployStorage(t *testing.T, serverURL, orgID, token string) string {
	t.Helper()
	resp := jsonRPCCall(t, serverURL, orgID, token, "eth_sendTransaction", []any{map[string]any{
		"from": anvilAccount0, "data": rd1304StorageBytecode, "gas": "0x200000",
	}})
	require.Nil(t, resp["error"], "deploy failed: %v", resp["error"])
	txHash, _ := resp["result"].(string)
	receipt := waitForReceipt(t, serverURL, orgID, token, txHash)
	require.Equal(t, "0x1", receipt["status"])
	addr, _ := receipt["contractAddress"].(string)
	require.NotEmpty(t, addr)
	return strings.ToLower(addr)
}

var rd1304Methods = []string{
	"debug_traceCall", "debug_traceTransaction", "eth_call", "eth_sendTransaction",
	"eth_getTransactionReceipt", "eth_getTransactionByHash", "eth_getStorageAt",
	"eth_blockNumber", "eth_chainId", "eth_estimateGas", "eth_getTransactionCount",
}

// Only the supported callTracer format is accepted for a granted target.
// The response must omit storage-tracer fields.
func TestRD1304_E2E_UnsupportedPrestateTracerDenied(t *testing.T) {
	env := setupCreate2Env(t)
	defer env.cleanup()

	did := "did:test:rd1304_prestate"
	orgID := createOrgWithUser(t, env.srv.DB(), "rd1304-p", "rd1304-p-grp", did,
		[]rbac.Claim{rbac.ClaimDeploy}, rd1304Methods, anvilAccount0)
	token := getJWTTokenForCreate2(t, env.serverURL, did)
	s := deployStorage(t, env.serverURL, orgID, token)

	// Control: the slot tier denies this non-admin the ordinary slot.
	st, _ := jsonRPCCallRaw(t, env.serverURL, orgID, token, "eth_getStorageAt", []any{s, "0x1", "latest"})
	require.GreaterOrEqual(t, st, 400, "control: the RD-805 tier must deny slot 1 to a non-admin")

	call := map[string]any{"from": anvilAccount0, "to": s, "data": rd1304GetSel}
	status, body := traceRPCCallRaw(t, env.serverURL, orgID, token, "debug_traceCall",
		[]any{call, "latest", map[string]any{"tracer": "prestateTracer"}})
	assert.GreaterOrEqual(t, status, 400, "prestateTracer must be denied; body=%s", string(body))
	assert.NotContains(t, strings.ToLower(string(body)), rd1304StorageMarker, "the slot-1 storage value must be absent via prestateTracer")

	status, body = traceRPCCallRaw(t, env.serverURL, orgID, token, "debug_traceTransaction",
		[]any{"0x" + strings.Repeat("00", 32)})
	_ = status // a replay of a non-existent tx is denied; asserted in unit tests
	assert.NotContains(t, strings.ToLower(string(body)), rd1304StorageMarker)

	status, body = traceRPCCallRaw(t, env.serverURL, orgID, token, "debug_traceCall",
		[]any{call, "latest", map[string]any{"tracer": "callTracer"}})
	require.Equal(t, http.StatusOK, status, "plain callTracer to a granted contract is allowed; body=%s", string(body))
	var out struct {
		Result map[string]any `json:"result"`
		Error  any            `json:"error"`
	}
	require.NoError(t, json.Unmarshal(body, &out))
	require.Nil(t, out.Error, "callTracer returned an error: %v", out.Error)
	assert.Equal(t, s, strings.ToLower(out.Result["to"].(string)))
	assert.NotContains(t, strings.ToLower(string(body)), rd1304StorageMarker, "callTracer must carry no storage")
}

// A participant replay without a tracer preset returns the call tree only.
func TestRD1304_E2E_DefaultStructLoggerServesCallTreeOnly(t *testing.T) {
	env := setupCreate2Env(t)
	defer env.cleanup()

	did := "did:test:rd1304_struct"
	orgID := createOrgWithUser(t, env.srv.DB(), "rd1304-s", "rd1304-s-grp", did,
		[]rbac.Claim{rbac.ClaimDeploy}, rd1304Methods, anvilAccount0)
	token := getJWTTokenForCreate2(t, env.serverURL, did)
	s := deployStorage(t, env.serverURL, orgID, token)

	resp := jsonRPCCall(t, env.serverURL, orgID, token, "eth_sendTransaction", []any{map[string]any{
		"from": anvilAccount0, "to": s, "data": rd1304SetCall, "gas": "0x100000",
	}})
	require.Nil(t, resp["error"], "set() failed: %v", resp["error"])
	txHash, _ := resp["result"].(string)
	waitForReceipt(t, env.serverURL, orgID, token, txHash)

	// Explicit struct-logger options are refused.
	status, body := traceRPCCallRaw(t, env.serverURL, orgID, token, "debug_traceTransaction",
		[]any{txHash, map[string]any{"enableMemory": true}})
	assert.GreaterOrEqual(t, status, 400, "struct-logger options must be refused; body=%s", string(body))

	// No config: the participant gets the call tree, not struct logs.
	status, body = traceRPCCallRaw(t, env.serverURL, orgID, token, "debug_traceTransaction", []any{txHash})
	require.Equal(t, http.StatusOK, status, "the sender may trace their own tx; body=%s", string(body))
	assert.NotContains(t, string(body), "structLogs")
	assert.NotContains(t, strings.ToLower(string(body)), rd1304StorageMarker)
	assert.Contains(t, strings.ToLower(string(body)), s)
}

// A same-org non-participant must not replay another user's transaction; the
// sender can.
func TestRD1304_E2E_NonParticipantTraceTransactionDenied(t *testing.T) {
	env := setupCreate2Env(t)
	defer env.cleanup()

	ownerDID := "did:test:rd1304_owner"
	orgID := createOrgWithUser(t, env.srv.DB(), "rd1304-n", "rd1304-n-grp", ownerDID,
		[]rbac.Claim{rbac.ClaimDeploy}, rd1304Methods, anvilAccount0)
	ownerToken := getJWTTokenForCreate2(t, env.serverURL, ownerDID)
	s := deployStorage(t, env.serverURL, orgID, ownerToken)

	resp := jsonRPCCall(t, env.serverURL, orgID, ownerToken, "eth_sendTransaction", []any{map[string]any{
		"from": anvilAccount0, "to": s, "data": rd1304SetCall, "gas": "0x100000",
	}})
	require.Nil(t, resp["error"], "set() failed: %v", resp["error"])
	txHash, _ := resp["result"].(string)
	waitForReceipt(t, env.serverURL, orgID, ownerToken, txHash)

	otherDID := "did:test:rd1304_other"
	addUserToOrg(t, env.srv.DB(), orgID, "rd1304-n-other", otherDID, nil, rd1304Methods, anvilAccount1)
	otherToken := getJWTTokenForCreate2(t, env.serverURL, otherDID)

	status, body := traceRPCCallRaw(t, env.serverURL, orgID, otherToken, "debug_traceTransaction",
		[]any{txHash, map[string]any{"tracer": "callTracer"}})
	assert.GreaterOrEqual(t, status, 400, "a same-org non-participant must not replay the tx; body=%s", string(body))
	assert.NotContains(t, strings.ToLower(string(body)), strings.ToLower(anvilAccount0), "the sender must not be revealed")

	status, body = traceRPCCallRaw(t, env.serverURL, orgID, ownerToken, "debug_traceTransaction",
		[]any{txHash, map[string]any{"tracer": "callTracer"}})
	assert.Equal(t, http.StatusOK, status, "the sender may replay their own tx; body=%s", string(body))
}

// Facade whose peek(s) STATICCALLs s.get() and returns the result:
//
//	interface IS { function get() external view returns (uint256); }
//	contract F { function peek(address s) external view returns (uint256) { return IS(s).get(); } }
const rd1304FacadeBytecode = "0x6080604052348015600e575f5ffd5b506102178061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610029575f3560e01c8063acefafae1461002d575b5f5ffd5b61004760048036038101906100429190610130565b61005d565b6040516100549190610173565b60405180910390f35b5f8173ffffffffffffffffffffffffffffffffffffffff16636d4ce63c6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156100a7573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906100cb91906101b6565b9050919050565b5f5ffd5b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6100ff826100d6565b9050919050565b61010f816100f5565b8114610119575f5ffd5b50565b5f8135905061012a81610106565b92915050565b5f60208284031215610145576101446100d2565b5b5f6101528482850161011c565b91505092915050565b5f819050919050565b61016d8161015b565b82525050565b5f6020820190506101865f830184610164565b92915050565b6101958161015b565b811461019f575f5ffd5b50565b5f815190506101b08161018c565b92915050565b5f602082840312156101cb576101ca6100d2565b5b5f6101d8848285016101a2565b9150509291505056fea2646970667358221220b1a124fd2e0f5e7f6a3a71def3d075052ec7389b7249522369419ef1e76c95d264736f6c634300081c0033"

const rd1304PeekSel = "0xacefafae"

func rd1304PeekCall(target string) string {
	return rd1304PeekSel + strings.Repeat("0", 24) + strings.TrimPrefix(strings.ToLower(target), "0x")
}

// deployFrom deploys bytecode through the proxy from the given linked EOA.
func deployFrom(t *testing.T, serverURL, orgID, token, from, bytecode string) string {
	t.Helper()
	resp := jsonRPCCall(t, serverURL, orgID, token, "eth_sendTransaction", []any{map[string]any{
		"from": from, "data": bytecode, "gas": "0x200000",
	}})
	require.Nil(t, resp["error"], "deploy failed: %v", resp["error"])
	txHash, _ := resp["result"].(string)
	receipt := waitForReceipt(t, serverURL, orgID, token, txHash)
	require.Equal(t, "0x1", receipt["status"])
	addr, _ := receipt["contractAddress"].(string)
	require.NotEmpty(t, addr)
	return strings.ToLower(addr)
}

// A same-org facade that internally STATICCALLs a FOREIGN-org contract: the
// entry target is the caller's own, so only the internal-frame check catches
// it. Denied on the trace path (and on eth_call, the read twin). Positive
// control: the same facade path with a same-org inner frame is served.
func TestRD1304_E2E_CrossOrgInternalFrameDenied(t *testing.T) {
	env := setupCreate2EnvWithReadTracing(t, true)
	defer env.cleanup()

	ownerDID := "did:test:rd1304_xorg_owner"
	orgA := createOrgWithUser(t, env.srv.DB(), "rd1304-xa", "rd1304-xa-grp", ownerDID,
		[]rbac.Claim{rbac.ClaimDeploy}, rd1304Methods, anvilAccount0)
	ownerToken := getJWTTokenForCreate2(t, env.serverURL, ownerDID)
	foreign := deployFrom(t, env.serverURL, orgA, ownerToken, anvilAccount0, rd1304StorageBytecode)

	tracerDID := "did:test:rd1304_xorg_tracer"
	orgB := createOrgWithUser(t, env.srv.DB(), "rd1304-xb", "rd1304-xb-grp", tracerDID,
		[]rbac.Claim{rbac.ClaimDeploy}, rd1304Methods, anvilAccount1)
	tracerToken := getJWTTokenForCreate2(t, env.serverURL, tracerDID)
	facade := deployFrom(t, env.serverURL, orgB, tracerToken, anvilAccount1, rd1304FacadeBytecode)

	call := map[string]any{"from": anvilAccount1, "to": facade, "data": rd1304PeekCall(foreign)}
	status, body := traceRPCCallRaw(t, env.serverURL, orgB, tracerToken, "debug_traceCall",
		[]any{call, "latest", map[string]any{"tracer": "callTracer"}})
	require.GreaterOrEqual(t, status, 400, "a cross-org internal frame must be denied; body=%s", string(body))
	assert.NotContains(t, strings.ToLower(string(body)), strings.TrimPrefix(foreign, "0x"), "the foreign address must not be echoed")
	assert.NotContains(t, strings.ToLower(string(body)), rd1304StorageMarker)

	// The read twin agrees.
	status, body = jsonRPCCallRaw(t, env.serverURL, orgB, tracerToken, "eth_call", []any{call, "latest"})
	assert.GreaterOrEqual(t, status, 400, "eth_call through the facade must be denied too; body=%s", string(body))

	// Positive control: the facade's internal frame into its own address
	// (same org, the authorized target) is served — so the denial above is the
	// cross-org frame, not the facade path.
	self := map[string]any{"from": anvilAccount1, "to": facade, "data": rd1304PeekCall(facade)}
	status, body = traceRPCCallRaw(t, env.serverURL, orgB, tracerToken, "debug_traceCall",
		[]any{self, "latest", map[string]any{"tracer": "callTracer"}})
	require.Equal(t, http.StatusOK, status, "a same-org internal frame is served; body=%s", string(body))
	assert.Contains(t, strings.ToLower(string(body)), "staticcall")
}
