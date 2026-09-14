package server

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"os"
	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/tracer"
	"testing"
	"time"
)

// The Python harness provides a real isolated Reth and its signed fixture transactions.
// DB, access controller, trace validator, preflight, signature and forwarding are real.
// Authenticated DID/session establishment is a fixture; no identity provider is contacted.
func TestNodeApprovalsRealReth(t *testing.T) {
	url := os.Getenv("OPS_TEST_RETH_URL")
	if url == "" {
		t.Skip("run poc/reth-signed-approvals/run.py")
	}
	ts := setupTestServerForRBAC(t)
	ctx := context.Background()
	router := "0x0000000000000000000000000000000000001100"
	relay := "0x0000000000000000000000000000000000001200"
	vaultA := "0x0000000000000000000000000000000000001300"
	vaultB := "0x0000000000000000000000000000000000002300"
	did, org, groupID, contractID := callerSameOrgWithGroup(t, ctx, ts, router)
	require.NoError(t, ts.db.CreateContractGrant(ctx, &rbac.ContractGrant{ID: uuid.New().String(), ContractID: contractID, GroupID: groupID}))
	for _, addr := range []string{relay, vaultA} {
		require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{ID: uuid.New().String(), OrgID: org, Address: addr, Name: addr}))
	}
	registerForeignOrgContract(t, ctx, ts, vaultB)
	_, err := ts.db.Conn().ExecContext(ctx, "UPDATE group_access SET allowed_methods=ARRAY['eth_sendTransaction'] WHERE group_id IN (SELECT id FROM groups WHERE org_id=$1)", org)
	require.NoError(t, err)
	outsider := createOrgGroupUserMembership(t, ctx, ts.db, []rbac.Claim{}, "eth_sendTransaction")
	_, err = ts.db.Conn().ExecContext(ctx, "UPDATE users SET kyc=true")
	require.NoError(t, err)
	rt := tracer.NewRuntimeTracer(tracer.RuntimeTracerConfig{NodeURL: url, Enabled: true, Timeout: 5 * time.Second})
	t.Cleanup(rt.Stop)
	tv := rbac.NewTraceValidator(ts.db)
	tv.SetCodeHashFetcher(rt)
	p := NewJSONRPCProcessorWithTracing(ts.rbacAccessCtrl, &noopRateLimiter{}, proxy.New(url), ts.db, rt, tv, NewCircuitBreaker(), NewConcurrencyLimiter(50, 0), "")
	p.nodeApprovals, err = nodeapproval.New(url, os.Getenv("OPS_TEST_APPROVAL_TARGET"), bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	t.Cleanup(p.nodeApprovals.Close)
	data, err := os.ReadFile(os.Getenv("OPS_TEST_TX_FILE"))
	require.NoError(t, err)
	var inputs map[string]string
	require.NoError(t, json.Unmarshal(data, &inputs))
	submit := func(raw, principal string) *ProcessResult {
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": []any{raw}})
		return p.processRawTransaction(ctx, &ProcessRequest{UserID: principal, Method: "eth_sendRawTransaction", Params: []any{raw}, Body: body, ClientIP: "127.0.0.1"})
	}
	t.Run("foreign_contract_denied", func(t *testing.T) { r := submit(inputs["foreign"], did); require.NotNil(t, r.Error) })
	t.Run("same_signer_different_DID_denied", func(t *testing.T) { r := submit(inputs["allow"], outsider); require.NotNil(t, r.Error) })
	t.Run("nested_foreign_contract_denied_by_DB_trace_validator", func(t *testing.T) {
		r := submit(inputs["nested_foreign"], did)
		require.NotNil(t, r.Error)
		require.Equal(t, ReasonCrossOrg, r.Error.Reason)
	})
	t.Run("same_org_signed_and_forwarded", func(t *testing.T) { r := submit(inputs["allow"], did); require.Nil(t, r.Error, "%+v", r.Error) })
}
