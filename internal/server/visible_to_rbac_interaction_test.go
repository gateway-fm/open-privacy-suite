package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests verify that visibleTo is additive on top of — never a substitute
// for — the existing RBAC gates that run BEFORE response filtering:
//
//   1. Method allowlist (AllowedMethods on the group's GroupAccess). visibleTo
//      cannot let a viewer call a method their group doesn't have.
//   2. Contract-grant / cross-org check (eth_getLogs targets a contract-address
//      filter, and CheckAccess denies when the address belongs to an org the
//      viewer isn't in). visibleTo cannot let a viewer query logs on a
//      cross-org contract.
//
// Plus a filter-level test that visibleTo for one tx does NOT leak logs from
// other (undisclosed) txs in the same response.
//
// Background: the demo script demo-verify-no-grant.sh in privacy-e2e-demo
// exercises the same properties end-to-end with Anvil. These are the Go
// integration equivalents so CI catches regressions without the full stack.

// -----------------------------------------------------------------------------
// 1. visibleTo must not widen the method allowlist.
// -----------------------------------------------------------------------------

func TestCheckAccess_VisibleTo_DoesNotBypassMethodAllowlist(t *testing.T) {
	ts := setupTestServerForRBAC(t)
	ctx := context.Background()

	orgID := uuid.New().String()
	groupID := uuid.New().String()
	viewerDID := "did:privado:no_tx_by_hash_" + uuid.New().String()[:8]
	viewerAddr := "0x" + strings.Repeat("a", 40)
	txHash := "0x" + strings.Repeat("c", 64)

	// Org with a group that allows eth_getLogs but NOT eth_getTransactionByHash.
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{
		ID: orgID, Slug: "methodlist-org-" + uuid.New().String()[:8], Name: "Allowlist Org",
	}))
	require.NoError(t, ts.db.CreateGroup(ctx, &rbac.Group{
		ID: groupID, OrgID: orgID, Slug: "restricted", Name: "Restricted",
	}))
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        groupID,
		Claims:         []rbac.Claim{},
		AllowedMethods: []string{"eth_getLogs"}, // deliberately missing eth_getTransactionByHash
	}))

	viewer := &rbac.User{ID: uuid.New().String(), ExternalID: viewerDID, KYC: true}
	require.NoError(t, ts.db.CreateUser(ctx, viewer))
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: viewer.ID, GroupID: groupID,
	}))
	require.NoError(t, ts.db.SystemLinkEthAddress(ctx, viewerDID, viewerAddr))

	// Record a visibleTo rule that would otherwise let the viewer see the tx.
	require.NoError(t, ts.db.SaveTxVisibility(ctx, txHash, []string{viewerDID}, "did:privado:sender", orgID))

	result, err := ts.rbacAccessCtrl.CheckAccess(ctx, &rbac.AccessCheckRequest{
		UserExternalID: viewerDID,
		OrgID:          orgID,
		Method:         rbac.MethodGetTransactionByHash,
		Params:         []any{txHash},
		RequiredClaims: []rbac.Claim{},
	})
	require.NoError(t, err)

	assert.False(t, result.Allowed,
		"visibleTo must NOT widen the method allowlist — eth_getTransactionByHash should be denied")
	assert.Contains(t, strings.ToLower(result.Reason), "method",
		"denial reason should reference the method-allowlist check; got: %s", result.Reason)
}

// -----------------------------------------------------------------------------
// 2. visibleTo must not bypass contract-address access (cross-org isolation).
// -----------------------------------------------------------------------------

func TestCheckAccess_VisibleTo_GetLogs_DoesNotBypassCrossOrgContract(t *testing.T) {
	ts := setupTestServerForRBAC(t)
	ctx := context.Background()

	orgA := uuid.New().String() // viewer's org
	orgB := uuid.New().String() // contract's org (different)
	groupID := uuid.New().String()
	viewerDID := "did:privado:cross_org_viewer_" + uuid.New().String()[:8]
	viewerAddr := "0x" + strings.Repeat("b", 40)
	contractAddr := "0x" + strings.Repeat("d", 40)
	txHash := "0x" + strings.Repeat("e", 64)

	// Two orgs.
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{
		ID: orgA, Slug: "viewer-org-" + uuid.New().String()[:8], Name: "Viewer Org",
	}))
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{
		ID: orgB, Slug: "contract-org-" + uuid.New().String()[:8], Name: "Contract Org",
	}))

	// Viewer is in org A, group allows eth_getLogs + read claim.
	require.NoError(t, ts.db.CreateGroup(ctx, &rbac.Group{
		ID: groupID, OrgID: orgA, Slug: "readers", Name: "Readers",
	}))
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        groupID,
		Claims:         []rbac.Claim{},
		AllowedMethods: []string{"eth_getLogs"},
	}))
	viewer := &rbac.User{ID: uuid.New().String(), ExternalID: viewerDID, KYC: true}
	require.NoError(t, ts.db.CreateUser(ctx, viewer))
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: viewer.ID, GroupID: groupID,
	}))
	require.NoError(t, ts.db.SystemLinkEthAddress(ctx, viewerDID, viewerAddr))

	// Contract registered to org B — viewer is NOT in org B.
	now := time.Now()
	require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{
		ID: uuid.New().String(), OrgID: orgB, Address: contractAddr,
		Name: "Cross-Org Token", DeployedAt: &now,
	}))

	// visibleTo rule: the viewer is listed for a tx on this cross-org contract.
	// Even so, CheckAccess must deny — visibleTo is a response-filter hint, not
	// an RBAC override.
	require.NoError(t, ts.db.SaveTxVisibility(ctx, txHash, []string{viewerDID}, "did:privado:sender", orgB))

	result, err := ts.rbacAccessCtrl.CheckAccess(ctx, &rbac.AccessCheckRequest{
		UserExternalID: viewerDID,
		Method:         rbac.MethodGetLogs,
		Params: []any{map[string]any{
			"address":   contractAddr,
			"fromBlock": "0x0",
			"toBlock":   "latest",
		}},
		TargetAddress:  contractAddr,
		RequiredClaims: nil,
	})
	require.NoError(t, err)

	assert.False(t, result.Allowed,
		"visibleTo must NOT grant access to logs on a cross-org contract")
	assert.True(t,
		strings.Contains(strings.ToLower(result.Reason), "contract") ||
			strings.Contains(strings.ToLower(result.Reason), "access"),
		"denial reason should reference the contract/access check; got: %s", result.Reason)
}

// -----------------------------------------------------------------------------
// 3. visibleTo on one tx must NOT leak logs from other txs in a getLogs response.
// -----------------------------------------------------------------------------
//
// Setup: three Transfer logs in the upstream response — from three different txs.
// The viewer has a visibleTo entry for exactly one (txA). None of the three txs
// have the viewer as the sender/recipient (ParamRule must_be=self fails on all).
// Expected: only the log from txA passes the filter.

func TestFilterLogsWithEventRules_VisibleTo_DoesNotLeakOtherTxs(t *testing.T) {
	const transferTopic0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	contractAddr := "0x" + strings.Repeat("c", 40)
	viewerDID := "did:privado:leak_test_viewer"
	viewerAddr := "0x" + strings.Repeat("1", 40) // linked, but never a participant below

	// senderTopic for each tx is a different "from" address (none = viewer).
	senderA := "0x" + strings.Repeat("a", 40)
	senderB := "0x" + strings.Repeat("b", 40)
	senderC := "0x" + strings.Repeat("d", 40)
	senderTopic := func(addr string) string { return "0x000000000000000000000000" + addr[2:] }

	txA := "0x" + strings.Repeat("1", 64)
	txB := "0x" + strings.Repeat("2", 64)
	txC := "0x" + strings.Repeat("3", 64)

	logsJSON, err := json.Marshal([]map[string]any{
		{
			"address":         contractAddr,
			"topics":          []string{transferTopic0, senderTopic(senderA)},
			"data":            "0x",
			"transactionHash": txA,
			"logIndex":        "0x0",
		},
		{
			"address":         contractAddr,
			"topics":          []string{transferTopic0, senderTopic(senderB)},
			"data":            "0x",
			"transactionHash": txB,
			"logIndex":        "0x0",
		},
		{
			"address":         contractAddr,
			"topics":          []string{transferTopic0, senderTopic(senderC)},
			"data":            "0x",
			"transactionHash": txC,
			"logIndex":        "0x0",
		},
	})
	require.NoError(t, err)
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "result": json.RawMessage(logsJSON),
	})
	require.NoError(t, err)

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{
						Topic0: transferTopic0, Name: "Transfer",
						ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}},
					},
				}},
			},
		},
	}

	// Viewer is on visibleTo list for txA only.
	visCtx := &rbac.TxVisibilityContext{
		ViewerDID: viewerDID,
		TxVisibility: map[string][]string{
			strings.ToLower(txA): {viewerDID},
			// txB and txC are absent — the viewer has no disclosure for them.
		},
	}

	filtered := FilterLogsWithEventRules(rbac.ReadProfileStandard, body, []string{viewerAddr}, perms, nil, visCtx, nil)

	var resp struct {
		Result []map[string]any `json:"result"`
	}
	require.NoError(t, json.Unmarshal(filtered, &resp),
		"filtered body should be valid JSON: %s", string(filtered))

	require.Len(t, resp.Result, 1,
		"exactly one log should survive — the one for txA. got: %s", string(filtered))

	got := strings.ToLower(fmt.Sprintf("%v", resp.Result[0]["transactionHash"]))
	assert.Equal(t, strings.ToLower(txA), got,
		"surviving log must be txA; visibleTo must NOT leak txB or txC")
}
