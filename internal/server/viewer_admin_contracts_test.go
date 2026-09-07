package server

import (
	"context"
	"encoding/json"
	"testing"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestViewerAdminContracts covers the ORG-SCOPED admin resolver used by
// response filters. This is the bridge between "holding ClaimAdmin" and
// "filter applies admin bypass" — the filter-mechanics tests
// (Test*FilterEventLogs*AdminBypass*) test the consumption side; these
// tests cover the claim-origin side.
//
// The core invariant under test: `isAdminByContract[addr] == true` MUST
// be derived from the viewer's claims in THE CONTRACT'S OWNING ORG
// ONLY, never merged across other orgs the viewer happens to belong
// to. This is the belt-and-braces check on top of migration 035's
// schema-level unique-address constraint.
func TestViewerAdminContracts(t *testing.T) {
	ctx := context.Background()
	ts := setupTestServerForRBAC(t)
	proc := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:     ts.rbacAccessCtrl,
		RateLimiter:        &noopRateLimiter{},
		AccessLogger:       ts.db,
		CircuitBreaker:     middleware.NewCircuitBreaker(),
		ConcurrencyLimiter: middleware.NewConcurrencyLimiter(50, 0),
	})

	// --- Fixture ---
	// Org A: Alice is org admin (is_org_admin=true on her group).
	//        Contract A1 is owned by org A.
	// Org B: Alice is a member but holds no admin claim (group has
	//        no operational claims). Contract B1 is owned by org B.
	// Org C: Alice is NOT a member. Bob is admin there. Contract C1 owned by org C.
	orgAID := uuid.New().String()
	orgBID := uuid.New().String()
	orgCID := uuid.New().String()
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{ID: orgAID, Slug: "vac-a-" + orgAID[:8], Name: "VAC A", Settings: map[string]any{}}))
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{ID: orgBID, Slug: "vac-b-" + orgBID[:8], Name: "VAC B", Settings: map[string]any{}}))
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{ID: orgCID, Slug: "vac-c-" + orgCID[:8], Name: "VAC C", Settings: map[string]any{}}))

	// Note: the viewerAdminContracts API takes the internal user UUID
	// (matching result.UserID in the JSON-RPC processor's access check
	// result), not the external DID.
	aliceUser := &rbac.User{ID: uuid.New().String(), ExternalID: "did:test:alice-" + uuid.New().String()[:8]}
	aliceUUID := aliceUser.ID
	require.NoError(t, ts.db.CreateUser(ctx, aliceUser))
	bobUser := &rbac.User{ID: uuid.New().String(), ExternalID: "did:test:bob-" + uuid.New().String()[:8]}
	require.NoError(t, ts.db.CreateUser(ctx, bobUser))

	// Org A: Alice is org admin (via group with is_org_admin=true).
	orgAAdminGroup := mustCreateGroup(t, ts.db, orgAID, "vac-a-admins", nil, true)
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: aliceUser.ID, GroupID: orgAAdminGroup,
	}))

	// Org B: Alice is a regular reader (no admin).
	orgBReaderGroup := mustCreateGroup(t, ts.db, orgBID, "vac-b-readers", nil, false)
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: aliceUser.ID, GroupID: orgBReaderGroup,
	}))

	// Org C: Bob is org admin. Alice is NOT a member.
	orgCAdminGroup := mustCreateGroup(t, ts.db, orgCID, "vac-c-admins", nil, true)
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: bobUser.ID, GroupID: orgCAdminGroup,
	}))

	// Register contracts in each org.
	contractA1 := "0x1111111111111111111111111111111111111111"
	contractB1 := "0x2222222222222222222222222222222222222222"
	contractC1 := "0x3333333333333333333333333333333333333333"
	require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{
		ID: uuid.New().String(), OrgID: orgAID, Address: contractA1, Name: "A1",
	}))
	require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{
		ID: uuid.New().String(), OrgID: orgBID, Address: contractB1, Name: "B1",
	}))
	require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{
		ID: uuid.New().String(), OrgID: orgCID, Address: contractC1, Name: "C1",
	}))

	unregistered := "0x9999999999999999999999999999999999999999"

	t.Run("org admin on owning org → map[addr]=true", func(t *testing.T) {
		got := proc.viewerAdminContracts(ctx, aliceUUID, []string{contractA1})
		require.True(t, got[contractA1], "org admin in contract's owning org must resolve to admin=true")
	})

	t.Run("member of owning org but no admin claim → absent", func(t *testing.T) {
		got := proc.viewerAdminContracts(ctx, aliceUUID, []string{contractB1})
		require.False(t, got[contractB1], "read-only member of owning org must NOT be admin")
	})

	t.Run("not a member of owning org → absent", func(t *testing.T) {
		// Alice is not in org C. Bob is admin there. Alice must not inherit
		// Bob's admin status just because the contract exists.
		got := proc.viewerAdminContracts(ctx, aliceUUID, []string{contractC1})
		require.False(t, got[contractC1], "non-member of owning org must never be admin on that org's contracts")
	})

	t.Run("unregistered contract → absent (spec: unregistered is denied)", func(t *testing.T) {
		got := proc.viewerAdminContracts(ctx, aliceUUID, []string{unregistered})
		require.False(t, got[unregistered], "unregistered address cannot resolve to admin")
	})

	t.Run("mixed input resolves per-address correctly", func(t *testing.T) {
		got := proc.viewerAdminContracts(ctx, aliceUUID, []string{
			contractA1,   // Alice is admin in A → true
			contractB1,   // Alice is reader in B → false
			contractC1,   // Alice is not in C → false
			unregistered, // unregistered → false
		})
		require.True(t, got[contractA1])
		require.False(t, got[contractB1])
		require.False(t, got[contractC1])
		require.False(t, got[unregistered])
	})

	t.Run("empty input returns empty map", func(t *testing.T) {
		got := proc.viewerAdminContracts(ctx, aliceUUID, nil)
		require.Empty(t, got)
	})

	t.Run("empty userID returns empty map (fail-closed)", func(t *testing.T) {
		got := proc.viewerAdminContracts(ctx, "", []string{contractA1})
		require.Empty(t, got)
	})

	t.Run("uppercase input is normalised to lowercase key", func(t *testing.T) {
		got := proc.viewerAdminContracts(ctx, aliceUUID, []string{
			"0x1111111111111111111111111111111111111111",
		})
		require.True(t, got[contractA1])
	})

	t.Run("duplicate addresses de-duped without inflating", func(t *testing.T) {
		got := proc.viewerAdminContracts(ctx, aliceUUID, []string{
			contractA1, contractA1, contractA1,
		})
		require.Len(t, got, 1)
		require.True(t, got[contractA1])
	})

	// Tier-3 per-contract admin path: user has ClaimAdmin on a specific
	// contract via contract_grant, but is_org_admin=false. This is the
	// other way HasAdminOnContract can return true.
	t.Run("tier-3 per-contract admin resolves to admin=true for that contract only", func(t *testing.T) {
		tier3Addr := "0x4444444444444444444444444444444444444444"
		tier3CID := uuid.New().String()
		require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{
			ID: tier3CID, OrgID: orgAID, Address: tier3Addr, Name: "T3",
		}))
		t3Group := mustCreateGroup(t, ts.db, orgAID, "vac-a-t3", []rbac.Claim{rbac.ClaimAdmin}, false)
		require.NoError(t, ts.db.CreateContractGrant(ctx, &rbac.ContractGrant{
			ID: uuid.New().String(), ContractID: tier3CID, GroupID: t3Group,
		}))
		charlieUser := &rbac.User{ID: uuid.New().String(), ExternalID: "did:test:charlie-" + uuid.New().String()[:8]}
		require.NoError(t, ts.db.CreateUser(ctx, charlieUser))
		require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{
			ID: uuid.New().String(), UserID: charlieUser.ID, GroupID: t3Group,
		}))

		got := proc.viewerAdminContracts(ctx, charlieUser.ID, []string{tier3Addr})
		require.True(t, got[tier3Addr], "tier-3 admin on the specific contract must resolve to admin=true")

		// And must NOT be admin on OTHER contracts in the same org.
		got = proc.viewerAdminContracts(ctx, charlieUser.ID, []string{contractA1})
		require.False(t, got[contractA1], "tier-3 per-contract admin must not bleed to other contracts")
	})
}

// TestApplyResponseFilter_AdminBypass_UsesUUIDFromAccessCheckResult is a
// regression test for the UUID-vs-DID bug where applyResponseFilter's
// callsites passed req.UserID (the JWT external DID) into
// viewerAdminContracts, which expects the internal user UUID — making
// the org-scoped admin bypass silently never fire for any logged-in
// admin. The unit-level TestViewerAdminContracts above always passed
// the right type (UUID), so the wiring bug slipped through. This test
// drives the fix from the actual JSON-RPC entry point: it constructs a
// ProcessRequest carrying the DID (matching production) and an
// AccessCheckResult carrying the UUID (matching production), invokes
// applyResponseFilter, and asserts the admin sees their org's logs.
func TestApplyResponseFilter_AdminBypass_UsesUUIDFromAccessCheckResult(t *testing.T) {
	ctx := context.Background()
	ts := setupTestServerForRBAC(t)
	proc := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:     ts.rbacAccessCtrl,
		RateLimiter:        &noopRateLimiter{},
		AccessLogger:       ts.db,
		CircuitBreaker:     middleware.NewCircuitBreaker(),
		ConcurrencyLimiter: middleware.NewConcurrencyLimiter(50, 0),
	})

	// Org with a contract; Alice is org admin (is_org_admin=true).
	orgID := uuid.New().String()
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{
		ID: orgID, Slug: "rxf-" + orgID[:8], Name: "ResponseFilterFixture", Settings: map[string]any{},
	}))
	aliceUser := &rbac.User{ID: uuid.New().String(), ExternalID: "did:test:rxf-alice-" + uuid.New().String()[:8]}
	require.NoError(t, ts.db.CreateUser(ctx, aliceUser))
	adminGroup := mustCreateGroup(t, ts.db, orgID, "rxf-admins", nil, true)
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: aliceUser.ID, GroupID: adminGroup,
	}))
	contractAddr := "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{
		ID: uuid.New().String(), OrgID: orgID, Address: contractAddr, Name: "RxF",
	}))

	// One Transfer log emitted by the org's contract. Pre-fix, the
	// filter would deny this because (a) admin bypass map is built
	// from req.UserID (DID) → empty map, (b) the org-admin code path
	// in computeOrgAdminPermissions sets ContractAccess[addr] but does
	// NOT populate EventRules, so the allowlist branch denies. The
	// only way an org admin sees logs is through the bypass map.
	logEntry := []byte(`{` +
		`"address":"` + contractAddr + `",` +
		`"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],` +
		`"data":"0x",` +
		`"blockNumber":"0x1",` +
		`"transactionHash":"0xabc"` +
		`}`)
	responseBody := []byte(`{"jsonrpc":"2.0","id":1,"result":[` + string(logEntry) + `]}`)

	// Production wiring: req.UserID is the JWT external DID; the
	// resolved AccessCheckResult.UserID is the internal UUID.
	req := &ProcessRequest{
		UserID: aliceUser.ExternalID, // DID — like production
		Method: "eth_getLogs",
		Params: []any{},
	}
	result := &rbac.AccessCheckResult{
		Allowed: true,
		UserID:  aliceUser.ID, // UUID — like production
		OrgID:   orgID,
	}

	filtered := proc.applyResponseFilter(ctx, req, result, responseBody)

	// Parse to count logs.
	var resp struct {
		Result []json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(filtered, &resp))
	require.Len(t, resp.Result, 1, "org admin must see logs from their org's contract via admin bypass; pre-fix this returned 0 because viewerAdminContracts was called with the DID")
}

// mustCreateGroup is a minimal group-creation helper for processor
// unit tests that need to assemble fixtures quickly. Mirrors the
// `createGroup` helper in e2e/access_visibility_symmetry_test.go —
// creates the group row AND the paired group_access row with empty
// claims, since most callers need group_access to exist.
func mustCreateGroup(t *testing.T, database *db.DB, orgID, name string, claims []rbac.Claim, isOrgAdmin bool) string {
	t.Helper()
	ctx := context.Background()
	gid := uuid.New().String()
	err := database.CreateGroup(ctx, &rbac.Group{
		ID:         gid,
		OrgID:      orgID,
		Slug:       name,
		Name:       name,
		Depth:      0,
		Path:       name,
		IsOrgAdmin: isOrgAdmin,
	})
	require.NoError(t, err)
	err = database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: gid, AllowedMethods: []string{}, Claims: claims,
	})
	require.NoError(t, err)
	return gid
}
