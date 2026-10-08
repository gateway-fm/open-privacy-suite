package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestAccessVisibilitySymmetry enforces the RD-849 invariant: for every
// (viewer, address) pair, the RPC access layer and the explorer visibility
// layer must agree. If CheckAccess allows a viewer to reach an address, the
// same viewer must see that address as VisibilityFull in GetBatchVisibility.
// If CheckAccess denies, visibility must be anything other than Full (Hidden
// or Redacted). Any asymmetry is a bug — historically we had tier 3 admin
// claim users with RPC access to all org contracts but only Redacted/Hidden
// visibility. This test exists to prevent regression to that state.
func TestAccessVisibilitySymmetry(t *testing.T) {
	ctx := context.Background()

	dbURL, dbCleanup := db.SetupTestContainer(t)
	t.Cleanup(dbCleanup)

	database, err := db.New(dbURL)
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })
	require.NoError(t, db.ResetTestDatabase(database))

	// --- Fixture: two orgs, various user configurations, two contracts per org.
	//
	//   orgA
	//     grantedGroup (claims: []) with grant on contractA1
	//     adminGroup   (claims: [admin])  — tier 3, no grants
	//     deployGroup  (claims: [deploy]) — tier 3, no grants
	//     orgAdminGroup (is_org_admin: true)
	//   orgB
	//     readerGroup (claims: []) with grant on contractB1
	//   Contracts
	//     contractA1 (orgA) — granted to grantedGroup
	//     contractA2 (orgA) — no grants (only org admin should see)
	//     contractB1 (orgB) — granted to orgB readerGroup
	//     contractB2 (orgB) — no grants (no one in orgA should see)
	orgAID := uuid.New().String()
	orgBID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgAID, Slug: "sym-a", Name: "Sym A", Settings: map[string]any{}}))
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgBID, Slug: "sym-b", Name: "Sym B", Settings: map[string]any{}}))

	grantedGID := createGroup(t, database, orgAID, "sym-a-granted", nil, false)
	adminGID := createGroup(t, database, orgAID, "sym-a-tier3-admin", []rbac.Claim{rbac.ClaimAdmin}, false)
	deployGID := createGroup(t, database, orgAID, "sym-a-tier3-deploy", []rbac.Claim{rbac.ClaimDeploy}, false)
	orgAdminGID := createGroup(t, database, orgAID, "sym-a-org-admin", nil, true)
	readerBGID := createGroup(t, database, orgBID, "sym-b-reader", nil, false)

	contractA1 := "0x1111111111111111111111111111111111111111"
	contractA2 := "0x2222222222222222222222222222222222222222"
	contractB1 := "0x3333333333333333333333333333333333333333"
	contractB2 := "0x4444444444444444444444444444444444444444"
	contractA1ID := createContract(t, database, orgAID, contractA1, "ContractA1")
	_ = createContract(t, database, orgAID, contractA2, "ContractA2")
	contractB1ID := createContract(t, database, orgBID, contractB1, "ContractB1")
	_ = createContract(t, database, orgBID, contractB2, "ContractB2")

	// Grants: grantedGroup → A1, readerBGroup → B1. No grants on A2 or B2.
	createGrant(t, database, contractA1ID, grantedGID)
	createGrant(t, database, contractB1ID, readerBGID)

	// Users: one per role. grantedUser is in grantedGroup; t3AdminUser in adminGroup; etc.
	// Each gets `eth_call` in AllowedMethods so the method allowlist doesn't
	// confound the access check.
	grantedUser := createUserInGroup(t, database, "did:sym:granted", grantedGID)
	t3AdminUser := createUserInGroup(t, database, "did:sym:t3admin", adminGID)
	t3DeployUser := createUserInGroup(t, database, "did:sym:t3deploy", deployGID)
	orgAdminUser := createUserInGroup(t, database, "did:sym:orgadmin", orgAdminGID)
	crossOrgUser := createUserInGroup(t, database, "did:sym:crossorg", readerBGID)

	_ = grantedUser
	_ = t3AdminUser
	_ = t3DeployUser
	_ = orgAdminUser
	_ = crossOrgUser

	// Another user's wallet (an orgB member). Org admins manage contracts, not
	// user wallets: this EOA is private to the orgA admin on both layers, and
	// stays [PRIVATE] on an explorer row kept by the transfer-participant union
	// (RD-1316, checked after the table).
	foreignEOA := "0x5555555555555555555555555555555555555555"
	createUserInGroup(t, database, "did:sym:orgb-wallet", readerBGID)
	require.NoError(t, database.SystemLinkEthAddress(ctx, "did:sym:orgb-wallet", foreignEOA))

	// Add eth_call to every group's AllowedMethods so method allowlist never blocks.
	for _, gid := range []string{grantedGID, adminGID, deployGID, orgAdminGID, readerBGID} {
		attachAllowedMethods(t, database, gid, []string{"eth_call", "eth_getBalance", "eth_getCode"})
	}

	controller := rbac.NewAccessController(database, 1*time.Minute)

	type tc struct {
		name        string
		viewerDID   string
		contract    string
		wantAllowed bool // expected CheckAccess outcome + expected VisibilityFull
	}

	cases := []tc{
		// Granted user on granted contract: both allow + Full.
		{"granted user → granted own-org contract", "did:sym:granted", contractA1, true},
		// Granted user on non-granted own-org contract: both deny + non-Full.
		{"granted user → non-granted own-org contract", "did:sym:granted", contractA2, false},
		// Tier 3 admin claim, no grant: both deny + non-Full. (RD-849 regression scenario.)
		{"tier 3 admin → granted own-org contract (no grant for admin group)", "did:sym:t3admin", contractA1, false},
		{"tier 3 admin → non-granted own-org contract", "did:sym:t3admin", contractA2, false},
		// Tier 3 deploy claim, no grant: both deny + non-Full.
		{"tier 3 deploy → granted own-org contract (no grant for deploy group)", "did:sym:t3deploy", contractA1, false},
		{"tier 3 deploy → non-granted own-org contract", "did:sym:t3deploy", contractA2, false},
		// Tier 2 org admin: both allow + Full on every org contract.
		{"org admin → granted own-org contract", "did:sym:orgadmin", contractA1, true},
		{"org admin → non-granted own-org contract", "did:sym:orgadmin", contractA2, true},
		// Cross-org: both deny + non-Full on the other org's contracts.
		{"orgB user → orgA granted contract", "did:sym:crossorg", contractA1, false},
		{"orgB user → orgA non-granted contract", "did:sym:crossorg", contractA2, false},
		{"orgA tier 3 admin → orgB contract", "did:sym:t3admin", contractB1, false},
		{"orgA tier 3 admin → orgB non-granted contract", "did:sym:t3admin", contractB2, false},
		// Org admin vs another user's wallet: both deny + non-Full (§2.1).
		{"org admin → another user's EOA", "did:sym:orgadmin", foreignEOA, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// RPC-layer check.
			accessResult, err := controller.CheckAccess(ctx, &rbac.AccessCheckRequest{
				UserExternalID: c.viewerDID,
				Method:         "eth_call",
				Params:         []any{map[string]any{"to": c.contract, "data": "0x"}, "latest"},
				TargetAddress:  c.contract,
			})
			require.NoError(t, err)

			// Explorer visibility check.
			visMap, err := database.GetBatchVisibility(ctx, c.viewerDID, []string{strings.ToLower(c.contract)})
			require.NoError(t, err)
			visFull := visMap[strings.ToLower(c.contract)] == explorer.VisibilityFull

			if c.wantAllowed {
				require.True(t, accessResult.Allowed, "expected RPC access allowed, got denied: %s", accessResult.Reason)
				require.True(t, visFull, "expected visibility Full when RPC access is allowed — symmetry violation")
			} else {
				require.False(t, accessResult.Allowed, "expected RPC access denied, got allowed")
				require.False(t, visFull, "expected visibility not-Full when RPC access is denied — symmetry violation")
			}

			// The symmetry assertion itself — flags any future asymmetry regardless of expectation.
			require.Equal(t, c.wantAllowed, accessResult.Allowed && visFull,
				"access/visibility mismatch: access.Allowed=%v, visibilityFull=%v", accessResult.Allowed, visFull)
		})
	}

	// RD-1316: a tx from that wallet (here to an orgB contract the admin cannot
	// see) that the transfer-participant union keeps for the org admin — passed
	// in directly as VisibleTxHashes — still renders the wallet [PRIVATE],
	// matching the RPC denial above. Only a genuine visibleTo listing reveals.
	t.Run("org admin → another user's EOA on a transfer-linked row", func(t *testing.T) {
		const hash = "0x5555000000000000000000000000000000000000000000000000000000000001"
		to := contractB2
		engine := explorer.NewRedactionEngine(nil, database)
		got, err := engine.RedactTransactions(ctx, []explorer.Transaction{{Hash: hash, From: foreignEOA, To: &to, Value: "5"}},
			"did:sym:orgadmin", explorer.RedactOpts{VisibleTxHashes: map[string]bool{hash: true}, ViewerIsAdmin: true})
		require.NoError(t, err)
		require.Len(t, got, 1, "the union keeps the row")
		require.Equal(t, "[PRIVATE]", got[0].From, "the explorer must not reveal what the RPC layer denies")
		require.NotContains(t, got[0].AddressMetadata, foreignEOA, "no addressMetadata key for the private wallet")
	})
}

// --- Helpers (keep local to this file — small and clear) ---

func createGroup(t *testing.T, database *db.DB, orgID, slug string, claims []rbac.Claim, isOrgAdmin bool) string {
	t.Helper()
	ctx := context.Background()
	gid := uuid.New().String()
	require.NoError(t, database.CreateGroup(ctx, &rbac.Group{
		ID: gid, OrgID: orgID, Slug: slug, Name: slug, Depth: 0, Path: slug, IsOrgAdmin: isOrgAdmin,
	}))
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: gid, AllowedMethods: []string{}, Claims: claims,
	}))
	return gid
}

func createUserInGroup(t *testing.T, database *db.DB, did, groupID string) string {
	t.Helper()
	ctx := context.Background()
	uid := uuid.New().String()
	require.NoError(t, database.CreateUser(ctx, &rbac.User{
		ID: uid, ExternalID: did, KYC: true, Banned: false, Metadata: map[string]any{},
	}))
	require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: uid, GroupID: groupID, Source: rbac.MembershipSourceAdmin,
	}))
	return uid
}

func createContract(t *testing.T, database *db.DB, orgID, address, name string) string {
	t.Helper()
	ctx := context.Background()
	cid := uuid.New().String()
	require.NoError(t, database.CreateContract(ctx, &rbac.Contract{
		ID: cid, OrgID: orgID, Address: strings.ToLower(address), Name: name, Metadata: map[string]any{},
	}))
	return cid
}

func createGrant(t *testing.T, database *db.DB, contractID, groupID string) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, database.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID: uuid.New().String(), ContractID: contractID, GroupID: groupID, Functions: nil,
	}))
}

func attachAllowedMethods(t *testing.T, database *db.DB, groupID string, methods []string) {
	t.Helper()
	ctx := context.Background()
	gas, err := database.GetGroupAccess(ctx, groupID)
	require.NoError(t, err)
	require.NotNil(t, gas)
	gas.AllowedMethods = methods
	require.NoError(t, database.UpdateGroupAccess(ctx, gas))
}
