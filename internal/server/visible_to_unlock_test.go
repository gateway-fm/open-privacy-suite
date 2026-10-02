package server

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

// TestVisibleToMaxSize_Constant pins the bound at 32. Lower values
// would break legitimate small workflows; higher values widen the
// blast-radius of an abusive sender listing arbitrary DIDs (RD-874
// security analysis §3, §8). If the bound is intentionally changed,
// update decisions.md §12 and REDACTION_SPEC.md to match — there's
// no separate runtime config knob for this.
func TestVisibleToMaxSize_Constant(t *testing.T) {
	require.Equal(t, 32, visibleToMaxSize)
}

// TestVisibleToUnlock_Matrix exercises the per-contract visibleTo
// unlock semantic end-to-end against a real database. Mirrors the
// matrix we need to defend per the RD-874 security analysis:
//
//   - flag off, viewer in eligible group + listed:        DENY (additive stays)
//   - flag on,  viewer in eligible group + listed:        ALLOW
//   - flag on,  viewer in eligible group, NOT listed:     DENY (event_rules:deny-all wins)
//   - flag on,  viewer cross-org + listed:                DENY (no group on contract's org)
//   - flag on,  viewer with no group at all + listed:     DENY (anon-equivalent)
//   - flag on,  group revoked, viewer was unlocked:       DENY (request-time check)
//
// Implementation runs RedactionEngine.RedactLogs (explorer side)
// against a wired DB. The RPC layer (rbac.FilterEventLogs) consumes
// the same shared rbac.UnlockableContracts helper plus
// processor_event_rules.go's buildVisibleToUnlockableMap, which has
// 1:1 logic with the explorer resolver — the symmetry test
// TestExplorerRedactorWiring_FullStack already checks the wiring
// surface, and this test covers the behaviour matrix.
func TestVisibleToUnlock_Matrix(t *testing.T) {
	ctx := context.Background()

	dbURL := sharedTestDBURL(t)

	database, err := db.New(dbURL)
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })
	require.NoError(t, db.ResetTestDatabase(database))

	// ----- Fixture --------------------------------------------------------
	// Org A holds the contract under test; Org B holds an unrelated
	// contract for the cross-org scenario.
	orgAID := uuid.New().String()
	orgBID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgAID, Slug: "vt-a", Name: "VT A", Settings: map[string]any{}}))
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgBID, Slug: "vt-b", Name: "VT B", Settings: map[string]any{}}))

	// Group with claims=[] in org A — viewer-eligible group via grant.
	aGroupGID := vtCreateGroup(t, database, orgAID, "vt-a-grantee", nil, false)
	// Group in org B — orthogonal.
	bGroupGID := vtCreateGroup(t, database, orgBID, "vt-b-grantee", nil, false)

	contractAddr := "0x1111111111111111111111111111111111111111"
	contractAID := vtCreateContractWithABI(t, database, orgAID, contractAddr, "VTContract", testEventABIVT)
	bAddr := "0x2222222222222222222222222222222222222222"
	_ = vtCreateContractWithABI(t, database, orgBID, bAddr, "BContract", testEventABIVT)

	// Grant: org A's grantee group has deny-all event_rules on the
	// contract. Without unlock, no events visible.
	vtCreateGrant(t, database, contractAID, aGroupGID, &rbac.EventRulesField{} /* deny-all */)

	// Users.
	vtCreateUserInGroup(t, database, "did:vt:alice", aGroupGID)   // eligible (in grantee group)
	vtCreateUserInGroup(t, database, "did:vt:bob", aGroupGID)     // eligible but not listed
	vtCreateUserInGroup(t, database, "did:vt:mallory", bGroupGID) // org B only — cross-org
	// did:vt:eve gets a user record but no group memberships.
	eveUID := uuid.New().String()
	require.NoError(t, database.CreateUser(ctx, &rbac.User{ID: eveUID, ExternalID: "did:vt:eve", KYC: true, Banned: false, Metadata: map[string]any{}}))

	// Wire the explorer redactor exactly as production does.
	accessCtrl := rbac.NewAccessController(database, 1*time.Minute)
	t.Cleanup(accessCtrl.Stop)
	engine := explorer.NewRedactionEngine(noopContractStore{}, database, rbac.ReadProfileStandard)
	wireExplorerRedactor(engine, database, accessCtrl, noopLogParticipantStore{}, nil)

	transferTopic := topicHex("Transfer(address,address,uint256)")
	transferTopic0x := "0x" + transferTopic
	txHash := "0xtxvtu1"

	makeLogs := func() []explorer.Log {
		return []explorer.Log{
			{ID: 1, Address: contractAddr, TxHash: txHash, Topic0: &transferTopic0x, Data: "0x"},
		}
	}
	// Listed = the genuine tx_visible_to listing (ListedTxHashes, RD-1307).
	opts := &explorer.RedactOpts{VisibleTxHashes: map[string]bool{txHash: true}, ListedTxHashes: map[string]bool{txHash: true}}

	// ----- Case 1: flag OFF — additive behaviour stays. ----------------
	// Even though alice is in eligible group + listed, deny-all rules
	// stand. Today's behaviour preserved.
	out, err := engine.RedactLogsWithOpts(ctx, makeLogs(), "did:vt:alice", opts)
	require.NoError(t, err)
	require.Empty(t, out, "flag OFF: deny-all event_rules must win even when listed in visibleTo")

	// Flip the flag on for the matrix below.
	require.NoError(t, database.UpdateContractAllowVisibleToUnlock(ctx, contractAID, true))
	accessCtrl.InvalidateOrg(ctx, orgAID)

	// ----- Case 2: flag ON, eligible viewer + listed — UNLOCKS. -------
	out, err = engine.RedactLogsWithOpts(ctx, makeLogs(), "did:vt:alice", opts)
	require.NoError(t, err)
	require.Len(t, out, 1, "flag ON + eligible + listed: log must pass via unlock")

	// ----- Case 3: flag ON, eligible viewer NOT listed — DENY. --------
	bobOpts := &explorer.RedactOpts{VisibleTxHashes: map[string]bool{}} // empty: not listed
	out, err = engine.RedactLogsWithOpts(ctx, makeLogs(), "did:vt:bob", bobOpts)
	require.NoError(t, err)
	require.Empty(t, out, "flag ON + eligible + NOT listed: deny-all event_rules must still drop the log")

	// ----- Case 4: flag ON, cross-org viewer + listed — DENY. ---------
	out, err = engine.RedactLogsWithOpts(ctx, makeLogs(), "did:vt:mallory", opts)
	require.NoError(t, err)
	require.Empty(t, out, "flag ON + cross-org + listed: must remain denied (no group in contract's owning org)")

	// ----- Case 5: flag ON, no-group viewer (eve) + listed — DENY. ---
	out, err = engine.RedactLogsWithOpts(ctx, makeLogs(), "did:vt:eve", opts)
	require.NoError(t, err)
	require.Empty(t, out, "flag ON + no group + listed: must remain denied (no contract_grant via any group)")

	// ----- Case 6: revoke alice's group membership — DENY at request time. -----
	// Find alice's user ID + her membership and delete it.
	aliceUser, err := database.GetUserByExternalID(ctx, "did:vt:alice")
	require.NoError(t, err)
	require.NotNil(t, aliceUser)
	memberships, err := database.ListUserMembershipsWithDetails(ctx, aliceUser.ID)
	require.NoError(t, err)
	require.NotEmpty(t, memberships)
	for _, m := range memberships {
		require.NotNil(t, m.Membership)
		require.NoError(t, database.DeleteMembership(ctx, m.Membership.ID))
	}
	accessCtrl.InvalidateOrg(ctx, orgAID)

	out, err = engine.RedactLogsWithOpts(ctx, makeLogs(), "did:vt:alice", opts)
	require.NoError(t, err)
	require.Empty(t, out, "flag ON + listed but group revoked: must be denied at request time (no cached unlock)")
}

// ---- fixture helpers (kept local to this file) -----------------------

const testEventABIVT = `[
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}
]`

func vtCreateGroup(t *testing.T, database *db.DB, orgID, slug string, claims []rbac.Claim, isOrgAdmin bool) string {
	t.Helper()
	ctx := context.Background()
	gid := uuid.New().String()
	require.NoError(t, database.CreateGroup(ctx, &rbac.Group{
		ID: gid, OrgID: orgID, Slug: slug, Name: slug, Depth: 0, Path: slug, IsOrgAdmin: isOrgAdmin,
	}))
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: gid, AllowedMethods: []string{"eth_call", "eth_getLogs"}, Claims: claims,
	}))
	return gid
}

func vtCreateUserInGroup(t *testing.T, database *db.DB, did, groupID string) string {
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

func vtCreateContractWithABI(t *testing.T, database *db.DB, orgID, address, name, abiJSON string) string {
	t.Helper()
	ctx := context.Background()
	cid := uuid.New().String()
	require.NoError(t, database.CreateContract(ctx, &rbac.Contract{
		ID: cid, OrgID: orgID, Address: strings.ToLower(address), Name: name, ABI: abiJSON, Metadata: map[string]any{},
	}))
	return cid
}

func vtCreateGrant(t *testing.T, database *db.DB, contractID, groupID string, eventRules *rbac.EventRulesField) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, database.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID: uuid.New().String(), ContractID: contractID, GroupID: groupID, Functions: nil, EventRules: eventRules,
	}))
}
