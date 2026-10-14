package db

import (
	"context"
	"testing"
	"time"

	"privacy-proxy/internal/explorer"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupOrgContract inserts an org, group, contract, and contract_grant.
// Returns the contractID and groupID for further assertions.
func setupOrgContract(t *testing.T, database *DB, contractAddr string) (contractID, groupID string) {
	t.Helper()
	ctx := context.Background()
	conn := database.Conn()

	orgID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "redaction-org-"+orgID[:8], "Redaction Test Org")
	require.NoError(t, err)

	groupID = uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path) VALUES ($1, $2, 'members', 'Members', 0, 'members')",
		groupID, orgID)
	require.NoError(t, err)

	contractID = uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, $4)",
		contractID, orgID, contractAddr, "Redaction Test Contract")
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id) VALUES ($1, $2, $3)",
		uuid.New().String(), contractID, groupID)
	require.NoError(t, err)

	return contractID, groupID
}

// addMember inserts a user with the given DID and adds them to groupID.
func addMember(t *testing.T, database *DB, did, groupID string) string {
	t.Helper()
	ctx := context.Background()
	userID := uuid.New().String()
	_, err := database.Conn().ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		userID, did)
	require.NoError(t, err)
	_, err = database.Conn().ExecContext(ctx,
		"INSERT INTO user_memberships (id, user_id, group_id, source) VALUES ($1, $2, $3, 'admin')",
		uuid.New().String(), userID, groupID)
	require.NoError(t, err)
	return userID
}

// addExpiredMember inserts a user with an already-expired membership.
func addExpiredMember(t *testing.T, database *DB, did, groupID string) string {
	t.Helper()
	ctx := context.Background()
	userID := uuid.New().String()
	_, err := database.Conn().ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		userID, did)
	require.NoError(t, err)
	_, err = database.Conn().ExecContext(ctx,
		"INSERT INTO user_memberships (id, user_id, group_id, source, expires_at) VALUES ($1, $2, $3, 'admin', NOW() - INTERVAL '1 day')",
		uuid.New().String(), userID, groupID)
	require.NoError(t, err)
	return userID
}

// ============================================================================
// GetBatchVisibility — org contract visibility
// ============================================================================

func TestGetBatchVisibility_OrgContract(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	const privateAddr = "0xaaaa000000000000000000000000000000000001"
	_, groupID := setupOrgContract(t, database, privateAddr)

	ctx := context.Background()

	t.Run("anonymous viewer sees Redacted not Hidden", func(t *testing.T) {
		// Anonymous (empty DID) should get VisibilityRedacted, not Hidden.
		// This ensures transactions involving the address show [PRIVATE] rather than being dropped.
		visMap, err := database.GetBatchVisibility(ctx, "", []string{privateAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[privateAddr],
			"org contract must be VisibilityRedacted for anonymous viewer (not Hidden)")
	})

	t.Run("non-member sees Redacted", func(t *testing.T) {
		visMap, err := database.GetBatchVisibility(ctx, "did:privado:outsider_batch", []string{privateAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[privateAddr])
	})

	t.Run("standard member with grant sees Full", func(t *testing.T) {
		const memberDID = "did:privado:batch_member"
		addMember(t, database, memberDID, groupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{privateAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[privateAddr],
			"standard group member with contract_grant must have VisibilityFull — "+
				"aligns explorer visibility with RPC access")
	})

	t.Run("admin member sees Full", func(t *testing.T) {
		const adminDID = "did:privado:admin_member"

		// Create an admin group
		adminGroupID := uuid.New().String()
		_, err := database.Conn().ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, (SELECT org_id FROM groups WHERE id = $2), 'admins', 'Admins', 0, 'admins', true)",
			adminGroupID, groupID)
		require.NoError(t, err)

		addMember(t, database, adminDID, adminGroupID)

		visMap, err := database.GetBatchVisibility(ctx, adminDID, []string{privateAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[privateAddr],
			"admin group member must have VisibilityFull for their org contract")
	})

	t.Run("contract admin (admin claim, NOT is_org_admin) does NOT see ungranted org contracts (3-tier model)", func(t *testing.T) {
		// 3-tier admin model: contract admins (tier 3) have admin claim in
		// group_access.claims but NOT is_org_admin=true. They should only see
		// contracts explicitly granted to their group, NOT all org contracts.
		// This reverses the old G11 behavior intentionally.
		const claimsAdminDID = "did:privado:claims_admin_member"

		// Create a second contract in the same org with no grants at all
		ungrantedAddr := "0xaaaa000000000000000000000000000000000099"
		ungrantedContractID := uuid.New().String()
		var orgID string
		err := database.Conn().QueryRowContext(ctx,
			"SELECT org_id FROM groups WHERE id = $1", groupID).Scan(&orgID)
		require.NoError(t, err)
		_, err = database.Conn().ExecContext(ctx,
			"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Ungranted Contract')",
			ungrantedContractID, orgID, ungrantedAddr)
		require.NoError(t, err)

		// Create contract admin group: is_org_admin=false, group_access.claims={admin}
		claimsAdminGroupID := uuid.New().String()
		_, err = database.Conn().ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'claims-admins', 'Claims Admins', 0, 'claims-admins', false)",
			claimsAdminGroupID, orgID)
		require.NoError(t, err)
		_, err = database.Conn().ExecContext(ctx,
			"INSERT INTO group_access (id, group_id, claims) VALUES ($1, $2, '{admin}')",
			uuid.New().String(), claimsAdminGroupID)
		require.NoError(t, err)

		addMember(t, database, claimsAdminDID, claimsAdminGroupID)

		// Contract admin (tier 3) must NOT see the ungranted contract.
		// They have no contract_grant on it and are not is_org_admin.
		visMap, err := database.GetBatchVisibility(ctx, claimsAdminDID, []string{privateAddr, ungrantedAddr})
		require.NoError(t, err)
		// The granted contract (privateAddr) has a grant to groupID, not claimsAdminGroupID.
		// So the contract admin does not see it either (no grant to THEIR group).
		assert.Equal(t, explorer.VisibilityRedacted, visMap[privateAddr],
			"contract admin without explicit grant to their group must NOT see this contract")
		assert.Equal(t, explorer.VisibilityRedacted, visMap[ungrantedAddr],
			"contract admin (tier 3) must NOT see ungranted org contracts — "+
				"only is_org_admin=true (tier 2) grants org-wide visibility")
	})

	t.Run("contract admin via grant sees Full", func(t *testing.T) {
		const grantAdminDID = "did:privado:grant_admin_member"

		// Create a NON-org-admin group in the same org.
		grantGroupID := uuid.New().String()
		_, err := database.Conn().ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, (SELECT org_id FROM groups WHERE id = $2), 'grant-admins', 'Grant Admins', 0, 'grant-admins', false)",
			grantGroupID, groupID)
		require.NoError(t, err)

		// Create a contract_grant linking the non-admin group to the contract with claims = '{admin}'.
		// First we need the contract ID for privateAddr.
		var contractID string
		err = database.Conn().QueryRowContext(ctx,
			"SELECT id FROM contracts WHERE LOWER(address) = $1", privateAddr).Scan(&contractID)
		require.NoError(t, err)

		_, err = database.Conn().ExecContext(ctx,
			"INSERT INTO contract_grants (id, contract_id, group_id, claims) VALUES ($1, $2, $3, '{admin}')",
			uuid.New().String(), contractID, grantGroupID)
		require.NoError(t, err)

		addMember(t, database, grantAdminDID, grantGroupID)

		visMap, err := database.GetBatchVisibility(ctx, grantAdminDID, []string{privateAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[privateAddr],
			"member of non-admin group with 'admin' contract_grant claim must have VisibilityFull")
	})

	t.Run("expired member sees Redacted", func(t *testing.T) {
		const expiredDID = "did:privado:expired_batch"
		addExpiredMember(t, database, expiredDID, groupID)

		visMap, err := database.GetBatchVisibility(ctx, expiredDID, []string{privateAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[privateAddr],
			"expired member must not retain access after expiry")
	})

	t.Run("unregistered address is Hidden (private by default)", func(t *testing.T) {
		const unregAddr = "0x9999000000000000000000000000000000000001"
		visMap, err := database.GetBatchVisibility(ctx, "", []string{unregAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityHidden, visMap[unregAddr],
			"unregistered address (not in contracts table) must be VisibilityHidden (private by default)")
	})

	t.Run("precompile address is Full", func(t *testing.T) {
		const precompileAddr = "0x0000000000000000000000000000000000000001"
		visMap, err := database.GetBatchVisibility(ctx, "", []string{precompileAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[precompileAddr],
			"precompile address must remain VisibilityFull")
	})

	t.Run("mixed batch: unregistered and private", func(t *testing.T) {
		const unregAddr = "0x9999000000000000000000000000000000000002"
		visMap, err := database.GetBatchVisibility(ctx, "", []string{privateAddr, unregAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[privateAddr])
		assert.Equal(t, explorer.VisibilityHidden, visMap[unregAddr],
			"unregistered address must be VisibilityHidden (private by default)")
	})
}

// TestGetBatchVisibility_NoAdminGroups verifies that org contracts are
// VisibilityRedacted even when no admin groups exist at all. Regression test
// for the bug where org contract detection was coupled with admin group lookup —
// if no admin groups existed, the contract fell through as VisibilityFull.
func TestGetBatchVisibility_NoAdminGroups(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()
	conn := database.Conn()

	orgID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "no-admin-org", "No Admin Org")
	require.NoError(t, err)

	groupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'readers', 'Readers', 0, 'readers', false)",
		groupID, orgID)
	require.NoError(t, err)

	contractAddr := "0xbbbb000000000000000000000000000000000099"
	contractID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'No Admin Contract')",
		contractID, orgID, contractAddr)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id, claims) VALUES ($1, $2, $3, '{read}')",
		uuid.New().String(), contractID, groupID)
	require.NoError(t, err)

	t.Run("anonymous sees Redacted", func(t *testing.T) {
		visMap, err := database.GetBatchVisibility(ctx, "", []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractAddr],
			"org contract must be Redacted for anonymous even with no admin groups")
	})

	t.Run("read-only member with grant sees Full", func(t *testing.T) {
		memberDID := "did:test:reader_no_admin"
		addMember(t, database, memberDID, groupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[contractAddr],
			"member of group with contract_grant sees Full regardless of claims — "+
				"aligns explorer visibility with RPC access")
	})
}

func TestGetBatchVisibility_EdgeCases(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()
	conn := database.Conn()

	t.Run("cross-org admin cannot see other org contracts as Full", func(t *testing.T) {
		// Org A: admin group + contract
		orgAID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
			orgAID, "edge-orgA-"+orgAID[:8], "Edge Org A")
		require.NoError(t, err)

		adminGroupA := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'admins', 'Admins', 0, 'admins', true)",
			adminGroupA, orgAID)
		require.NoError(t, err)

		contractAAddr := "0xaa01000000000000000000000000000000000001"
		contractAID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Contract A')",
			contractAID, orgAID, contractAAddr)
		require.NoError(t, err)

		// Org B: contract only (no admin groups needed for this test)
		orgBID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
			orgBID, "edge-orgB-"+orgBID[:8], "Edge Org B")
		require.NoError(t, err)

		contractBAddr := "0xbb01000000000000000000000000000000000001"
		contractBID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Contract B')",
			contractBID, orgBID, contractBAddr)
		require.NoError(t, err)

		// User is admin of Org A
		const crossAdminDID = "did:test:cross_org_admin"
		addMember(t, database, crossAdminDID, adminGroupA)

		visMap, err := database.GetBatchVisibility(ctx, crossAdminDID, []string{contractAAddr, contractBAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[contractAAddr],
			"admin of Org A must see own org contract as Full")
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractBAddr],
			"admin of Org A must NOT see Org B contract as Full — cross-org isolation")
	})

	t.Run("deploy grant holder sees Full", func(t *testing.T) {
		orgID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
			orgID, "edge-deploy-"+orgID[:8], "Deploy Org")
		require.NoError(t, err)

		groupID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'deployers', 'Deployers', 0, 'deployers', false)",
			groupID, orgID)
		require.NoError(t, err)

		contractAddr := "0xdd01000000000000000000000000000000000001"
		contractID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Deploy Contract')",
			contractID, orgID, contractAddr)
		require.NoError(t, err)

		_, err = conn.ExecContext(ctx,
			"INSERT INTO contract_grants (id, contract_id, group_id, claims) VALUES ($1, $2, $3, '{deploy}')",
			uuid.New().String(), contractID, groupID)
		require.NoError(t, err)

		const deployDID = "did:test:deploy_member"
		addMember(t, database, deployDID, groupID)

		visMap, err := database.GetBatchVisibility(ctx, deployDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[contractAddr],
			"any grant holder sees Full — explorer visibility aligns with RPC access")
	})

	t.Run("contract with no grants still Redacted", func(t *testing.T) {
		orgID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
			orgID, "edge-nogrant-"+orgID[:8], "No Grant Org")
		require.NoError(t, err)

		contractAddr := "0xee01000000000000000000000000000000000001"
		contractID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'No Grant Contract')",
			contractID, orgID, contractAddr)
		require.NoError(t, err)

		// No groups, no contract_grants — just a bare contract

		// Anonymous viewer
		visMap, err := database.GetBatchVisibility(ctx, "", []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractAddr],
			"org contract with no grants must still be Redacted for anonymous viewer")

		// Authenticated but unrelated viewer
		visMap, err = database.GetBatchVisibility(ctx, "did:test:unrelated_viewer", []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractAddr],
			"org contract with no grants must still be Redacted for authenticated viewer")
	})

	t.Run("user EOA: anonymous sees Hidden", func(t *testing.T) {
		eoaAddr := "0xff01000000000000000000000000000000000001"
		eoaDID := "did:test:eoa_owner"

		// Create user and link ETH address
		userID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
			userID, eoaDID)
		require.NoError(t, err)

		err = database.SystemLinkEthAddress(ctx, eoaDID, eoaAddr)
		require.NoError(t, err)

		// Anonymous viewer
		visMap, err := database.GetBatchVisibility(ctx, "", []string{eoaAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityHidden, visMap[eoaAddr],
			"anonymous must see owned EOA as Hidden (not Redacted, not Full)")
	})

	t.Run("user views own EOA as Full", func(t *testing.T) {
		eoaAddr := "0xff02000000000000000000000000000000000001"
		eoaDID := "did:test:own_eoa_viewer"

		userID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
			userID, eoaDID)
		require.NoError(t, err)

		err = database.SystemLinkEthAddress(ctx, eoaDID, eoaAddr)
		require.NoError(t, err)

		visMap, err := database.GetBatchVisibility(ctx, eoaDID, []string{eoaAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[eoaAddr],
			"user must see their own EOA as Full (ownerDID == viewerDID)")
	})

	t.Run("address case insensitivity", func(t *testing.T) {
		orgID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
			orgID, "edge-case-"+orgID[:8], "Case Org")
		require.NoError(t, err)

		// Store contract with mixed-case address
		mixedCaseAddr := "0xAAAA000000000000000000000000000000000099"
		contractID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Case Contract')",
			contractID, orgID, mixedCaseAddr)
		require.NoError(t, err)

		// Query with lowercase
		lowercaseAddr := "0xaaaa000000000000000000000000000000000099"
		visMap, err := database.GetBatchVisibility(ctx, "", []string{lowercaseAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[lowercaseAddr],
			"org contract must be found despite case mismatch between stored and queried address")
	})

	t.Run("multi-org batch: admin sees own org Full, other Redacted", func(t *testing.T) {
		// Org X: admin group + contract
		orgXID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
			orgXID, "edge-orgX-"+orgXID[:8], "Edge Org X")
		require.NoError(t, err)

		adminGroupX := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'admins', 'Admins', 0, 'admins', true)",
			adminGroupX, orgXID)
		require.NoError(t, err)

		contractXAddr := "0xcc01000000000000000000000000000000000001"
		contractXID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Contract X')",
			contractXID, orgXID, contractXAddr)
		require.NoError(t, err)

		// Org Y: regular group + contract (user is NOT a member)
		orgYID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
			orgYID, "edge-orgY-"+orgYID[:8], "Edge Org Y")
		require.NoError(t, err)

		regularGroupY := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'members', 'Members', 0, 'members', false)",
			regularGroupY, orgYID)
		require.NoError(t, err)

		contractYAddr := "0xcc02000000000000000000000000000000000001"
		contractYID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Contract Y')",
			contractYID, orgYID, contractYAddr)
		require.NoError(t, err)

		_, err = conn.ExecContext(ctx,
			"INSERT INTO contract_grants (id, contract_id, group_id) VALUES ($1, $2, $3)",
			uuid.New().String(), contractYID, regularGroupY)
		require.NoError(t, err)

		// User is admin of Org X only
		const multiOrgDID = "did:test:multi_org_admin"
		addMember(t, database, multiOrgDID, adminGroupX)

		// Single batch call with both contracts
		visMap, err := database.GetBatchVisibility(ctx, multiOrgDID, []string{contractXAddr, contractYAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[contractXAddr],
			"admin must see own org contract as Full in mixed batch")
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractYAddr],
			"admin must see other org contract as Redacted in mixed batch")
	})
}

// ============================================================================
// 3-tier admin model: visibility scoping
// ============================================================================

// TestGetBatchVisibility_GroupAccessAdminClaim verifies the 3-tier visibility model:
// - Group with admin claim + contract_grant = VisibilityFull (tier 3, scoped to granted contracts)
// - Group with admin claim WITHOUT grant = VisibilityRedacted (tier 3 does NOT get org-wide visibility)
// - Group with is_org_admin = true = VisibilityFull on ALL org contracts (tier 2)
func TestGetBatchVisibility_GroupAccessAdminClaim(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()
	conn := database.Conn()

	// Setup: org + contract + non-admin group with contract_grant
	orgID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "g11-org-"+orgID[:8], "G11 Test Org")
	require.NoError(t, err)

	contractAddr := "0xg110000000000000000000000000000000000001"
	contractID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'G11 Contract')",
		contractID, orgID, contractAddr)
	require.NoError(t, err)

	// Group with group_access.claims = ['admin'] (NOT is_org_admin)
	adminClaimGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'admin-claim', 'Admin Claim Group', 0, 'admin-claim', false)",
		adminClaimGroupID, orgID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO group_access (id, group_id, allowed_methods, claims) VALUES ($1, $2, '{\"*\"}', '{admin}')",
		uuid.New().String(), adminClaimGroupID)
	require.NoError(t, err)

	// contract_grant linking the group to the contract (no claims on the grant itself)
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id) VALUES ($1, $2, $3)",
		uuid.New().String(), contractID, adminClaimGroupID)
	require.NoError(t, err)

	// Group with group_access.claims = ['read'] and a contract_grant
	readClaimGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'read-claim', 'Read Claim Group', 0, 'read-claim', false)",
		readClaimGroupID, orgID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO group_access (id, group_id, allowed_methods, claims) VALUES ($1, $2, '{\"*\"}', '{read}')",
		uuid.New().String(), readClaimGroupID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id) VALUES ($1, $2, $3)",
		uuid.New().String(), contractID, readClaimGroupID)
	require.NoError(t, err)

	// Group with group_access.claims = ['admin'] but NO contract_grant
	noGrantGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'admin-no-grant', 'Admin No Grant', 0, 'admin-no-grant', false)",
		noGrantGroupID, orgID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO group_access (id, group_id, allowed_methods, claims) VALUES ($1, $2, '{\"*\"}', '{admin}')",
		uuid.New().String(), noGrantGroupID)
	require.NoError(t, err)
	// No contract_grant for this group

	t.Run("group_access admin claim + grant = VisibilityFull", func(t *testing.T) {
		const memberDID = "did:test:g11_admin_claim_member"
		addMember(t, database, memberDID, adminClaimGroupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[contractAddr],
			"member of group with 'admin' in group_access.claims + contract_grant must get VisibilityFull (G11 fix)")
	})

	t.Run("group_access read claim + grant = VisibilityFull", func(t *testing.T) {
		const memberDID = "did:test:g11_read_claim_member"
		addMember(t, database, memberDID, readClaimGroupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[contractAddr],
			"member of group with contract_grant sees Full regardless of claims — "+
				"explorer visibility aligns with RPC access")
	})

	t.Run("group_access admin claim without grant sees Redacted (3-tier model)", func(t *testing.T) {
		// 3-tier model: contract admin (tier 3) with admin claim but NO
		// contract_grant does NOT see the contract. Only is_org_admin (tier 2)
		// grants org-wide visibility. This intentionally reverses the old G11 behavior.
		const memberDID = "did:test:g11_admin_no_grant_member"
		addMember(t, database, memberDID, noGrantGroupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractAddr],
			"contract admin (tier 3) without grant must see Redacted — "+
				"only is_org_admin=true (tier 2) gets org-wide visibility")
	})

	t.Run("is_org_admin still works", func(t *testing.T) {
		const adminDID = "did:test:g11_org_admin_member"

		orgAdminGroupID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'org-admins', 'Org Admins', 0, 'org-admins', true)",
			orgAdminGroupID, orgID)
		require.NoError(t, err)

		addMember(t, database, adminDID, orgAdminGroupID)

		visMap, err := database.GetBatchVisibility(ctx, adminDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[contractAddr],
			"is_org_admin group member must still get VisibilityFull (existing behavior preserved)")
	})
}

// TestGetBatchVisibility_NoGrantNoFull verifies that users in a group WITHOUT
// a contract_grant on the specific contract still see Redacted. The grant-holder
// visibility upgrade must not leak to non-grant groups in the same org.
func TestGetBatchVisibility_NoGrantNoFull(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()
	conn := database.Conn()

	orgID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "nogrant-org-"+orgID[:8], "No Grant Org")
	require.NoError(t, err)

	contractAddr := "0xng01000000000000000000000000000000000001"
	contractID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'No Grant Contract')",
		contractID, orgID, contractAddr)
	require.NoError(t, err)

	// Group A: has a contract_grant on this contract
	grantedGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'granted', 'Granted Group', 0, 'granted', false)",
		grantedGroupID, orgID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id, claims) VALUES ($1, $2, $3, '{read}')",
		uuid.New().String(), contractID, grantedGroupID)
	require.NoError(t, err)

	// Group B: same org, NO contract_grant on this contract
	noGrantGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'no-grant', 'No Grant Group', 0, 'no-grant', false)",
		noGrantGroupID, orgID)
	require.NoError(t, err)

	t.Run("member of granted group sees Full", func(t *testing.T) {
		const memberDID = "did:test:nogrant_granted_member"
		addMember(t, database, memberDID, grantedGroupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityFull, visMap[contractAddr],
			"member of group WITH contract_grant must see Full")
	})

	t.Run("member of non-granted group in same org sees Redacted", func(t *testing.T) {
		const memberDID = "did:test:nogrant_no_grant_member"
		addMember(t, database, memberDID, noGrantGroupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractAddr],
			"member of group WITHOUT contract_grant must see Redacted — "+
				"being in the same org is not enough without a grant")
	})

	t.Run("member of different org sees Redacted", func(t *testing.T) {
		// Create a separate org with a group
		otherOrgID := uuid.New().String()
		_, err := conn.ExecContext(ctx,
			"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
			otherOrgID, "other-org-"+otherOrgID[:8], "Other Org")
		require.NoError(t, err)

		otherGroupID := uuid.New().String()
		_, err = conn.ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'members', 'Members', 0, 'members', false)",
			otherGroupID, otherOrgID)
		require.NoError(t, err)

		const memberDID = "did:test:nogrant_other_org_member"
		addMember(t, database, memberDID, otherGroupID)

		visMap, err := database.GetBatchVisibility(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityRedacted, visMap[contractAddr],
			"member of a different org must see Redacted — cross-org isolation")
	})
}

// TestGetBatchVisibilityDetailed_GroupAccessAdminClaim verifies the 3-tier
// visibility model for GetBatchVisibilityDetailed: admin claim + grant = Full.
func TestGetBatchVisibilityDetailed_GroupAccessAdminClaim(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()
	conn := database.Conn()

	orgID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "g11d-org-"+orgID[:8], "G11 Detailed Test Org")
	require.NoError(t, err)

	contractAddr := "0xg11d000000000000000000000000000000000001"
	contractID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'G11D Contract')",
		contractID, orgID, contractAddr)
	require.NoError(t, err)

	// Group with group_access.claims = ['admin'] + contract_grant
	adminClaimGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'admin-claim-d', 'Admin Claim Detailed', 0, 'admin-claim-d', false)",
		adminClaimGroupID, orgID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO group_access (id, group_id, allowed_methods, claims) VALUES ($1, $2, '{\"*\"}', '{admin}')",
		uuid.New().String(), adminClaimGroupID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id) VALUES ($1, $2, $3)",
		uuid.New().String(), contractID, adminClaimGroupID)
	require.NoError(t, err)

	// Group with group_access.claims = ['read'] + contract_grant
	readClaimGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'read-claim-d', 'Read Claim Detailed', 0, 'read-claim-d', false)",
		readClaimGroupID, orgID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO group_access (id, group_id, allowed_methods, claims) VALUES ($1, $2, '{\"*\"}', '{read}')",
		uuid.New().String(), readClaimGroupID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO contract_grants (id, contract_id, group_id) VALUES ($1, $2, $3)",
		uuid.New().String(), contractID, readClaimGroupID)
	require.NoError(t, err)

	t.Run("group_access admin claim + grant = VisibilityFull", func(t *testing.T) {
		const memberDID = "did:test:g11d_admin_claim_member"
		addMember(t, database, memberDID, adminClaimGroupID)

		visMap, err := database.GetBatchVisibilityDetailed(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		vis := visMap[contractAddr]
		assert.Equal(t, explorer.VisibilityFull, vis.Level,
			"member of group with 'admin' in group_access.claims + contract_grant must get VisibilityFull (G11 fix)")
		assert.True(t, vis.Visible)
		assert.Equal(t, explorer.ReasonRBACGroupMember, vis.Reason)
	})

	t.Run("group_access read claim + grant = VisibilityFull (Detailed gives Full to any grant holder)", func(t *testing.T) {
		const memberDID = "did:test:g11d_read_claim_member"
		addMember(t, database, memberDID, readClaimGroupID)

		visMap, err := database.GetBatchVisibilityDetailed(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		vis := visMap[contractAddr]
		// GetBatchVisibilityDetailed (privacy dashboard) gives Full to
		// any grant holder regardless of claims. This differs from GetBatchVisibility
		// (redaction engine) which only gives Full to admins.
		assert.Equal(t, explorer.VisibilityFull, vis.Level,
			"Detailed: any grant holder sees Full (for privacy dashboard)")
		assert.True(t, vis.Visible)
	})

	t.Run("anonymous sees Redacted", func(t *testing.T) {
		visMap, err := database.GetBatchVisibilityDetailed(ctx, "", []string{contractAddr})
		require.NoError(t, err)
		vis := visMap[contractAddr]
		assert.Equal(t, explorer.VisibilityRedacted, vis.Level,
			"anonymous viewer must see org contract as Redacted")
		assert.False(t, vis.Visible)
	})
}

// ============================================================================
// ViewerHasContractAccess
// ============================================================================

func TestViewerHasContractAccess(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	const contractAddr = "0xbbbb000000000000000000000000000000000001"
	contractID, groupID := setupOrgContract(t, database, contractAddr)

	ctx := context.Background()

	t.Run("member has access", func(t *testing.T) {
		const memberDID = "did:privado:has_access_member"
		addMember(t, database, memberDID, groupID)

		ok, err := database.ViewerHasContractAccess(ctx, memberDID, contractID)
		require.NoError(t, err)
		assert.True(t, ok, "group member must have contract access")
	})

	t.Run("non-member has no access", func(t *testing.T) {
		ok, err := database.ViewerHasContractAccess(ctx, "did:privado:no_access_outsider", contractID)
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("empty DID has no access", func(t *testing.T) {
		ok, err := database.ViewerHasContractAccess(ctx, "", contractID)
		require.NoError(t, err)
		assert.False(t, ok, "empty DID must not match any user")
	})

	t.Run("expired membership has no access", func(t *testing.T) {
		const expiredDID = "did:privado:expired_contract_access"
		addExpiredMember(t, database, expiredDID, groupID)

		ok, err := database.ViewerHasContractAccess(ctx, expiredDID, contractID)
		require.NoError(t, err)
		assert.False(t, ok, "expired membership must not grant access")
	})

	t.Run("wrong contract ID has no access", func(t *testing.T) {
		const memberDID = "did:privado:wrong_contract_member"
		addMember(t, database, memberDID, groupID)

		ok, err := database.ViewerHasContractAccess(ctx, memberDID, uuid.New().String())
		require.NoError(t, err)
		assert.False(t, ok, "member of one contract must not access a different contract")
	})
}

// ============================================================================
// Disclosure grants do not affect ordinary visibility
// ============================================================================

// setupDisclosureGrant creates the full disclosure chain:
//
//	org → group → viewer membership → user (target) → eth_address_link
//	    → disclosure_request → disclosure_grant
//
// The viewer is seeded as a member of a group inside the disclosure's org so
// the fixture represents a valid same-org disclosure grant.
// Returns (orgID, targetUserID, grantID).
func setupDisclosureGrant(t *testing.T, database *DB, viewerDID, targetDID, targetEthAddr string, expiresAt time.Time) (orgID, targetUserID, grantID string) {
	t.Helper()
	ctx := context.Background()
	conn := database.Conn()

	orgID = uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "disc-org-"+orgID[:8], "Disclosure Test Org")
	require.NoError(t, err)

	// Group + viewer membership inside the disclosure's org so the
	// grant is valid in the requester's org.
	groupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path) VALUES ($1, $2, 'members', 'Members', 0, 'members')",
		groupID, orgID)
	require.NoError(t, err)
	addMember(t, database, viewerDID, groupID)

	// Create target user
	targetUserID = uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		targetUserID, targetDID)
	require.NoError(t, err)

	// Link ETH address to target user
	err = database.SystemLinkEthAddress(ctx, targetDID, targetEthAddr)
	require.NoError(t, err)

	// Create disclosure request (viewer → target). The "full" level here is
	// intentional — the historical helper assumed full disclosure implicitly
	// via empty scope; post-RD-1009 the level must be explicit, and full keeps
	// the original test semantics intact.
	requestID := uuid.New().String()
	_, err = conn.ExecContext(ctx, `
		INSERT INTO disclosure_requests
			(id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		VALUES ($1, $2, $3, $4, '{"disclosure_level":"full"}'::jsonb, 'Integration test', 'approved', NOW())`,
		requestID, viewerDID, targetUserID, orgID)
	require.NoError(t, err)

	// Create disclosure grant (mirrors the request's level — same rationale).
	grantID = uuid.New().String()
	tokenHash := "testhash_" + grantID[:8]
	_, err = conn.ExecContext(ctx, `
		INSERT INTO disclosure_grants
			(id, request_id, grant_token_hash, scope, granted_at, expires_at)
		VALUES ($1, $2, $3, '{"disclosure_level":"full"}'::jsonb, NOW(), $4)`,
		grantID, requestID, tokenHash, expiresAt)
	require.NoError(t, err)

	return orgID, targetUserID, grantID
}

// ============================================================================
// GetBatchVisibility — disclosure grants are ignored
// ============================================================================

func TestGetBatchVisibility_DisclosureGrant(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()

	const viewerDID = "did:test:disc_batch_viewer"
	const targetDID = "did:test:disc_batch_target"
	const targetEthAddr = "0xd15c000000000000000000000000000000000010"

	futureExpiry := time.Now().Add(24 * time.Hour)
	setupDisclosureGrant(t, database, viewerDID, targetDID, targetEthAddr, futureExpiry)

	t.Run("viewer with disclosure grant sees Hidden", func(t *testing.T) {
		visMap, err := database.GetBatchVisibility(ctx, viewerDID, []string{targetEthAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityHidden, visMap[targetEthAddr],
			"disclosure grants do not affect regular read visibility")
	})

	t.Run("different viewer sees Hidden (EOA with no grant)", func(t *testing.T) {
		visMap, err := database.GetBatchVisibility(ctx, "did:test:disc_other_viewer", []string{targetEthAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityHidden, visMap[targetEthAddr],
			"viewer without disclosure grant must see other user's EOA as Hidden")
	})

	t.Run("anonymous sees Hidden (EOA)", func(t *testing.T) {
		visMap, err := database.GetBatchVisibility(ctx, "", []string{targetEthAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityHidden, visMap[targetEthAddr],
			"anonymous viewer must see owned EOA as Hidden")
	})
}

// ============================================================================
// GetBatchVisibility ignores every disclosure level on ordinary reads.
// ============================================================================

// setupDisclosureGrantWithLevel is like setupDisclosureGrant but writes
// the supplied disclosure_level into the request/grant scope JSON. Pass an
// empty string to leave scope as `{}` (the pre-fix legacy shape) — these
// tests exercise that path explicitly.
func setupDisclosureGrantWithLevel(t *testing.T, database *DB, viewerDID, targetDID, targetEthAddr, level string, expiresAt time.Time) (orgID, targetUserID, grantID string) {
	t.Helper()
	ctx := context.Background()
	conn := database.Conn()

	orgID = uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "disc-lvl-"+orgID[:8], "Disclosure Level Test Org")
	require.NoError(t, err)

	groupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path) VALUES ($1, $2, 'members', 'Members', 0, 'members')",
		groupID, orgID)
	require.NoError(t, err)
	addMember(t, database, viewerDID, groupID)

	targetUserID = uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		targetUserID, targetDID)
	require.NoError(t, err)

	err = database.SystemLinkEthAddress(ctx, targetDID, targetEthAddr)
	require.NoError(t, err)

	scopeJSON := "{}"
	if level != "" {
		scopeJSON = `{"disclosure_level":"` + level + `"}`
	}

	requestID := uuid.New().String()
	_, err = conn.ExecContext(ctx, `
		INSERT INTO disclosure_requests
			(id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, 'level test', 'approved', NOW())`,
		requestID, viewerDID, targetUserID, orgID, scopeJSON)
	require.NoError(t, err)

	grantID = uuid.New().String()
	tokenHash := "testhash_lvl_" + grantID[:8]
	_, err = conn.ExecContext(ctx, `
		INSERT INTO disclosure_grants
			(id, request_id, grant_token_hash, scope, granted_at, expires_at)
		VALUES ($1, $2, $3, $4::jsonb, NOW(), $5)`,
		grantID, requestID, tokenHash, scopeJSON, expiresAt)
	require.NoError(t, err)

	return orgID, targetUserID, grantID
}

func TestGetBatchVisibility_DisclosureGrant_LevelPseudonymous(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()

	const viewerDID = "did:test:lvl_pseudo_viewer"
	const targetDID = "did:test:lvl_pseudo_target"
	const targetEthAddr = "0xd15c000000000000000000000000000000000050"

	setupDisclosureGrantWithLevel(t, database, viewerDID, targetDID, targetEthAddr,
		"pseudonymous", time.Now().Add(24*time.Hour))

	visMap, err := database.GetBatchVisibility(ctx, viewerDID, []string{targetEthAddr})
	require.NoError(t, err)
	assert.Equal(t, explorer.VisibilityHidden, visMap[targetEthAddr],
		"disclosure grants do not affect regular read visibility")
}

func TestGetBatchVisibility_DisclosureGrant_LevelRedacted(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()

	const viewerDID = "did:test:lvl_red_viewer"
	const targetDID = "did:test:lvl_red_target"
	const targetEthAddr = "0xd15c000000000000000000000000000000000051"

	setupDisclosureGrantWithLevel(t, database, viewerDID, targetDID, targetEthAddr,
		"redacted", time.Now().Add(24*time.Hour))

	visMap, err := database.GetBatchVisibility(ctx, viewerDID, []string{targetEthAddr})
	require.NoError(t, err)
	assert.Equal(t, explorer.VisibilityHidden, visMap[targetEthAddr],
		"disclosure grants do not affect regular read visibility")
}

func TestGetBatchVisibility_DisclosureGrant_LevelFull(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()

	const viewerDID = "did:test:lvl_full_viewer"
	const targetDID = "did:test:lvl_full_target"
	const targetEthAddr = "0xd15c000000000000000000000000000000000052"

	setupDisclosureGrantWithLevel(t, database, viewerDID, targetDID, targetEthAddr,
		"full", time.Now().Add(24*time.Hour))

	visMap, err := database.GetBatchVisibility(ctx, viewerDID, []string{targetEthAddr})
	require.NoError(t, err)
	assert.Equal(t, explorer.VisibilityHidden, visMap[targetEthAddr],
		"disclosure grants do not affect regular read visibility")
}

func TestGetBatchVisibility_DisclosureGrant_LevelMissing_FailSafeRedacted(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()

	const viewerDID = "did:test:lvl_missing_viewer"
	const targetDID = "did:test:lvl_missing_target"
	const targetEthAddr = "0xd15c000000000000000000000000000000000053"

	// scope = `{}` (no disclosure_level key) — exercises the legacy / missing path.
	setupDisclosureGrantWithLevel(t, database, viewerDID, targetDID, targetEthAddr,
		"", time.Now().Add(24*time.Hour))

	visMap, err := database.GetBatchVisibility(ctx, viewerDID, []string{targetEthAddr})
	require.NoError(t, err)
	assert.Equal(t, explorer.VisibilityHidden, visMap[targetEthAddr],
		"disclosure grants do not affect regular read visibility")
}

// ============================================================================
// GetBatchVisibilityDetailed — disclosure grant reason
// ============================================================================

func TestGetBatchVisibilityDetailed_DisclosureGrant(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()

	const viewerDID = "did:test:disc_detailed_viewer"
	const targetDID = "did:test:disc_detailed_target"
	const targetEthAddr = "0xd15c000000000000000000000000000000000020"

	futureExpiry := time.Now().Add(24 * time.Hour)
	setupDisclosureGrant(t, database, viewerDID, targetDID, targetEthAddr, futureExpiry)

	t.Run("disclosure grant returns Hidden with no_access reason", func(t *testing.T) {
		visMap, err := database.GetBatchVisibilityDetailed(ctx, viewerDID, []string{targetEthAddr})
		require.NoError(t, err)
		vis := visMap[targetEthAddr]
		assert.Equal(t, explorer.VisibilityHidden, vis.Level)
		assert.False(t, vis.Visible)
		assert.Equal(t, explorer.ReasonNoAccess, vis.Reason)
	})

	t.Run("different viewer sees Hidden with no_access reason", func(t *testing.T) {
		visMap, err := database.GetBatchVisibilityDetailed(ctx, "did:test:disc_detail_other", []string{targetEthAddr})
		require.NoError(t, err)
		vis := visMap[targetEthAddr]
		assert.Equal(t, explorer.VisibilityHidden, vis.Level)
		assert.False(t, vis.Visible)
		assert.Equal(t, explorer.ReasonNoAccess, vis.Reason)
	})

	t.Run("own address takes precedence over disclosure grant", func(t *testing.T) {
		// The target viewing their own address should get own_address, not disclosure_grant
		visMap, err := database.GetBatchVisibilityDetailed(ctx, targetDID, []string{targetEthAddr})
		require.NoError(t, err)
		vis := visMap[targetEthAddr]
		assert.Equal(t, explorer.VisibilityFull, vis.Level)
		assert.True(t, vis.Visible)
		assert.Equal(t, explorer.ReasonOwnAddress, vis.Reason,
			"own_address must take precedence over disclosure_grant")
	})
}

// ============================================================================
// GetVisibleTxHashesForDID — tx_visible_to integration with disclosure context
// ============================================================================

func TestGetVisibleTxHashesForDID_DisclosureContext(t *testing.T) {
	database := setupVisibilityDB(t)
	ctx := context.Background()

	const viewerDID = "did:test:disc_txvis_viewer"
	const otherDID = "did:test:disc_txvis_other"

	// Genuine visibleTo shares remain an independent ordinary-read authority.
	tx1 := "0xd15c111111111111111111111111111111111111111111111111111111111111"
	tx2 := "0xd15c222222222222222222222222222222222222222222222222222222222222"
	tx3 := "0xd15c333333333333333333333333333333333333333333333333333333333333"

	// tx1 and tx2 visible to the disclosure viewer
	require.NoError(t, database.SaveTxVisibility(ctx, tx1, []string{viewerDID}, "did:sender", "org-1"))
	require.NoError(t, database.SaveTxVisibility(ctx, tx2, []string{viewerDID, otherDID}, "did:sender", "org-1"))
	// tx3 only visible to other
	require.NoError(t, database.SaveTxVisibility(ctx, tx3, []string{otherDID}, "did:sender", "org-1"))

	t.Run("viewer sees their disclosed tx hashes", func(t *testing.T) {
		hashes, err := database.GetVisibleTxHashesForDID(ctx, viewerDID)
		require.NoError(t, err)
		assert.Len(t, hashes, 2)
		assert.Contains(t, hashes, tx1)
		assert.Contains(t, hashes, tx2)
	})

	t.Run("other viewer sees their tx hashes only", func(t *testing.T) {
		hashes, err := database.GetVisibleTxHashesForDID(ctx, otherDID)
		require.NoError(t, err)
		assert.Len(t, hashes, 2)
		assert.Contains(t, hashes, tx2)
		assert.Contains(t, hashes, tx3)
	})

	t.Run("unrelated DID gets empty", func(t *testing.T) {
		hashes, err := database.GetVisibleTxHashesForDID(ctx, "did:test:disc_txvis_nobody")
		require.NoError(t, err)
		assert.Nil(t, hashes)
	})

	t.Run("empty DID returns nil", func(t *testing.T) {
		hashes, err := database.GetVisibleTxHashesForDID(ctx, "")
		require.NoError(t, err)
		assert.Nil(t, hashes)
	})
}

// ============================================================================
// Disclosure grant does NOT leak into non-granted viewers (G17 security)
// ============================================================================

func TestDisclosureGrant_NoLeakToOtherViewers(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()

	const viewer1DID = "did:test:disc_leak_viewer1"
	const viewer2DID = "did:test:disc_leak_viewer2"
	const targetDID = "did:test:disc_leak_target"
	const targetEthAddr = "0xd15c000000000000000000000000000000000030"

	futureExpiry := time.Now().Add(24 * time.Hour)

	// Only viewer1 has a disclosure grant on the target
	setupDisclosureGrant(t, database, viewer1DID, targetDID, targetEthAddr, futureExpiry)

	t.Run("granted viewer sees Hidden", func(t *testing.T) {
		visMap, err := database.GetBatchVisibility(ctx, viewer1DID, []string{targetEthAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityHidden, visMap[targetEthAddr])
	})

	t.Run("non-granted viewer sees Hidden", func(t *testing.T) {
		visMap, err := database.GetBatchVisibility(ctx, viewer2DID, []string{targetEthAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityHidden, visMap[targetEthAddr],
			"disclosure grant for viewer1 must NOT leak to viewer2 — G17 security boundary")
	})

	t.Run("detailed: non-granted viewer sees Hidden with no_access", func(t *testing.T) {
		visMap, err := database.GetBatchVisibilityDetailed(ctx, viewer2DID, []string{targetEthAddr})
		require.NoError(t, err)
		vis := visMap[targetEthAddr]
		assert.Equal(t, explorer.VisibilityHidden, vis.Level)
		assert.Equal(t, explorer.ReasonNoAccess, vis.Reason,
			"non-granted viewer must get no_access reason — grant must not leak")
	})
}

// ============================================================================
// Disclosure grant on multiple addresses
// ============================================================================

func TestDisclosureGrant_MultipleAddresses(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()
	conn := database.Conn()

	const viewerDID = "did:test:disc_multi_viewer"
	const targetDID = "did:test:disc_multi_target"
	const addr1 = "0xd15c000000000000000000000000000000000041"
	const addr2 = "0xd15c000000000000000000000000000000000042"
	const unlinkedAddr = "0xd15c000000000000000000000000000000000043"

	orgID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "disc-multi-"+orgID[:8], "Disclosure Multi Org")
	require.NoError(t, err)

	// Group + viewer membership in the disclosure's org so the M13 org-scoping
	// requirements for the grant API are satisfied.
	groupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path) VALUES ($1, $2, 'members', 'Members', 0, 'members')",
		groupID, orgID)
	require.NoError(t, err)
	addMember(t, database, viewerDID, groupID)

	// Create target user with TWO linked ETH addresses
	targetUserID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		targetUserID, targetDID)
	require.NoError(t, err)

	err = database.SystemLinkEthAddress(ctx, targetDID, addr1)
	require.NoError(t, err)
	err = database.SystemLinkEthAddress(ctx, targetDID, addr2)
	require.NoError(t, err)

	// Create disclosure grant. Multi-address test asserts the multi-row join
	// behaviour; the level just needs to be a real, supported value (full).
	requestID := uuid.New().String()
	_, err = conn.ExecContext(ctx, `
		INSERT INTO disclosure_requests
			(id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		VALUES ($1, $2, $3, $4, '{"disclosure_level":"full"}'::jsonb, 'Multi-address test', 'approved', NOW())`,
		requestID, viewerDID, targetUserID, orgID)
	require.NoError(t, err)

	grantID := uuid.New().String()
	tokenHash := "testhash_multi_" + grantID[:8]
	_, err = conn.ExecContext(ctx, `
		INSERT INTO disclosure_grants
			(id, request_id, grant_token_hash, scope, granted_at, expires_at)
		VALUES ($1, $2, $3, '{"disclosure_level":"full"}'::jsonb, NOW(), $4)`,
		grantID, requestID, tokenHash, time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	t.Run("batch visibility: both addresses Hidden, unlinked Hidden", func(t *testing.T) {
		visMap, err := database.GetBatchVisibility(ctx, viewerDID, []string{addr1, addr2, unlinkedAddr})
		require.NoError(t, err)
		assert.Equal(t, explorer.VisibilityHidden, visMap[addr1],
			"disclosure grants do not affect regular read visibility")
		assert.Equal(t, explorer.VisibilityHidden, visMap[addr2],
			"disclosure grants do not affect regular read visibility")
		assert.Equal(t, explorer.VisibilityHidden, visMap[unlinkedAddr],
			"unlinked address must remain Hidden")
	})
}

// ============================================================================
// GetBatchEventAccess
// ============================================================================

func TestGetBatchEventAccess(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	const contractAddr = "0xeeee000000000000000000000000000000000001"
	ctx := context.Background()

	// Setup: org, group, contract, grant (no event_rules by default)
	contractID, groupID := setupOrgContract(t, database, contractAddr)

	const memberDID = "did:privado:event_member"
	addMember(t, database, memberDID, groupID)

	t.Run("empty addresses returns empty map", func(t *testing.T) {
		result, err := database.GetBatchEventAccess(ctx, memberDID, nil)
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("empty viewer DID returns empty map", func(t *testing.T) {
		result, err := database.GetBatchEventAccess(ctx, "", []string{contractAddr})
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("member without event_rules has no event access", func(t *testing.T) {
		// Default contract_grant has NULL event_rules
		result, err := database.GetBatchEventAccess(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.False(t, result[contractAddr], "NULL event_rules means no event access")
	})

	t.Run("member with empty array event_rules has no event access", func(t *testing.T) {
		_, err := database.Conn().ExecContext(ctx,
			"UPDATE contract_grants SET event_rules = '[]' WHERE contract_id = $1 AND group_id = $2",
			contractID, groupID)
		require.NoError(t, err)

		result, err := database.GetBatchEventAccess(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.False(t, result[contractAddr], "empty array event_rules means no event access")
	})

	t.Run("member with non-empty event_rules has event access", func(t *testing.T) {
		_, err := database.Conn().ExecContext(ctx,
			`UPDATE contract_grants SET event_rules = '[{"topic0":"0xddf252"}]' WHERE contract_id = $1 AND group_id = $2`,
			contractID, groupID)
		require.NoError(t, err)

		result, err := database.GetBatchEventAccess(ctx, memberDID, []string{contractAddr})
		require.NoError(t, err)
		assert.True(t, result[contractAddr], "non-empty event_rules grants event access")
	})

	t.Run("org admin always has event access", func(t *testing.T) {
		// Reset event_rules to NULL
		_, err := database.Conn().ExecContext(ctx,
			"UPDATE contract_grants SET event_rules = NULL WHERE contract_id = $1 AND group_id = $2",
			contractID, groupID)
		require.NoError(t, err)

		// Create admin group
		const adminDID = "did:privado:event_admin"
		adminGroupID := uuid.New().String()
		var orgID string
		err = database.Conn().QueryRowContext(ctx,
			"SELECT org_id FROM groups WHERE id = $1", groupID).Scan(&orgID)
		require.NoError(t, err)
		_, err = database.Conn().ExecContext(ctx,
			"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'event-admins', 'Event Admins', 0, 'event-admins', true)",
			adminGroupID, orgID)
		require.NoError(t, err)
		addMember(t, database, adminDID, adminGroupID)

		result, err := database.GetBatchEventAccess(ctx, adminDID, []string{contractAddr})
		require.NoError(t, err)
		assert.True(t, result[contractAddr], "org admin always has event access")
	})

	t.Run("expired member has no event access", func(t *testing.T) {
		const expiredDID = "did:privado:event_expired"
		// Set event_rules to non-empty so the grant would qualify
		_, err := database.Conn().ExecContext(ctx,
			`UPDATE contract_grants SET event_rules = '[{"topic0":"0xddf252"}]' WHERE contract_id = $1 AND group_id = $2`,
			contractID, groupID)
		require.NoError(t, err)

		addExpiredMember(t, database, expiredDID, groupID)

		result, err := database.GetBatchEventAccess(ctx, expiredDID, []string{contractAddr})
		require.NoError(t, err)
		assert.False(t, result[contractAddr], "expired member has no event access")
	})

	t.Run("non-member has no event access", func(t *testing.T) {
		result, err := database.GetBatchEventAccess(ctx, "did:privado:stranger", []string{contractAddr})
		require.NoError(t, err)
		assert.False(t, result[contractAddr])
	})
}
