package db

import (
	"context"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
)

// RD-1267 review finding P1 #2 — the generation bump must commit WITH the
// authorization mutation, not merely before it.
//
// The revoke handlers used to invalidate the cache and then delete the
// grant/group/contract in a separate statement. That ordering is exploitable:
//
//  1. handler invalidates            -> generation becomes N
//  2. a compute snapshots generation N and reads the STILL-PRESENT grant
//  3. handler's delete commits
//  4. the compute publishes at N     -> generation is still N, so ACCEPTED
//
// and the revoked grant is served from cache for the whole TTL. The sequence
// is reproduced deterministically below, because the publication takes the
// baseline generation as an explicit argument — no concurrency needed to pin
// the defect.

// revokeFixtures builds an org, user, group, membership, contract and grant,
// returning the ids the revoke paths need.
func revokeFixtures(t *testing.T, db *DB, ctx context.Context) (userID, orgID, groupID, contractID, grantID string) {
	t.Helper()
	userID, orgID = cacheGenFixtures(t, db, ctx)

	group := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: orgID,
		Slug:  "revoke-grp-" + uuid.New().String()[:8],
		Name:  "Revoke Group",
	}
	if err := db.CreateGroup(ctx, group); err != nil {
		t.Fatalf("create group: %v", err)
	}
	membership := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  userID,
		GroupID: group.ID,
	}
	if err := db.CreateMembership(ctx, membership); err != nil {
		t.Fatalf("create membership: %v", err)
	}
	contract := &rbac.Contract{
		ID:      uuid.New().String(),
		OrgID:   orgID,
		Address: "0x" + uuid.New().String()[:8] + "000000000000000000000000000000",
		Name:    "Revoke Contract",
	}
	if err := db.CreateContract(ctx, contract); err != nil {
		t.Fatalf("create contract: %v", err)
	}
	grant := &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contract.ID,
		GroupID:    group.ID,
	}
	if err := db.CreateContractGrant(ctx, grant); err != nil {
		t.Fatalf("create grant: %v", err)
	}
	return userID, orgID, group.ID, contract.ID, grant.ID
}

// TestDeleteContractGrantAndInvalidate_RejectsPublicationSnapshottedBeforeRevoke
// is the regression test. The compute snapshots the generation BEFORE the
// revoke, exactly as it would in the exploitable interleaving; the atomic
// revoke must then reject its publication.
func TestDeleteContractGrantAndInvalidate_RejectsPublicationSnapshottedBeforeRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	userID, orgID, groupID, _, grantID := revokeFixtures(t, db, ctx)

	// A compute begins: it snapshots the generation and reads the grant, which
	// is still present. These permissions therefore still carry the grant.
	genBefore, err := db.CacheGeneration(ctx)
	if err != nil {
		t.Fatalf("CacheGeneration: %v", err)
	}
	stale := cacheGenPerms(userID, orgID, "eth_call")

	// The admin revokes the grant. Invalidation and delete commit together.
	if err := db.DeleteContractGrantAndInvalidate(ctx, grantID, groupID); err != nil {
		t.Fatalf("DeleteContractGrantAndInvalidate: %v", err)
	}

	// The bump must be observable, otherwise the guard has nothing to compare.
	genAfter, err := db.CacheGeneration(ctx)
	if err != nil {
		t.Fatalf("CacheGeneration after revoke: %v", err)
	}
	if genAfter == genBefore {
		t.Fatalf("generation did not move across the revoke (%d); the bump is not committing with the mutation", genAfter)
	}

	// The in-flight compute now tries to publish what it read before the
	// revoke. It must be refused.
	published, err := db.SetCachedPermissionsAtGeneration(ctx, stale, genBefore)
	if err != nil {
		t.Fatalf("SetCachedPermissionsAtGeneration: %v", err)
	}
	if published {
		t.Error("a publication snapshotted before the revoke was accepted; the revoked grant would stay usable for the cache TTL")
	}

	// And nothing stale is left behind for the next reader.
	cached, err := db.GetCachedPermissions(ctx, userID, orgID)
	if err != nil {
		t.Fatalf("GetCachedPermissions: %v", err)
	}
	if cached != nil {
		t.Error("stale permissions are present in the cache after the revoke")
	}
}

// TestDeleteGroupAndInvalidate_RejectsPublicationSnapshottedBeforeRevoke is the
// same property for the delete-group path.
func TestDeleteGroupAndInvalidate_RejectsPublicationSnapshottedBeforeRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	userID, orgID, groupID, _, _ := revokeFixtures(t, db, ctx)

	genBefore, err := db.CacheGeneration(ctx)
	if err != nil {
		t.Fatalf("CacheGeneration: %v", err)
	}
	stale := cacheGenPerms(userID, orgID, "eth_call")

	// Memberships, grants and access rows are ON DELETE CASCADE from groups
	// (001_initial_schema.sql), which is what the plain delete-group handler
	// relies on.
	if err := db.DeleteGroupAndInvalidate(ctx, groupID); err != nil {
		t.Fatalf("DeleteGroupAndInvalidate: %v", err)
	}

	published, err := db.SetCachedPermissionsAtGeneration(ctx, stale, genBefore)
	if err != nil {
		t.Fatalf("SetCachedPermissionsAtGeneration: %v", err)
	}
	if published {
		t.Error("a publication snapshotted before the group delete was accepted; the deleted group's access would stay usable for the cache TTL")
	}
}

// TestDeleteContractAndInvalidate_RejectsPublicationSnapshottedBeforeRevoke is
// the same property for the delete-contract path, which invalidates org-wide.
func TestDeleteContractAndInvalidate_RejectsPublicationSnapshottedBeforeRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	userID, orgID, _, contractID, _ := revokeFixtures(t, db, ctx)

	genBefore, err := db.CacheGeneration(ctx)
	if err != nil {
		t.Fatalf("CacheGeneration: %v", err)
	}
	stale := cacheGenPerms(userID, orgID, "eth_call")

	// Contract grants are ON DELETE CASCADE from contracts, which is what the
	// plain delete-contract handler relies on.
	if err := db.DeleteContractAndInvalidate(ctx, contractID, orgID); err != nil {
		t.Fatalf("DeleteContractAndInvalidate: %v", err)
	}

	published, err := db.SetCachedPermissionsAtGeneration(ctx, stale, genBefore)
	if err != nil {
		t.Fatalf("SetCachedPermissionsAtGeneration: %v", err)
	}
	if published {
		t.Error("a publication snapshotted before the contract delete was accepted")
	}
}

// TestRevokeOrdering_TwoStepIsExploitable_AtomicIsNot is the discriminating
// test: it runs BOTH orderings against a real database so the atomic variant's
// value is demonstrated rather than asserted.
//
// The two-step sequence is what the handlers did before this change. It is
// reproduced here directly (invalidate, then delete in a separate statement)
// to show the publication is accepted — the fail-open outcome. The atomic
// sequence rejects the same publication. If the handlers ever regress to the
// two-step form, the behaviour proven exploitable here is what returns.
func TestRevokeOrdering_TwoStepIsExploitable_AtomicIsNot(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()

	t.Run("two-step invalidate-then-delete accepts a stale publication", func(t *testing.T) {
		userID, orgID, groupID, _, grantID := revokeFixtures(t, db, ctx)

		// Step 1 of the old handler: invalidate. This bumps the generation.
		if err := db.InvalidateCacheForGroup(ctx, groupID); err != nil {
			t.Fatalf("InvalidateCacheForGroup: %v", err)
		}
		// A compute now snapshots the generation and reads the grant, which
		// step 2 has not yet removed.
		gen, err := db.CacheGeneration(ctx)
		if err != nil {
			t.Fatalf("CacheGeneration: %v", err)
		}
		stale := cacheGenPerms(userID, orgID, "eth_call")

		// Step 2 of the old handler: the delete finally commits.
		if err := db.DeleteContractGrant(ctx, grantID); err != nil {
			t.Fatalf("DeleteContractGrant: %v", err)
		}

		// The generation has not moved since the snapshot, so the guard has no
		// signal and the revoked permissions are published.
		published, err := db.SetCachedPermissionsAtGeneration(ctx, stale, gen)
		if err != nil {
			t.Fatalf("SetCachedPermissionsAtGeneration: %v", err)
		}
		if !published {
			t.Skip("two-step ordering no longer reproduces the window; the exploit premise has changed and this test needs revisiting")
		}
		t.Log("confirmed: the two-step ordering publishes permissions for an already-revoked grant")
	})

	t.Run("atomic invalidate+delete rejects the same publication", func(t *testing.T) {
		userID, orgID, groupID, _, grantID := revokeFixtures(t, db, ctx)

		gen, err := db.CacheGeneration(ctx)
		if err != nil {
			t.Fatalf("CacheGeneration: %v", err)
		}
		stale := cacheGenPerms(userID, orgID, "eth_call")

		if err := db.DeleteContractGrantAndInvalidate(ctx, grantID, groupID); err != nil {
			t.Fatalf("DeleteContractGrantAndInvalidate: %v", err)
		}

		published, err := db.SetCachedPermissionsAtGeneration(ctx, stale, gen)
		if err != nil {
			t.Fatalf("SetCachedPermissionsAtGeneration: %v", err)
		}
		if published {
			t.Error("the atomic revoke accepted a publication snapshotted before it; the guard is not effective")
		}
	})
}
