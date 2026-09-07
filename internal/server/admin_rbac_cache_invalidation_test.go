package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedDBCache writes a synthetic DB permission-cache entry for (user, org).
// Used by RD-838 tests to reliably reproduce the "stale cached entry" state
// without depending on the resolver's own publication, which is guarded: it
// only writes when the cache generation has not moved (RD-1267), so a test
// cannot simply ask for a resolve and rely on a row appearing. This calls the
// concrete *db.DB method, deliberately bypassing the guard — seeding a known
// row is exactly the case the guard should not police.
func seedDBCache(t *testing.T, server *testServerRBAC, userID, orgID string) {
	t.Helper()
	err := server.db.SetCachedPermissions(context.Background(), &rbac.EffectivePermissions{
		ID:             uuid.New().String(),
		UserID:         userID,
		OrgID:          orgID,
		AllowedMethods: []string{"eth_call"},
		ContractAccess: map[string]rbac.ContractAccess{},
		Claims:         []rbac.Claim{},
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(5 * time.Minute),
	})
	require.NoError(t, err)
}

// RD-838: RBAC permission caches (in-memory + DB) must be invalidated immediately
// when an admin mutation changes a user's effective permissions. These tests
// prove that the fix propagates changes within a single request — no TTL wait,
// no backend restart — which is what `demo-verify-no-grant.sh` now expects.

// TestCacheInvalidation_MembershipToggle is the primary acceptance test from the
// ticket: toggle membership via the admin API, then immediately call a gated
// method as that user — the gate state must match without any sleep or restart.
func TestCacheInvalidation_MembershipToggle(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "cache-inv-membership-org")
	group := createTestGroup(t, server, org.ID, "cache-inv-membership-group")

	// Give the group permission to call eth_call with no extra claims needed.
	setAccessBody, _ := json.Marshal(map[string]any{
		"allowed_methods": []string{"eth_call"},
		"claims":          []string{},
	})
	accessReq := httptest.NewRequest(http.MethodPut,
		fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID),
		bytes.NewReader(setAccessBody))
	accessReq.Header.Set("Content-Type", "application/json")
	accessW := httptest.NewRecorder()
	server.router.ServeHTTP(accessW, accessReq)
	require.Equal(t, http.StatusOK, accessW.Code)

	// Create a KYC'd user and put them in the group.
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:cache-invalidation-user",
		KYC:        true,
	}
	require.NoError(t, server.db.CreateUser(ctx, user))

	membership := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: group.ID,
		Source:  rbac.MembershipSourceAdmin,
	}
	require.NoError(t, server.db.CreateMembership(ctx, membership))

	// First CheckAccess populates the in-memory cache.
	res, err := server.rbacAccessCtrl.CheckAccess(ctx, &rbac.AccessCheckRequest{
		UserExternalID: user.ExternalID,
		OrgID:          org.ID,
		Method:         "eth_call",
	})
	require.NoError(t, err)
	require.True(t, res.Allowed, "user with membership should be allowed before revocation")
	require.Equal(t, 1, server.rbacAccessCtrl.CacheStats().Entries,
		"in-memory cache should have exactly one entry after CheckAccess")

	// Confirm the resolver's cache write landed before we trigger the
	// invalidation, so the test is genuinely exercising "invalidate an
	// existing row" and not "invalidate nothing".
	//
	// This was originally a race barrier: the publish ran in a goroutine
	// started by CheckAccess, which could land AFTER the DELETE handler and
	// resurrect the row. That goroutine is gone — the publish is now
	// synchronous inside the resolve, under the generation guard — so this is
	// a plain precondition assertion and should pass on the first poll.
	require.Eventually(t, func() bool {
		cached, err := server.db.GetCachedPermissions(ctx, user.ID, org.ID)
		return err == nil && cached != nil
	}, 5*time.Second, 10*time.Millisecond,
		"resolver cache write should have landed before the invalidation test runs")

	// Seed the DB cache synchronously so we can reliably observe invalidation.
	// (The Eventually above guarantees the goroutine is done; this upsert
	// gives us a stable row identity for the post-delete assertion.)
	seedDBCache(t, server, user.ID, org.ID)
	dbCached, err := server.db.GetCachedPermissions(ctx, user.ID, org.ID)
	require.NoError(t, err)
	require.NotNil(t, dbCached)

	// ACT: revoke the membership via the admin HTTP API — same path operators hit.
	delReq := httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/api/users/%s/memberships/%s", user.ID, membership.ID), nil)
	delW := httptest.NewRecorder()
	server.router.ServeHTTP(delW, delReq)
	require.Equal(t, http.StatusOK, delW.Code)

	// ASSERT: both cache layers must be cleared before the handler returned.
	// If either layer is still populated, live traffic would see stale perms
	// for up to cacheTTL (5 minutes by default) — this is the exact bug RD-838
	// is fixing.
	assert.Zero(t, server.rbacAccessCtrl.CacheStats().Entries,
		"in-memory cache must be cleared for the affected user")
	dbCached, err = server.db.GetCachedPermissions(ctx, user.ID, org.ID)
	require.NoError(t, err)
	assert.Nil(t, dbCached, "DB permission cache must be cleared for the affected user")

	// Re-resolving access in the same request must reflect the new state.
	res, err = server.rbacAccessCtrl.CheckAccess(ctx, &rbac.AccessCheckRequest{
		UserExternalID: user.ExternalID,
		OrgID:          org.ID,
		Method:         "eth_call",
	})
	require.NoError(t, err)
	assert.False(t, res.Allowed,
		"access must be denied immediately after membership removal — no TTL wait")

	// ACT again: re-add the user to the group and verify access is restored
	// within the same request. This is demo-verify-no-grant.sh Phase 4.
	reAddBody, _ := json.Marshal(map[string]any{"group_id": group.ID})
	reAddReq := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/users/%s/memberships", user.ID),
		bytes.NewReader(reAddBody))
	reAddReq.Header.Set("Content-Type", "application/json")
	reAddW := httptest.NewRecorder()
	server.router.ServeHTTP(reAddW, reAddReq)
	require.Equal(t, http.StatusCreated, reAddW.Code)

	res, err = server.rbacAccessCtrl.CheckAccess(ctx, &rbac.AccessCheckRequest{
		UserExternalID: user.ExternalID,
		OrgID:          org.ID,
		Method:         "eth_call",
	})
	require.NoError(t, err)
	assert.True(t, res.Allowed,
		"access must be restored immediately after re-adding membership — no TTL wait")
}

// TestCacheInvalidation_GroupAccessUpdate verifies that changing a group's
// allowed methods propagates to every member's cache within the same request.
func TestCacheInvalidation_GroupAccessUpdate(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "cache-inv-access-org")
	group := createTestGroup(t, server, org.ID, "cache-inv-access-group")

	// Start with eth_call allowed.
	setAccess := func(methods []string) {
		body, _ := json.Marshal(map[string]any{
			"allowed_methods": methods,
			"claims":          []string{},
		})
		req := httptest.NewRequest(http.MethodPut,
			fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID),
			bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	}
	setAccess([]string{"eth_call"})

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:access-update-user",
		KYC:        true,
	}
	require.NoError(t, server.db.CreateUser(ctx, user))
	require.NoError(t, server.db.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: group.ID,
		Source:  rbac.MembershipSourceAdmin,
	}))

	// Prime the caches.
	res, err := server.rbacAccessCtrl.CheckAccess(ctx, &rbac.AccessCheckRequest{
		UserExternalID: user.ExternalID,
		OrgID:          org.ID,
		Method:         "eth_call",
	})
	require.NoError(t, err)
	require.True(t, res.Allowed)
	require.Equal(t, 1, server.rbacAccessCtrl.CacheStats().Entries)

	// Narrow the group's allowed methods — must immediately deny eth_call.
	setAccess([]string{"eth_blockNumber"})

	assert.Zero(t, server.rbacAccessCtrl.CacheStats().Entries,
		"in-memory cache must be cleared when group access changes")

	res, err = server.rbacAccessCtrl.CheckAccess(ctx, &rbac.AccessCheckRequest{
		UserExternalID: user.ExternalID,
		OrgID:          org.ID,
		Method:         "eth_call",
	})
	require.NoError(t, err)
	assert.False(t, res.Allowed,
		"eth_call must be denied immediately after group access change")
}

// TestCacheInvalidation_BatchDeleteGroups verifies that the batch-delete endpoint
// clears the in-memory cache as well as the DB cache. Before the RD-838 fix, it
// only cleared the DB cache inside the transaction, so in-memory entries survived
// until TTL.
func TestCacheInvalidation_BatchDeleteGroups(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "cache-inv-batch-org")
	group := createTestGroup(t, server, org.ID, "cache-inv-batch-group")

	body, _ := json.Marshal(map[string]any{
		"allowed_methods": []string{"eth_call"},
		"claims":          []string{},
	})
	accessReq := httptest.NewRequest(http.MethodPut,
		fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID),
		bytes.NewReader(body))
	accessReq.Header.Set("Content-Type", "application/json")
	accessW := httptest.NewRecorder()
	server.router.ServeHTTP(accessW, accessReq)
	require.Equal(t, http.StatusOK, accessW.Code)

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:batch-user",
		KYC:        true,
	}
	require.NoError(t, server.db.CreateUser(ctx, user))
	require.NoError(t, server.db.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: group.ID,
		Source:  rbac.MembershipSourceAdmin,
	}))

	res, err := server.rbacAccessCtrl.CheckAccess(ctx, &rbac.AccessCheckRequest{
		UserExternalID: user.ExternalID,
		OrgID:          org.ID,
		Method:         "eth_call",
	})
	require.NoError(t, err)
	require.True(t, res.Allowed)
	require.Equal(t, 1, server.rbacAccessCtrl.CacheStats().Entries)

	// Batch-delete the group.
	batchBody, _ := json.Marshal(map[string]any{"group_ids": []string{group.ID}})
	batchReq := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/orgs/%s/groups/batch-delete", org.ID),
		bytes.NewReader(batchBody))
	batchReq.Header.Set("Content-Type", "application/json")
	batchW := httptest.NewRecorder()
	server.router.ServeHTTP(batchW, batchReq)
	require.Equal(t, http.StatusOK, batchW.Code)

	assert.Zero(t, server.rbacAccessCtrl.CacheStats().Entries,
		"batch-delete must also invalidate the in-memory cache, not just the DB cache")
}
