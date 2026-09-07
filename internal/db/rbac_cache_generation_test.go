package db

import (
	"context"
	"testing"
	"time"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
)

// RD-1267: the permission cache is shared SQL and invalidation is a DELETE
// committed by the mutating transaction, so the guard against publishing a
// stale compute has to work against real PostgreSQL semantics — not just in
// process. These tests exercise the two orderings that matter.

func cacheGenFixtures(t *testing.T, db *DB, ctx context.Context) (userID, orgID string) {
	t.Helper()
	org := &rbac.Organization{
		ID:       uuid.New().String(),
		Slug:     "cachegen-org-" + uuid.New().String()[:8],
		Name:     "Cache Generation Org",
		Settings: map[string]any{},
	}
	if err := db.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("create org: %v", err)
	}
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:cachegen-" + uuid.New().String()[:8],
		KYC:        true,
	}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user.ID, org.ID
}

func cacheGenPerms(userID, orgID string, method string) *rbac.EffectivePermissions {
	return &rbac.EffectivePermissions{
		ID:             uuid.New().String(),
		UserID:         userID,
		OrgID:          orgID,
		AllowedMethods: []string{method},
		Claims:         []rbac.Claim{rbac.ClaimDeploy},
		ContractAccess: map[string]rbac.ContractAccess{},
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(5 * time.Minute),
	}
}

// A publication whose baseline generation is current must land.
func TestSetCachedPermissionsAtGeneration_PublishesWhenGenerationUnchanged(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	userID, orgID := cacheGenFixtures(t, db, ctx)

	gen, err := db.CacheGeneration(ctx)
	if err != nil {
		t.Fatalf("read generation: %v", err)
	}

	published, err := db.SetCachedPermissionsAtGeneration(ctx, cacheGenPerms(userID, orgID, "eth_call"), gen)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !published {
		t.Fatal("published = false with an unchanged generation; the guard would disable caching entirely")
	}

	cached, err := db.GetCachedPermissions(ctx, userID, orgID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if cached == nil {
		t.Fatal("entry was reported published but is not in the cache")
	}
}

// The core RD-1267 case: an invalidation commits after the baseline was read,
// so the publication must be refused and the cache must stay empty.
func TestSetCachedPermissionsAtGeneration_RefusesAfterInvalidation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	userID, orgID := cacheGenFixtures(t, db, ctx)

	// Baseline read before the "compute".
	gen, err := db.CacheGeneration(ctx)
	if err != nil {
		t.Fatalf("read generation: %v", err)
	}

	// A mutation commits mid-compute: it deletes nothing (nothing cached yet)
	// and bumps the generation. This is exactly the window that used to let a
	// revoked grant survive in cache for the full TTL.
	if err := db.InvalidateCacheForOrg(ctx, orgID); err != nil {
		t.Fatalf("invalidate: %v", err)
	}

	published, err := db.SetCachedPermissionsAtGeneration(ctx, cacheGenPerms(userID, orgID, "eth_call"), gen)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if published {
		t.Error("stale permissions were published after an invalidation committed")
	}

	cached, err := db.GetCachedPermissions(ctx, userID, orgID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if cached != nil {
		t.Errorf("cache holds a stale entry (methods=%v) after an invalidation; it must be empty so the next resolve recomputes", cached.AllowedMethods)
	}

	// The counter moved, and monotonically.
	after, err := db.CacheGeneration(ctx)
	if err != nil {
		t.Fatalf("read generation: %v", err)
	}
	if after <= gen {
		t.Errorf("generation did not advance: before=%d after=%d", gen, after)
	}
}

// Every invalidation entry point must bump the counter, including the *Tx
// variants used by the admin handlers — those are the ones that never call
// through the resolver, and the reason the counter cannot live in process.
func TestInvalidationPathsBumpGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	userID, orgID := cacheGenFixtures(t, db, ctx)

	cases := []struct {
		name string
		run  func() error
	}{
		{"DB.InvalidateCacheForUser", func() error { return db.InvalidateCacheForUser(ctx, userID) }},
		{"DB.InvalidateCacheForOrg", func() error { return db.InvalidateCacheForOrg(ctx, orgID) }},
		{"DB.InvalidateCacheForGroup", func() error { return db.InvalidateCacheForGroup(ctx, uuid.New().String()) }},
		{"Tx.InvalidateCacheForOrg", func() error {
			return db.WithTx(ctx, func(tx *Tx) error { return tx.InvalidateCacheForOrg(ctx, orgID) })
		}},
		{"Tx.InvalidateCacheForGroup", func() error {
			return db.WithTx(ctx, func(tx *Tx) error { return tx.InvalidateCacheForGroup(ctx, uuid.New().String()) })
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before, err := db.CacheGeneration(ctx)
			if err != nil {
				t.Fatalf("read generation: %v", err)
			}
			if err := tc.run(); err != nil {
				t.Fatalf("invalidate: %v", err)
			}
			after, err := db.CacheGeneration(ctx)
			if err != nil {
				t.Fatalf("read generation: %v", err)
			}
			if after != before+1 {
				t.Errorf("generation %d -> %d, want +1; this path would not stop a stale publication", before, after)
			}
		})
	}
}

// The ordering the FOR SHARE lock exists for: an invalidating transaction that
// has run its DELETE and bump but has NOT committed yet. A plain read under
// READ COMMITTED would see the old generation, publish, and the row would
// survive the already-executed DELETE. The publication must instead block on
// the counter's row lock and then refuse.
func TestSetCachedPermissionsAtGeneration_SerializesAgainstUncommittedInvalidation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	userID, orgID := cacheGenFixtures(t, db, ctx)

	gen, err := db.CacheGeneration(ctx)
	if err != nil {
		t.Fatalf("read generation: %v", err)
	}

	// Open an invalidating transaction and run its DELETE + bump, holding it open.
	tx, err := db.BeginTx(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := tx.InvalidateCacheForOrg(ctx, orgID); err != nil {
		t.Fatalf("invalidate in tx: %v", err)
	}

	// Publish concurrently: it must block on the generation row rather than
	// racing ahead with the stale baseline.
	type result struct {
		published bool
		err       error
	}
	done := make(chan result, 1)
	go func() {
		p, err := db.SetCachedPermissionsAtGeneration(ctx, cacheGenPerms(userID, orgID, "eth_call"), gen)
		done <- result{p, err}
	}()

	select {
	case r := <-done:
		t.Fatalf("publication completed while the invalidation was still open (published=%v, err=%v); it did not serialize on the generation row", r.published, r.err)
	case <-time.After(300 * time.Millisecond):
		// Correct: blocked on the row lock.
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	r := <-done
	if r.err != nil {
		t.Fatalf("publish after unblocking: %v", r.err)
	}
	if r.published {
		t.Error("published stale permissions after the invalidation committed")
	}

	cached, err := db.GetCachedPermissions(ctx, userID, orgID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if cached != nil {
		t.Error("cache holds a stale entry that the invalidation's DELETE had already passed over")
	}
}
