package rbac

import (
	"context"
	"testing"
	"time"
)

// guardOnlyStore opts into nothing: it embeds the inert shared fake, so it
// inherits fakeStore's fail-CLOSED generation defaults.
type guardOnlyStore struct{ fakeStore }

// TestResolvePermissions_UnopinionatedStoreNeverPublishes pins the fail-closed
// default that replaced RD-1267's fail-open fallback (RD-1276).
//
// The guard used to be an optional capability, type-asserted at runtime, and a
// Store that did not implement it fell through to an unconditional publish
// with cacheable=true — the exact fail-open this machinery exists to prevent,
// and it would have been inherited silently by any second Store
// implementation. The capability is now embedded in Store, so "no guard" is a
// compile error rather than a runtime fallback; this test covers the remaining
// runtime axis, namely that a store which refuses to publish is reported as
// non-cacheable rather than assumed safe.
func TestResolvePermissions_UnopinionatedStoreNeverPublishes(t *testing.T) {
	r := NewResolver(&guardOnlyStore{}, time.Minute)

	perms, cacheable, err := r.ResolvePermissionsCacheable(context.Background(), "user-1", "org-1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if perms == nil {
		t.Fatal("expected a permission set even when nothing is published")
	}
	if cacheable {
		t.Error("a store that did not publish must never be reported as cacheable: an upper cache would then hold an entry the shared cache refused")
	}
}
