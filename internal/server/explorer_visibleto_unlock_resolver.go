package server

import (
	"context"

	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"
)

// dbVisibleToUnlockResolver implements explorer.VisibleToUnlockResolver
// with rbac.UnlockableContracts — the same helper the JSON-RPC layer's
// processor_event_rules.go::buildVisibleToUnlockableMap calls — so the two
// layers agree on the (viewer, contract) → unlock set by construction, as
// the access / visibility symmetry invariant in REDACTION_SPEC.md requires.
type dbVisibleToUnlockResolver struct {
	access *rbac.AccessController
}

func newDBVisibleToUnlockResolver(access *rbac.AccessController) *dbVisibleToUnlockResolver {
	return &dbVisibleToUnlockResolver{access: access}
}

// Resolve returns the subset of the supplied addresses that are
// (a) registered with `allow_visibleto_unlock = true` AND (b) the
// viewer is unlock-eligible for. See explorer.VisibleToUnlockResolver
// for the full contract.
func (r *dbVisibleToUnlockResolver) Resolve(ctx context.Context, viewerDID string, addresses []string) map[string]bool {
	return rbac.UnlockableContracts(ctx, r.access, viewerDID, addresses)
}

// Compile-time assertion that *dbVisibleToUnlockResolver satisfies
// explorer.VisibleToUnlockResolver.
var _ explorer.VisibleToUnlockResolver = (*dbVisibleToUnlockResolver)(nil)
