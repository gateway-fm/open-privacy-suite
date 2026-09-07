package rbac

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"privacy-proxy/internal/crypto"
)

// Resolver computes effective permissions for users.
type Resolver struct {
	store         Store
	cacheTTL      time.Duration
	encryptionKey []byte // AES-256 key for decrypting stored RPC API keys (nil = no encryption)

	// inFlight tracks computations that are in progress to prevent cache stampede
	inFlight   map[string]*inFlightEntry
	inFlightMu sync.RWMutex
}

// inFlightEntry holds the result of an in-progress permission computation.
// Uses a closed channel as a broadcast signal so all waiting goroutines are woken.
type inFlightEntry struct {
	done  chan struct{} // closed when computation is complete
	perms *EffectivePermissions
	err   error
	// publishable carries the RD-1267 verdict to singleflight waiters. A
	// waiter never ran the compute, so it cannot re-derive whether an
	// invalidation raced it; it must inherit the computing goroutine's
	// answer, or the waiter would copy discarded permissions into the
	// upper cache that the computing goroutine correctly withheld.
	publishable bool
}

// NewResolver creates a new permission resolver.
func NewResolver(store Store, cacheTTL time.Duration) *Resolver {
	return &Resolver{
		store:    store,
		cacheTTL: cacheTTL,
		inFlight: make(map[string]*inFlightEntry),
	}
}

// SetEncryptionKey configures the AES-256 key used to decrypt RPC API keys
// stored in the database. If nil, API keys are assumed to be plaintext.
func (r *Resolver) SetEncryptionKey(key []byte) {
	r.encryptionKey = key
}

// ResolvePermissions computes the effective permissions for a user in an organization.
// It first checks the cache, then computes permissions if not cached.
// Uses single-flight pattern to prevent cache stampede when multiple requests
// come in simultaneously for the same user+org combination.
//
// Callers that copy the result into a longer-lived cache of their own must use
// ResolvePermissionsCacheable instead — see its doc comment.
func (r *Resolver) ResolvePermissions(ctx context.Context, userID, orgID string) (*EffectivePermissions, error) {
	perms, _, err := r.ResolvePermissionsCacheable(ctx, userID, orgID)
	return perms, err
}

// ResolvePermissionsCacheable is ResolvePermissions plus the RD-1267 verdict:
// cacheable reports whether the returned permissions may be copied into a
// longer-lived cache.
//
// cacheable is false when an invalidation committed while the compute was in
// flight, or when the guard could not establish that it did not. The caller
// still receives the permissions — they were true of the state that was read,
// and the request that triggered the resolve is entitled to them — but
// persisting them would leave a just-revoked grant usable for the whole cache
// TTL. AccessController therefore skips its in-memory/Redis PermissionCache
// write when this is false; the next request resolves fresh state.
//
// The verdict is returned separately rather than carried on
// EffectivePermissions because it describes this *resolution*, not the
// permission set: the same permissions are publishable or not depending on
// whether a mutation happened to race the compute, and the flag must not be
// serialised into the cached payload.
func (r *Resolver) ResolvePermissionsCacheable(ctx context.Context, userID, orgID string) (*EffectivePermissions, bool, error) {
	cacheKey := userID + ":" + orgID

	// Check in-memory cache first (fast path)
	cached, err := r.store.GetCachedPermissions(ctx, userID, orgID)
	if err != nil {
		return nil, false, err
	}
	if cached != nil {
		// Already published by whoever computed it, so it is safe to hold in
		// an upper cache as well.
		return cached, true, nil
	}

	// Check if another goroutine is already computing this permission
	r.inFlightMu.RLock()
	entry, exists := r.inFlight[cacheKey]
	r.inFlightMu.RUnlock()

	if exists {
		// Wait for the in-progress computation
		select {
		case <-entry.done:
			return entry.perms, entry.publishable, entry.err
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}

	// No computation in progress, start one
	entry = &inFlightEntry{
		done: make(chan struct{}),
	}

	r.inFlightMu.Lock()
	// Double-check after acquiring write lock
	if existing, exists := r.inFlight[cacheKey]; exists {
		// Another goroutine beat us, wait on their computation
		r.inFlightMu.Unlock()
		select {
		case <-existing.done:
			return existing.perms, existing.publishable, existing.err
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
	r.inFlight[cacheKey] = entry
	r.inFlightMu.Unlock()

	// Snapshot the cache generation before reading any state (RD-1267). If a
	// mutation commits while the compute is in flight, its invalidation finds
	// nothing to delete — nothing is cached yet — and an unconditional
	// publication would leave the pre-mutation permissions in the shared
	// cache for the full TTL, keeping a revoked grant usable. Comparing the
	// generation at publication time detects exactly that window.
	//
	// genKnown == false means we could not establish a baseline, in which
	// case nothing is published: discarding costs one recompute, publishing
	// blind risks serving stale permissions.
	genStore, genCapable := r.store.(CacheGenerationStore)
	var (
		genBefore int64
		genKnown  bool
	)
	if genCapable {
		g, gErr := genStore.CacheGeneration(ctx)
		if gErr != nil {
			slog.Warn("rbac resolver: cannot read cache generation, skipping cache publication",
				"user_id", userID, "org_id", orgID, "err", gErr)
		} else {
			genBefore, genKnown = g, true
		}
	}

	// Compute permissions
	perms, err := r.computePermissions(ctx, userID, orgID)

	// Cache the result synchronously (RD-984), and do it BEFORE publishing
	// the result and removing the in-flight entry: while the write is in
	// progress, a new caller sees a cache miss but still finds the in-flight
	// entry and waits. With the write after removal there was a window
	// (entry gone, cache not yet written) where a late arrival recomputed —
	// see TestResolvePermissions_NoRecomputeDuringCacheWrite. The write
	// stays synchronous: the previous fire-and-forget goroutine could race
	// InvalidateUser / InvalidateOrg from a concurrent mutation and
	// repopulate the cache with stale permissions for the 5-minute TTL.
	// publishable mirrors the SQL publication decision so upper caches make the
	// same call (RD-1267). It stays false unless we positively establish that
	// no invalidation raced this compute.
	publishable := false
	if err == nil {
		switch {
		case genCapable && genKnown:
			published, cErr := genStore.SetCachedPermissionsAtGeneration(ctx, perms, genBefore)
			switch {
			case cErr != nil:
				// Cache-write failure is not a correctness issue (the
				// returned perms are still authoritative); a future call
				// will re-resolve from the DB. Don't fail the request.
				// Not publishable: the write failing means we never
				// confirmed the generation still held, so an upper cache
				// must not hold the entry either.
				slog.Warn("rbac resolver: SetCachedPermissionsAtGeneration failed", "user_id", userID, "org_id", orgID, "err", cErr)
			case !published:
				// An invalidation committed during the compute. The caller
				// still gets what was true when it was read; the cache stays
				// empty so the next request resolves fresh state.
				slog.Debug("rbac resolver: discarded cache publication, invalidated during compute (RD-1267)",
					"user_id", userID, "org_id", orgID, "generation", genBefore)
			default:
				publishable = true
			}
		case genCapable && !genKnown:
			// Baseline unknown — already logged above. Fail safe: publish nothing.
		default:
			// Store without the generation capability (test doubles): keep the
			// previous unconditional publish. Production uses *db.DB, which
			// implements CacheGenerationStore under a compile-time assertion.
			publishable = true
			if cErr := r.store.SetCachedPermissions(ctx, perms); cErr != nil {
				slog.Warn("rbac resolver: SetCachedPermissions failed", "user_id", userID, "org_id", orgID, "err", cErr)
			}
		}
	}

	// Store result and broadcast to all waiting goroutines
	entry.perms = perms
	entry.err = err
	entry.publishable = publishable
	close(entry.done)

	// Clean up in-flight entry
	r.inFlightMu.Lock()
	delete(r.inFlight, cacheKey)
	r.inFlightMu.Unlock()

	if err != nil {
		return nil, false, err
	}

	return perms, publishable, nil
}

// computePermissions calculates effective permissions using the contract-centric RBAC model.
//
// Algorithm:
//  1. Get user's memberships in the org
//  2. Check for org admin memberships - if found, grant all claims on all contracts
//  3. For each membership, get the group's OWN access and contract grants (flat, no hierarchy)
//  4. Merge permissions across multiple group memberships (UNION - user benefits from all groups)
func (r *Resolver) computePermissions(ctx context.Context, userID, orgID string) (*EffectivePermissions, error) {
	// Get user's memberships in this org with details
	memberships, err := r.store.ListUserMembershipsInOrg(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}

	if len(memberships) == 0 {
		// User has no memberships - return empty permissions
		return &EffectivePermissions{
			ID:             uuid.New().String(),
			UserID:         userID,
			OrgID:          orgID,
			AllowedMethods: []string{},
			ContractAccess: make(map[string]ContractAccess),
			Claims:         []Claim{},
			ComputedAt:     time.Now(),
			ExpiresAt:      time.Now().Add(r.cacheTTL),
		}, nil
	}

	// Check if user is member of any org admin group
	isOrgAdmin := false
	for _, m := range memberships {
		if m.Group.IsOrgAdmin {
			isOrgAdmin = true
			break
		}
	}

	// If user is org admin, grant all claims on all contracts
	if isOrgAdmin {
		return r.computeOrgAdminPermissions(ctx, userID, orgID, memberships)
	}

	// Batch-load every group's access, grants and granted contracts up front,
	// so the merge loop below issues no queries at all (RD-1263).
	batch, err := r.loadGroupPerms(ctx, membershipGroupIDs(memberships), true)
	if err != nil {
		return nil, err
	}

	// Track final merged permissions across all memberships
	var finalMethods []string
	finalContractAccess := make(map[string]ContractAccess)
	var finalClaims []Claim
	var finalRPCAPIKey string
	firstMembership := true

	for _, m := range memberships {
		// Get the group's own permissions directly (flat — no hierarchy walk)
		membershipPerms := r.groupPerms(batch, m.Group.ID)

		if firstMembership {
			// First membership - use its permissions as baseline
			finalMethods = membershipPerms.AllowedMethods
			finalContractAccess = membershipPerms.ContractAccess
			finalClaims = membershipPerms.Claims
			finalRPCAPIKey = membershipPerms.RPCAPIKey
			firstMembership = false
		} else {
			// Subsequent memberships - UNION the permissions (user benefits from all groups)
			finalMethods = unionStrings(finalMethods, membershipPerms.AllowedMethods)
			finalContractAccess = unionContractAccess(finalContractAccess, membershipPerms.ContractAccess)
			finalClaims = unionClaims(finalClaims, membershipPerms.Claims)

			// RPC API key: use first non-empty key found across memberships.
			if finalRPCAPIKey == "" && membershipPerms.RPCAPIKey != "" {
				finalRPCAPIKey = membershipPerms.RPCAPIKey
			}
		}
	}

	return &EffectivePermissions{
		ID:             uuid.New().String(),
		UserID:         userID,
		OrgID:          orgID,
		AllowedMethods: finalMethods,
		ContractAccess: finalContractAccess,
		Claims:         ExpandClaims(finalClaims), // expand so admin→deploy etc. are included
		RPCAPIKey:      finalRPCAPIKey,
		ComputedAt:     time.Now(),
		ExpiresAt:      r.cacheExpiry(memberships),
	}, nil
}

// cacheExpiry returns when a resolved-permission cache entry should expire:
// the normal cache TTL, but never later than the soonest membership
// expires_at. This makes a time-boxed grant (regulator access window —
// RD-1145) revoke promptly: the cache cannot outlive the membership
// window, so once the window passes the next ResolvePermissions re-runs and
// ListUserMembershipsInOrg filters the now-expired row out (fail-closed).
// Without the cap, an expiry landing mid-cache would keep granting access for
// up to the full TTL. The memberships passed here are already
// expiry-filtered, so any non-nil ExpiresAt is in the future.
func (r *Resolver) cacheExpiry(memberships []*MembershipWithDetails) time.Time {
	exp := time.Now().Add(r.cacheTTL)
	for _, m := range memberships {
		if m.Membership != nil && m.Membership.ExpiresAt != nil && m.Membership.ExpiresAt.Before(exp) {
			exp = *m.Membership.ExpiresAt
		}
	}
	return exp
}

// computeOrgAdminPermissions computes permissions for org admin users.
// Org admins get all claims on all contracts in the organization.
func (r *Resolver) computeOrgAdminPermissions(ctx context.Context, userID, orgID string, memberships []*MembershipWithDetails) (*EffectivePermissions, error) {
	// Get all contracts in the organization
	contracts, err := r.store.ListContracts(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// Build contract access with all claims for each contract
	allClaims := AllClaims()
	contractAccess := make(map[string]ContractAccess)
	for _, contract := range contracts {
		contractAccess[strings.ToLower(contract.Address)] = ContractAccess{
			Claims:    allClaims,
			Functions: nil, // all functions
		}
	}

	// Still compute methods and API key from memberships (take the most
	// permissive). Only the groups' access rows are read: org admins already
	// hold all claims on every contract above, so the grants and contracts
	// halves are not consulted at all (RD-1263 — this path used to issue the
	// full per-group query trio and discard the contract half).
	batch, err := r.loadGroupPerms(ctx, membershipGroupIDs(memberships), false)
	if err != nil {
		return nil, err
	}

	var finalMethods []string
	var finalRPCAPIKey string

	for _, m := range memberships {
		// Get the group's own permissions directly (flat — no hierarchy walk)
		membershipPerms := r.groupPerms(batch, m.Group.ID)

		finalMethods = unionStrings(finalMethods, membershipPerms.AllowedMethods)
		if finalRPCAPIKey == "" && membershipPerms.RPCAPIKey != "" {
			finalRPCAPIKey = membershipPerms.RPCAPIKey
		}
	}

	return &EffectivePermissions{
		ID:             uuid.New().String(),
		UserID:         userID,
		OrgID:          orgID,
		AllowedMethods: finalMethods,
		ContractAccess: contractAccess,
		Claims:         allClaims, // Org admins get all default claims too
		RPCAPIKey:      finalRPCAPIKey,
		ComputedAt:     time.Now(),
		ExpiresAt:      r.cacheExpiry(memberships),
	}, nil
}

// groupPermsBatch holds the batch-loaded inputs the per-group permission
// builder needs, so building each group's permissions costs no queries.
type groupPermsBatch struct {
	access    map[string]*GroupAccess
	grants    map[string][]*ContractGrant
	contracts map[string]*Contract
}

// membershipGroupIDs returns the distinct group IDs of the given memberships,
// preserving membership order.
func membershipGroupIDs(memberships []*MembershipWithDetails) []string {
	ids := make([]string, 0, len(memberships))
	seen := make(map[string]bool, len(memberships))
	for _, m := range memberships {
		if seen[m.Group.ID] {
			continue
		}
		seen[m.Group.ID] = true
		ids = append(ids, m.Group.ID)
	}
	return ids
}

// loadGroupPerms batch-loads everything groupPerms needs for the given groups:
// their access rows, their contract grants, and the granted contracts. Three
// queries regardless of group count — one when withGrants is false, which is
// all the org-admin path reads (RD-1263: this replaced a per-group
// GetGroupAccess + ListContractGrantsByGroup + GetContractsByIDs trio, so the
// cache-miss fan-out no longer scales with membership count).
//
// The contracts query is skipped when no group has a grant, matching the
// previous per-group behaviour.
func (r *Resolver) loadGroupPerms(ctx context.Context, groupIDs []string, withGrants bool) (*groupPermsBatch, error) {
	access, err := r.store.GetGroupAccessBatch(ctx, groupIDs)
	if err != nil {
		return nil, err
	}
	batch := &groupPermsBatch{access: access}

	if !withGrants {
		return batch, nil
	}

	grants, err := r.store.ListContractGrantsBatch(ctx, groupIDs)
	if err != nil {
		return nil, err
	}
	batch.grants = grants

	var contractIDs []string
	seen := make(map[string]bool)
	for _, groupID := range groupIDs {
		for _, grant := range grants[groupID] {
			if seen[grant.ContractID] {
				continue
			}
			seen[grant.ContractID] = true
			contractIDs = append(contractIDs, grant.ContractID)
		}
	}
	if len(contractIDs) > 0 {
		contracts, err := r.store.GetContractsByIDs(ctx, contractIDs)
		if err != nil {
			return nil, err
		}
		batch.contracts = contracts
	}

	return batch, nil
}

// groupPerms builds one group's permissions from batch-loaded data (flat — no
// hierarchy walk). Pure in-memory: same result as querying that group directly.
func (r *Resolver) groupPerms(batch *groupPermsBatch, groupID string) *groupPermSet {
	access := batch.access[groupID]

	result := &groupPermSet{
		AllowedMethods: []string{},
		ContractAccess: make(map[string]ContractAccess),
		Claims:         []Claim{},
	}

	if access != nil {
		if access.AllowedMethods != nil {
			result.AllowedMethods = access.AllowedMethods
		}
		if access.Claims != nil {
			result.Claims = access.Claims
		}

		// Decrypt RPC API key if present
		if access.RPCAPIKey != nil && *access.RPCAPIKey != "" {
			decrypted, err := crypto.Decrypt(*access.RPCAPIKey, r.encryptionKey)
			if err != nil {
				// Decryption failed — use the raw value (may be legacy plaintext)
				result.RPCAPIKey = *access.RPCAPIKey
			} else {
				result.RPCAPIKey = decrypted
			}
		}
	}

	// Build contract access from grants using group's claims. batch.grants is
	// nil when the caller asked for access only; a nil-map read yields no
	// grants, leaving ContractAccess empty.
	for _, grant := range batch.grants[groupID] {
		contract, ok := batch.contracts[grant.ContractID]
		if !ok {
			continue // Contract deleted, skip
		}
		address := strings.ToLower(contract.Address)
		result.ContractAccess[address] = ContractAccess{
			Claims:     result.Claims,
			Functions:  grant.Functions,
			EventRules: grant.EventRules,
		}
	}

	return result
}

// groupPermSet holds the permissions of a single group. Groups are flat since
// RD-804 (parent_id is retained but ignored), so this is one group's own
// access row plus its contract grants — callers merge across memberships.
type groupPermSet struct {
	AllowedMethods []string
	ContractAccess map[string]ContractAccess // address -> access
	Claims         []Claim
	RPCAPIKey      string // The group's own key, "" when unset
}

// InvalidateUserPermissions invalidates the cache for a specific user.
func (r *Resolver) InvalidateUserPermissions(ctx context.Context, userID string) error {
	return r.store.InvalidateCacheForUser(ctx, userID)
}

// InvalidateOrgPermissions invalidates the cache for all users in an organization.
func (r *Resolver) InvalidateOrgPermissions(ctx context.Context, orgID string) error {
	return r.store.InvalidateCacheForOrg(ctx, orgID)
}

// InvalidateGroupPermissions invalidates the cache for all users in a group.
func (r *Resolver) InvalidateGroupPermissions(ctx context.Context, groupID string) error {
	return r.store.InvalidateCacheForGroup(ctx, groupID)
}

// Helper functions

// intersectStrings returns the intersection of two string slices (case-insensitive).
func intersectStrings(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return []string{}
	}

	set := make(map[string]bool)
	for _, s := range a {
		set[strings.ToLower(s)] = true
	}

	var result []string
	for _, s := range b {
		if set[strings.ToLower(s)] {
			result = append(result, s)
		}
	}

	return result
}

// unionStrings returns the union of two string slices (case-insensitive dedup).
func unionStrings(a, b []string) []string {
	set := make(map[string]string) // lowercase -> original
	for _, s := range a {
		set[strings.ToLower(s)] = s
	}
	for _, s := range b {
		key := strings.ToLower(s)
		if _, exists := set[key]; !exists {
			set[key] = s
		}
	}

	result := make([]string, 0, len(set))
	for _, v := range set {
		result = append(result, v)
	}
	return result
}

// IntersectClaims returns the intersection of two claim slices.
// Used both by the resolver (hierarchy computation) and by admin handlers
// (computing effective claims for display).
func IntersectClaims(a, b []Claim) []Claim {
	if len(a) == 0 || len(b) == 0 {
		return []Claim{}
	}

	set := make(map[Claim]bool)
	for _, c := range a {
		set[c] = true
	}

	var result []Claim
	for _, c := range b {
		if set[c] {
			result = append(result, c)
		}
	}

	return result
}

// unionClaims returns the union of two claim slices.
func unionClaims(a, b []Claim) []Claim {
	set := make(map[Claim]bool)
	for _, c := range a {
		set[c] = true
	}
	for _, c := range b {
		set[c] = true
	}

	result := make([]Claim, 0, len(set))
	for c := range set {
		result = append(result, c)
	}
	return result
}

// intersectFunctions returns the intersection of two FunctionRule slices by selector.
// If either is nil, it means "all functions allowed" - return the other.
// If both are nil, return nil (all allowed).
// If both have values, return rules whose selectors appear in both (keeping the
// stricter param_rules from whichever side has them).
func intersectFunctions(a, b []FunctionRule) []FunctionRule {
	// nil means "all functions allowed"
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}

	// Non-nil but empty = "no functions allowed" — intersection with anything is empty
	if len(a) == 0 || len(b) == 0 {
		return []FunctionRule{}
	}

	// Index b by selector for O(n) lookup
	bMap := make(map[string]FunctionRule, len(b))
	for _, rule := range b {
		bMap[strings.ToLower(rule.Selector)] = rule
	}

	result := []FunctionRule{}
	for _, ruleA := range a {
		if ruleB, ok := bMap[strings.ToLower(ruleA.Selector)]; ok {
			// Both sides allow this selector - keep the one with param rules
			// (stricter). If both have param rules, keep b's (child narrows parent).
			merged := ruleA
			if len(ruleB.ParamRules) > 0 {
				merged.ParamRules = ruleB.ParamRules
			}
			result = append(result, merged)
		}
	}
	return result
}

// unionFunctions returns the union of two FunctionRule slices by selector.
// If either is nil, it means "all functions allowed" - return nil.
// If both have values, return the union (user gets all allowed functions).
func unionFunctions(a, b []FunctionRule) []FunctionRule {
	// nil means "all functions allowed" - if either is unrestricted, result is unrestricted
	if a == nil || b == nil {
		return nil
	}

	// Both have restrictions - union them (user gets all allowed functions)
	seen := make(map[string]FunctionRule, len(a))
	for _, rule := range a {
		seen[strings.ToLower(rule.Selector)] = rule
	}
	for _, rule := range b {
		key := strings.ToLower(rule.Selector)
		if existing, ok := seen[key]; ok {
			// Both sides allow this selector. If either side has no param rules,
			// the union is the less restrictive one (no param rules).
			if len(existing.ParamRules) == 0 || len(rule.ParamRules) == 0 {
				seen[key] = FunctionRule{Selector: rule.Selector}
			}
			// else: both have param rules, keep existing (arbitrary but consistent)
		} else {
			seen[key] = rule
		}
	}

	result := make([]FunctionRule, 0, len(seen))
	for _, rule := range seen {
		result = append(result, rule)
	}
	return result
}

// unionEventRules returns the union of two EventRulesField pointers.
// nil pointer means "deny" (no contribution to the union).
// If either is wildcard → return wildcard.
// If both are deny → return nil (deny).
// If one is deny → return the other.
// Both have rules → union by topic0 (existing merge logic).
func unionEventRules(a, b *EventRulesField) *EventRulesField {
	// nil means deny — no contribution
	aDeny := a == nil || a.IsDeny()
	bDeny := b == nil || b.IsDeny()

	// If either is wildcard, result is wildcard
	if a != nil && a.IsWildcard() {
		return a
	}
	if b != nil && b.IsWildcard() {
		return b
	}

	// Both deny → deny
	if aDeny && bDeny {
		return nil
	}
	// One deny → return the other
	if aDeny {
		return b
	}
	if bDeny {
		return a
	}

	// Both have rules — union them by topic0
	aRules := a.GetRules()
	bRules := b.GetRules()

	seen := make(map[string]EventRule, len(aRules))
	for _, rule := range aRules {
		seen[strings.ToLower(rule.Topic0)] = rule
	}
	for _, rule := range bRules {
		key := strings.ToLower(rule.Topic0)
		if existing, ok := seen[key]; ok {
			// Both sides allow this event. If either side has no param rules,
			// the union is the less restrictive one (no param rules).
			if len(existing.ParamRules) == 0 || len(rule.ParamRules) == 0 {
				seen[key] = EventRule{Topic0: rule.Topic0, Name: rule.Name}
			}
			// else: both have param rules, keep existing (arbitrary but consistent)
		} else {
			seen[key] = rule
		}
	}

	rules := make([]EventRule, 0, len(seen))
	for _, rule := range seen {
		rules = append(rules, rule)
	}
	return &EventRulesField{Rules: rules}
}

// unionContractAccess merges two ContractAccess maps, taking the UNION of claims and functions.
// Used when merging permissions across multiple memberships - user benefits from all groups.
func unionContractAccess(a, b map[string]ContractAccess) map[string]ContractAccess {
	if len(a) == 0 && len(b) == 0 {
		return make(map[string]ContractAccess)
	}
	if len(a) == 0 {
		// Return a copy of b
		result := make(map[string]ContractAccess, len(b))
		for k, v := range b {
			result[k] = v
		}
		return result
	}
	if len(b) == 0 {
		// Return a copy of a
		result := make(map[string]ContractAccess, len(a))
		for k, v := range a {
			result[k] = v
		}
		return result
	}

	result := make(map[string]ContractAccess)

	// Copy all from a
	for addr, access := range a {
		result[strings.ToLower(addr)] = access
	}

	// Merge in all from b
	for addr, access := range b {
		lc := strings.ToLower(addr)
		if existing, has := result[lc]; has {
			// Union the claims, functions, and event rules for this contract
			result[lc] = ContractAccess{
				Claims:     unionClaims(existing.Claims, access.Claims),
				Functions:  unionFunctions(existing.Functions, access.Functions),
				EventRules: unionEventRules(existing.EventRules, access.EventRules),
			}
		} else {
			result[lc] = access
		}
	}

	return result
}

// HasClaim is a helper to check if a claim exists in a slice.
func HasClaim(claims []Claim, claim Claim) bool {
	return slices.Contains(claims, claim)
}
