package rbac

import (
	"context"
	"fmt"
	"strings"

	"privacy-proxy/internal/evm/precompile"
)

// OrgContext encapsulates organization-scoped access decisions.
// It provides a unified interface for all cross-org isolation checks,
// pre-loading user membership data once for efficient reuse.
//
// Usage:
//
//	orgCtx, err := NewOrgContext(ctx, store, user, targetAddress)
//	if err != nil { return err }  // Cross-org violation detected early
//
//	// Later, for additional address checks:
//	err = orgCtx.CheckAddressInScope(ctx, anotherAddress)
type OrgContext struct {
	org        *Organization   // The determined org context (can be nil for public/no-target)
	user       *User           // The authenticated user
	userOrgIDs map[string]bool // Pre-loaded: all orgs user belongs to
	store      Store           // For additional lookups
	// ownerOrgCache memoizes GetContractOwnerOrgID for the lifetime of this
	// (request-scoped) context, keyed by normalized address. The construction
	// path already resolves the target's owner org; later same-address lookups
	// in CheckAccess reuse it instead of issuing a duplicate DB round-trip on
	// the hot path (RD-1112). Request-scoped, so it cannot serve stale data.
	ownerOrgCache map[string]string
}

// NewOrgContext creates an OrgContext from a target address.
// This determines the org context based on contract ownership:
//   - If target is owned by an org the user belongs to, use that org
//   - If target is public (not owned by any org), org is nil
//   - If target is owned by an org the user does NOT belong to, returns error
//
// Parameters:
//   - ctx: Context for database calls
//   - store: RBAC store for lookups
//   - user: The authenticated user
//   - targetAddress: The target contract address (can be empty)
//
// Returns:
//   - OrgContext if valid
//   - Error if cross-org isolation is violated
func NewOrgContext(ctx context.Context, store Store, user *User, targetAddress string) (*OrgContext, error) {
	// Pre-load user's org memberships
	userOrgIDs, err := GetUserOrgIDs(ctx, store, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user organizations: %w", err)
	}

	oc := &OrgContext{
		user:       user,
		userOrgIDs: userOrgIDs,
		store:      store,
	}

	// If no target address, org context remains nil (will use default org later)
	if targetAddress == "" {
		return oc, nil
	}

	// Determine org from target address ownership
	addr := strings.ToLower(strings.TrimSpace(targetAddress))
	ownerOrgID, err := store.GetContractOwnerOrgID(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to get contract owner: %w", err)
	}
	// Memoize the target's owner so the duplicate same-address lookups in
	// CheckAccess become cache hits instead of extra DB round-trips (RD-1112).
	oc.ownerOrgCache = map[string]string{addr: ownerOrgID}

	if ownerOrgID == "" {
		// Contract is public (not owned by any org)
		return oc, nil
	}

	// Contract is owned by an org - verify user is a member
	if !userOrgIDs[ownerOrgID] {
		return nil, fmt.Errorf(ErrContractAccessDenied)
	}

	// User is a member - set the org context
	org, err := store.GetOrganization(ctx, ownerOrgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}
	oc.org = org

	return oc, nil
}

// NewOrgContextForOrg creates an OrgContext for an explicit org.
// Used when the organization is already known (e.g., deployments using user's default org).
func NewOrgContextForOrg(ctx context.Context, store Store, user *User, orgID string) (*OrgContext, error) {
	// Pre-load user's org memberships
	userOrgIDs, err := GetUserOrgIDs(ctx, store, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user organizations: %w", err)
	}

	// Verify user is a member of the specified org
	if !userOrgIDs[orgID] {
		return nil, fmt.Errorf("user is not a member of organization %s", orgID)
	}

	org, err := store.GetOrganization(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	return &OrgContext{
		org:        org,
		user:       user,
		userOrgIDs: userOrgIDs,
		store:      store,
	}, nil
}

// OrgID returns the organization ID, or empty string if public context.
func (oc *OrgContext) OrgID() string {
	if oc.org == nil {
		return ""
	}
	return oc.org.ID
}

// Org returns the organization, or nil if public context.
func (oc *OrgContext) Org() *Organization {
	return oc.org
}

// OwnerOrgID returns the org that owns addr, memoized for the lifetime of this
// request-scoped context. The first lookup for a given (normalized) address
// hits the store; subsequent lookups of the same address — including the
// target address already resolved during construction — are served from the
// memo, eliminating duplicate DB round-trips on the hot path (RD-1112).
// It is always correct: a cache miss falls back to the store.
func (oc *OrgContext) OwnerOrgID(ctx context.Context, addr string) (string, error) {
	key := strings.ToLower(strings.TrimSpace(addr))
	if oc.ownerOrgCache != nil {
		if v, ok := oc.ownerOrgCache[key]; ok {
			return v, nil
		}
	}
	v, err := oc.store.GetContractOwnerOrgID(ctx, key)
	if err != nil {
		return "", err
	}
	if oc.ownerOrgCache == nil {
		oc.ownerOrgCache = make(map[string]string, 2)
	}
	oc.ownerOrgCache[key] = v
	return v, nil
}

// User returns the user.
func (oc *OrgContext) User() *User {
	return oc.user
}

// UserOrgIDs returns the set of org IDs the user belongs to.
func (oc *OrgContext) UserOrgIDs() map[string]bool {
	return oc.userOrgIDs
}

// IsPublicContext returns true if no org context was determined.
// This happens when the target address is not owned by any org.
func (oc *OrgContext) IsPublicContext() bool {
	return oc.org == nil
}

// UserBelongsToOrg returns true if the user belongs to the determined org.
// Always returns true for public context (no org = no restriction).
func (oc *OrgContext) UserBelongsToOrg() bool {
	if oc.org == nil {
		return true
	}
	return oc.userOrgIDs[oc.org.ID]
}

// CheckAddressInScope validates that an address is accessible in this org context.
// Used for operations that interact with multiple addresses (e.g., eth_getLogs).
//
// Rules:
//   - If address is in current org context: allowed
//   - If address is in another org user belongs to: allowed (multi-org support)
//   - If address is in an org user does NOT belong to: denied
//   - If address is public (not registered to any org): allowed
func (oc *OrgContext) CheckAddressInScope(ctx context.Context, address string) error {
	addr := strings.ToLower(strings.TrimSpace(address))
	if addr == "" {
		return nil // No address to check
	}

	ownerOrgID, err := oc.store.GetContractOwnerOrgID(ctx, addr)
	if err != nil {
		return fmt.Errorf("failed to check contract owner: %w", err)
	}

	if ownerOrgID == "" {
		// Not owned by any org — only precompiles are allowed.
		// All other unregistered addresses are private by default.
		if precompile.IsPrecompileAddress(addr) {
			return nil
		}
		return fmt.Errorf(ErrContractAccessDenied)
	}

	// Contract is owned by an org - check if user is a member
	if !oc.userOrgIDs[ownerOrgID] {
		return fmt.Errorf(ErrContractAccessDenied)
	}

	return nil
}

// CheckMultiAddressesInScope validates multiple addresses are all in scope.
// Returns error on first cross-org violation found.
func (oc *OrgContext) CheckMultiAddressesInScope(ctx context.Context, addresses []string) error {
	for _, addr := range addresses {
		if err := oc.CheckAddressInScope(ctx, addr); err != nil {
			return err
		}
	}
	return nil
}

// CheckDefaultClaimsAllowed validates whether default_claims can be used for an address.
// Only truly unregistered addresses (precompiles) fall through here. Every registered
// contract — including contracts in the user's own org — requires an explicit
// contract_grant. This keeps the RPC access layer symmetric with the explorer
// visibility layer (RD-817 3-tier admin model, RD-849).
//
// Symmetry invariant: if CheckAccess allows a viewer to reach an address, the same
// viewer must see that address as VisibilityFull in GetBatchVisibility, and vice
// versa. The visibility layer grants Full only via is_org_admin (tier 2) or an
// explicit contract_grant (tier 3 with a grant, or any claim holder with a grant).
// This function enforces the same contract at the access layer.
//
// is_org_admin users (tier 2) are unaffected — they get all org contracts
// materialized as explicit ContractAccess in computeOrgAdminPermissions, so they
// hit hasExplicitAccess and return nil immediately.
//
// Deployers on their self-deployed contracts are unaffected — access.go adds an
// auto-grant (ContractAccess) before calling this function, so hasExplicitAccess
// is true.
//
// Parameters:
//   - ctx: Context
//   - address: The target address
//   - hasExplicitAccess: Whether user has explicit ContractAccess for this address
//
// Returns:
//   - nil if the address is unregistered and is a precompile (public)
//   - error otherwise (explicit grant required)
func (oc *OrgContext) CheckDefaultClaimsAllowed(ctx context.Context, address string, hasExplicitAccess bool) error {
	if hasExplicitAccess {
		return nil
	}

	addr := strings.ToLower(strings.TrimSpace(address))
	if addr == "" {
		return nil
	}

	ownerOrgID, err := oc.store.GetContractOwnerOrgID(ctx, addr)
	if err != nil {
		return fmt.Errorf("failed to check contract ownership: %w", err)
	}

	if ownerOrgID == "" {
		// Unregistered — only precompiles are public. All other unregistered
		// addresses are private by default.
		if precompile.IsPrecompileAddress(addr) {
			return nil
		}
	}

	// Registered contracts (any org, including user's own) require an explicit
	// grant. Same rule as the explorer visibility layer.
	return fmt.Errorf(ErrContractAccessDenied)
}

// GetUserOrgIDs returns the set of organization IDs the user belongs to.
func GetUserOrgIDs(ctx context.Context, store Store, userID string) (map[string]bool, error) {
	memberships, err := store.ListActiveUserMembershipsWithDetails(ctx, userID)
	if err != nil {
		return nil, err
	}

	orgIDs := make(map[string]bool)
	for _, m := range memberships {
		if m.Group != nil {
			orgIDs[m.Group.OrgID] = true
		}
	}

	return orgIDs, nil
}
