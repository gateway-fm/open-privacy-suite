package rbac

import (
	"context"
	"strings"
)

// IsViewerEligibleForVisibleToUnlock implements the eligibility gate for
// the RD-874 per-contract visibleTo unlock semantic.
//
// Returns true if and only if:
//
//  1. viewerDID resolves to a real user record (anonymous viewers — no
//     `users` row — are denied).
//  2. The contract is registered (the address has an owning org).
//  3. In the contract's owning org, the viewer is EITHER
//     a. a member of an org-admin group (`is_org_admin`) — the contract
//     owner's own authority, which already reaches every org contract; OR
//     b. a member of an ELIGIBLE group that holds a `contract_grant` on this
//     contract. Having the grant is enough, even if its event_rules say
//     deny-all. A group is eligible unless it is a system group
//     (`is_system`) or the seeded default group (`DefaultGroupID`), which
//     auto-provisioned users join: a grant reached only through either
//     would let a sender unlock for any registered user (RD-874 security
//     analysis; REDACTION_SPEC §3.7.1; RD-1306).
//
// Memberships are read per request from the store (expired ones excluded),
// so a revoked membership or grant stops the unlock on the next read.
//
// Returning true does NOT by itself grant the unlock. The two other
// preconditions — `contract.AllowVisibleToUnlock` AND viewer listed in
// the tx's `visibleTo` set — must also hold. Callers are expected to
// pre-compute this map per request and pass it down to the filter
// layers so the per-log check stays O(1).
//
// Cross-org isolation: only memberships in the contract's owning org are
// considered, so access in another org never makes a viewer eligible.
// Any lookup error fails closed (false).
func IsViewerEligibleForVisibleToUnlock(ctx context.Context, access *AccessController, viewerDID, contractAddress string) bool {
	if access == nil || viewerDID == "" || contractAddress == "" {
		return false
	}
	store := access.Store()
	if store == nil {
		return false
	}
	addr := strings.ToLower(contractAddress)

	user, err := store.GetUserByExternalID(ctx, viewerDID)
	if err != nil || user == nil {
		return false
	}

	ownerOrgID, err := store.GetContractOwnerOrgID(ctx, addr)
	if err != nil || ownerOrgID == "" {
		return false
	}

	memberships, err := store.ListUserMembershipsInOrg(ctx, user.ID, ownerOrgID)
	if err != nil {
		return false
	}
	var eligibleGroupIDs []string
	for _, m := range memberships {
		if m == nil || m.Group == nil || m.Group.OrgID != ownerOrgID {
			continue
		}
		if m.Group.IsOrgAdmin {
			return true
		}
		if m.Group.IsSystem || m.Group.ID == DefaultGroupID {
			continue
		}
		eligibleGroupIDs = append(eligibleGroupIDs, m.Group.ID)
	}
	if len(eligibleGroupIDs) == 0 {
		return false
	}

	contract, err := store.GetContractByAddressGlobal(ctx, addr)
	if err != nil || contract == nil || contract.OrgID != ownerOrgID {
		return false
	}
	grants, err := store.ListContractGrantsBatch(ctx, eligibleGroupIDs)
	if err != nil {
		return false
	}
	for _, gid := range eligibleGroupIDs {
		for _, g := range grants[gid] {
			if g != nil && g.ContractID == contract.ID {
				return true
			}
		}
	}
	return false
}
