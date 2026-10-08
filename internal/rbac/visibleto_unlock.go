package rbac

import (
	"context"
	"strings"

	"privacy-proxy/internal/viewscope"
)

// UnlockableContracts returns the lowercase addresses among contractAddrs for
// which the RD-874 per-contract visibleTo unlock can fire for viewerDID: the
// contract is registered with `allow_visibleto_unlock` set AND the viewer is
// unlock-eligible on it (see IsViewerEligibleForVisibleToUnlock for the
// boundary). The caller still has to check, per log, that the viewer is
// listed in that log's own transaction's visibleTo.
//
// This is the single helper both layers use — the RPC's
// buildVisibleToUnlockableMap and the explorer's dbVisibleToUnlockResolver —
// so the unlock set per (viewer, contract) cannot drift between them, and a
// policy profile that must restrict the unlock has one place to do it.
//
// A viewer organization scope, when present, limits the set to contracts
// owned by that organization. An empty scope produces an empty set.
//
// Cost per request: one contract lookup per unique address; the user and its
// memberships/grants are loaded only if some contract is flagged, once per
// owning org. Every lookup error fails closed (the contract is omitted).
func UnlockableContracts(ctx context.Context, access *AccessController, viewerDID string, contractAddrs []string) map[string]bool {
	out := make(map[string]bool)
	if access == nil || viewerDID == "" || len(contractAddrs) == 0 {
		return out
	}
	scope, scoped := viewscope.Org(ctx)
	if scoped && scope == "" {
		return out
	}
	store := access.Store()
	if store == nil {
		return out
	}

	flagged := make(map[string]*Contract)
	seen := make(map[string]struct{}, len(contractAddrs))
	for _, a := range contractAddrs {
		addr := strings.ToLower(a)
		if addr == "" {
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		c, err := store.GetContractByAddressGlobal(ctx, addr)
		if err != nil || c == nil || !c.AllowVisibleToUnlock || c.OrgID == "" {
			continue
		}
		if scoped && c.OrgID != scope {
			continue
		}
		flagged[addr] = c
	}
	if len(flagged) == 0 {
		return out
	}

	user, err := store.GetUserByExternalID(ctx, viewerDID)
	if err != nil || user == nil {
		return out
	}
	byOrg := make(map[string]unlockEligibility)
	for addr, c := range flagged {
		e, ok := byOrg[c.OrgID]
		if !ok {
			e = loadUnlockEligibility(ctx, store, user.ID, c.OrgID)
			byOrg[c.OrgID] = e
		}
		if e.covers(c) {
			out[addr] = true
		}
	}
	return out
}

// IsViewerEligibleForVisibleToUnlock implements the eligibility gate for
// the RD-874 per-contract visibleTo unlock semantic, independent of the
// contract's flag.
//
// Returns true if and only if:
//
//  1. viewerDID resolves to a real user record (anonymous viewers — no
//     `users` row — are denied).
//  2. The contract is registered (it has an owning org).
//  3. In the contract's owning org, the viewer is EITHER
//     a. a member of an org-admin group (`is_org_admin`) — the contract
//     owner's own authority, which already reaches every org contract; OR
//     b. a member of an ELIGIBLE group that holds a `contract_grant` on this
//     contract. Having the grant is enough, even if its event_rules say
//     deny-all. A group is eligible unless it is a system group
//     (`is_system`) or the seeded default group (`DefaultGroupID`), which
//     auto-provisioned users join (REDACTION_SPEC §3.7.1; RD-1306).
//     A group an operator
//     configures as an identity provider's automatic group is treated like
//     any other group: granting it a flagged contract is the operator's
//     choice.
//
// Memberships (expired ones excluded) and grants are read per request from
// the store, so a revoked membership or grant stops the unlock on the next
// read. Only memberships in the contract's owning org count, so access in
// another org never makes a viewer eligible. Any lookup error fails closed.
// A viewer organization scope additionally requires the contract's owner
// to match that scope; an empty scope is ineligible.
func IsViewerEligibleForVisibleToUnlock(ctx context.Context, access *AccessController, viewerDID, contractAddress string) bool {
	if access == nil || viewerDID == "" || contractAddress == "" {
		return false
	}
	scope, scoped := viewscope.Org(ctx)
	if scoped && scope == "" {
		return false
	}
	store := access.Store()
	if store == nil {
		return false
	}
	c, err := store.GetContractByAddressGlobal(ctx, strings.ToLower(contractAddress))
	if err != nil || c == nil || c.OrgID == "" {
		return false
	}
	if scoped && c.OrgID != scope {
		return false
	}
	user, err := store.GetUserByExternalID(ctx, viewerDID)
	if err != nil || user == nil {
		return false
	}
	return loadUnlockEligibility(ctx, store, user.ID, c.OrgID).covers(c)
}

// unlockEligibility is a viewer's unlock eligibility within one owning org.
// The zero value is "not eligible for anything".
type unlockEligibility struct {
	orgAdmin           bool
	grantedContractIDs map[string]bool
}

func (e unlockEligibility) covers(c *Contract) bool {
	return e.orgAdmin || e.grantedContractIDs[c.ID]
}

// loadUnlockEligibility resolves the viewer's eligibility in orgID from their
// memberships there (see IsViewerEligibleForVisibleToUnlock). Errors yield the
// zero value (fail-closed).
func loadUnlockEligibility(ctx context.Context, store Store, userID, orgID string) unlockEligibility {
	memberships, err := store.ListUserMembershipsInOrg(ctx, userID, orgID)
	if err != nil {
		return unlockEligibility{}
	}
	var groupIDs []string
	for _, m := range memberships {
		if m == nil || m.Group == nil || m.Group.OrgID != orgID {
			continue
		}
		if m.Group.IsOrgAdmin {
			return unlockEligibility{orgAdmin: true}
		}
		if m.Group.IsSystem || m.Group.ID == DefaultGroupID {
			continue
		}
		groupIDs = append(groupIDs, m.Group.ID)
	}
	if len(groupIDs) == 0 {
		return unlockEligibility{}
	}
	grants, err := store.ListContractGrantsBatch(ctx, groupIDs)
	if err != nil {
		return unlockEligibility{}
	}
	ids := make(map[string]bool)
	for _, gid := range groupIDs {
		for _, g := range grants[gid] {
			if g != nil && g.ContractID != "" {
				ids[g.ContractID] = true
			}
		}
	}
	return unlockEligibility{grantedContractIDs: ids}
}
