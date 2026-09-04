package db

import (
	"context"
	"strings"

	"privacy-proxy/internal/evm/precompile"
	"privacy-proxy/internal/explorer"
)

// GetBatchVisibility resolves visibility rules for a list of addresses efficiently.
// It replaces N+1 queries by looking up all address owners and their grants in bulk.
func (d *DB) GetBatchVisibility(ctx context.Context, viewerDID string, addresses []string) (explorer.VisibilityMap, error) {
	result := make(explorer.VisibilityMap)
	if len(addresses) == 0 {
		return result, nil
	}

	// 1. Deduplicate and normalize addresses
	addrSet := make(map[string]bool)
	for _, a := range addresses {
		addrSet[strings.ToLower(a)] = true
	}
	var uniqueAddrs []string
	for a := range addrSet {
		uniqueAddrs = append(uniqueAddrs, a)
		// Default to hidden
		result[a] = explorer.VisibilityHidden
	}

	// 2. Look up owners for all unique addresses
	queryOwners := `
		SELECT LOWER(eth_address), did
		FROM eth_address_links
		WHERE LOWER(eth_address) = ANY($1)
		  AND revoked = false`

	rows, err := d.conn.QueryContext(ctx, queryOwners, uniqueAddrs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	addressOwners := make(map[string]string)
	for rows.Next() {
		var addr, did string
		if err := rows.Scan(&addr, &did); err != nil {
			return nil, err
		}
		addressOwners[addr] = did
	}

	// 3. Process first pass: Public addresses and Own addresses
	var targetDIDs []string
	didToAddresses := make(map[string][]string)

	for _, addr := range uniqueAddrs {
		ownerDID, hasOwner := addressOwners[addr]

		if !hasOwner {
			// No eth_address_links owner. Precompiles are always visible;
			// all other unowned addresses default to Hidden (private by default).
			if precompile.IsPrecompileAddress(addr) {
				result[addr] = explorer.VisibilityFull
			}
			// else: stays VisibilityHidden (set in initialization above)
			continue
		}

		if ownerDID == viewerDID && viewerDID != "" {
			// Own address
			result[addr] = explorer.VisibilityFull
			continue
		}

		// Otherwise, it belongs to someone else. We need to check grants.
		targetDIDs = append(targetDIDs, ownerDID)
		didToAddresses[ownerDID] = append(didToAddresses[ownerDID], addr)
	}

	// 4. Org contract visibility check
	// Collect addresses that have no eth_address_links owner AND are not precompiles.
	// These might be org-owned contracts — check for grants/admin access.
	var publicAddrs []string
	for _, addr := range uniqueAddrs {
		if _, hasOwner := addressOwners[addr]; !hasOwner && !precompile.IsPrecompileAddress(addr) {
			publicAddrs = append(publicAddrs, addr)
		}
	}

	if len(publicAddrs) > 0 {
		// Step 1: Find ALL org-owned contracts and default them to VisibilityRedacted.
		// This is separate from admin group lookup — a contract is private regardless
		// of whether any admin groups exist.
		orgContractDetect := `
			SELECT LOWER(c.address) FROM contracts c
			WHERE LOWER(c.address) = ANY($1)`
		orgDetectRows, err := d.conn.QueryContext(ctx, orgContractDetect, publicAddrs)
		if err != nil {
			return nil, err
		}
		defer orgDetectRows.Close()

		var orgContractAddrs []string
		for orgDetectRows.Next() {
			var addr string
			if err := orgDetectRows.Scan(&addr); err != nil {
				return nil, err
			}
			result[addr] = explorer.VisibilityRedacted
			orgContractAddrs = append(orgContractAddrs, addr)
		}

		// Step 2: For authenticated viewers, check if they have access to any of
		// these contracts. A viewer gets VisibilityFull if they are a member of:
		//   - An is_org_admin group (sees ALL contracts in their org — tier 2), OR
		//   - Any group that has a contract_grant on the specific contract (any claim)
		//
		// 3-tier admin model: 'admin' in group_access.claims (tier 3, contract admin)
		// does NOT grant org-wide contract visibility. Contract admins see only
		// contracts explicitly granted to their group via contract_grant.
		if viewerDID != "" && len(orgContractAddrs) > 0 {
			grantedGroupQuery := `
				SELECT LOWER(c.address) AS addr, g.id AS group_id
				FROM contracts c
				JOIN groups g ON g.org_id = c.org_id
				LEFT JOIN contract_grants cg ON cg.contract_id = c.id AND cg.group_id = g.id
				WHERE LOWER(c.address) = ANY($1)
				  AND (g.is_org_admin = true
				       OR cg.id IS NOT NULL)`

			orgRows, err := d.conn.QueryContext(ctx, grantedGroupQuery, orgContractAddrs)
			if err != nil {
				return nil, err
			}
			defer orgRows.Close()

			// Map: address -> set of group_ids that grant visibility
			contractGroupIDs := make(map[string]map[string]bool)
			for orgRows.Next() {
				var addr, groupID string
				if err := orgRows.Scan(&addr, &groupID); err != nil {
					return nil, err
				}
				if contractGroupIDs[addr] == nil {
					contractGroupIDs[addr] = make(map[string]bool)
				}
				contractGroupIDs[addr][groupID] = true
			}

			if len(contractGroupIDs) > 0 {
				allGroupIDs := make(map[string]bool)
				for _, groups := range contractGroupIDs {
					for gid := range groups {
						allGroupIDs[gid] = true
					}
				}
				groupIDSlice := make([]string, 0, len(allGroupIDs))
				for gid := range allGroupIDs {
					groupIDSlice = append(groupIDSlice, gid)
				}

				memberQuery := `
					SELECT DISTINCT m.group_id
					FROM user_memberships m
					JOIN users u ON u.id = m.user_id
					WHERE u.external_id = $1
					  AND m.group_id = ANY($2)
					  AND (m.expires_at IS NULL OR m.expires_at > NOW())`

				memberRows, err := d.conn.QueryContext(ctx, memberQuery, viewerDID, groupIDSlice)
				if err != nil {
					return nil, err
				}
				defer memberRows.Close()

				viewerGroups := make(map[string]bool)
				for memberRows.Next() {
					var gid string
					if err := memberRows.Scan(&gid); err != nil {
						return nil, err
					}
					viewerGroups[gid] = true
				}

				// Upgrade to VisibilityFull for contracts where viewer is in a granted group
				for addr, groups := range contractGroupIDs {
					for gid := range groups {
						if viewerGroups[gid] {
							result[addr] = explorer.VisibilityFull
							break
						}
					}
				}
			}
		}
	}

	// Check disclosure grants: viewer may have active disclosure grants on some
	// addresses. Disclosed addresses appear in regular explorer views, labeled
	// "Disclosed" via addressMetadata. The grant's scope.disclosure_level is
	// mapped to the corresponding VisibilityLevel (full/pseudonymous/redacted) —
	// see disclosureLevelToVisibility. Pre-fix this code path always upgraded
	// to VisibilityFull, dropping the level and leaking real addresses on every
	// tx-list / tx-detail surface for auditors holding pseudonymous or redacted
	// grants.
	if viewerDID != "" {
		grantedAddrs, err := d.getDisclosedAddressesWithLevels(ctx, viewerDID)
		if err == nil {
			for _, grant := range grantedAddrs {
				addr := strings.ToLower(grant.Address)
				current, exists := result[addr]
				if !exists {
					continue
				}
				if visibilityRank(grant.Level) > visibilityRank(current) {
					result[addr] = grant.Level
				}
			}
		}
	}

	return result, nil
}

// GetBatchVisibilityDetailed resolves visibility for a list of addresses, returning
// full AddressVisibility results including reason, pseudonym, and grant metadata.
// This uses the same logic as GetBatchVisibility (which the redactor depends on)
// but captures extra information needed by the API layer.
func (d *DB) GetBatchVisibilityDetailed(ctx context.Context, viewerDID string, addresses []string) (map[string]explorer.AddressVisibility, error) {
	result := make(map[string]explorer.AddressVisibility)
	if len(addresses) == 0 {
		return result, nil
	}

	// 1. Deduplicate and normalize addresses
	addrSet := make(map[string]bool)
	for _, a := range addresses {
		addrSet[strings.ToLower(a)] = true
	}
	var uniqueAddrs []string
	for a := range addrSet {
		uniqueAddrs = append(uniqueAddrs, a)
		// Default to hidden
		result[a] = explorer.AddressVisibility{
			Address: a,
			Visible: false,
			Level:   explorer.VisibilityHidden,
			Reason:  explorer.ReasonNoAccess,
		}
	}

	// 2. Look up owners for all unique addresses
	queryOwners := `
		SELECT LOWER(eth_address), did
		FROM eth_address_links
		WHERE LOWER(eth_address) = ANY($1)
		  AND revoked = false`

	rows, err := d.conn.QueryContext(ctx, queryOwners, uniqueAddrs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	addressOwners := make(map[string]string)
	for rows.Next() {
		var addr, did string
		if err := rows.Scan(&addr, &did); err != nil {
			return nil, err
		}
		addressOwners[addr] = did
	}

	// 3. Process first pass: Public addresses and Own addresses
	var targetDIDs []string
	didToAddresses := make(map[string][]string)

	for _, addr := range uniqueAddrs {
		ownerDID, hasOwner := addressOwners[addr]

		if !hasOwner {
			// No eth_address_links owner. Precompiles are always visible;
			// all other unowned addresses default to Hidden (private by default).
			if precompile.IsPrecompileAddress(addr) {
				result[addr] = explorer.AddressVisibility{
					Address: addr,
					Visible: true,
					Level:   explorer.VisibilityFull,
					Reason:  explorer.ReasonPublicAddress,
				}
			}
			// else: stays VisibilityHidden (set in initialization above)
			continue
		}

		if ownerDID == viewerDID && viewerDID != "" {
			// Own address
			result[addr] = explorer.AddressVisibility{
				Address: addr,
				Visible: true,
				Level:   explorer.VisibilityFull,
				Reason:  explorer.ReasonOwnAddress,
			}
			continue
		}

		// Otherwise, it belongs to someone else. We need to check grants.
		targetDIDs = append(targetDIDs, ownerDID)
		didToAddresses[ownerDID] = append(didToAddresses[ownerDID], addr)
	}

	// 4. Org contract visibility check — only non-precompile unowned addresses
	var publicAddrs []string
	for _, addr := range uniqueAddrs {
		if _, hasOwner := addressOwners[addr]; !hasOwner && !precompile.IsPrecompileAddress(addr) {
			publicAddrs = append(publicAddrs, addr)
		}
	}

	if len(publicAddrs) > 0 {
		// Detect which addresses are org-owned contracts.
		orgContractDetect := `
			SELECT LOWER(c.address) AS addr
			FROM contracts c
			WHERE LOWER(c.address) = ANY($1)`

		orgDetectRows, err := d.conn.QueryContext(ctx, orgContractDetect, publicAddrs)
		if err != nil {
			return nil, err
		}
		defer orgDetectRows.Close()

		var orgContractAddrs []string
		for orgDetectRows.Next() {
			var addr string
			if err := orgDetectRows.Scan(&addr); err != nil {
				return nil, err
			}
			orgContractAddrs = append(orgContractAddrs, addr)
			result[addr] = explorer.AddressVisibility{
				Address: addr,
				Visible: false,
				Level:   explorer.VisibilityRedacted,
				Reason:  explorer.ReasonNoAccess,
			}
		}

		// Find which groups grant visibility (same logic as GetBatchVisibility).
		// Org admin (is_org_admin) sees ALL org contracts (tier 2).
		// Contract grant holders see their granted contracts (any claim, including tier 3 admin).
		if viewerDID != "" && len(orgContractAddrs) > 0 {
			orgContractQuery := `
				SELECT LOWER(c.address) AS addr, g.id AS group_id
				FROM contracts c
				JOIN groups g ON g.org_id = c.org_id
				LEFT JOIN contract_grants cg ON cg.contract_id = c.id AND cg.group_id = g.id
				WHERE LOWER(c.address) = ANY($1)
				  AND (g.is_org_admin = true
				       OR cg.id IS NOT NULL)`

			orgRows, err := d.conn.QueryContext(ctx, orgContractQuery, orgContractAddrs)
			if err != nil {
				return nil, err
			}
			defer orgRows.Close()

			contractGroupIDs := make(map[string]map[string]bool)
			for orgRows.Next() {
				var addr, groupID string
				if err := orgRows.Scan(&addr, &groupID); err != nil {
					return nil, err
				}
				if contractGroupIDs[addr] == nil {
					contractGroupIDs[addr] = make(map[string]bool)
				}
				contractGroupIDs[addr][groupID] = true
			}

			if len(contractGroupIDs) > 0 {
				allGroupIDs := make(map[string]bool)
				for _, groups := range contractGroupIDs {
					for gid := range groups {
						allGroupIDs[gid] = true
					}
				}
				groupIDSlice := make([]string, 0, len(allGroupIDs))
				for gid := range allGroupIDs {
					groupIDSlice = append(groupIDSlice, gid)
				}

				memberQuery := `
					SELECT DISTINCT m.group_id
					FROM user_memberships m
					JOIN users u ON u.id = m.user_id
					WHERE u.external_id = $1
					  AND m.group_id = ANY($2)
					  AND (m.expires_at IS NULL OR m.expires_at > NOW())`

				memberRows, err := d.conn.QueryContext(ctx, memberQuery, viewerDID, groupIDSlice)
				if err != nil {
					return nil, err
				}
				defer memberRows.Close()

				viewerGroups := make(map[string]bool)
				for memberRows.Next() {
					var gid string
					if err := memberRows.Scan(&gid); err != nil {
						return nil, err
					}
					viewerGroups[gid] = true
				}

				for addr, groups := range contractGroupIDs {
					for gid := range groups {
						if viewerGroups[gid] {
							result[addr] = explorer.AddressVisibility{
								Address: addr,
								Visible: true,
								Level:   explorer.VisibilityFull,
								Reason:  explorer.ReasonRBACGroupMember,
							}
							break
						}
					}
				}
			}
		}
	}

	// Check disclosure grants — see GetBatchVisibility for rationale. The
	// grant's scope.disclosure_level controls the resulting VisibilityLevel:
	// "full" → VisibilityFull (real address shown), "pseudonymous" →
	// VisibilityPseudonymous (Address-XXXX substituted by applyRedaction),
	// "redacted" → VisibilityRedacted ([PRIVATE] substituted). Missing /
	// unknown level fails safe to VisibilityRedacted.
	if viewerDID != "" {
		grantedAddrs, err := d.getDisclosedAddressesWithLevels(ctx, viewerDID)
		if err == nil {
			for _, grant := range grantedAddrs {
				addr := strings.ToLower(grant.Address)
				current, exists := result[addr]
				if !exists {
					continue
				}
				if visibilityRank(grant.Level) > visibilityRank(current.Level) {
					result[addr] = explorer.AddressVisibility{
						Address: addr,
						Visible: grant.Level != explorer.VisibilityHidden,
						Level:   grant.Level,
						Reason:  explorer.ReasonDisclosureGrant,
					}
				}
			}
		}
	}

	return result, nil
}

// getDisclosedAddressesForViewer returns ETH addresses that the viewer has an
// active disclosure grant on. Kept for the auditor-list code path and existing
// tests; GetBatchVisibility uses getDisclosedAddressesWithLevels so the grant's
// scope.disclosure_level can be honoured.
//
// The grant lookup is scoped to disclosure requests whose `org_id` matches an
// org the viewer is currently a member of (M13: defence-in-depth against
// cross-org leakage even if disclosure creation is partially exploited).
func (d *DB) getDisclosedAddressesForViewer(ctx context.Context, viewerDID string) ([]string, error) {
	grants, err := d.getDisclosedAddressesWithLevels(ctx, viewerDID)
	if err != nil {
		return nil, err
	}
	if len(grants) == 0 {
		return nil, nil
	}
	addrs := make([]string, 0, len(grants))
	for _, g := range grants {
		addrs = append(addrs, g.Address)
	}
	return addrs, nil
}

// disclosedGrantedAddress is the per-address view of an active disclosure grant
// the viewer holds. Address is the lowercased ETH address; Level is the
// visibility ceiling the grant's scope.disclosure_level resolves to (see
// disclosureLevelToVisibility for the mapping).
type disclosedGrantedAddress struct {
	Address string
	Level   explorer.VisibilityLevel
}

// getDisclosedAddressesWithLevels returns each active disclosure-grant address
// paired with the VisibilityLevel implied by the grant's
// scope.disclosure_level. Same org-scoping (M13) as the bare-address sibling.
//
// When the viewer holds multiple grants on the same address (e.g. one legacy
// grant with empty scope and one new grant with `disclosure_level=full`), the
// caller-side merge in GetBatchVisibility / GetBatchVisibilityDetailed picks
// the MAX level via visibilityRank — more permissive grants win.
func (d *DB) getDisclosedAddressesWithLevels(ctx context.Context, viewerDID string) ([]disclosedGrantedAddress, error) {
	if viewerDID == "" {
		return nil, nil
	}

	query := `
		SELECT LOWER(eal.eth_address),
		       COALESCE(g.scope->>'disclosure_level', '')
		FROM disclosure_grants g
		JOIN disclosure_requests r ON g.request_id = r.id
		JOIN users target_u ON r.target_user_id = target_u.id
		JOIN eth_address_links eal ON eal.did = target_u.external_id
		JOIN users viewer_u ON viewer_u.external_id = $1
		JOIN user_memberships m ON m.user_id = viewer_u.id
		JOIN groups gr ON gr.id = m.group_id
		WHERE r.requester_did = $1
		  AND eal.revoked = false
		  AND g.revoked_at IS NULL
		  AND g.expires_at > NOW()
		  AND gr.org_id = r.org_id
		  AND (m.expires_at IS NULL OR m.expires_at > NOW())`

	rows, err := d.conn.QueryContext(ctx, query, viewerDID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// De-dupe by address while keeping the MAX level — handles the multi-grant
	// case (same viewer, same target address, two grants of different levels).
	byAddr := make(map[string]explorer.VisibilityLevel)
	for rows.Next() {
		var addr, lvlStr string
		if err := rows.Scan(&addr, &lvlStr); err != nil {
			return nil, err
		}
		lvl := disclosureLevelToVisibility(lvlStr)
		if existing, ok := byAddr[addr]; !ok || visibilityRank(lvl) > visibilityRank(existing) {
			byAddr[addr] = lvl
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]disclosedGrantedAddress, 0, len(byAddr))
	for addr, lvl := range byAddr {
		out = append(out, disclosedGrantedAddress{Address: addr, Level: lvl})
	}
	return out, nil
}

// disclosureLevelToVisibility maps a disclosure_request.scope.disclosure_level
// string to the VisibilityLevel the redactor uses. Unknown / empty levels fail
// safe to VisibilityRedacted ([PRIVATE] placeholder) — see /docs/disclosure
// §"Fail-Safe Defaults": legacy grants with empty scope must not silently
// upgrade to Full just because a grant exists.
func disclosureLevelToVisibility(level string) explorer.VisibilityLevel {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "full":
		return explorer.VisibilityFull
	case "pseudonymous":
		return explorer.VisibilityPseudonymous
	case "redacted":
		return explorer.VisibilityRedacted
	default:
		return explorer.VisibilityRedacted
	}
}

// visibilityRank assigns a total order over VisibilityLevel for use when two
// independent sources (own-address, RBAC group, disclosure grant, multiple
// grants of different levels) all claim a stake on the same address. The
// higher rank wins: a less-permissive grant must NOT downgrade a more
// permissive one. Mapping:
//
//	Hidden       → 0  (no signal)
//	Redacted     → 1  ([PRIVATE] placeholder visible)
//	Pseudonymous → 2  (Address-XXXX visible)
//	Full         → 3  (real address visible)
func visibilityRank(l explorer.VisibilityLevel) int {
	switch l {
	case explorer.VisibilityFull:
		return 3
	case explorer.VisibilityPseudonymous:
		return 2
	case explorer.VisibilityRedacted:
		return 1
	default:
		return 0
	}
}

// GetBatchEventAccess checks which contracts the viewer has event/log access to.
// Returns a map of lowercase contract address -> bool (true = has event access).
func (d *DB) GetBatchEventAccess(ctx context.Context, viewerDID string, contractAddresses []string) (map[string]bool, error) {
	result := make(map[string]bool)
	if len(contractAddresses) == 0 || viewerDID == "" {
		return result, nil
	}

	// Normalize
	uniqueAddrs := make([]string, 0, len(contractAddresses))
	seen := make(map[string]bool)
	for _, a := range contractAddresses {
		lower := strings.ToLower(a)
		if !seen[lower] {
			seen[lower] = true
			uniqueAddrs = append(uniqueAddrs, lower)
		}
	}

	query := `
		SELECT DISTINCT LOWER(c.address)
		FROM contracts c
		JOIN groups g ON g.org_id = c.org_id
		LEFT JOIN contract_grants cg ON cg.contract_id = c.id AND cg.group_id = g.id
		JOIN user_memberships m ON m.group_id = g.id
		JOIN users u ON u.id = m.user_id
		WHERE LOWER(c.address) = ANY($1)
		  AND u.external_id = $2
		  AND (m.expires_at IS NULL OR m.expires_at > NOW())
		  AND (
		    g.is_org_admin = true
		    OR (cg.event_rules IS NOT NULL AND cg.event_rules::text != '[]' AND cg.event_rules::text != 'null')
		  )`

	rows, err := d.conn.QueryContext(ctx, query, uniqueAddrs, viewerDID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var addr string
		if err := rows.Scan(&addr); err != nil {
			return nil, err
		}
		result[addr] = true
	}
	return result, rows.Err()
}

// GetLinkedAddresses returns the lowercase ETH addresses linked to a DID.
func (d *DB) GetLinkedAddresses(ctx context.Context, did string) ([]string, error) {
	if did == "" {
		return nil, nil
	}

	query := `
		SELECT LOWER(eth_address)
		FROM eth_address_links
		WHERE did = $1
		  AND revoked = false`

	rows, err := d.conn.QueryContext(ctx, query, did)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var addrs []string
	for rows.Next() {
		var addr string
		if err := rows.Scan(&addr); err != nil {
			return nil, err
		}
		addrs = append(addrs, addr)
	}
	return addrs, rows.Err()
}
