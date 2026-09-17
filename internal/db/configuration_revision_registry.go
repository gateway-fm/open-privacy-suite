package db

import (
	"context"
	"encoding/json"
	"strings"

	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/rbac"
)

func configurationRegistry(ctx context.Context, q DBTX, scope configuration.Scope, active *ConfigurationRevision, lock bool) (configuration.RegistrySnapshot, []configuration.LegacyExecutionGrant, error) {
	snapshot := configuration.RegistrySnapshot{Scope: scope, Contracts: []configuration.ContractState{}}
	managed := map[string]bool{}
	managedGrants := map[string][]string{}
	if active != nil {
		snapshot.ActiveRevision = active.Revision
		doc, err := configuration.Parse([]byte(active.Source))
		if err != nil {
			return snapshot, nil, err
		}
		spec, ok := doc.Spec.(configuration.RegistrySpec)
		if !ok || doc.Scope != scope {
			return snapshot, nil, ConfigurationConflict("active registry source does not match its stream")
		}
		for _, c := range spec.Contracts {
			managed[c.ID] = true
			for _, g := range c.ReadGrants {
				managedGrants[c.ID] = append(managedGrants[c.ID], g.ID)
			}
		}
	}
	query := `SELECT id FROM contracts WHERE org_id=$1 ORDER BY id`
	if lock {
		query += ` FOR UPDATE`
	}
	rows, err := q.QueryContext(ctx, query, scope.ID)
	if err != nil {
		return snapshot, nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return snapshot, nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return snapshot, nil, err
	}
	exportRows := []configuration.RegistryRow{}
	for _, id := range ids {
		contract, err := getContract(ctx, q, id)
		if err != nil {
			return snapshot, nil, err
		}
		query := `SELECT ` + contractGrantColumns + ` FROM contract_grants WHERE contract_id=$1 ORDER BY id`
		if lock {
			query += ` FOR UPDATE`
		}
		rows, err := q.QueryContext(ctx, query, id)
		if err != nil {
			return snapshot, nil, err
		}
		grants, err := scanContractGrants(rows)
		rows.Close()
		if err != nil {
			return snapshot, nil, err
		}
		exportRow := configuration.RegistryRow{Contract: contract, Grants: []configuration.GrantRow{}}
		for _, grant := range grants {
			claims := []string{}
			var claimsJSON []byte
			if err := q.QueryRowContext(ctx, `SELECT to_json(claims) FROM contract_grants WHERE id=$1`, grant.ID).Scan(&claimsJSON); err != nil {
				return snapshot, nil, err
			}
			if err := json.Unmarshal(claimsJSON, &claims); err != nil {
				return snapshot, nil, err
			}
			exportRow.Grants = append(exportRow.Grants, configuration.GrantRow{Grant: grant, Claims: claims})
		}
		exportRows = append(exportRows, exportRow)
	}
	spec, execution, err := configuration.ExportRegistry(exportRows)
	if err != nil {
		return snapshot, nil, ConfigurationConflict("registry import requires repair before revision activation: %w", err)
	}
	for _, contract := range spec.Contracts {
		snapshot.Contracts = append(snapshot.Contracts, configuration.ContractState{Contract: contract, Managed: managed[contract.ID], ManagedGrantIDs: managedGrants[contract.ID]})
	}
	return snapshot, execution, nil
}

func validateConfigurationRegistry(ctx context.Context, q DBTX, view ConfigurationActivation, lock bool) error {
	groups := map[string]bool{}
	for _, state := range view.Groups.Groups {
		groups[state.Group.ID] = true
	}
	if view.GroupDiff != nil {
		groups = map[string]bool{}
		for _, group := range view.GroupDiff.Projection {
			groups[group.ID] = true
		}
	}
	contracts := []configuration.Contract{}
	for _, state := range view.Registry.Contracts {
		contracts = append(contracts, state.Contract)
	}
	if view.RegistryDiff != nil {
		contracts = view.RegistryDiff.Projection
	}
	addresses := map[string]bool{}
	for _, contract := range contracts {
		addresses[contract.Address] = true
	}
	groupIDs := []string{}
	for id := range groups {
		groupIDs = append(groupIDs, id)
	}
	for _, contract := range contracts {
		events, err := rbac.ExtractEventSignatures(string(contract.ABI))
		if err != nil {
			return err
		}
		eventByTopic := map[string]rbac.EventSignature{}
		for _, event := range events {
			eventByTopic[strings.ToLower(event.Topic0)] = event
		}
		for _, grant := range contract.ReadGrants {
			if !groups[grant.GroupID] {
				return ConfigurationConflict("registry grant must reference an existing group in the same organization")
			}
			customCount := 0
			for _, rule := range grant.EventRules.Rules {
				event := eventByTopic[rule.Topic0]
				for _, param := range rule.ParamRules {
					if !strings.HasPrefix(param.MustBe, "0x") || event.Inputs[param.Index].Type != "address" {
						continue
					}
					customCount++
					if customCount > 100 {
						return ConfigurationConflict("too many custom event addresses in grant")
					}
					if err := validateConfigurationEventAddress(ctx, q, view.Scope.ID, groupIDs, param.MustBe, addresses[param.MustBe], lock); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func validateConfigurationEventAddress(ctx context.Context, q DBTX, orgID string, groupIDs []string, address string, projectedLocal, lock bool) error {
	local := projectedLocal
	for _, table := range []string{"contracts", "preregistered_addresses"} {
		query := `SELECT org_id FROM ` + table + ` WHERE lower(address)=$1 ORDER BY id`
		if lock {
			query += ` FOR SHARE`
		}
		rows, err := q.QueryContext(ctx, query, address)
		if err != nil {
			return err
		}
		for rows.Next() {
			var owner string
			if err := rows.Scan(&owner); err != nil {
				rows.Close()
				return err
			}
			if owner != orgID {
				rows.Close()
				return ConfigurationConflict("event address belongs to a different organization")
			}
			local = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	if local {
		return nil
	}
	query := `SELECT e.id FROM eth_address_links e JOIN users u ON u.external_id=e.did JOIN user_memberships m ON m.user_id=u.id
        WHERE lower(e.eth_address)=$1 AND NOT e.revoked AND NOT u.banned AND m.group_id=ANY($2::uuid[])
        AND (m.expires_at IS NULL OR m.expires_at>NOW()) ORDER BY e.id`
	if lock {
		query += ` FOR SHARE OF e`
	}
	rows, err := q.QueryContext(ctx, query, address, groupIDs)
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		found = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if !found {
		return ConfigurationConflict("event address is unregistered or outside the organization")
	}
	return nil
}

func projectConfiguration(ctx context.Context, tx *Tx, view ConfigurationActivation) error {
	projectionScope := view.Scope.ID
	if view.Scope.Kind == "platform" {
		projectionScope = "platform"
	}
	if _, err := tx.tx.ExecContext(ctx, `SELECT set_config('ops.configuration_projection',$1,true)`, projectionScope); err != nil {
		return err
	}
	if view.Scope.Kind == "platform" {
		return projectConfigurationPlatform(ctx, tx, view)
	}
	deletes := configuration.GroupDiff{}
	if view.GroupDiff != nil {
		updates := *view.GroupDiff
		updates.Changes = nil
		for _, change := range view.GroupDiff.Changes {
			if change.Action == "delete" {
				deletes.Changes = append(deletes.Changes, change)
			} else {
				updates.Changes = append(updates.Changes, change)
			}
		}
		if err := projectConfigurationGroups(ctx, tx, view.Scope, updates); err != nil {
			return err
		}
	}
	if view.RegistryDiff != nil {
		if err := projectConfigurationRegistry(ctx, tx, view.Scope, *view.RegistryDiff); err != nil {
			return err
		}
	}
	if len(deletes.Changes) != 0 {
		if err := projectConfigurationGroups(ctx, tx, view.Scope, deletes); err != nil {
			return err
		}
	}
	if err := projectConfigurationCompliance(ctx, tx, view); err != nil {
		return err
	}
	return projectConfigurationExecution(ctx, tx, &view)
}

// AuthorizeDeploymentRegistration permits only INSERTs from an internal,
// verified deployment reconciliation transaction. It cannot authorize a
// desired-state UPDATE or DELETE, and must never be exposed as an API flag.
func (tx *Tx) AuthorizeDeploymentRegistration(ctx context.Context, orgID string) error {
	if err := lockConfigurationScope(ctx, tx.tx, configuration.Scope{Kind: "organization", ID: orgID}); err != nil {
		return err
	}
	_, err := tx.tx.ExecContext(ctx, `SELECT set_config('ops.configuration_operation','deployment-registration',true),set_config('ops.configuration_operation_scope',$1,true)`, orgID)
	return err
}

func projectConfigurationRegistry(ctx context.Context, tx *Tx, scope configuration.Scope, diff configuration.RegistryDiff) error {
	contracts := map[string]configuration.Contract{}
	grants := map[string]configuration.ReadGrant{}
	grantContract := map[string]string{}
	for _, contract := range diff.Projection {
		contracts[contract.ID] = contract
		for _, grant := range contract.ReadGrants {
			grants[grant.ID] = grant
			grantContract[grant.ID] = contract.ID
		}
	}
	// Remove explicitly reviewed links before resources; additions run after
	// group creation and contract creation so co-activation has no FK gaps.
	for _, change := range diff.Changes {
		if change.Action == "delete" && change.Resource == "readGrant" {
			if err := tx.DeleteContractGrant(ctx, change.ID); err != nil {
				return err
			}
		}
	}
	for _, change := range diff.Changes {
		if change.Resource != "contract" {
			continue
		}
		if change.Action == "delete" {
			if err := tx.DeleteContract(ctx, change.ID); err != nil {
				return err
			}
			continue
		}
		contract := contracts[change.ID]
		if change.Action == "create" {
			if err := tx.CreateContract(ctx, &rbac.Contract{ID: contract.ID, OrgID: scope.ID, Address: contract.Address, Name: contract.Name, ABI: string(contract.ABI), Metadata: map[string]any{}}); err != nil {
				return err
			}
		}
		if _, err := tx.tx.ExecContext(ctx, `UPDATE contracts SET name=$2,abi=$3,allow_visibleto_unlock=$4,events_allow_dynamic_payload=$5,updated_at=NOW() WHERE id=$1 AND org_id=$6`, contract.ID, contract.Name, string(contract.ABI), contract.AllowVisibleToUnlock, contract.EventsAllowDynamicPayload, scope.ID); err != nil {
			return err
		}
	}
	for _, change := range diff.Changes {
		if change.Resource != "readGrant" || change.Action == "delete" {
			continue
		}
		grant := grants[change.ID]
		var eventRules *rbac.EventRulesField
		switch grant.EventRules.Mode {
		case "all":
			eventRules = &rbac.EventRulesField{Wildcard: true}
		case "allowlist":
			eventRules = &rbac.EventRulesField{Rules: []rbac.EventRule{}}
			for _, rule := range grant.EventRules.Rules {
				eventRules.Rules = append(eventRules.Rules, rbac.EventRule{Topic0: rule.Topic0, Name: rule.Name, ParamRules: rule.ParamRules})
			}
		}
		if change.Action == "create" {
			if err := tx.CreateContractGrant(ctx, &rbac.ContractGrant{ID: grant.ID, ContractID: grantContract[grant.ID], GroupID: grant.GroupID, Functions: []rbac.FunctionRule{}, EventRules: eventRules}); err != nil {
				return err
			}
		} else {
			raw, err := json.Marshal(eventRules)
			if err != nil {
				return err
			}
			if _, err := tx.tx.ExecContext(ctx, `UPDATE contract_grants SET event_rules=$2,updated_at=NOW() WHERE id=$1`, grant.ID, raw); err != nil {
				return err
			}
		}
	}
	return tx.InvalidateCacheForOrg(ctx, scope.ID)
}
