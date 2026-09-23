package configuration

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"privacy-proxy/internal/rbac"
)

// A non-nil error is a *SourceError.
func DiffGroups(document *Document, snapshot GroupSnapshot) (GroupDiff, error) {
	v0, err := diffGroups(document, snapshot)
	if err != nil {
		return v0, sourceError(err)
	}
	return v0, nil
}

// diffGroups is DiffGroups before its error is typed.
func diffGroups(document *Document, snapshot GroupSnapshot) (GroupDiff, error) {
	result := GroupDiff{Changes: []GroupChange{}, PreservedDrift: []string{}, Projection: []Group{}}
	if document == nil {
		return result, fmt.Errorf("document is required")
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return result, fmt.Errorf("document cannot be serialized")
	}
	d, err := Parse(raw)
	if err != nil {
		return result, err
	}
	if d.Kind != Groups {
		return result, fmt.Errorf("group diff requires groups kind")
	}
	if d.Scope != snapshot.Scope {
		return result, fmt.Errorf("configuration scope changed")
	}
	if d.BaseRevision != snapshot.ActiveRevision {
		return result, fmt.Errorf("configuration base is stale")
	}
	wanted := map[string]Group{}
	for _, group := range d.Spec.(GroupsSpec).Groups {
		wanted[group.ID] = group
	}
	deletions := map[string]Deletion{}
	for _, deletion := range d.Deletions {
		if _, present := wanted[deletion.ID]; present {
			return result, fmt.Errorf("resource %s is both present and deleted", deletion.ID)
		}
		deletions[deletion.ID] = deletion
	}
	seen := map[string]bool{}
	for _, state := range snapshot.Groups {
		id := state.Group.ID
		if seen[id] || !canonicalUUID(id) || state.LiveMemberships < 0 {
			return result, fmt.Errorf("invalid group snapshot")
		}
		seen[id] = true
		before := state.Group
		after, present := wanted[id]
		deletion, deleted := deletions[id]
		if !present {
			if !state.Managed {
				if deleted {
					return result, fmt.Errorf("unmanaged resource %s must be adopted before deletion", id)
				}
				result.PreservedDrift = append(result.PreservedDrift, id)
				result.Projection = append(result.Projection, before)
				continue
			}
			if !deleted {
				return result, fmt.Errorf("omitted group %s requires an explicit deletion", id)
			}
			if state.Protected {
				return result, fmt.Errorf("protected group %s cannot be deleted", id)
			}
			if state.LiveMemberships > 0 && (deletion.LiveMemberships == nil || *deletion.LiveMemberships != state.LiveMemberships) {
				return result, fmt.Errorf("group %s membership count must be acknowledged exactly", id)
			}
			if deletion.LiveMemberships != nil && *deletion.LiveMemberships != state.LiveMemberships {
				return result, fmt.Errorf("group %s membership count changed", id)
			}
			result.Changes = append(result.Changes, GroupChange{Action: "delete", ID: id, Before: &before, LiveMemberships: state.LiveMemberships, RequiresPlatform: before.IsOrgAdmin})
			continue
		}
		changed := !reflect.DeepEqual(before, after)
		if state.Protected && changed {
			return result, fmt.Errorf("protected group %s cannot be changed", id)
		}
		result.Projection = append(result.Projection, after)
		if changed || !state.Managed {
			action := "update"
			if !state.Managed {
				action = "adopt"
			}
			result.Changes = append(result.Changes, GroupChange{Action: action, ID: id, Before: &before, After: &after,
				LiveMemberships: state.LiveMemberships, RequiresPlatform: changed && (before.IsOrgAdmin || after.IsOrgAdmin)})
		}
	}
	for id := range deletions {
		if !seen[id] {
			return result, fmt.Errorf("deletion names an unknown group %s", id)
		}
	}
	for id, after := range wanted {
		if seen[id] {
			continue
		}
		result.Projection = append(result.Projection, after)
		result.Changes = append(result.Changes, GroupChange{Action: "create", ID: id, After: &after, RequiresPlatform: after.IsOrgAdmin})
	}
	sort.Slice(result.Changes, func(i, j int) bool { return result.Changes[i].ID < result.Changes[j].ID })
	sort.Strings(result.PreservedDrift)
	sort.Slice(result.Projection, func(i, j int) bool { return result.Projection[i].ID < result.Projection[j].ID })
	// New identifiers must not collide with a preserved unmanaged name/slug.
	projection := GroupsSpec{Groups: result.Projection}
	if err := normalizeGroups(&projection, document.Scope); err != nil {
		return result, err
	}
	beforeAdmins, afterAdmins := int64(0), int64(0)
	activeMembers := map[string]int64{}
	for _, state := range snapshot.Groups {
		activeMembers[state.Group.ID] = state.ActiveMembers
		if state.Group.IsOrgAdmin {
			beforeAdmins += state.ActiveMembers
		}
	}
	for _, group := range result.Projection {
		if group.IsOrgAdmin {
			afterAdmins += activeMembers[group.ID]
		}
	}
	if beforeAdmins > 0 && afterAdmins == 0 {
		return result, fmt.Errorf("configuration cannot remove the last live full administrator")
	}
	return result, nil
}

func ExportGroup(group *rbac.Group, access *rbac.GroupAccess) Group {
	out := Group{AllowedMethods: []string{}, Claims: []string{}}
	if group == nil {
		return out
	}
	out.ID, out.Slug, out.Name, out.Description = group.ID, group.Slug, group.Name, group.Description
	out.IsOrgAdmin, out.IsOrgReadonlyAdmin = group.IsOrgAdmin, group.IsOrgReadonlyAdmin
	if access != nil {
		out.AllowedMethods = append(out.AllowedMethods, rbac.ExpandWildcardMethods(access.AllowedMethods)...)
		for _, claim := range rbac.ExpandClaims(access.Claims) {
			out.Claims = append(out.Claims, string(claim))
		}
		out.VerboseErrors = access.VerboseErrors
		if access.RPCAPIKeySource != nil && *access.RPCAPIKeySource != "" {
			out.RpcCredential = &SecretRef{FromEnv: *access.RPCAPIKeySource}
		}
	}
	sort.Strings(out.AllowedMethods)
	sort.Strings(out.Claims)
	return out
}

// ExportRegistry splits the existing inventory into registry-owned read
// configuration and execution import material. It does not guess claims from
// group defaults and never normalizes nil functions into an empty slice.
// A non-nil error is a *SourceError.
func ExportRegistry(rows []RegistryRow) (RegistrySpec, []LegacyExecutionGrant, error) {
	v0, v1, err := exportRegistry(rows)
	if err != nil {
		return v0, v1, sourceError(err)
	}
	return v0, v1, nil
}

// exportRegistry is ExportRegistry before its error is typed.
func exportRegistry(rows []RegistryRow) (RegistrySpec, []LegacyExecutionGrant, error) {
	spec := RegistrySpec{Contracts: []Contract{}}
	execution := []LegacyExecutionGrant{}
	for _, row := range rows {
		if row.Contract == nil {
			return spec, nil, fmt.Errorf("registry export contains a missing contract")
		}
		contract := row.Contract
		abiJSON := contract.ABI
		if abiJSON == "" {
			abiJSON = "[]"
		}
		out := Contract{ID: contract.ID, Address: contract.Address, Name: contract.Name, ABI: json.RawMessage(abiJSON),
			AllowVisibleToUnlock: contract.AllowVisibleToUnlock, EventsAllowDynamicPayload: contract.EventsAllowDynamicPayload, ReadGrants: []ReadGrant{}}
		for _, item := range row.Grants {
			if item.Grant == nil {
				return spec, nil, fmt.Errorf("registry export contains a missing grant")
			}
			grant := item.Grant
			read := ReadGrant{ID: grant.ID, GroupID: grant.GroupID, LegacyClaims: append([]string{}, item.Claims...), EventRules: EventRules{Mode: "none", Rules: []EventRule{}}}
			if grant.EventRules != nil {
				if grant.EventRules.Wildcard {
					read.EventRules.Mode = "all"
				} else if len(grant.EventRules.Rules) != 0 {
					read.EventRules.Mode = "allowlist"
					for _, rule := range grant.EventRules.Rules {
						read.EventRules.Rules = append(read.EventRules.Rules, EventRule{Topic0: rule.Topic0, Name: rule.Name, ParamRules: append([]rbac.ParamRule{}, rule.ParamRules...)})
					}
				}
			}
			out.ReadGrants = append(out.ReadGrants, read)
			var functions []rbac.FunctionRule
			if grant.Functions != nil {
				functions = make([]rbac.FunctionRule, len(grant.Functions))
				for i, rule := range grant.Functions {
					functions[i] = rule
					functions[i].ParamRules = append([]rbac.ParamRule(nil), rule.ParamRules...)
				}
			}
			execution = append(execution, LegacyExecutionGrant{Address: contract.Address, GroupID: grant.GroupID, Functions: functions})
		}
		spec.Contracts = append(spec.Contracts, out)
	}
	if err := normalizeRegistry(&spec); err != nil {
		return spec, nil, err
	}
	sort.Slice(execution, func(i, j int) bool {
		if execution[i].Address != execution[j].Address {
			return execution[i].Address < execution[j].Address
		}
		return execution[i].GroupID < execution[j].GroupID
	})
	return spec, execution, nil
}
