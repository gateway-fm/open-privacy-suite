package configuration

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// A non-nil error is a *SourceError.
func DiffRegistry(document *Document, snapshot RegistrySnapshot) (RegistryDiff, error) {
	v0, err := diffRegistry(document, snapshot)
	if err != nil {
		return v0, sourceError(err)
	}
	return v0, nil
}

// diffRegistry is DiffRegistry before its error is typed.
func diffRegistry(document *Document, snapshot RegistrySnapshot) (RegistryDiff, error) {
	result := RegistryDiff{Changes: []RegistryChange{}, PreservedDrift: []string{}, Projection: []Contract{}}
	if document == nil {
		return result, fmt.Errorf("document is required")
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return result, fmt.Errorf("document cannot be serialized")
	}
	doc, err := Parse(raw)
	if err != nil {
		return result, err
	}
	if doc.Kind != ContractRegistry || doc.Scope != snapshot.Scope {
		return result, fmt.Errorf("registry scope or kind changed")
	}
	if doc.BaseRevision != snapshot.ActiveRevision {
		return result, fmt.Errorf("registry base is stale")
	}
	wanted := map[string]Contract{}
	for _, c := range doc.Spec.(RegistrySpec).Contracts {
		wanted[c.ID] = c
	}
	deletions := map[string]bool{}
	for _, deletion := range doc.Deletions {
		deletions[deletion.ID] = true
	}
	consumeDelete := func(id string, managed bool) error {
		if !managed {
			return fmt.Errorf("unmanaged resource %s must be adopted before deletion", id)
		}
		if !deletions[id] {
			return fmt.Errorf("omitted resource %s requires an explicit deletion", id)
		}
		delete(deletions, id)
		return nil
	}
	for _, state := range snapshot.Contracts {
		before := state.Contract
		after, present := wanted[before.ID]
		managedGrants := map[string]bool{}
		for _, id := range state.ManagedGrantIDs {
			managedGrants[id] = true
		}
		if !present {
			if !state.Managed && !deletions[before.ID] {
				result.PreservedDrift = append(result.PreservedDrift, before.ID)
				result.Projection = append(result.Projection, before)
				continue
			}
			if err := consumeDelete(before.ID, state.Managed); err != nil {
				return result, err
			}
			for _, grant := range before.ReadGrants {
				if err := consumeDelete(grant.ID, managedGrants[grant.ID]); err != nil {
					return result, err
				}
				result.Changes = append(result.Changes, RegistryChange{Action: "delete", Resource: "readGrant", ID: grant.ID})
			}
			result.Changes = append(result.Changes, RegistryChange{Action: "delete", Resource: "contract", ID: before.ID})
			continue
		}
		if after.Address != before.Address {
			return result, fmt.Errorf("contract address is immutable; register a separate contract")
		}
		grants := map[string]ReadGrant{}
		for _, grant := range after.ReadGrants {
			grants[grant.ID] = grant
		}
		projected := []ReadGrant{}
		for _, old := range before.ReadGrants {
			next, present := grants[old.ID]
			if !present {
				if !managedGrants[old.ID] && !deletions[old.ID] {
					result.PreservedDrift = append(result.PreservedDrift, old.ID)
					projected = append(projected, old)
					continue
				}
				if err := consumeDelete(old.ID, managedGrants[old.ID]); err != nil {
					return result, err
				}
				result.Changes = append(result.Changes, RegistryChange{Action: "delete", Resource: "readGrant", ID: old.ID})
				continue
			}
			if next.GroupID != old.GroupID || !reflect.DeepEqual(next.LegacyClaims, old.LegacyClaims) {
				return result, fmt.Errorf("read grant group and legacy claims are immutable")
			}
			if !reflect.DeepEqual(old, next) || !managedGrants[old.ID] {
				action := "update"
				if !managedGrants[old.ID] {
					action = "adopt"
				}
				result.Changes = append(result.Changes, RegistryChange{Action: action, Resource: "readGrant", ID: old.ID})
			}
			projected = append(projected, next)
			delete(grants, old.ID)
		}
		for _, grant := range grants {
			if len(grant.LegacyClaims) != 0 {
				return result, fmt.Errorf("legacy claims are immutable historical metadata; new grants require []")
			}
			projected = append(projected, grant)
			result.Changes = append(result.Changes, RegistryChange{Action: "create", Resource: "readGrant", ID: grant.ID})
		}
		after.ReadGrants = projected
		oldMetadata, newMetadata := before, after
		oldMetadata.ReadGrants = nil
		newMetadata.ReadGrants = nil
		if !reflect.DeepEqual(oldMetadata, newMetadata) || !state.Managed {
			action := "update"
			if !state.Managed {
				action = "adopt"
			}
			result.Changes = append(result.Changes, RegistryChange{Action: action, Resource: "contract", ID: before.ID})
		}
		result.Projection = append(result.Projection, after)
		delete(wanted, before.ID)
	}
	for _, contract := range wanted {
		result.Changes = append(result.Changes, RegistryChange{Action: "create", Resource: "contract", ID: contract.ID})
		for _, grant := range contract.ReadGrants {
			if len(grant.LegacyClaims) != 0 {
				return result, fmt.Errorf("legacy claims are immutable historical metadata; new grants require []")
			}
			result.Changes = append(result.Changes, RegistryChange{Action: "create", Resource: "readGrant", ID: grant.ID})
		}
		result.Projection = append(result.Projection, contract)
	}
	if len(deletions) != 0 {
		return result, fmt.Errorf("deletion must name an omitted existing managed resource")
	}
	projection := RegistrySpec{Contracts: result.Projection}
	if err := normalizeRegistry(&projection); err != nil {
		return result, err
	}
	sort.Strings(result.PreservedDrift)
	sort.Slice(result.Changes, func(i, j int) bool { return result.Changes[i].ID < result.Changes[j].ID })
	return result, nil
}
