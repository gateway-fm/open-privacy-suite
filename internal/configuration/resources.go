package configuration

import (
	"fmt"
	"reflect"
	"sort"
)

// diffResources is shared by revision projections with stable resource IDs.
// A source may adopt drift but cannot delete a resource it has never owned.
func diffResources[T any](kind string, current, wanted []T, managedIDs []string, deletions []Deletion, used map[string]bool, idOf func(T) string) ([]T, []ResourceChange, []string, error) {
	result, changes, drift := []T{}, []ResourceChange{}, []string{}
	managed, deleted := map[string]bool{}, map[string]bool{}
	for _, id := range managedIDs {
		managed[id] = true
	}
	for _, del := range deletions {
		deleted[del.ID] = true
	}
	target, seen := map[string]T{}, map[string]bool{}
	for _, row := range wanted {
		id := idOf(row)
		if _, ok := target[id]; ok {
			return nil, nil, nil, fmt.Errorf("duplicate %s resource", kind)
		}
		target[id] = row
		if deleted[id] {
			return nil, nil, nil, fmt.Errorf("resource %s is both present and deleted", id)
		}
	}
	for _, before := range current {
		id := idOf(before)
		if seen[id] {
			return nil, nil, nil, fmt.Errorf("duplicate current resource")
		}
		seen[id] = true
		after, present := target[id]
		if !present {
			if !managed[id] {
				if deleted[id] {
					return nil, nil, nil, fmt.Errorf("unmanaged resource %s must be adopted before deletion", id)
				}
				result = append(result, before)
				drift = append(drift, id)
				continue
			}
			if !deleted[id] {
				return nil, nil, nil, fmt.Errorf("omitted %s %s requires explicit deletion", kind, id)
			}
			used[id] = true
			changes = append(changes, ResourceChange{Action: "delete", Resource: kind, ID: id})
			continue
		}
		result = append(result, after)
		if !managed[id] || !reflect.DeepEqual(before, after) {
			action := "update"
			if !managed[id] {
				action = "adopt"
			}
			changes = append(changes, ResourceChange{Action: action, Resource: kind, ID: id})
		}
	}
	for _, after := range wanted {
		id := idOf(after)
		if !seen[id] {
			result = append(result, after)
			changes = append(changes, ResourceChange{Action: "create", Resource: kind, ID: id})
		}
	}
	sort.Slice(result, func(i, j int) bool { return idOf(result[i]) < idOf(result[j]) })
	sort.Slice(changes, func(i, j int) bool { return changes[i].ID < changes[j].ID })
	sort.Strings(drift)
	return result, changes, drift, nil
}
