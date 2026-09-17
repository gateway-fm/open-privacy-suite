package configuration

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

type SharedInfrastructure struct {
	ID          string `json:"id"`
	Address     string `json:"address"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Codehash    string `json:"codehash"`
}
type Tenant struct {
	ID             string `json:"id"`
	TenantID       string `json:"tenantId"`
	Label          string `json:"label"`
	DefaultOrgID   string `json:"defaultOrgId"`
	DefaultGroupID string `json:"defaultGroupId"`
	AutoProvision  bool   `json:"autoProvision"`
}
type PlatformSpec struct {
	SharedInfrastructure []SharedInfrastructure `json:"sharedInfrastructure"`
	Tenants              []Tenant               `json:"tenants"`
}

func (PlatformSpec) configurationKind() Kind { return Platform }

type PlatformSnapshot struct {
	ActiveRevision int64        `json:"activeRevision"`
	Spec           PlatformSpec `json:"spec"`
	ManagedIDs     []string     `json:"managedIds"`
}
type PlatformDiff struct {
	Changes        []ResourceChange `json:"changes"`
	PreservedDrift []string         `json:"preservedDrift"`
	Projection     PlatformSpec     `json:"projection"`
}

func normalizePlatform(s *PlatformSpec) error {
	ids, addresses := map[string]bool{}, map[string]bool{}
	for _, v := range s.SharedInfrastructure {
		pin, err := hex.DecodeString(strings.TrimPrefix(v.Codehash, "0x"))
		if !canonicalUUID(v.ID) || ids[v.ID] || !canonicalAddress(v.Address) || addresses[v.Address] || v.Name == "" || len(v.Name) > 255 || len(v.Description) > 4096 || err != nil || len(pin) != 32 || len(v.Codehash) != 66 || strings.ToLower(v.Codehash) != v.Codehash {
			return fmt.Errorf("invalid or unpinned shared infrastructure")
		}
		ids[v.ID], addresses[v.Address] = true, true
	}
	tenants := map[string]bool{}
	for _, v := range s.Tenants {
		if !canonicalUUID(v.ID) || ids[v.ID] || !canonicalUUID(v.TenantID) || tenants[v.TenantID] || len(v.Label) > 1024 || (v.DefaultOrgID != "" && !canonicalUUID(v.DefaultOrgID)) || (v.DefaultGroupID != "" && (!canonicalUUID(v.DefaultGroupID) || v.DefaultOrgID == "")) {
			return fmt.Errorf("invalid or duplicate platform tenant")
		}
		ids[v.ID], tenants[v.TenantID] = true, true
	}
	sort.Slice(s.SharedInfrastructure, func(i, j int) bool { return s.SharedInfrastructure[i].ID < s.SharedInfrastructure[j].ID })
	sort.Slice(s.Tenants, func(i, j int) bool { return s.Tenants[i].ID < s.Tenants[j].ID })
	return nil
}

// A non-nil error is a *SourceError.
func DiffPlatform(doc *Document, snapshot PlatformSnapshot) (PlatformDiff, error) {
	v0, err := diffPlatform(doc, snapshot)
	if err != nil {
		return v0, sourceError(err)
	}
	return v0, nil
}

// diffPlatform is DiffPlatform before its error is typed.
func diffPlatform(doc *Document, snapshot PlatformSnapshot) (PlatformDiff, error) {
	out := PlatformDiff{Changes: []ResourceChange{}, PreservedDrift: []string{}}
	if doc == nil || doc.Kind != Platform || doc.Scope.Kind != "platform" || doc.Scope.ID != "" || doc.BaseRevision != snapshot.ActiveRevision {
		return out, fmt.Errorf("platform scope or base changed")
	}
	spec, ok := doc.Spec.(PlatformSpec)
	if !ok {
		return out, fmt.Errorf("invalid platform source")
	}
	used := map[string]bool{}
	shared, changes, drift, err := diffResources("sharedInfrastructure", snapshot.Spec.SharedInfrastructure, spec.SharedInfrastructure, snapshot.ManagedIDs, doc.Deletions, used, func(v SharedInfrastructure) string { return v.ID })
	if err != nil {
		return out, err
	}
	out.Changes = append(out.Changes, changes...)
	out.PreservedDrift = append(out.PreservedDrift, drift...)
	tenants, changes, drift, err := diffResources("tenant", snapshot.Spec.Tenants, spec.Tenants, snapshot.ManagedIDs, doc.Deletions, used, func(v Tenant) string { return v.ID })
	if err != nil {
		return out, err
	}
	out.Changes = append(out.Changes, changes...)
	out.PreservedDrift = append(out.PreservedDrift, drift...)
	for _, del := range doc.Deletions {
		if !used[del.ID] {
			return out, fmt.Errorf("deletion names unknown platform resource %s", del.ID)
		}
	}
	beforeShared := map[string]string{}
	for _, v := range snapshot.Spec.SharedInfrastructure {
		beforeShared[v.ID] = v.Address
	}
	for _, v := range shared {
		if old, ok := beforeShared[v.ID]; ok && old != v.Address {
			return out, fmt.Errorf("shared infrastructure address is immutable")
		}
	}
	beforeTenant := map[string]string{}
	for _, v := range snapshot.Spec.Tenants {
		beforeTenant[v.ID] = v.TenantID
	}
	for _, v := range tenants {
		if old, ok := beforeTenant[v.ID]; ok && old != v.TenantID {
			return out, fmt.Errorf("tenant identifier is immutable")
		}
	}
	out.Projection = PlatformSpec{SharedInfrastructure: shared, Tenants: tenants}
	sort.Strings(out.PreservedDrift)
	if err := normalizePlatform(&out.Projection); err != nil {
		return out, err
	}
	return out, nil
}
