package configuration

import (
	"encoding/hex"
	"fmt"
	"net/url"
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

// PriceFeedFormatCoinGeckoSimple is the one response shape the poller reads:
// CoinGecko's /simple/price, {id:{currency:price}}. Token identity still comes
// from the compliance stream's coingeckoId, whatever host serves the shape.
const PriceFeedFormatCoinGeckoSimple = "coingecko-simple"

// Bounds on a declared refresh interval: the floor the environment setting
// also has, and one day. Whether an interval is short enough for this
// deployment's staleness threshold is the server's check, not the document's.
const (
	MinPriceFeedRefreshSeconds = 60
	MaxPriceFeedRefreshSeconds = 86400
)

// PriceFeed names the price source the deployment polls and how often. It is
// desired state for the pricing service; a deployment whose environment turns
// price fetching off stores it and does nothing with it.
type PriceFeed struct {
	URI                    string `json:"uri"`
	RefreshIntervalSeconds int    `json:"refreshIntervalSeconds"`
	Format                 string `json:"format"`
}
type PlatformSpec struct {
	SharedInfrastructure []SharedInfrastructure `json:"sharedInfrastructure"`
	Tenants              []Tenant               `json:"tenants"`
	// PriceFeed, when present, names the endpoint and interval the pricing
	// service polls; absent means the environment defaults apply.
	PriceFeed *PriceFeed `json:"priceFeed,omitempty" optional:"true"`
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
	if err := validatePriceFeed(s.PriceFeed); err != nil {
		return err
	}
	sort.Slice(s.SharedInfrastructure, func(i, j int) bool { return s.SharedInfrastructure[i].ID < s.SharedInfrastructure[j].ID })
	sort.Slice(s.Tenants, func(i, j int) bool { return s.Tenants[i].ID < s.Tenants[j].ID })
	return nil
}

// validatePriceFeed checks what a document alone can decide: the one known
// format, the interval bounds, and that the URI is a destination and nothing
// else — absolute http(s) with a host, no credentials, no fragment. Whether
// that destination is allowed in this deployment is checked by the server.
func validatePriceFeed(f *PriceFeed) error {
	if f == nil {
		return nil
	}
	if f.Format != PriceFeedFormatCoinGeckoSimple {
		return fmt.Errorf("priceFeed.format must be %q", PriceFeedFormatCoinGeckoSimple)
	}
	if f.RefreshIntervalSeconds < MinPriceFeedRefreshSeconds || f.RefreshIntervalSeconds > MaxPriceFeedRefreshSeconds {
		return fmt.Errorf("priceFeed.refreshIntervalSeconds must be between %d and %d", MinPriceFeedRefreshSeconds, MaxPriceFeedRefreshSeconds)
	}
	u, err := url.Parse(f.URI)
	if err != nil || len(f.URI) > 2048 || (u.Scheme != "https" && u.Scheme != "http") || u.Opaque != "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("priceFeed.uri must be an absolute http(s) URL with a host and without credentials or fragment")
	}
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
	// The feed is one resource without an id: present or absent, so absence
	// is the deletion and no entry in deletions is needed.
	before, after := snapshot.Spec.PriceFeed, spec.PriceFeed
	switch {
	case before == nil && after != nil:
		out.Changes = append(out.Changes, ResourceChange{Action: "create", Resource: "priceFeed", ID: "priceFeed"})
	case before != nil && after == nil:
		out.Changes = append(out.Changes, ResourceChange{Action: "delete", Resource: "priceFeed", ID: "priceFeed"})
	case before != nil && after != nil && *before != *after:
		out.Changes = append(out.Changes, ResourceChange{Action: "update", Resource: "priceFeed", ID: "priceFeed"})
	}
	out.Projection = PlatformSpec{SharedInfrastructure: shared, Tenants: tenants, PriceFeed: after}
	sort.Strings(out.PreservedDrift)
	if err := normalizePlatform(&out.Projection); err != nil {
		return out, err
	}
	return out, nil
}
