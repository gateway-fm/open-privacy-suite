package configuration

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/compliance"
)

type ComplianceSettings struct {
	Enabled            bool    `json:"enabled"`
	ThresholdFiat      float64 `json:"thresholdFiat"`
	Currency           string  `json:"currency"`
	UnknownPricePolicy string  `json:"unknownPricePolicy"`
	EnforcementMode    string  `json:"enforcementMode"`
}
type AddressThreshold struct {
	ID            string  `json:"id"`
	Address       string  `json:"address"`
	ThresholdFiat float64 `json:"thresholdFiat"`
	Note          string  `json:"note"`
}
type TokenPrice struct {
	ID               string             `json:"id"`
	TokenAddress     string             `json:"tokenAddress"`
	Symbol           string             `json:"symbol"`
	Decimals         int                `json:"decimals"`
	PricesByCurrency map[string]float64 `json:"pricesByCurrency"`
	CoingeckoID      string             `json:"coingeckoId"`
}
type ComplianceSpec struct {
	Settings          ComplianceSettings `json:"settings"`
	AddressThresholds []AddressThreshold `json:"addressThresholds"`
	TokenPrices       []TokenPrice       `json:"tokenPrices"`
}

func (ComplianceSpec) configurationKind() Kind { return Compliance }

type ComplianceSnapshot struct {
	Scope          Scope          `json:"scope"`
	ActiveRevision int64          `json:"activeRevision"`
	Spec           ComplianceSpec `json:"spec"`
	ManagedIDs     []string       `json:"managedIds"`
}
type ResourceChange struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	ID       string `json:"id"`
}
type ComplianceDiff struct {
	Changes        []ResourceChange `json:"changes"`
	PreservedDrift []string         `json:"preservedDrift"`
	Projection     ComplianceSpec   `json:"projection"`
}

func normalizeCompliance(s *ComplianceSpec) error {
	if !exactThreshold(s.Settings.ThresholdFiat) || !compliance.IsValidCurrency(s.Settings.Currency) ||
		(s.Settings.UnknownPricePolicy != "allowed" && s.Settings.UnknownPricePolicy != "forbidden") ||
		!compliance.IsValidEnforcementMode(compliance.EnforcementMode(s.Settings.EnforcementMode)) {
		return fmt.Errorf("invalid compliance settings")
	}
	ids, addresses := map[string]bool{}, map[string]bool{}
	for _, row := range s.AddressThresholds {
		if !canonicalUUID(row.ID) || ids[row.ID] || !canonicalAddress(row.Address) || addresses[row.Address] || !exactThreshold(row.ThresholdFiat) || len(row.Note) > 4096 {
			return fmt.Errorf("invalid or duplicate address threshold")
		}
		ids[row.ID], addresses[row.Address] = true, true
	}
	addresses = map[string]bool{}
	for _, row := range s.TokenPrices {
		if !canonicalUUID(row.ID) || ids[row.ID] || (row.TokenAddress != "native" && !canonicalAddress(row.TokenAddress)) || addresses[row.TokenAddress] || row.Decimals < 0 || row.Decimals > 255 || len(row.Symbol) == 0 || len(row.Symbol) > 20 || len(row.CoingeckoID) > 100 || strings.TrimSpace(row.CoingeckoID) != row.CoingeckoID {
			return fmt.Errorf("invalid or duplicate token price")
		}
		ids[row.ID], addresses[row.TokenAddress] = true, true
		for currency, price := range row.PricesByCurrency {
			if !compliance.IsValidCurrency(currency) || !finiteNonnegative(price) || price >= 1e12 {
				return fmt.Errorf("invalid manual token price")
			}
		}
	}
	sort.Slice(s.AddressThresholds, func(i, j int) bool { return s.AddressThresholds[i].ID < s.AddressThresholds[j].ID })
	sort.Slice(s.TokenPrices, func(i, j int) bool { return s.TokenPrices[i].ID < s.TokenPrices[j].ID })
	return nil
}
func finiteNonnegative(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 }

// Threshold columns are NUMERIC(20,2). Reject source values PostgreSQL would
// silently round; multiplying the binary float by 100 would incorrectly reject
// ordinary exact decimal inputs such as 0.29.
func exactThreshold(v float64) bool {
	if !finiteNonnegative(v) || v >= 1e18 {
		return false
	}
	text := strconv.FormatFloat(v, 'f', -1, 64)
	point := strings.IndexByte(text, '.')
	return point < 0 || len(text)-point-1 <= 2
}

// Existing compliance runtime models use float64. Preserve the authored decimal
// through their JSON round trip instead of silently accepting more precision
// than those models can carry. Prices remain JSON decimals, not 8-place values;
// only their backing price_fiat integer range is constrained above.
func validateComplianceWireNumbers(value any) error {
	switch value := value.(type) {
	case json.Number:
		if len(value.String()) > 128 {
			return fmt.Errorf("compliance number exceeds supported decimal precision")
		}
		v, err := value.Float64()
		if err != nil || !finiteNonnegative(v) {
			return fmt.Errorf("invalid compliance number")
		}
		if v == 0 {
			// Reject underflow without constructing a rational with an attacker-
			// chosen huge exponent. Arbitrarily spelled numeric zero needs no power.
			mantissa := strings.FieldsFunc(value.String(), func(r rune) bool { return r == 'e' || r == 'E' })[0]
			if strings.ContainsAny(mantissa, "123456789") {
				return fmt.Errorf("compliance number exceeds supported decimal precision")
			}
			return nil
		}
		a, ok := new(big.Rat).SetString(value.String())
		b, projected := new(big.Rat).SetString(strconv.FormatFloat(v, 'g', -1, 64))
		if !ok || !projected || a.Cmp(b) != 0 {
			return fmt.Errorf("compliance number exceeds supported decimal precision")
		}
	case map[string]any:
		for _, child := range value {
			if err := validateComplianceWireNumbers(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := validateComplianceWireNumbers(child); err != nil {
				return err
			}
		}
	}
	return nil
}
func canonicalAddress(v string) bool {
	return len(v) == 42 && strings.ToLower(v) == v && common.IsHexAddress(v)
}

// A non-nil error is a *SourceError.
func DiffCompliance(doc *Document, snapshot ComplianceSnapshot) (ComplianceDiff, error) {
	v0, err := diffCompliance(doc, snapshot)
	if err != nil {
		return v0, sourceError(err)
	}
	return v0, nil
}

// diffCompliance is DiffCompliance before its error is typed.
func diffCompliance(doc *Document, snapshot ComplianceSnapshot) (ComplianceDiff, error) {
	result := ComplianceDiff{Changes: []ResourceChange{}, PreservedDrift: []string{}}
	if doc == nil || doc.Kind != Compliance || doc.Scope != snapshot.Scope || doc.BaseRevision != snapshot.ActiveRevision {
		return result, fmt.Errorf("compliance scope or base changed")
	}
	spec, ok := doc.Spec.(ComplianceSpec)
	if !ok {
		return result, fmt.Errorf("invalid compliance source")
	}
	used := map[string]bool{}
	thresholds, changes, drift, err := diffResources("addressThreshold", snapshot.Spec.AddressThresholds, spec.AddressThresholds, snapshot.ManagedIDs, doc.Deletions, used, func(v AddressThreshold) string { return v.ID })
	if err != nil {
		return result, err
	}
	result.Changes = append(result.Changes, changes...)
	result.PreservedDrift = append(result.PreservedDrift, drift...)
	prices, changes, drift, err := diffResources("tokenPrice", snapshot.Spec.TokenPrices, spec.TokenPrices, snapshot.ManagedIDs, doc.Deletions, used, func(v TokenPrice) string { return v.ID })
	if err != nil {
		return result, err
	}
	result.Changes = append(result.Changes, changes...)
	result.PreservedDrift = append(result.PreservedDrift, drift...)
	for _, del := range doc.Deletions {
		if !used[del.ID] {
			return result, fmt.Errorf("deletion names unknown resource %s", del.ID)
		}
	}
	if snapshot.Spec.Settings != spec.Settings {
		result.Changes = append(result.Changes, ResourceChange{Action: "update", Resource: "settings", ID: "settings"})
	}
	result.Projection = ComplianceSpec{Settings: spec.Settings, AddressThresholds: thresholds, TokenPrices: prices}
	if err := normalizeCompliance(&result.Projection); err != nil {
		return result, err
	}
	sort.Strings(result.PreservedDrift)
	return result, nil
}
