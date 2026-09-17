package policydsl

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// NormalizeProxyPairs validates an explicit, bounded operator declaration.
// No relationship is inferred from selectors, metadata or obsolete DB tables.
func NormalizeProxyPairs(pairs []LegacyProxyPair) ([]LegacyProxyPair, error) {
	if len(pairs) > 64 {
		return nil, fmt.Errorf("at most 64 explicit proxy pairs are supported")
	}
	out := append([]LegacyProxyPair(nil), pairs...)
	seen := map[string]bool{}
	for i := range out {
		pair := &out[i]
		if !common.IsHexAddress(pair.StorageAddress) || !common.IsHexAddress(pair.CodeAddress) || strings.EqualFold(pair.StorageAddress, pair.CodeAddress) {
			return nil, fmt.Errorf("proxy pair requires distinct exact storage and code addresses")
		}
		pair.StorageAddress = strings.ToLower(pair.StorageAddress)
		pair.CodeAddress = strings.ToLower(pair.CodeAddress)
		key := pair.StorageAddress + pair.CodeAddress
		if seen[key] {
			return nil, fmt.Errorf("proxy pair is duplicated")
		}
		seen[key] = true
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StorageAddress != out[j].StorageAddress {
			return out[i].StorageAddress < out[j].StorageAddress
		}
		return out[i].CodeAddress < out[j].CodeAddress
	})
	return out, nil
}

// ApplyProxyPairs expands reviewed relationships into ordinary explicit DSL
// DELEGATECALL rules. Each binding retains the implementation's selector and
// argument limits; no group or function permission is invented from ownership.
// A non-nil error is a *ValidationError.
func ApplyProxyPairs(policy *Policy, pairs []LegacyProxyPair) (*Policy, error) {
	v0, err := applyProxyPairs(policy, pairs)
	if err != nil {
		return v0, validationError(err)
	}
	return v0, nil
}

// applyProxyPairs is ApplyProxyPairs before its error is typed.
func applyProxyPairs(policy *Policy, pairs []LegacyProxyPair) (*Policy, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy is required")
	}
	checked, err := NormalizeProxyPairs(pairs)
	if err != nil {
		return nil, err
	}
	out := policy.clone()
	for _, pair := range checked {
		matched := false
		for i, original := range out.Bindings {
			for _, rule := range original.Allow {
				if rule.TargetClass != "" || rule.CodeAddress != "" || !strings.EqualFold(rule.StorageAddress, pair.CodeAddress) {
					continue
				}
				pairRule := rule
				pairRule.StorageAddress = pair.StorageAddress
				pairRule.CodeAddress = pair.CodeAddress
				pairRule.CallTypes = []CallType{CallTypeDelegateCall}
				out.Bindings[i].Allow = append(out.Bindings[i].Allow, pairRule)
				matched = true
			}
		}
		if !matched {
			return nil, &LegacyImportError{Issues: []LegacyImportIssue{{Address: pair.StorageAddress, Reason: "Explicit proxy pair has no implementation execution rules to preserve; add reviewed literal implementation rules or an explicit code/storage DELEGATECALL rule."}}}
		}
	}
	return out, nil
}
