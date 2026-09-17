package policydsl

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"sort"
	"strings"
)

// LegacySnapshot is a directory adapter's explicit source snapshot. Claims come
// from group_access, gated by that group's contract_grants; the obsolete claims
// column on contract_grants is deliberately not represented here.
type LegacySnapshot struct {
	Groups []LegacyGroup
	// These are checked source records. Actual deployment relationships are
	// resolved by the node for the named principal, never inferred from signer.
	IndividualDeployerAddresses []string
	PreregisteredAddresses      []string
	ProxyPairs                  []LegacyProxyPair
}

// LegacyProxyPair is an operator-reviewed code/storage relationship, not a
// prediction inferred from a function selector or an obsolete proxy table.
type LegacyProxyPair struct {
	StorageAddress string `json:"storageAddress"`
	CodeAddress    string `json:"codeAddress"`
}

type LegacyGroup struct {
	ID       string
	OrgAdmin bool
	Claims   []string
	Grants   []LegacyGrant
}

type LegacyGrant struct {
	Address string
	// Nil permits all functions, including receive/fallback. A non-nil empty
	// slice is an events-only grant and contributes no execution rules.
	Functions []LegacyFunction
}

type LegacyFunction struct {
	Selector   string
	ParamRules []LegacyParamRule
}

type LegacyParamRule struct {
	Index  int
	MustBe string
}

type LegacyImportIssue struct {
	Group   string `json:"group,omitempty"`
	Address string `json:"address,omitempty"`
	Reason  string `json:"reason"`
}

// LegacyImportError is a reviewable report. Unsupported input never returns a
// partial policy that a caller could accidentally activate.
type LegacyImportError struct {
	Issues []LegacyImportIssue `json:"issues"`
}

func (e *LegacyImportError) Error() string {
	return fmt.Sprintf("legacy execution policy import needs review: %d unsupported source records", len(e.Issues))
}

// ImportLegacy converts supported current RBAC execution grants. Visibility,
// event rules and RPC method allowlists remain their existing separate gates.
// The returned policy must still pass the normal review/activation lifecycle.
func ImportLegacy(snapshot LegacySnapshot, cat Catalog) (*Policy, error) {
	p := &Policy{APIVersion: APIVersion, Kind: Kind, Org: cat.Org, NestedCalls: NestedCallsRequireOwnRule}
	var issues []LegacyImportIssue
	issue := func(group, address, reason string) {
		issues = append(issues, LegacyImportIssue{Group: group, Address: address, Reason: reason})
	}
	for _, address := range snapshot.IndividualDeployerAddresses {
		if _, known := cat.Contracts[strings.ToLower(address)]; !common.IsHexAddress(address) || !known {
			issue("", address, "individual deployer target must be registered to this organization")
		}
	}
	for _, address := range snapshot.PreregisteredAddresses {
		if !common.IsHexAddress(address) {
			issue("", address, "preregistered deployment target must be a valid address")
		}
	}
	exceptionGroups := map[string]map[string]bool{}
	for _, group := range snapshot.Groups {
		for _, grant := range group.Grants {
			address := strings.ToLower(grant.Address)
			if exceptionGroups[address] == nil {
				exceptionGroups[address] = map[string]bool{}
			}
			exceptionGroups[address][group.ID] = true
		}
	}
	var exceptions []DeployerException
	for address, groups := range exceptionGroups {
		e := DeployerException{StorageAddress: address}
		for group := range groups {
			e.Groups = append(e.Groups, group)
		}
		sort.Strings(e.Groups)
		exceptions = append(exceptions, e)
	}
	sort.Slice(exceptions, func(i, j int) bool { return exceptions[i].StorageAddress < exceptions[j].StorageAddress })
	groups := append([]LegacyGroup(nil), snapshot.Groups...)
	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
	for gi, group := range groups {
		if gi > 0 && group.ID == groups[gi-1].ID {
			issue(group.ID, "", "duplicate source group")
			continue
		}
		if _, ok := cat.Groups[group.ID]; !ok || group.ID == "" {
			issue(group.ID, "", "source group is absent from the organisation catalog")
			continue
		}
		var claims uint8
		for _, claim := range group.Claims {
			switch claim {
			case "admin":
				claims |= ClaimAdmin | ClaimDeploy | ClaimUpgrade
			case "deploy":
				claims |= ClaimDeploy
			case "upgrade":
				claims |= ClaimUpgrade
			default:
				issue(group.ID, "", "unsupported operational claim "+claim)
			}
		}
		if group.OrgAdmin {
			claims = ClaimAdmin | ClaimDeploy | ClaimUpgrade
		}
		binding := Binding{Group: group.ID, Allow: []FrameRule{
			{TargetClass: "eoa", Selector: "0x"},
			{TargetClass: "precompile", Selector: "*"},
			{TargetClass: "shared", Selector: "*"},
		}}
		if !group.OrgAdmin {
			binding.Allow = append(binding.Allow, FrameRule{TargetClass: "deployer", Selector: "*", Except: cloneDeployerExceptions(exceptions)})
		}
		if claims&ClaimDeploy != 0 {
			binding.Allow = append(binding.Allow, FrameRule{TargetClass: "create", Selector: "*", CallTypes: []CallType{CallTypeCreate, CallTypeCreate2}})
			binding.Allow = append(binding.Allow, FrameRule{TargetClass: "pending", Selector: "*"})
		}
		if group.OrgAdmin {
			// Org-admin is a role, not the similarly named operational claim.
			binding.Allow = append(binding.Allow, FrameRule{TargetClass: "org", Selector: "*", AllowUpgrade: true, CallTypes: []CallType{CallTypeCall, CallTypeStaticCall, CallTypeDelegateCall, CallTypeCallCode}})
		} else {
			grants := append([]LegacyGrant(nil), group.Grants...)
			sort.Slice(grants, func(i, j int) bool { return strings.ToLower(grants[i].Address) < strings.ToLower(grants[j].Address) })
			for grantIndex, grant := range grants {
				address := strings.ToLower(grant.Address)
				if grantIndex > 0 && strings.EqualFold(grants[grantIndex-1].Address, address) {
					issue(group.ID, address, "duplicate source contract grant")
					continue
				}
				code, known := cat.Contracts[address]
				if !known {
					issue(group.ID, address, "granted address is absent from the organisation catalog")
					continue
				}
				if grant.Functions == nil {
					binding.Allow = append(binding.Allow, FrameRule{StorageAddress: address, Selector: "*", AllowUpgrade: claims&ClaimUpgrade != 0})
					continue
				}
				functions := append([]LegacyFunction(nil), grant.Functions...)
				sort.Slice(functions, func(i, j int) bool {
					return strings.ToLower(functions[i].Selector) < strings.ToLower(functions[j].Selector)
				})
				for fi, function := range functions {
					selector := strings.ToLower(function.Selector)
					if fi > 0 && strings.EqualFold(functions[fi-1].Selector, selector) {
						issue(group.ID, address, "duplicate function selector needs explicit constraint review")
						continue
					}
					if code.ABI == "" {
						issue(group.ID, address, "explicit function selector needs its registered ABI before migration")
						continue
					}
					rule := FrameRule{StorageAddress: address, Selector: selector, ABIDigest: ABIDigest(code.ABI), AllowUpgrade: claims&ClaimUpgrade != 0}
					for _, param := range function.ParamRules {
						if param.MustBe != "self" {
							issue(group.ID, address, "legacy parameter constraint is not the supported self condition")
							continue
						}
						rule.Args = append(rule.Args, ArgConstraint{Index: param.Index, AddressEquals: &AddressMatch{Source: AddressSourcePrincipalLinked}})
					}
					binding.Allow = append(binding.Allow, rule)
				}
			}
		}
		p.Bindings = append(p.Bindings, binding)
	}
	if len(issues) == 0 {
		expanded, err := ApplyProxyPairs(p, snapshot.ProxyPairs)
		if err != nil {
			issue("", "", "proxy migration: "+err.Error())
		} else {
			p = expanded
		}
	}
	if len(issues) == 0 {
		if _, err := Validate(p, cat); err != nil {
			issue("", "", "converted policy failed strict validation: "+err.Error())
		}
	}
	if len(issues) > 0 {
		sort.Slice(issues, func(i, j int) bool {
			a, b := issues[i], issues[j]
			if a.Group != b.Group {
				return a.Group < b.Group
			}
			if a.Address != b.Address {
				return a.Address < b.Address
			}
			return a.Reason < b.Reason
		})
		return nil, &LegacyImportError{Issues: issues}
	}
	return p, nil
}
