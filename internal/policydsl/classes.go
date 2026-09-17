package policydsl

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

const (
	ClaimAdmin     uint8 = 1
	ClaimDeploy    uint8 = 2
	ClaimUpgrade   uint8 = 4
	CodeUnknown    uint8 = 0
	CodeEOA        uint8 = 1
	CodeContract   uint8 = 2
	CodePrecompile uint8 = 3
)

// compileClassRule prepares rules that deliberately do not decode an ABI.
// Wildcard includes receive/fallback; empty input is a separate explicit rule.
func compileClassRule(r FrameRule, cat Catalog) (frameKey, *compiledRule, error) {
	var key frameKey
	if r.Selector != "*" && r.Selector != "0x" {
		return key, nil, fmt.Errorf("target classes require selector * or 0x")
	}
	if len(r.Args) != 0 || r.ABIDigest != "" {
		return key, nil, fmt.Errorf("wildcard and empty-input rules must not declare args or abiDigest")
	}
	key.targetClass = r.TargetClass
	key.selectorMode = selectorAny
	if r.Selector == "0x" {
		key.selectorMode = selectorEmpty
	}
	if r.TargetClass != "" && (r.StorageAddress != "" || r.CodeAddress != "") {
		return key, nil, fmt.Errorf("targetClass and literal addresses are mutually exclusive")
	}
	switch r.TargetClass {
	case "":
		if !common.IsHexAddress(r.StorageAddress) {
			return key, nil, fmt.Errorf("storageAddress must be a valid address")
		}
		key.storage = common.HexToAddress(r.StorageAddress)
		key.code = key.storage
		if r.CodeAddress != "" {
			if !common.IsHexAddress(r.CodeAddress) {
				return key, nil, fmt.Errorf("codeAddress must be a valid address")
			}
			key.code = common.HexToAddress(r.CodeAddress)
		}
		if _, ok := cat.Contracts[catalogKey(key.storage.Hex())]; !ok {
			return key, nil, fmt.Errorf("storageAddress is not registered to this organisation")
		}
		if _, ok := cat.Contracts[catalogKey(key.code.Hex())]; !ok {
			return key, nil, fmt.Errorf("codeAddress is not registered to this organisation")
		}
	case "org", "shared", "precompile":
	case "deployer", "pending":
		if r.AllowUpgrade || r.Selector != "*" {
			return key, nil, fmt.Errorf("deployer/pending rules require selector * and do not grant upgrades")
		}
	case "eoa":
		if r.Selector != "0x" {
			return key, nil, fmt.Errorf("eoa rules require selector 0x for empty calldata")
		}
	case "create":
		if r.Selector != "*" || len(r.CallTypes) == 0 || r.AllowUpgrade {
			return key, nil, fmt.Errorf("create rules require selector *, explicit create callTypes, and no allowUpgrade")
		}
	default:
		return key, nil, fmt.Errorf("unknown targetClass %q", r.TargetClass)
	}
	var kinds map[CallType]struct{}
	if r.TargetClass == "create" {
		kinds = make(map[CallType]struct{})
		for _, kind := range r.CallTypes {
			if kind != CallTypeCreate && kind != CallTypeCreate2 {
				return key, nil, fmt.Errorf("create rules permit only create/create2")
			}
			if _, dup := kinds[kind]; dup {
				return key, nil, fmt.Errorf("duplicate create callType")
			}
			kinds[kind] = struct{}{}
		}
	} else {
		var err error
		kinds, err = resolveCallTypes(r)
		if err != nil {
			return key, nil, err
		}
		for kind := range kinds {
			if r.TargetClass != "" && r.TargetClass != "org" && (kind == CallTypeDelegateCall || kind == CallTypeCallCode) {
				return key, nil, fmt.Errorf("shared, eoa and precompile classes permit only call/staticcall")
			}
			if key.code != key.storage && (kind == CallTypeCall || kind == CallTypeStaticCall) {
				return key, nil, fmt.Errorf("code differs from storage for call/staticcall")
			}
		}
	}
	compiled := &compiledRule{sig: r.TargetClass + " " + r.Selector, selectorMode: key.selectorMode, exactLen: key.selectorMode == selectorEmpty, callTypes: kinds, allowUpgrade: r.AllowUpgrade}
	var err error
	compiled.exceptions, err = compileDeployerExceptions(r, cat)
	if err != nil {
		return key, nil, err
	}
	if r.MaxValue != nil {
		if !isPlainDecimal(*r.MaxValue) {
			return key, nil, fmt.Errorf("maxValue must be unsigned decimal")
		}
		compiled.maxValue, _ = new(big.Int).SetString(*r.MaxValue, 10)
		if compiled.maxValue.BitLen() > 256 {
			return key, nil, fmt.Errorf("maxValue must fit uint256")
		}
	}
	if r.MaxDepth != nil {
		if *r.MaxDepth < 0 {
			return key, nil, fmt.Errorf("maxDepth must be nonnegative")
		}
		depth := *r.MaxDepth
		compiled.maxDepth = &depth
	}
	if r.CallerAddress != "" {
		if !common.IsHexAddress(r.CallerAddress) {
			return key, nil, fmt.Errorf("callerAddress must be an Ethereum address")
		}
		caller := common.HexToAddress(r.CallerAddress)
		compiled.caller = &caller
	}
	return key, compiled, nil
}

// upgradeAddressIndex mirrors the legacy upgrade guard. Checking an upgrade
// pointer does not depend on a nested call actually using that implementation.
func upgradeAddressIndex(data []byte) (int, bool) {
	if len(data) < 4 {
		return 0, false
	}
	switch [4]byte(data[:4]) {
	case [4]byte{0x36, 0x59, 0xcf, 0xe6}, [4]byte{0x4f, 0x1e, 0xf2, 0x86}, [4]byte{0xd7, 0x84, 0xd4, 0x26}:
		return 0, true
	case [4]byte{0x99, 0xa8, 0x8e, 0xc4}, [4]byte{0x96, 0x23, 0x60, 0x9d}:
		return 1, true
	default:
		return 0, false
	}
}

func (key frameKey) matchesTarget(org string, f Frame) bool {
	same := f.CodeAddress == f.StorageAddress
	switch key.targetClass {
	case "":
		return f.CodeAddress == key.code && f.StorageAddress == key.storage
	case "org":
		return f.CodeOrg == org && f.StorageOrg == org
	case "deployer":
		return same && f.StorageDeployer
	case "pending":
		return same && f.StoragePending
	case "shared":
		return same && f.CodeKind == CodeContract && f.CodeShared && f.StorageShared
	case "eoa":
		return same && f.CodeKind == CodeEOA && f.CodeOrg == "" && f.StorageOrg == ""
	case "precompile":
		return same && f.CodeKind == CodePrecompile
	case "create":
		return f.CallType == CallTypeCreate || f.CallType == CallTypeCreate2
	default:
		return false
	}
}

func (r *compiledRule) checkAuthority(ctx Context, f Frame, groupClaims uint8, key frameKey) (DenialCode, error) {
	if key.targetClass == "" || key.targetClass == "org" || key.targetClass == "create" || key.targetClass == "deployer" || key.targetClass == "pending" {
		if f.CodeOrg != ctx.Org || f.StorageOrg != ctx.Org {
			return DenialOwnership, fmt.Errorf("code and storage must belong to policy organisation")
		}
	}
	if r.deployerExcepted(ctx, f) {
		return DenialNoMatchingRule, fmt.Errorf("deployer fallback is excluded for this target and membership")
	}
	if key.targetClass == "pending" && groupClaims&(ClaimAdmin|ClaimDeploy) == 0 {
		return DenialOperationalClaim, fmt.Errorf("binding group lacks pending deployment authority")
	}
	if f.CallType == CallTypeCreate || f.CallType == CallTypeCreate2 {
		if groupClaims&(ClaimAdmin|ClaimDeploy) == 0 {
			return DenialOperationalClaim, fmt.Errorf("binding group lacks deploy claim")
		}
		if len(f.Calldata) == 0 {
			return DenialMalformedCalldata, fmt.Errorf("deployment initcode is empty")
		}
		if f.Depth > 0 && f.CallerOrg != ctx.Org {
			return DenialOwnership, fmt.Errorf("factory belongs to another organisation")
		}
		return "", nil
	}
	if index, upgrade := upgradeAddressIndex(f.Calldata); upgrade {
		offset := 4 + 32*index
		if len(f.Calldata) < offset+32 {
			return DenialMalformedCalldata, fmt.Errorf("upgrade target is truncated")
		}
		word := f.Calldata[offset : offset+32]
		for _, b := range word[:12] {
			if b != 0 {
				return DenialMalformedCalldata, fmt.Errorf("upgrade target is not a canonical address")
			}
		}
		if !r.allowUpgrade || groupClaims&(ClaimAdmin|ClaimUpgrade) == 0 {
			return DenialOperationalClaim, fmt.Errorf("binding does not authorize upgrades")
		}
		if f.UpgradeTargetOrg != ctx.Org || common.BytesToAddress(word) == (common.Address{}) {
			return DenialOwnership, fmt.Errorf("upgrade target must belong to policy organisation")
		}
	}
	return "", nil
}
