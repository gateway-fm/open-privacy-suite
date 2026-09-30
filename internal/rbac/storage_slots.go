package rbac

import (
	"strings"
)

// erc1967Slots is the set of standard EIP-1967 storage slot hashes
// (implementation, admin, beacon) used by upgradeable proxy contracts
// to keep proxy metadata in predictable locations. Inlined here
// because they're consumed only by the eth_getStorageAt allowlist
// below; the historical home in internal/evm/bytecode/proxy.go was
// deleted alongside the dead deploy-time bytecode analyzer.
var erc1967Slots = []string{
	"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", // implementation
	"0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", // admin
	"0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50", // beacon
}

// diamondStorageSlot is the EIP-2535 Diamond storage slot.
const diamondStorageSlot = "0xc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c"

// WellKnownStorageSlots is the set of storage slots that non-admin users may
// read via eth_getStorageAt or prove via eth_getProof. These are infrastructure
// metadata slots defined by EIP-1967 (proxy implementation/admin/beacon) and
// EIP-2535 (Diamond storage). They contain only contract addresses, not
// business data.
//
// This allowlist is intentionally hardcoded — new standards require a code change
// with security review. Do NOT make this configurable.
var WellKnownStorageSlots map[string]bool

func init() {
	WellKnownStorageSlots = make(map[string]bool, len(erc1967Slots)+1)
	for _, slot := range erc1967Slots {
		WellKnownStorageSlots[strings.ToLower(slot)] = true
	}
	WellKnownStorageSlots[strings.ToLower(diamondStorageSlot)] = true
}

// IsWellKnownStorageSlot checks if a storage slot is in the infrastructure allowlist.
// The slot should be a hex string (with or without 0x prefix).
// Returns false for empty/invalid slots (fail-closed).
func IsWellKnownStorageSlot(slot string) bool {
	if slot == "" {
		return false
	}
	slot = strings.ToLower(strings.TrimSpace(slot))
	// Normalize: ensure 0x prefix for map lookup
	if !strings.HasPrefix(slot, "0x") {
		slot = "0x" + slot
	}
	// No padding: the constants are full 32-byte hex, so a short-form spelling
	// of a slot never matches and is denied (fail-closed).
	return WellKnownStorageSlots[slot]
}

// extractStorageSlot extracts the storage slot (params[1]) from eth_getStorageAt params.
// Returns empty string if params are missing or malformed (fail-closed: will be denied).
func extractStorageSlot(params []any) string {
	if len(params) < 2 {
		return ""
	}
	slot, ok := params[1].(string)
	if !ok {
		return ""
	}
	return slot
}

// extractProofStorageKeys extracts the storage keys (params[1]) from
// eth_getProof params: [address, storageKeys[], block]. ok is false unless
// params[1] is a JSON array whose every element is a string — a missing, null
// or non-array key list, or any non-string key, is malformed and must be
// denied by the caller (fail-closed). An empty array is well-formed: it asks
// for an account-only proof.
func extractProofStorageKeys(params []any) (keys []string, ok bool) {
	if len(params) < 2 {
		return nil, false
	}
	list, isList := params[1].([]any)
	if !isList {
		return nil, false
	}
	keys = make([]string, 0, len(list))
	for _, k := range list {
		s, isString := k.(string)
		if !isString {
			return nil, false
		}
		keys = append(keys, s)
	}
	return keys, true
}

// requestedStorageKeys returns the storage slots whose raw values a
// storage-read request would return: the single slot of eth_getStorageAt, or
// every key of eth_getProof (whose storageProof[].value carries each value).
// ok is false for a malformed request or a method that is not a storage read.
func requestedStorageKeys(method string, params []any) (keys []string, ok bool) {
	switch method {
	case MethodGetStorageAt:
		return []string{extractStorageSlot(params)}, true
	case MethodGetProof:
		return extractProofStorageKeys(params)
	}
	return nil, false
}

// isStorageReadMethod reports whether the (alias-resolved) method returns raw
// contract storage values and is therefore subject to the storage-slot tier.
func isStorageReadMethod(method string) bool {
	return method == MethodGetStorageAt || method == MethodGetProof
}
