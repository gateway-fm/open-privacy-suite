package rbac

import "strings"

// StateOverrideDeniedReason is the AccessCheckResult.Reason for an override
// denial. Operator-facing only (never on the wire); shared so callers that map
// reasons to audit codes (dry-run's sanitizeDryRunReason) match it exactly.
const StateOverrideDeniedReason = "state, code and block overrides are not permitted"

const (
	overrideKindState     = "state_override"
	overrideKindBlock     = "block_override"
	overrideKindMalformed = "malformed_override"

	// maxOverrideAwareParams caps the positional params for the eth_call /
	// eth_estimateGas family. The valid shapes are [call], [call, block],
	// [call, block, stateOverride], [call, block, stateOverride, blockOverride].
	// Anything longer is rejected fail-closed rather than forwarded.
	maxOverrideAwareParams = 4
)

// eip1898BlockKeys are the only keys a params[1] object may carry when it is a
// block reference (EIP-1898). Other object keys are unsupported in that position.
var eip1898BlockKeys = []string{"blockNumber", "blockHash", "requireCanonical"}

// debugOverrideKeys are the debug_traceCall config keys that change the state
// or block the call executes against, with the audit label for each.
var debugOverrideKeys = []struct {
	name string
	kind string
}{
	{"stateOverrides", overrideKindState},
	{"stateOverride", overrideKindState},
	{"blockOverrides", overrideKindBlock},
	{"blockOverride", overrideKindBlock},
	{"txIndex", overrideKindBlock},
}

// keyFoldsTo reports whether a JSON object key would be matched to name by a
// case-insensitive decoder, covering simple folding and lowercase matching.
func keyFoldsTo(key, name string) bool {
	return strings.EqualFold(key, name) || strings.ToLower(key) == strings.ToLower(name)
}

// DetectStateOverride classifies unsupported simulation options (RD-1305).
// It checks both raw and operator-aliased methods. Positional state/block
// overrides must be null or empty objects; debug-trace override and
// replay-position keys must be absent. The block-reference slot accepts only
// null, a string or an EIP-1898 object, and createAccessList retains its
// boolean optimization option. Unknown or malformed override values are
// refused. The returned kind is an internal audit label; callers use an
// opaque denial.
func DetectStateOverride(method string, params []any) (bool, string) {
	raw := CanonicalizeMethod(method)
	if denied, kind := detectStateOverrideForMethod(raw, params); denied {
		return true, kind
	}
	resolved := CanonicalizeMethod(ResolveMethodAlias(raw))
	if resolved != raw {
		return detectStateOverrideForMethod(resolved, params)
	}
	return false, ""
}

// detectStateOverrideForMethod applies the option policy to one canonical name.
func detectStateOverrideForMethod(resolved string, params []any) (bool, string) {
	switch resolved {
	case "eth_call", "eth_estimateGas", "eth_createAccessList":
		// Reject an over-long param list outright.
		if len(params) > maxOverrideAwareParams {
			return true, overrideKindMalformed
		}
		// params[1] must be a block reference: null, a tag/hex string or an
		// EIP-1898 object. Any other object or type is refused.
		if denied, kind := classifyBlockRefSlot(params, 1); denied {
			return true, kind
		}
		// eth_createAccessList retains a boolean optimization option at params[2].
		if resolved == "eth_createAccessList" && len(params) > 2 {
			if _, isBool := params[2].(bool); isBool {
				return classifyOverrideSlot(params, 3, overrideKindBlock)
			}
		}
		// params[2] = state-override set, params[3] = block-override set.
		if denied, kind := classifyOverrideSlot(params, 2, overrideKindState); denied {
			return true, kind
		}
		if denied, kind := classifyOverrideSlot(params, 3, overrideKindBlock); denied {
			return true, kind
		}
		return false, ""
	case "debug_traceCall":
		// The config object at params[2] may embed the override sets.
		if len(params) <= 2 || params[2] == nil {
			return false, ""
		}
		cfg, ok := params[2].(map[string]any)
		if !ok {
			// A non-object config is the sibling tracer/access concern
			// (RD-1304), not an override we can read — leave it be here.
			return false, ""
		}
		for key := range cfg {
			for _, k := range debugOverrideKeys {
				if keyFoldsTo(key, k.name) {
					// Trace override keys must be absent, regardless of value.
					return true, k.kind
				}
			}
		}
		return false, ""
	default:
		return false, ""
	}
}

// classifyBlockRefSlot accepts only the block-reference shapes in the block
// slot: nil, a string (tag or number) or an object whose keys are all EIP-1898
// block keys. An object with any other key is an override set; any other type
// is not a block reference and is refused as malformed. The block parser
// remains responsible for validating the block-reference values themselves.
func classifyBlockRefSlot(params []any, idx int) (bool, string) {
	if len(params) <= idx || params[idx] == nil {
		return false, ""
	}
	switch v := params[idx].(type) {
	case string:
		return false, ""
	case map[string]any:
		for key := range v {
			if !isEIP1898BlockKey(key) {
				return true, overrideKindState
			}
		}
		return false, ""
	default:
		return true, overrideKindMalformed
	}
}

func isEIP1898BlockKey(key string) bool {
	for _, k := range eip1898BlockKeys {
		if strings.EqualFold(key, k) {
			return true
		}
	}
	return false
}

// classifyOverrideSlot inspects a positional param and classifies it.
func classifyOverrideSlot(params []any, idx int, kind string) (bool, string) {
	if len(params) <= idx {
		return false, ""
	}
	return classifyOverrideValue(params[idx], kind)
}

// classifyOverrideValue applies the value rule to a single positional slot:
//   - nil or empty object → no override (false)
//   - non-empty object → override present (deny, kind)
//   - any other non-nil type → malformed (deny, malformed) — fail closed
func classifyOverrideValue(v any, kind string) (bool, string) {
	if v == nil {
		return false, ""
	}
	m, ok := v.(map[string]any)
	if !ok {
		return true, overrideKindMalformed
	}
	if len(m) == 0 {
		return false, ""
	}
	return true, kind
}
