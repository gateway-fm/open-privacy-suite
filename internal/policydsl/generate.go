package policydsl

import (
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// SolidityVersion is the exact compiler the generated source is written for.
//
// It is pinned rather than ranged: a policy artifact is reviewed and approved as
// specific bytecode, and a different compiler can produce different bytecode
// from the same source.
const SolidityVersion = "0.8.35"

// ContractName is the name of the generated contract.
const ContractName = "ExecutionPolicy"

// CheckFrameSignature is the entry point every generated policy exposes.
//
// A policy decides one frame at a time. The caller, whether that is this process
// or a node adapter, walks the frames of an execution and requires every one of
// them to be permitted.
const CheckFrameSignature = "checkFrame(uint8,address,address,address,address[],bytes32[],bytes)"

// Reason codes returned alongside the decision. They mirror the Go evaluator's
// denial codes so the two implementations can be compared on both halves of the
// answer, not only on allow or deny.
const (
	reasonOK                 = 0
	reasonNoMatchingRule     = 1
	reasonArgumentConstraint = 2
	reasonMalformedCalldata  = 3
)

// callTypeOrdinal is the wire encoding of a call type. The generated contract
// compares against these numbers, so they are part of the artifact's contract
// with its caller and must not be reordered.
var callTypeOrdinal = map[CallType]uint8{
	CallTypeCall:         0,
	CallTypeStaticCall:   1,
	CallTypeDelegateCall: 2,
	CallTypeCallCode:     3,
}

// CallTypeOrdinal returns the wire encoding of a call type.
func CallTypeOrdinal(ct CallType) (uint8, bool) {
	n, ok := callTypeOrdinal[ct]
	return n, ok
}

// GroupID is how a group identifier is passed to a generated policy.
//
// Group names are hashed so the contract compares fixed-size words instead of
// strings, which keeps the check cheap and its cost independent of how an
// operator chose to name a group.
func GroupID(group string) common.Hash {
	return crypto.Keccak256Hash([]byte(group))
}

// GenerateSolidity renders a validated policy as Solidity source.
//
// The generator only ever emits from the validated model, never from text a
// policy author supplied, so there is no path by which a document can inject
// code into the contract. Everything it writes is a comparison against a value
// the validator has already checked.
func GenerateSolidity(v *Validated) (string, error) {
	if v == nil {
		return "", fmt.Errorf("policydsl: no validated policy to generate from")
	}

	var b strings.Builder

	b.WriteString("// SPDX-License-Identifier: Apache-2.0\n")
	b.WriteString("// Code generated from an approved ContractExecutionPolicy. DO NOT EDIT.\n")
	b.WriteString("//\n")
	b.WriteString(fmt.Sprintf("// apiVersion: %s\n", v.policy.APIVersion))
	b.WriteString(fmt.Sprintf("// org:        %s\n", v.policy.Org))
	b.WriteString(fmt.Sprintf("// nestedCalls: %s\n", v.policy.NestedCalls))
	b.WriteString("//\n")
	b.WriteString("// Every frame of an execution must be permitted on its own. This contract\n")
	b.WriteString("// answers for one frame; the caller walks them all and requires each to pass.\n")
	b.WriteString(fmt.Sprintf("pragma solidity %s;\n\n", SolidityVersion))

	b.WriteString(fmt.Sprintf("contract %s {\n", ContractName))
	b.WriteString(fmt.Sprintf("    uint16 internal constant OK = %d;\n", reasonOK))
	b.WriteString(fmt.Sprintf("    uint16 internal constant NO_MATCHING_RULE = %d;\n", reasonNoMatchingRule))
	b.WriteString(fmt.Sprintf("    uint16 internal constant ARGUMENT_CONSTRAINT = %d;\n", reasonArgumentConstraint))
	b.WriteString(fmt.Sprintf("    uint16 internal constant MALFORMED_CALLDATA = %d;\n\n", reasonMalformedCalldata))

	b.WriteString("    /// @notice Decide whether one observed call frame is permitted.\n")
	b.WriteString("    /// @dev Pure: a policy reads only the facts it is handed. It holds no state,\n")
	b.WriteString("    ///      so it cannot accumulate counters or remember earlier calls.\n")
	b.WriteString("    function checkFrame(\n")
	b.WriteString("        uint8 callType,\n")
	b.WriteString("        address storageAddress,\n")
	b.WriteString("        address codeAddress,\n")
	b.WriteString("        address signer,\n")
	b.WriteString("        address[] calldata linked,\n")
	b.WriteString("        bytes32[] calldata groups,\n")
	b.WriteString("        bytes calldata payload\n")
	b.WriteString("    ) external pure returns (bool allowed, uint16 reason) {\n")
	b.WriteString("        if (payload.length < 4) return (false, MALFORMED_CALLDATA);\n")
	b.WriteString("        bytes4 sel = bytes4(payload[0:4]);\n\n")
	b.WriteString("        // Denials are ranked so the most specific explanation survives: an\n")
	b.WriteString("        // argument that is out of bounds says so rather than reporting the same\n")
	b.WriteString("        // thing as a call the policy never mentions.\n")
	b.WriteString("        uint16 worst = NO_MATCHING_RULE;\n\n")
	b.WriteString("        for (uint256 i = 0; i < groups.length; i++) {\n")
	b.WriteString("            bytes32 g = groups[i];\n\n")

	// Groups are emitted in a fixed order so the same policy always renders the
	// same source, and therefore always compiles to the same bytecode.
	groups := make([]string, 0, len(v.byGroup))
	for group := range v.byGroup {
		groups = append(groups, group)
	}
	sort.Strings(groups)

	// Each rule's argument checks live in their own function. Inlining them all
	// into the dispatch loop exhausts the EVM's addressable stack once a policy
	// has more than a couple of rules, and separate functions also give a
	// reviewer one readable block per rule.
	var bodies strings.Builder
	next := 0

	for _, group := range groups {
		if err := writeGroupBlock(&b, &bodies, &next, group, v.byGroup[group]); err != nil {
			return "", err
		}
	}

	b.WriteString("        }\n\n")
	b.WriteString("        return (false, worst);\n")
	b.WriteString("    }\n")
	b.WriteString(bodies.String())
	b.WriteString("}\n")

	return b.String(), nil
}

// writeGroupBlock emits the dispatch for the rules bound to one group.
func writeGroupBlock(b, bodies *strings.Builder, next *int, group string, index map[frameKey][]*compiledRule) error {
	b.WriteString(fmt.Sprintf("            // group %s\n", solidityComment(group)))
	b.WriteString(fmt.Sprintf("            if (g == %s) {\n", GroupID(group).Hex()))

	keys := make([]frameKey, 0, len(index))
	for key := range index {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].storage != keys[j].storage {
			return keys[i].storage.Hex() < keys[j].storage.Hex()
		}
		if keys[i].code != keys[j].code {
			return keys[i].code.Hex() < keys[j].code.Hex()
		}
		return string(keys[i].selector[:]) < string(keys[j].selector[:])
	})

	for _, key := range keys {
		for _, rule := range index[key] {
			n := *next
			*next++
			if err := writeRuleDispatch(b, n, key, rule); err != nil {
				return err
			}
			if err := writeRuleBody(bodies, n, group, rule); err != nil {
				return err
			}
		}
	}

	b.WriteString("            }\n\n")
	return nil
}

// writeRuleDispatch emits the guard that routes a frame to one rule.
func writeRuleDispatch(b *strings.Builder, n int, key frameKey, rule *compiledRule) error {
	cond, err := callTypeCondition(rule)
	if err != nil {
		return err
	}

	b.WriteString(fmt.Sprintf("                // %s\n", solidityComment(rule.sig)))
	b.WriteString(fmt.Sprintf("                if (storageAddress == %s && codeAddress == %s && sel == %s) {\n",
		solidityAddress(key.storage), solidityAddress(key.code), solidityBytes4(key.selector)))
	b.WriteString(fmt.Sprintf("                    if (%s) {\n", cond))
	b.WriteString(fmt.Sprintf("                        uint16 r = _rule%d(signer, linked, payload);\n", n))
	b.WriteString("                        if (r == OK) return (true, OK);\n")
	b.WriteString("                        if (worst == NO_MATCHING_RULE) worst = r;\n")
	b.WriteString("                    }\n")
	b.WriteString("                }\n")
	return nil
}

// writeRuleBody emits one rule's argument checks as its own function.
func writeRuleBody(b *strings.Builder, n int, group string, rule *compiledRule) error {
	b.WriteString(fmt.Sprintf("\n    /// @dev group %s, %s\n", solidityComment(group), solidityComment(rule.sig)))
	b.WriteString(fmt.Sprintf("    function _rule%d(address signer, address[] calldata linked, bytes calldata payload)\n", n))
	b.WriteString("        internal pure returns (uint16)\n")
	b.WriteString("    {\n")

	// Length is checked before any slot is read, so a short payload can never be
	// indexed past its end.
	b.WriteString(fmt.Sprintf("        if (payload.length < %d) return MALFORMED_CALLDATA;\n", rule.headLen()))
	if rule.exactLen {
		b.WriteString("        // Every argument of this signature sits in the head, so anything past\n")
		b.WriteString("        // it is calldata a callee reading raw input would still see.\n")
		b.WriteString(fmt.Sprintf("        if (payload.length != %d) return MALFORMED_CALLDATA;\n", rule.headLen()))
	}

	for _, arg := range rule.args {
		if err := writeArgCheck(b, arg); err != nil {
			return err
		}
	}

	b.WriteString("        return OK;\n")
	b.WriteString("    }\n")
	return nil
}

// writeArgCheck emits one argument constraint.
func writeArgCheck(b *strings.Builder, arg compiledArg) error {
	offset := 4 + 32*arg.index
	b.WriteString(fmt.Sprintf("\n        uint256 w%d = uint256(bytes32(payload[%d:%d]));\n", arg.index, offset, offset+32))

	switch arg.kind {
	case argAddress:
		// Anything above the low 20 bytes means the slot is not a canonically
		// encoded address, whatever it would truncate to.
		b.WriteString(fmt.Sprintf("        if (w%d >> 160 != 0) return MALFORMED_CALLDATA;\n", arg.index))
		switch arg.source {
		case AddressSourceSigner:
			// The zero address is what an unset signer looks like, so a policy
			// requiring the signer cannot be satisfied when none was supplied.
			b.WriteString("        if (signer == address(0)) return ARGUMENT_CONSTRAINT;\n")
			b.WriteString(fmt.Sprintf("        if (address(uint160(w%d)) != signer) return ARGUMENT_CONSTRAINT;\n", arg.index))
		case AddressSourcePrincipalLinked:
			b.WriteString(fmt.Sprintf("        bool found%d = false;\n", arg.index))
			b.WriteString("        for (uint256 k = 0; k < linked.length; k++) {\n")
			b.WriteString(fmt.Sprintf("            if (linked[k] == address(uint160(w%d))) { found%d = true; break; }\n", arg.index, arg.index))
			b.WriteString("        }\n")
			b.WriteString(fmt.Sprintf("        if (!found%d) return ARGUMENT_CONSTRAINT;\n", arg.index))
		case AddressSourceLiteral:
			b.WriteString(fmt.Sprintf("        if (address(uint160(w%d)) != %s) return ARGUMENT_CONSTRAINT;\n", arg.index, solidityAddress(arg.literal)))
		default:
			return fmt.Errorf("policydsl: cannot generate an address constraint with source %q", arg.source)
		}

	case argUint:
		if arg.bits < 256 {
			b.WriteString(fmt.Sprintf("        if (w%d >> %d != 0) return MALFORMED_CALLDATA;\n", arg.index, arg.bits))
		}
		b.WriteString(fmt.Sprintf("        if (w%d > %s) return ARGUMENT_CONSTRAINT;\n", arg.index, decimalLiteral(arg.max)))

	default:
		return fmt.Errorf("policydsl: cannot generate a constraint of an unsupported kind on argument %d", arg.index)
	}

	return nil
}

// callTypeCondition renders the permitted frame kinds as a comparison.
func callTypeCondition(rule *compiledRule) (string, error) {
	ordinals := make([]int, 0, len(rule.callTypes))
	for ct := range rule.callTypes {
		n, ok := callTypeOrdinal[ct]
		if !ok {
			return "", fmt.Errorf("policydsl: cannot generate a rule permitting unknown call type %q", ct)
		}
		ordinals = append(ordinals, int(n))
	}
	sort.Ints(ordinals)

	parts := make([]string, 0, len(ordinals))
	for _, n := range ordinals {
		parts = append(parts, fmt.Sprintf("callType == %d", n))
	}
	if len(parts) == 0 {
		// Unreachable for a validated policy; emitting false keeps a generator
		// bug from becoming a permission.
		return "false", nil
	}
	return strings.Join(parts, " || "), nil
}

// solidityAddress renders an address as a checksummed literal, which is the form
// the compiler accepts without a warning.
func solidityAddress(a common.Address) string { return a.Hex() }

// solidityBytes4 renders a selector literal.
func solidityBytes4(sel [4]byte) string {
	return fmt.Sprintf("bytes4(0x%02x%02x%02x%02x)", sel[0], sel[1], sel[2], sel[3])
}

// decimalLiteral renders a bound as a plain decimal literal.
func decimalLiteral(n *big.Int) string { return n.String() }

// solidityComment strips anything that could end a comment or start a new line,
// so an operator-chosen name cannot break out of the comment it appears in.
func solidityComment(s string) string {
	replacer := strings.NewReplacer("\n", " ", "\r", " ", "*/", "", "/*", "", "//", "")
	return replacer.Replace(s)
}
