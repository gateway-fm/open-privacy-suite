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

// CheckSignature is the node's facts/frame entry point. The caller must resolve
// identity and current facts before invoking it for each actual EVM frame.
const CheckSignature = "check((address,address[],bytes32[],bytes32,bytes32,bytes32,bytes32,uint8,bool,bool,uint8,bytes32,uint8[],bool,bool),(uint8,address,address,address,bytes,uint256,uint256))"

// CheckFrameSignature is retained for offline compatibility with old fixtures.
// It has no ownership/value/depth/caller facts and is never a node entry point.
const CheckFrameSignature = "checkFrame(uint8,address,address,address,address[],bytes32[],bytes)"

// Reason codes returned alongside the decision. They mirror the Go evaluator's
// denial codes so the two implementations can be compared on both halves of the
// answer, not only on allow or deny.
const (
	reasonOK                 = 0
	reasonNoMatchingRule     = 1
	reasonArgumentConstraint = 2
	reasonMalformedCalldata  = 3
	reasonOwnership          = 4
	reasonValue              = 5
	reasonDepth              = 6
	reasonUnsupportedCreate  = 7
	reasonCaller             = 8
	reasonOperationalClaim   = 9
	reasonInvalidFacts       = 10
)

// callTypeOrdinal is the wire encoding of a call type. The generated contract
// compares against these numbers, so they are part of the artifact's contract
// with its caller and must not be reordered.
var callTypeOrdinal = map[CallType]uint8{
	CallTypeCall:         0,
	CallTypeStaticCall:   1,
	CallTypeDelegateCall: 2,
	CallTypeCallCode:     3,
	CallTypeCreate:       4,
	CallTypeCreate2:      5,
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

// OrgID encodes a stable database organisation identifier. Missing ownership
// uses the zero word, which no compiled policy organisation can match.
func OrgID(org string) common.Hash {
	if org == "" {
		return common.Hash{}
	}
	return crypto.Keccak256Hash([]byte(org))
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
	tables := newExceptionTables()

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
	b.WriteString(fmt.Sprintf("    uint16 internal constant MALFORMED_CALLDATA = %d;\n", reasonMalformedCalldata))
	b.WriteString(fmt.Sprintf("    uint16 internal constant OWNERSHIP = %d;\n", reasonOwnership))
	b.WriteString(fmt.Sprintf("    uint16 internal constant VALUE = %d;\n", reasonValue))
	b.WriteString(fmt.Sprintf("    uint16 internal constant DEPTH = %d;\n", reasonDepth))
	b.WriteString(fmt.Sprintf("    uint16 internal constant UNSUPPORTED_CREATE = %d;\n", reasonUnsupportedCreate))
	b.WriteString(fmt.Sprintf("    uint16 internal constant CALLER = %d;\n\n", reasonCaller))
	b.WriteString(fmt.Sprintf("    uint16 internal constant OPERATIONAL_CLAIM = %d;\n", reasonOperationalClaim))
	b.WriteString(fmt.Sprintf("    uint16 internal constant INVALID_FACTS = %d;\n", reasonInvalidFacts))
	var entries strings.Builder
	writeEntryPoints(&entries, v.policy.Org)
	entrySource := entries.String()
	if v.hasRecordReads() {
		entrySource = strings.ReplaceAll(entrySource, " pure ", " view ")
	}
	b.WriteString(entrySource)
	b.WriteString("        bytes4 sel;\n        if (payload.length >= 4) sel = bytes4(payload[0:4]);\n\n")
	b.WriteString(`        if (frame.kind != 4 && frame.kind != 5) {
            uint256 upgradeOffset;
            if (sel == 0x3659cfe6 || sel == 0x4f1ef286 || sel == 0xd784d426) upgradeOffset = 4;
            if (sel == 0x99a88ec4 || sel == 0x9623609d) upgradeOffset = 36;
            if (upgradeOffset != 0) {
                if (payload.length < upgradeOffset + 32) return MALFORMED_CALLDATA;
                uint256 target = uint256(bytes32(payload[upgradeOffset:upgradeOffset + 32]));
                if (target >> 160 != 0) return MALFORMED_CALLDATA;
                frame.upgrade = true;
                frame.upgradeAddress = address(uint160(target));
            }
        }
`)
	b.WriteString("        // Denials are ranked so the most specific explanation survives: an\n")
	b.WriteString("        // argument that is out of bounds says so rather than reporting the same\n")
	b.WriteString("        // thing as a call the policy never mentions.\n")
	b.WriteString("        uint16 worst = NO_MATCHING_RULE;\n\n")
	b.WriteString("        for (uint256 i = 0; i < groups.length; i++) {\n")
	b.WriteString("            bytes32 g = groups[i];\n")
	b.WriteString("            if (frame.complete) frame.groupClaim = frame.groupClaims[i];\n\n")

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
		if err := writeGroupBlock(&b, &bodies, &next, group, v.byGroup[group], tables); err != nil {
			return "", err
		}
	}

	b.WriteString("        }\n\n")
	b.WriteString("        if (worst != NO_MATCHING_RULE) return worst;\n")
	// A group with no matching rule must not hide a specific denial from a
	// later group. Tag only the common fallback; the node combines in group
	// order and removes the tag after trying the signer's applicable groups.
	fallback := ""
	if v.perGroup {
		fallback = "256 + "
	}
	fmt.Fprintf(&b, "        if (frame.kind == 4 || frame.kind == 5) return %sUNSUPPORTED_CREATE;\n", fallback)
	fmt.Fprintf(&b, "        if (frame.complete && (frame.codeOrg != frame.policyOrg || frame.storageOrg != frame.policyOrg)) return %sOWNERSHIP;\n", fallback)
	fmt.Fprintf(&b, "        if (payload.length < 4) return %sMALFORMED_CALLDATA;\n", fallback)
	fmt.Fprintf(&b, "        return %sworst;\n", fallback)
	b.WriteString("    }\n")
	b.WriteString(bodies.String())
	tables.write(&b)
	b.WriteString("}\n")

	return b.String(), nil
}

// exceptionTables emits each distinct deployer-exception table once and lets
// every rule that carries it call the same function. The legacy import gives
// every non-admin group the SAME organisation-wide table, so inlining it per
// rule multiplies one table by the number of groups: 28 contracts across 7
// groups is 196 inlined blocks, which on its own exceeds the runtime bytecode
// limit. Sharing changes no decision — the same addresses and groups are
// consulted — it only stops copying them.
type exceptionTables struct {
	index map[string]int
	order []string
	byKey map[string][]DeployerException
}

func newExceptionTables() *exceptionTables {
	return &exceptionTables{index: map[string]int{}, byKey: map[string][]DeployerException{}}
}

// use returns the function name for this table, registering it on first sight.
// Tables are keyed by their content, so identical tables share one function and
// the order of emission follows first use, keeping generation deterministic.
func (t *exceptionTables) use(exceptions []DeployerException) string {
	if len(exceptions) == 0 {
		return ""
	}
	var key strings.Builder
	for _, e := range exceptions {
		key.WriteString(strings.ToLower(e.StorageAddress))
		key.WriteByte('|')
		for _, g := range e.Groups {
			key.WriteString(g)
			key.WriteByte(',')
		}
		key.WriteByte(';')
	}
	k := key.String()
	if _, seen := t.index[k]; !seen {
		t.index[k] = len(t.order)
		t.order = append(t.order, k)
		t.byKey[k] = exceptions
	}
	return fmt.Sprintf("_excepted%d", t.index[k])
}

// write emits the registered tables as pure helpers returning true when the
// frame's target is excluded for one of the frame's groups.
func (t *exceptionTables) write(b *strings.Builder) {
	for i, k := range t.order {
		fmt.Fprintf(b, "\n    /// @dev deployer exceptions shared by every rule that declares them\n")
		fmt.Fprintf(b, "    function _excepted%d(FrameContext memory frame) internal pure returns (bool) {\n", i)
		for _, exception := range t.byKey[k] {
			fmt.Fprintf(b, "        if (frame.storageAddress == %s) {\n            for (uint256 ei=0; ei<frame.groups.length; ei++) {\n", solidityAddress(common.HexToAddress(exception.StorageAddress)))
			var conditions []string
			for _, group := range exception.Groups {
				conditions = append(conditions, "frame.groups[ei] == "+GroupID(group).Hex())
			}
			fmt.Fprintf(b, "                if (%s) return true;\n            }\n        }\n", strings.Join(conditions, " || "))
		}
		b.WriteString("        return false;\n    }\n")
	}
}

func writeEntryPoints(b *strings.Builder, org string) {
	b.WriteString(`    struct Facts {
        address signer;
        address[] linkedAddresses;
        bytes32[] groups;
        bytes32 policyOrg;
        bytes32 callerOrg;
        bytes32 codeOrg;
        bytes32 storageOrg;
        uint8 claims;
        bool codeShared;
        bool storageShared;
        uint8 codeKind;
        bytes32 upgradeTargetOrg;
        uint8[] groupClaims;
        bool storageDeployer;
        bool storagePending;
    }
    struct Call {
        uint8 kind;
        address caller;
        address codeAddress;
        address storageAddress;
        bytes data;
        uint256 value;
        uint256 depth;
    }
    struct FrameContext {
        uint8 kind;
        address caller;
        address codeAddress;
        address storageAddress;
        uint256 value;
        uint256 depth;
        bool complete;
        bytes32 policyOrg;
        bytes32 callerOrg;
        bytes32 codeOrg;
        bytes32 storageOrg;
        bool codeShared;
        bool storageShared;
        uint8 codeKind;
        bytes32 upgradeTargetOrg;
        uint8[] groupClaims;
        uint8 groupClaim;
        bool upgrade;
        address upgradeAddress;
        bool storageDeployer;
        bool storagePending;
        bytes32[] groups;
    }

    /// @notice Check one actual frame against resolved, block-pinned facts.
    /// @dev The node validates identity, bans, links and membership expiry first.
    function check(Facts calldata facts, Call calldata frame) external pure returns (uint256) {
`)
	fmt.Fprintf(b, "        if (facts.policyOrg != %s) return OWNERSHIP;\n", OrgID(org).Hex())
	b.WriteString(`        if (facts.groups.length != facts.groupClaims.length || facts.codeKind > 3) return INVALID_FACTS;
        FrameContext memory observed;
        observed.kind = frame.kind;
        observed.caller = frame.caller;
        observed.codeAddress = frame.codeAddress;
        observed.storageAddress = frame.storageAddress;
        observed.value = frame.value;
        observed.depth = frame.depth;
        observed.complete = true;
        observed.policyOrg = facts.policyOrg;
        observed.callerOrg = facts.callerOrg;
        observed.codeOrg = facts.codeOrg;
        observed.storageOrg = facts.storageOrg;
        observed.codeShared = facts.codeShared;
        observed.storageShared = facts.storageShared;
        observed.codeKind = facts.codeKind;
        observed.upgradeTargetOrg = facts.upgradeTargetOrg;
        observed.groupClaims = facts.groupClaims;
        observed.storageDeployer = facts.storageDeployer;
        observed.storagePending = facts.storagePending;
        observed.groups = facts.groups;
        return _checkFrame(facts.signer, facts.linkedAddresses, facts.groups, frame.data, observed);
    }

    /// @notice Offline compatibility only. The node must call check(Facts,Call).
    /// @dev Rules needing fields absent from this interface cannot pass here.
    function checkFrame(uint8 callType, address storageAddress, address codeAddress, address signer,
        address[] calldata linked, bytes32[] calldata groups, bytes calldata payload)
        external pure returns (bool allowed, uint16 reason)
    {
        FrameContext memory observed;
        observed.kind = callType;
        observed.codeAddress = codeAddress;
        observed.storageAddress = storageAddress;
        reason = _checkFrame(signer, linked, groups, payload, observed);
        return (reason == OK, reason);
    }

    function _checkFrame(address signer, address[] calldata linked, bytes32[] calldata groups,
        bytes calldata payload, FrameContext memory frame) internal pure returns (uint16)
    {
`)
}

// writeGroupBlock emits the dispatch for the rules bound to one group.
func writeGroupBlock(b, bodies *strings.Builder, next *int, group string, index map[frameKey][]*compiledRule, tables *exceptionTables) error {
	b.WriteString(fmt.Sprintf("            // group %s\n", solidityComment(group)))
	b.WriteString(fmt.Sprintf("            if (g == %s) {\n", GroupID(group).Hex()))

	keys := sortedFrameKeys(index)

	for _, key := range keys {
		for _, rule := range index[key] {
			n := *next
			*next++
			if err := writeRuleDispatch(b, n, key, rule); err != nil {
				return err
			}
			if err := writeRuleBody(bodies, n, group, key, rule, tables); err != nil {
				return err
			}
		}
	}

	b.WriteString("            }\n\n")
	return nil
}

func sortedFrameKeys(index map[frameKey][]*compiledRule) []frameKey {
	keys := make([]frameKey, 0, len(index))
	for key := range index {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.targetClass != b.targetClass {
			return a.targetClass < b.targetClass
		}
		if a.storage != b.storage {
			return a.storage.Hex() < b.storage.Hex()
		}
		if a.code != b.code {
			return a.code.Hex() < b.code.Hex()
		}
		if a.selectorMode != b.selectorMode {
			return a.selectorMode < b.selectorMode
		}
		return string(a.selector[:]) < string(b.selector[:])
	})
	return keys
}

// writeRuleDispatch emits the guard that routes a frame to one rule.
func writeRuleDispatch(b *strings.Builder, n int, key frameKey, rule *compiledRule) error {
	cond, err := callTypeCondition(rule)
	if err != nil {
		return err
	}

	b.WriteString(fmt.Sprintf("                // %s\n", solidityComment(rule.sig)))
	target := targetCondition(key)
	selector := "true"
	if key.selectorMode == selectorExact {
		selector = fmt.Sprintf("payload.length >= 4 && sel == %s", solidityBytes4(key.selector))
	}
	if key.selectorMode == selectorEmpty {
		selector = "payload.length == 0"
	}
	fmt.Fprintf(b, "                if ((%s) && (%s)) {\n", target, selector)

	b.WriteString(fmt.Sprintf("                    if (%s) {\n", cond))
	b.WriteString(fmt.Sprintf("                        uint16 r = _rule%d(signer, linked, payload, frame);\n", n))
	b.WriteString("                        if (r == OK) return OK;\n")
	b.WriteString("                        if (worst == NO_MATCHING_RULE) worst = r;\n")
	b.WriteString("                    }\n")
	b.WriteString("                }\n")
	return nil
}

func targetCondition(key frameKey) string {
	switch key.targetClass {
	case "":
		return fmt.Sprintf("frame.storageAddress == %s && frame.codeAddress == %s", solidityAddress(key.storage), solidityAddress(key.code))
	case "org":
		return "frame.codeOrg == frame.policyOrg && frame.storageOrg == frame.policyOrg"
	case "deployer":
		return "frame.codeAddress == frame.storageAddress && frame.storageDeployer"
	case "pending":
		return "frame.codeAddress == frame.storageAddress && frame.storagePending"
	case "shared":
		return "frame.codeAddress == frame.storageAddress && frame.codeKind == 2 && frame.codeShared && frame.storageShared"
	case "eoa":
		return "frame.codeAddress == frame.storageAddress && frame.codeKind == 1 && frame.codeOrg == bytes32(0) && frame.storageOrg == bytes32(0)"
	case "precompile":
		return "frame.codeAddress == frame.storageAddress && frame.codeKind == 3"
	case "create":
		return "frame.kind == 4 || frame.kind == 5"
	default:
		return "false"
	}
}

// writeRuleBody emits one rule's argument checks as its own function.
func writeRuleBody(b *strings.Builder, n int, group string, key frameKey, rule *compiledRule, tables *exceptionTables) error {
	b.WriteString(fmt.Sprintf("\n    /// @dev group %s, %s\n", solidityComment(group), solidityComment(rule.sig)))
	b.WriteString(fmt.Sprintf("    function _rule%d(address signer, address[] calldata linked, bytes calldata payload, FrameContext memory frame)\n", n))
	mutability := "pure"
	if rule.hasRecordRead() {
		mutability = "view"
	}
	fmt.Fprintf(b, "        internal %s returns (uint16)\n", mutability)
	b.WriteString("    {\n")
	if rule.maxValue != nil || rule.maxDepth != nil || rule.caller != nil || rule.hasRecordRead() {
		b.WriteString("        if (!frame.complete) return NO_MATCHING_RULE;\n")
	}

	if key.targetClass != "" {
		b.WriteString("        if (!frame.complete) return NO_MATCHING_RULE;\n")
	}
	if key.targetClass == "" || key.targetClass == "org" || key.targetClass == "create" || key.targetClass == "deployer" || key.targetClass == "pending" {
		b.WriteString("        if (frame.complete && (frame.codeOrg != frame.policyOrg || frame.storageOrg != frame.policyOrg)) return OWNERSHIP;\n")
	}
	if fn := tables.use(rule.exceptions); fn != "" {
		fmt.Fprintf(b, "        if (%s(frame)) return NO_MATCHING_RULE;\n", fn)
	}
	if key.targetClass == "pending" {
		b.WriteString("        if ((frame.groupClaim & 3) == 0) return OPERATIONAL_CLAIM;\n")
	}
	if key.targetClass == "create" {
		b.WriteString("        if ((frame.groupClaim & 3) == 0) return OPERATIONAL_CLAIM;\n")
		b.WriteString("        if (payload.length == 0) return MALFORMED_CALLDATA;\n")
		b.WriteString("        if (frame.depth > 0 && frame.callerOrg != frame.policyOrg) return OWNERSHIP;\n")
	} else {
		if rule.allowUpgrade {
			b.WriteString("        if (frame.upgrade) {\n")
			b.WriteString("            if (!frame.complete || (frame.groupClaim & 5) == 0) return OPERATIONAL_CLAIM;\n")
			b.WriteString("            if (frame.upgradeTargetOrg != frame.policyOrg || frame.upgradeAddress == address(0)) return OWNERSHIP;\n        }\n")
		} else {
			b.WriteString("        if (frame.upgrade) return OPERATIONAL_CLAIM;\n")
		}
	}

	// Length is checked before any slot is read, so a short payload can never be
	// indexed past its end.
	b.WriteString(fmt.Sprintf("        if (payload.length < %d) return MALFORMED_CALLDATA;\n", rule.headLen()))
	if rule.exactLen {
		b.WriteString("        // Every argument of this signature sits in the head, so anything past\n")
		b.WriteString("        // it is calldata a callee reading raw input would still see.\n")
		b.WriteString(fmt.Sprintf("        if (payload.length != %d) return MALFORMED_CALLDATA;\n", rule.headLen()))
	}
	if rule.maxValue != nil {
		fmt.Fprintf(b, "        if (frame.value > %s) return VALUE;\n", rule.maxValue.String())
	}
	if rule.maxDepth != nil {
		fmt.Fprintf(b, "        if (frame.depth > %d) return DEPTH;\n", *rule.maxDepth)
	}
	if rule.caller != nil {
		fmt.Fprintf(b, "        if (frame.caller != %s) return CALLER;\n", solidityAddress(*rule.caller))
	}

	for _, arg := range rule.args {
		if arg.kind == argRecordParty {
			fmt.Fprintf(b, "        uint16 recordReason%d = _record%d_%d(linked, payload, frame.storageAddress);\n", arg.index, n, arg.index)
			fmt.Fprintf(b, "        if (recordReason%d != OK) return recordReason%d;\n", arg.index, arg.index)
			continue
		}
		if err := writeArgCheck(b, arg); err != nil {
			return err
		}
	}

	b.WriteString("        return OK;\n")
	b.WriteString("    }\n")
	for _, arg := range rule.args {
		if arg.kind == argRecordParty {
			writeRecordPartyCheck(b, n, arg, rule.headLen())
		}
	}
	return nil
}

// writeArgCheck emits one argument constraint.
func writeArgCheck(b *strings.Builder, arg compiledArg) error {
	offset := arg.offset
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
		parts = append(parts, fmt.Sprintf("frame.kind == %d", n))
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

// solidityComment renders an operator-chosen name safely inside a comment.
//
// It keeps only characters that cannot end a comment or start a line, rather
// than removing dangerous sequences: a replacer that deleted "*/" would turn
// "**//" into "*/", because removing the inner pair leaves the outer characters
// adjacent. The reachable input is a function signature from a registered ABI,
// which is operator-influenced, so this has to hold for adversarial text.
func solidityComment(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '*' || r == '/' || r == '\\':
			// The three characters that can open or close a comment.
			b.WriteByte(' ')
		case r == '\n' || r == '\r' || r == '\u2028' || r == '\u2029':
			// Anything that could end the line and escape a // comment.
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
