package rbac

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// ABIProvider looks up the ABI for a contract address. Returns empty string if
// the ABI is not available. Addresses are lowercase with 0x prefix.
type ABIProvider interface {
	GetContractABI(address string) string
}

// DynamicPayloadAllower is an optional interface implemented by ABIProvider
// instances that also know whether a contract has been opted out of the
// M15 dynamic-payload drop gate (`contracts.events_allow_dynamic_payload`).
//
// Pre-M15, RedactLogs and FilterEventLogs scanned only AddressTy +
// bytes32-typed STATIC slots of an event's non-indexed params for
// embedded private addresses. Dynamic types — `bytes`, `string`,
// dynamic arrays, dynamic structs — were passed through verbatim, so
// any contract that embedded addresses inside a `bytes` payload (bridge
// contracts, forwarders, smart-wallet calldata, etc.) leaked foreign-
// org addresses to any viewer who could read the event log.
//
// Default-fix (close-by-default): when this interface is implemented
// AND the contract returns false for IsEventsAllowDynamicPayload, the
// filter drops the entire log if the matched event's ABI declares any
// dynamic non-indexed parameter. Admins, participants, and visibleTo-
// unlocked viewers are unaffected — the drop slots in AFTER those
// bypasses, mirroring the explorer-side gate in redactor.go.
//
// The optional-interface pattern (type-assertion in FilterEventLogs)
// keeps the legacy two-method ABIProvider interface intact: callers
// that don't implement DynamicPayloadAllower (most tests) silently
// disable the gate, which is the pre-M15 behaviour. Production server
// startup wires storeABIProvider, which implements both.
type DynamicPayloadAllower interface {
	IsEventsAllowDynamicPayload(address string) bool
}

// TxVisibilityProvider looks up per-tx visibleTo rules from the database.
type TxVisibilityProvider interface {
	GetBatchTxVisibility(ctx context.Context, txHashes []string) (map[string][]string, error)
}

// TxVisibilityContext provides per-tx visibleTo data for the current filter pass.
// When non-nil, it extends (never restricts) the existing event rule filtering:
// if a log's topic0 matches an event rule but param rules fail, the viewer's DID
// is checked against the tx's visibleTo list as a fallback.
//
// UnlockableContracts (RD-874) carries the per-contract pre-computation
// of the visibleTo unlock semantic. The map key is a lowercase
// 0x-prefixed contract address; the value is true iff
// `contract.allow_visibleto_unlock` is set AND the viewer holds an
// eligible group membership on the contract (see
// rbac.IsViewerEligibleForVisibleToUnlock for the gate). When the map
// reports true for a log's emitting contract AND the viewer is in the
// tx's visibleTo set, the log passes the filter unconditionally —
// bypassing the deny-when-no-ABI gate, event_rules, and param_rules
// for that one tx. Empty / nil map = unlock disabled, additive
// behaviour applies.
type TxVisibilityContext struct {
	ViewerDID           string              // The DID of the user viewing the logs
	TxVisibility        map[string][]string // tx_hash (lowercase) -> visible_to_dids
	UnlockableContracts map[string]bool     // contract address (lowercase) -> unlock pre-resolved true

	// ParticipantTxHashes (RD-1162) is the pre-resolved set of transaction
	// hashes (lowercase) the viewer participated in — their linked address is
	// the tx `from` or `to`. When a log belongs to one of these txs AND the
	// viewer holds a grant on the emitting contract, the log is admitted even
	// if the event is not in the viewer's event_rules allowlist and carries no
	// address of theirs — they authored/participated in the tx and already
	// know its contents. Populated by the RPC layer: the receipt path derives
	// it from the receipt's from/to; the eth_getLogs path resolves each tx's
	// sender via a batched upstream eth_getTransactionByHash. Empty/nil = no
	// participant admission (backward compatible).
	ParticipantTxHashes map[string]bool

	// RecordAudience (RD-1206 rule 71), when set, admits a log whose governed
	// event's captured record audience includes the viewer. It is ADDITIVE
	// (admit-or-abstain, never deny) and independent of the visibleTo machinery
	// above — a record's audience is captured from a PRIOR call, not this log's
	// tx. nil = event-audience gating off.
	RecordAudience RecordAudienceGate
}

// RecordAudienceGate decides whether the viewer is in a log's governed event's
// captured record audience. The implementation loads the contract's policy +
// captures (RD-1206) and delegates to MethodPolicyDocument.EventAudienceAdmits,
// so the RPC filter and the explorer redactor share one decision. Must be
// fail-safe: return false on any decode/lookup failure (the log then falls
// through to the baseline). contractABI is the already-resolved ABI.
type RecordAudienceGate interface {
	EventLogAdmits(contractAddr, contractABI string, topics []string, data string) bool
}

// logEntry is the minimal structure needed to inspect an Ethereum log for
// event filtering. Fields mirror the JSON-RPC log representation.
type logEntry struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `json:"data"`
}

// FilterEventLogs filters a slice of raw JSON log entries based on the caller's
// event rules from their effective permissions.
//
// Semantics:
//   - If no event_rules are configured (nil or []): deny all logs for that contract.
//   - If event_rules are configured: allowlist mode — only listed topic0s pass.
//   - For rules with ParamRules ("self" constraints): the log must also have
//     the caller's address in the constrained parameter positions (OR semantics
//     across multiple ParamRules on the same event).
//   - Union semantics across grants: if any grant allows the event, it passes.
//   - Per-tx visibleTo: if topic0 matches an event rule but param rules fail,
//     the viewer's DID is checked against the tx's visibleTo list as a fallback.
//     This is purely additive — it never restricts existing access.
//   - **No resolvable ABI ⇒ deny-all** for the emitting contract regardless
//     of event_rules (RD-875, closes decisions.md §2 G5). Without an ABI we
//     cannot decode non-indexed `address`-typed parameters from the log's
//     `data` blob, so private addresses embedded there would leak verbatim.
//     Operators must register an ABI (custom upload, or set `token_type` on
//     the contract for the built-in registry per RD-793) before any event
//     access can take effect. Admin-bypass viewers (`isAdminByContract`)
//     are unaffected — they see everything regardless.
//
// userAddresses are the caller's linked ETH addresses (lowercase 0x-prefixed).
// perms contains the resolved effective permissions with ContractAccess and EventRules.
// abiProvider supplies contract ABIs for param rule decoding. When non-nil
// and it returns "" for a contract, that contract's logs are denied (RD-875).
// When nil, the ABI gate is disabled — used by tests that don't wire an ABI
// provider; production paths always pass a non-nil provider.
// visCtx provides optional per-tx visibleTo data (may be nil for backward compat).
// FilterEventLogs filters a slice of log entries.
//
// `isAdminByContract` is an ORG-SCOPED map populated by the caller: the
// key is the contract's lowercased address, and the entry is true iff
// the viewer holds the admin claim in THAT CONTRACT'S OWNING ORG (not
// merged across all orgs the viewer belongs to). This is the admin
// bypass input — a viewer with ClaimAdmin on a contract in a different
// org MUST NOT appear here for this contract. See
// JSONRPCProcessor.viewerAdminContracts for the resolver.
//
// The scoping matters even though migration 035 enforces unique address
// → one org at the schema level: belt + braces. If that invariant ever
// weakens (manual DB edit, future multi-org feature, migration bug),
// the runtime check still denies cross-org admin leaks.
func FilterEventLogs(
	logs []json.RawMessage,
	perms *EffectivePermissions,
	userAddresses []string,
	abiProvider ABIProvider,
	visCtx *TxVisibilityContext,
	isAdminByContract map[string]bool,
) []json.RawMessage {
	if len(logs) == 0 {
		return logs
	}

	// Fail-closed: if permissions couldn't be resolved, deny all logs.
	if perms == nil {
		return []json.RawMessage{}
	}

	// Build lowercase address set for O(1) lookup.
	addrSet := make(map[string]bool, len(userAddresses))
	for _, a := range userAddresses {
		addrSet[strings.ToLower(a)] = true
	}

	filtered := make([]json.RawMessage, 0, len(logs))
	for _, rawLog := range logs {
		var entry logEntry
		if err := json.Unmarshal(rawLog, &entry); err != nil {
			continue // skip malformed
		}

		contractAddr := strings.ToLower(entry.Address)

		// Admin bypass (org-scoped, pre-computed): users with the admin
		// claim in the log's emitting-contract's owning org see ALL logs
		// on that contract regardless of event rules. Covers tier-2 org
		// admins (is_org_admin=true) and tier-3 per-contract admins. The
		// caller is responsible for scoping this to the contract's own
		// org — see function docs for why.
		if isAdminByContract[contractAddr] {
			filtered = append(filtered, rawLog)
			continue
		}

		// RD-874 visibleTo unlock: when the contract has the per-contract
		// `allow_visibleto_unlock` flag set AND the viewer was found
		// eligible (caller pre-resolves both into UnlockableContracts) AND
		// the viewer is listed in the tx's visibleTo set, the log passes
		// unconditionally — bypassing the deny-when-no-ABI gate,
		// event_rules, and param_rules. The unlock is per-tx-all-events
		// per the CTO call notes; without the flag (default), additive
		// semantics below apply unchanged.
		if visCtx != nil && visCtx.UnlockableContracts[contractAddr] && isViewerInVisibleTo(visCtx, rawLog) {
			filtered = append(filtered, rawLog)
			continue
		}

		// RD-875 deny-without-ABI gate: closes decisions.md §2 G5. Without
		// a registered ABI we cannot decode non-indexed `address`-typed
		// params in the log's `data` field — private addresses embedded
		// there would leak verbatim. Drop the log for this viewer (admin
		// bypass above is the only exception). nil abiProvider disables
		// the gate (test ergonomics — production paths always inject a
		// real provider via newStoreABIProvider).
		var contractABI string
		if abiProvider != nil {
			contractABI = abiProvider.GetContractABI(contractAddr)
			if contractABI == "" {
				continue
			}
		}

		access := perms.GetContractAccess(contractAddr)

		// RD-1206 rule 71: additive record-audience admit. When a method policy
		// governs this log's event AND the caller is in the record's captured
		// audience, the log passes — bypassing the M15 dynamic-payload gate and
		// the event-rule allowlist below, exactly like the RD-874 visibleTo
		// unlock (the record's initiating call explicitly designated this
		// audience). Bounded by contract eligibility (access != nil): the record
		// gate only ADDS viewers who already hold the contract grant, never
		// widens past it. Fail-safe: the gate returns false on any decode/lookup
		// failure, so the log falls through to the deny-by-default baseline.
		if access != nil && visCtx != nil && visCtx.RecordAudience != nil &&
			visCtx.RecordAudience.EventLogAdmits(contractAddr, contractABI, entry.Topics, entry.Data) {
			filtered = append(filtered, rawLog)
			continue
		}

		// M15 dynamic-payload drop (security audit follow-up to RD-915):
		// drop logs whose matching event declares any dynamic non-indexed
		// param (`bytes`, `string`, dynamic arrays, dynamic structs) for
		// non-Full viewers. Pre-M15 the static-slot scanner could not
		// reach addresses embedded in dynamic payloads, so bridge /
		// forwarder / smart-wallet contracts leaked foreign-org address
		// material verbatim in their event data.
		//
		// Slot precedence: admin bypass and visibleTo unlock above ALREADY
		// passed the log through; this gate only fires for viewers who
		// fell through to the regular access path. Participants on the
		// parent tx are handled at the RPC layer one level up (see
		// FilterReceiptLogsWithEventRules — only participants reach this
		// function for receipts; for eth_getLogs participation is not the
		// gate, RBAC is).
		//
		// Per-contract opt-out: when the ABIProvider implements the
		// DynamicPayloadAllower interface AND
		// IsEventsAllowDynamicPayload(addr) returns true, the operator
		// has explicitly attested that the contract's dynamic payloads
		// are safe (ERC-20 string symbol, etc.) and the gate is bypassed
		// for THAT contract. Default is close-by-default (drop).
		//
		// Anonymous events (no topic0) are treated as "no matching event"
		// — the helper returns false and we fall through. Anonymous-event
		// dynamic-payload leakage is a separate concern (covered by the
		// deny-all default in event_rules below).
		if contractABI != "" && len(entry.Topics) > 0 {
			allowDynamic := false
			if dpa, ok := abiProvider.(DynamicPayloadAllower); ok {
				allowDynamic = dpa.IsEventsAllowDynamicPayload(contractAddr)
			}
			if !allowDynamic && eventHasDynamicNonIndexedParam(contractABI, entry.Topics[0]) {
				continue
			}
		}

		// RD-1162: participant/sender bypass of the event-rule allowlist.
		// If the caller is a participant (from/to) of this log's transaction
		// AND holds a grant on the emitting contract, the log is visible even
		// when the event is not in their event_rules allowlist or carries no
		// address of theirs (e.g. PaymentCompleted, keyed by a business id).
		// They authored/participated in the tx and already know its contents.
		//
		// Bounded by contract access (access != nil): logs emitted by contracts
		// the viewer has no grant on stay dropped, so a tx that internally
		// touched a foreign-org contract never leaks that contract's logs —
		// mirroring the explorer participant override (REDACTION_SPEC §3.7),
		// which upgrades Redacted→Full but keeps Hidden dropped.
		//
		// Slots AFTER the deny-no-ABI (RD-875) and M15 dynamic-payload gates
		// above (consistent with the explorer, where participants do not bypass
		// those): participation relaxes only the allowlist/param/self checks,
		// never the embedded-address protections. So an address-less event on a
		// granted contract becomes visible to its tx's participants, while an
		// event with a dynamic non-indexed payload still requires the operator's
		// events_allow_dynamic_payload attestation.
		if access != nil && logTxIsParticipant(visCtx, rawLog) {
			filtered = append(filtered, rawLog)
			continue
		}

		if access == nil {
			// No RBAC access to this contract — check visibleTo as fallback.
			// The sender explicitly shared this tx with the viewer.
			if isViewerInVisibleTo(visCtx, rawLog) {
				filtered = append(filtered, rawLog)
			}
			continue
		}

		// Wildcard: all events visible for this contract.
		if access.EventRules != nil && access.EventRules.IsWildcard() {
			filtered = append(filtered, rawLog)
			continue
		}

		// Deny all: no event rules configured or empty rules.
		// nil pointer and nil/empty Rules both mean deny.
		rules := eventRulesGetRules(access.EventRules)
		if len(rules) == 0 {
			continue
		}

		// Allowlist mode: the log's topic0 must match one of the allowed event rules.
		if len(entry.Topics) == 0 {
			// Anonymous event (no topic0) — blocked in allowlist mode.
			continue
		}

		topic0 := strings.ToLower(entry.Topics[0])
		if eventAllowed(topic0, entry, rules, addrSet, contractAddr, abiProvider) {
			filtered = append(filtered, rawLog)
		} else if eventTopic0Matches(topic0, rules) && isViewerInVisibleTo(visCtx, rawLog) {
			// Topic0 is in the allowlist but param rules failed.
			// visibleTo extends param rule checks as a fallback.
			filtered = append(filtered, rawLog)
		}
	}

	return filtered
}

// isViewerInVisibleTo checks if the viewer's DID appears in the visibleTo
// list for the transaction that produced this log entry.
func isViewerInVisibleTo(visCtx *TxVisibilityContext, rawLog json.RawMessage) bool {
	if visCtx == nil || visCtx.ViewerDID == "" || len(visCtx.TxVisibility) == 0 {
		return false
	}
	var logMeta struct {
		TransactionHash string `json:"transactionHash"`
	}
	if err := json.Unmarshal(rawLog, &logMeta); err != nil || logMeta.TransactionHash == "" {
		return false
	}
	dids, ok := visCtx.TxVisibility[strings.ToLower(logMeta.TransactionHash)]
	if !ok {
		return false
	}
	for _, did := range dids {
		if did == visCtx.ViewerDID {
			return true
		}
	}
	return false
}

// logTxIsParticipant reports whether the transaction that produced this log
// entry is one the caller participated in (their linked address is the tx
// from/to), per the pre-resolved visCtx.ParticipantTxHashes set (RD-1162).
// Nil/empty context or set = no participant information (backward compatible:
// callers that do not resolve senders leave it nil and this returns false).
func logTxIsParticipant(visCtx *TxVisibilityContext, rawLog json.RawMessage) bool {
	if visCtx == nil || len(visCtx.ParticipantTxHashes) == 0 {
		return false
	}
	var logMeta struct {
		TransactionHash string `json:"transactionHash"`
	}
	if err := json.Unmarshal(rawLog, &logMeta); err != nil || logMeta.TransactionHash == "" {
		return false
	}
	return visCtx.ParticipantTxHashes[strings.ToLower(logMeta.TransactionHash)]
}

// eventTopic0Matches checks if the given topic0 matches any event rule's Topic0,
// without checking param rules. Used to determine if visibleTo should be
// considered as a fallback (topic0 must be in the allowlist).
func eventTopic0Matches(topic0 string, rules []EventRule) bool {
	for _, rule := range rules {
		if strings.EqualFold(rule.Topic0, topic0) {
			return true
		}
	}
	return false
}

// eventAllowed checks if a log with the given topic0 is allowed by any of the
// event rules. Returns true if the event is in the allowlist and all param
// constraints are satisfied.
func eventAllowed(
	topic0 string,
	entry logEntry,
	rules []EventRule,
	addrSet map[string]bool,
	contractAddr string,
	abiProvider ABIProvider,
) bool {
	for _, rule := range rules {
		if !strings.EqualFold(rule.Topic0, topic0) {
			continue
		}

		// Topic0 matches this rule.
		// nil or empty ParamRules = no constraints, topic0 match is sufficient.
		if len(rule.ParamRules) == 0 {
			return true
		}

		// Check param rules: at least one "self" constraint must match (OR semantics).
		if checkEventParamRules(entry, rule.ParamRules, addrSet, contractAddr, abiProvider) {
			return true
		}
	}
	return false
}

// checkEventParamRules checks if the caller satisfies any of the param rule
// constraints on an event. OR semantics: if ANY constrained parameter matches,
// the check passes.
//
// Supported must_be values:
//   - "self"     — param must encode one of the caller's linked addresses
//   - "0x..."    — param must match the given literal hex value (type-aware comparison)
func checkEventParamRules(
	entry logEntry,
	paramRules []ParamRule,
	addrSet map[string]bool,
	contractAddr string,
	abiProvider ABIProvider,
) bool {
	var abiJSON string
	if abiProvider != nil {
		abiJSON = abiProvider.GetContractABI(contractAddr)
	}
	return MatchesEventParamRules(
		EventLogInputs{
			ContractAddress: entry.Address,
			Topics:          entry.Topics,
			Data:            entry.Data,
		},
		paramRules,
		addrSet,
		abiJSON,
	)
}

// isHexValue returns true if s is a 0x-prefixed hex string of non-zero length.
func isHexValue(s string) bool {
	if len(s) < 4 || !strings.HasPrefix(s, "0x") {
		return false
	}
	_, err := hex.DecodeString(s[2:])
	return err == nil
}

// matchesParamSelf checks if the event parameter at the given ABI index
// encodes one of the user's linked addresses.
func matchesParamSelf(
	entry logEntry,
	paramIndex int,
	addrSet map[string]bool,
	parsedEvent *abi.Event,
) bool {
	if parsedEvent == nil {
		// No ABI: fall back to checking topics for address-like values.
		// Indexed param at ABI index i goes to topics[1+indexedOffset].
		// Without ABI we can only check if the index maps to a topic position.
		topicIdx := paramIndex + 1 // rough guess: assume all params up to index are indexed
		if topicIdx < len(entry.Topics) {
			return topicMatchesAddr(entry.Topics[topicIdx], addrSet)
		}
		return false
	}

	if paramIndex < 0 || paramIndex >= len(parsedEvent.Inputs) {
		return false
	}

	input := parsedEvent.Inputs[paramIndex]
	if input.Indexed {
		// Find which topic slot this indexed param occupies.
		// topics[0] = event signature. topics[1..3] = indexed params in order.
		indexedPos := 0
		for i := 0; i < paramIndex; i++ {
			if parsedEvent.Inputs[i].Indexed {
				indexedPos++
			}
		}
		topicSlot := indexedPos + 1
		if topicSlot < len(entry.Topics) {
			return topicMatchesAddr(entry.Topics[topicSlot], addrSet)
		}
		return false
	}

	// Non-indexed param: ABI-decode the data field.
	return dataParamMatchesAddr(entry.Data, parsedEvent, paramIndex, addrSet)
}

// matchesParamCustom checks if the event parameter at the given ABI index
// matches the literal hex value specified in mustBe. The comparison is
// type-aware based on the ABI:
//   - address: 20-byte hex comparison (case-insensitive)
//   - uint256: numeric comparison of hex-encoded big integers
//   - bytes32: direct 32-byte hex comparison
//   - bool:    "0x01" for true, "0x00" for false
//
// For indexed params the raw 32-byte topic is compared directly.
// For non-indexed params the data field is ABI-decoded.
func matchesParamCustom(
	entry logEntry,
	paramIndex int,
	mustBe string,
	parsedEvent *abi.Event,
) bool {
	if parsedEvent == nil {
		// No ABI: fall back to direct topic comparison for indexed params.
		topicIdx := paramIndex + 1
		if topicIdx < len(entry.Topics) {
			return topicMatchesHex(entry.Topics[topicIdx], mustBe)
		}
		return false
	}

	if paramIndex < 0 || paramIndex >= len(parsedEvent.Inputs) {
		return false
	}

	input := parsedEvent.Inputs[paramIndex]
	if input.Indexed {
		topicSlot := indexedTopicSlot(parsedEvent, paramIndex)
		if topicSlot < len(entry.Topics) {
			return topicMatchesHexTyped(entry.Topics[topicSlot], mustBe, input.Type.String())
		}
		return false
	}

	// Non-indexed: ABI-decode the data and compare the value.
	return dataParamMatchesCustom(entry.Data, parsedEvent, paramIndex, mustBe)
}

// indexedTopicSlot returns the topic index (1-based) for an indexed param at
// the given ABI position.
func indexedTopicSlot(parsedEvent *abi.Event, paramIndex int) int {
	indexedPos := 0
	for i := 0; i < paramIndex; i++ {
		if parsedEvent.Inputs[i].Indexed {
			indexedPos++
		}
	}
	return indexedPos + 1
}

// topicMatchesHex compares a 32-byte topic to a hex value with no type info.
// Performs a case-insensitive comparison after zero-padding the mustBe value
// to 32 bytes.
func topicMatchesHex(topic string, mustBe string) bool {
	return topicMatchesHexTyped(topic, mustBe, "")
}

// topicMatchesHexTyped compares a 32-byte topic to a hex value with type awareness.
// For address types, extracts the last 20 bytes and compares. For uint256,
// compares as big integers. For all others, does a direct padded comparison.
func topicMatchesHexTyped(topic string, mustBe string, abiType string) bool {
	t := strings.ToLower(strings.TrimPrefix(topic, "0x"))
	m := strings.ToLower(strings.TrimPrefix(mustBe, "0x"))

	if len(t) != 64 {
		return false
	}

	switch {
	case abiType == "address":
		// Address comparison: compare last 40 hex chars (20 bytes).
		// mustBe can be either a 20-byte address or a 32-byte padded value.
		if len(m) == 40 {
			// Verify topic has zero padding in the first 12 bytes.
			if strings.Trim(t[:24], "0") != "" {
				return false
			}
			return t[24:] == m
		}
		if len(m) == 64 {
			return t == m
		}
		return false

	case strings.HasPrefix(abiType, "uint"):
		// Numeric comparison as big.Int.
		topicInt, ok1 := new(big.Int).SetString(t, 16)
		mustBeInt, ok2 := new(big.Int).SetString(m, 16)
		if !ok1 || !ok2 {
			return false
		}
		return topicInt.Cmp(mustBeInt) == 0

	case abiType == "bool":
		// Normalize: strip leading zeros, then compare.
		topicStripped := strings.TrimLeft(t, "0")
		mustStripped := strings.TrimLeft(m, "0")
		topicBool := topicStripped == "1"
		mustBool := mustStripped == "1"
		topicFalse := topicStripped == ""
		mustFalse := mustStripped == ""
		return (topicBool && mustBool) || (topicFalse && mustFalse)

	default:
		// bytes32, bytes, or unknown: pad mustBe to 64 hex chars (right-pad for
		// bytesN, but indexed topics are always left-padded to 32 bytes).
		// Direct comparison after padding mustBe to 64 chars on the left with zeros.
		if len(m) > 64 {
			return false
		}
		padded := strings.Repeat("0", 64-len(m)) + m
		return t == padded
	}
}

// dataParamMatchesCustom decodes the non-indexed parameters from the log data
// field and checks if the parameter at paramIndex matches the custom mustBe value.
func dataParamMatchesCustom(
	data string,
	parsedEvent *abi.Event,
	paramIndex int,
	mustBe string,
) bool {
	if data == "" || data == "0x" {
		return false
	}

	dataHex := strings.TrimPrefix(data, "0x")
	dataBytes, err := hex.DecodeString(dataHex)
	if err != nil {
		return false
	}

	// Collect non-indexed inputs to determine ABI decode ordering.
	var nonIndexed abi.Arguments
	nonIndexedABIIdx := -1
	niCount := 0
	for i, inp := range parsedEvent.Inputs {
		if !inp.Indexed {
			nonIndexed = append(nonIndexed, inp)
			if i == paramIndex {
				nonIndexedABIIdx = niCount
			}
			niCount++
		}
	}
	if nonIndexedABIIdx < 0 {
		return false
	}

	values, err := nonIndexed.Unpack(dataBytes)
	if err != nil {
		return false
	}
	if nonIndexedABIIdx >= len(values) {
		return false
	}

	return compareDecodedValue(values[nonIndexedABIIdx], mustBe, parsedEvent.Inputs[paramIndex].Type.String())
}

// compareDecodedValue compares an ABI-decoded Go value against a hex mustBe string.
func compareDecodedValue(decoded interface{}, mustBe string, abiType string) bool {
	m := strings.ToLower(strings.TrimPrefix(mustBe, "0x"))

	switch v := decoded.(type) {
	case common.Address:
		return strings.ToLower(v.Hex()[2:]) == m || (len(m) == 64 && m[24:] == strings.ToLower(v.Hex()[2:]))

	case *big.Int:
		mustBeInt, ok := new(big.Int).SetString(m, 16)
		if !ok {
			return false
		}
		return v.Cmp(mustBeInt) == 0

	case bool:
		// Normalize: strip leading zeros, then compare.
		// "1", "01", "000...001" all mean true. "0", "00", "000...000" all mean false.
		stripped := strings.TrimLeft(m, "0")
		if stripped == "1" {
			return v
		}
		if stripped == "" { // all zeros
			return !v
		}
		return false

	case [32]byte:
		return hex.EncodeToString(v[:]) == m

	default:
		// For other types, encode to hex and compare.
		return false
	}
}

// topicMatchesAddr checks if a 32-byte topic hex string encodes one of the
// user's addresses (zero-padded address format).
func topicMatchesAddr(topic string, addrSet map[string]bool) bool {
	t := strings.ToLower(topic)
	if len(t) != 66 || !strings.HasPrefix(t, "0x") {
		return false
	}
	// Address is last 40 chars, first 24 chars must be zero padding.
	prefix := t[2:26]
	if strings.Trim(prefix, "0") != "" {
		return false
	}
	addr := "0x" + t[26:]
	return addrSet[addr]
}

// dataParamMatchesAddr decodes the non-indexed parameters from the log data
// field and checks if the parameter at paramIndex is an address matching one
// of the user's addresses.
func dataParamMatchesAddr(
	data string,
	parsedEvent *abi.Event,
	paramIndex int,
	addrSet map[string]bool,
) bool {
	if data == "" || data == "0x" {
		return false
	}

	dataHex := strings.TrimPrefix(data, "0x")
	dataBytes, err := hex.DecodeString(dataHex)
	if err != nil {
		return false
	}

	// Collect non-indexed inputs to determine ABI decode ordering.
	var nonIndexed abi.Arguments
	nonIndexedABIIdx := -1
	niCount := 0
	for i, inp := range parsedEvent.Inputs {
		if !inp.Indexed {
			nonIndexed = append(nonIndexed, inp)
			if i == paramIndex {
				nonIndexedABIIdx = niCount
			}
			niCount++
		}
	}

	if nonIndexedABIIdx < 0 {
		return false // param is not non-indexed (shouldn't happen, handled above)
	}

	// Attempt ABI unpack.
	values, err := nonIndexed.Unpack(dataBytes)
	if err != nil {
		return false
	}

	if nonIndexedABIIdx >= len(values) {
		return false
	}

	addr, ok := values[nonIndexedABIIdx].(common.Address)
	if !ok {
		return false
	}

	return addrSet[strings.ToLower(addr.Hex())]
}

// eventRulesGetRules safely extracts the rules slice from an EventRulesField pointer.
// Returns nil if the pointer is nil or if the field is in wildcard/deny mode.
func eventRulesGetRules(f *EventRulesField) []EventRule {
	if f == nil {
		return nil
	}
	return f.GetRules()
}

// eventHasDynamicNonIndexedParam reports whether the event matching
// topic0 in contractABI declares ANY non-indexed parameter of a
// dynamically-sized ABI type (`bytes`, `string`, dynamic arrays — incl.
// fixed-length arrays of dynamic types — or tuples containing any
// dynamic field).
//
// Used by FilterEventLogs (and the explorer's RedactLogs via a mirror)
// to drive the M15 drop gate: dynamic payloads can embed foreign-org
// addresses that the pre-M15 static-slot scanner cannot find. When the
// ABI lookup fails (parse error, no matching event, no ABI provided),
// the function conservatively returns FALSE — at this point the caller
// has already cleared the deny-when-no-ABI gate (RD-875) via an admin
// bypass or visibleTo unlock, so withholding the drop is acceptable.
//
// Indexed params are NEVER considered dynamic for this gate: dynamic
// types appearing as indexed are stored as keccak256 hashes in topics,
// not raw bytes — no address material survives.
func eventHasDynamicNonIndexedParam(contractABI string, topic0 string) bool {
	if contractABI == "" || topic0 == "" {
		return false
	}
	ev := findEventByTopic0(contractABI, topic0)
	if ev == nil {
		return false
	}
	for _, inp := range ev.Inputs {
		if inp.Indexed {
			continue
		}
		if isDynamicABIType(inp.Type) {
			return true
		}
	}
	return false
}

// isDynamicABIType reports whether an abi.Type is dynamically-sized in
// the ABI encoding sense. Mirrors go-ethereum's internal classification:
//   - bytes, string                       — always dynamic
//   - T[] (slice)                         — always dynamic
//   - T[N] (fixed array) where T dynamic  — dynamic
//   - tuple containing any dynamic field  — dynamic
//
// Plain fixed-size types (bytesN, intN, uintN, bool, address, function)
// are static.
func isDynamicABIType(t abi.Type) bool {
	switch t.T {
	case abi.StringTy, abi.BytesTy, abi.SliceTy:
		return true
	case abi.ArrayTy:
		if t.Elem == nil {
			return false
		}
		return isDynamicABIType(*t.Elem)
	case abi.TupleTy:
		for _, ft := range t.TupleElems {
			if ft != nil && isDynamicABIType(*ft) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// findEventByTopic0 finds the event in a contract ABI that matches the given topic0.
func findEventByTopic0(contractABI string, topic0 string) *abi.Event {
	parsed, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		return nil
	}
	topic0Lower := strings.ToLower(topic0)
	for _, ev := range parsed.Events {
		sig := "0x" + hex.EncodeToString(ev.ID.Bytes())
		if strings.ToLower(sig) == topic0Lower {
			ev := ev // capture
			return &ev
		}
	}
	return nil
}
