package explorer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"privacy-proxy/internal/rbac"
)

// VisibilityMap maps an address (lowercase) to its resolved visibility level
type VisibilityMap map[string]VisibilityLevel

// visibilityMapFromDetailed projects the level-only VisibilityMap out of a
// detailed visibility result (RD-1123). GetBatchVisibilityDetailed is an exact
// superset of GetBatchVisibility: both DB methods iterate the same deduplicated
// address set, initialise every address to VisibilityHidden, and resolve each
// level through identical branches (own-address, precompile, org-contract grant,
// disclosure-grant rank-merge). The only difference is that the detailed variant
// additionally carries Reason / Visible / Pseudonym metadata. Therefore
// detailed[addr].Level == plain[addr] for every address, and deriving the plain
// map from the detailed one lets each Redact* entry point issue ONE visibility
// query instead of two — eliminating a redundant per-request DB round-trip with
// no change to the levels the redactor sees.
func visibilityMapFromDetailed(detailed map[string]AddressVisibility) VisibilityMap {
	m := make(VisibilityMap, len(detailed))
	for addr, v := range detailed {
		m[addr] = v.Level
	}
	return m
}

// ContractStore is the minimal interface RedactionEngine needs from the explorer store.
type ContractStore interface {
	GetContract(ctx context.Context, address string) (*Contract, error)
}

// EventRuleChecker resolves event-level access rules for a viewer on a
// given contract address. The interface mirrors the RPC-side event-rule
// resolution (see rbac.FilterEventLogs) so the explorer redactor and the
// JSON-RPC filter behave identically — required by the Layer 1 / Layer 2
// symmetry invariant in REDACTION_SPEC.md.
//
// Returns a tri-state EventRulesResolution:
//   - Wildcard == true                  ⇒ all events for this contract are
//     visible to the viewer; allowlist
//     is irrelevant. Mirrors the
//     rbac.EventRulesField{"*"} state.
//   - Wildcard == false, len(Rules) > 0 ⇒ allowlist mode; only listed
//     topic0s pass.
//   - Wildcard == false, len(Rules) == 0 ⇒ **deny-all** (RD-842 / RD-888).
//     Same as `event_rules: null` in
//     the database — operator intent
//     is "no events visible until
//     rules are configured." Anonymous
//     logs (no topic0) are also
//     blocked in this mode.
//
// Implementations MUST return the deny-all state when there is no
// applicable grant for the viewer on the contract. **Never default to
// allow-on-missing** — that was the pre-RD-888 behaviour and the cause of
// the RPC/explorer symmetry break (RPC denied, explorer leaked).
type EventRuleChecker interface {
	// GetEventRulesForContract returns the viewer's event-rule resolution
	// for a contract address. See the interface docstring for tri-state
	// semantics.
	GetEventRulesForContract(ctx context.Context, viewerDID string, contractAddress string) EventRulesResolution
}

// EventRulesResolution describes a viewer's event-rule access for one
// contract. See EventRuleChecker docstring for tri-state semantics.
type EventRulesResolution struct {
	// Wildcard true ⇒ all events visible, allowlist ignored.
	Wildcard bool
	// Rules is the allowlist of (topic0) entries. Honoured only when
	// Wildcard is false. Empty Rules with Wildcard=false ⇒ deny-all.
	Rules []EventRuleInfo
}

// EventRuleInfo is a lightweight event rule representation used by the
// redactor. Topic0 is the event signature hash (0x-prefixed, lowercase).
//
// ParamRules are optional per-parameter constraints that mirror the RPC
// layer's rbac.EventRule.ParamRules field. When present, a log whose
// topic0 matches this rule must additionally satisfy at least one of
// the param-rule constraints (OR semantics) — typed against the
// contract's ABI. When empty, topic0 match alone is sufficient.
//
// Pre-this fix the explorer's EventRuleInfo carried only Topic0, so
// param-rule constraints configured on a grant (e.g.
// `{topic0: Transfer, params: [{index: 0, must_be: self}]}`) were
// silently ignored — RPC enforced them, explorer leaked. The audit
// classified this as HIGH because it lets viewers see Transfer logs
// for *other* people's transfers on a contract where the operator
// intended "only your own transfers."
type EventRuleInfo struct {
	Topic0     string
	ParamRules []rbac.ParamRule
}

// ABIResolver resolves the ABI for a contract address using the same
// "custom upload first, then built-in registry fallback" semantics as
// rbac.ResolveContractABI. Centralised here so the explorer redactor and
// the JSON-RPC layer (storeABIProvider in internal/server) consult one
// source of truth — required by the access/visibility symmetry invariant
// in REDACTION_SPEC.md.
//
// Returns the empty string when no ABI is resolvable (no custom upload
// AND no built-in match for the contract's metadata.token_type). Callers
// must treat empty as "no resolvable ABI" — the deny-when-no-ABI gate
// (RD-889 / mirrors RD-875 at the RPC layer) drops logs from such
// contracts rather than risk leaking private addresses embedded in
// non-indexed event data parameters that we cannot decode.
type ABIResolver interface {
	Resolve(ctx context.Context, address string) string
}

// AdminContractsResolver returns the subset of supplied contract
// addresses where the viewer holds admin-equivalent privileges (tier-2
// org-admin OR tier-3 per-contract admin claim). The result mirrors the
// JSON-RPC layer's processor_event_rules.go::viewerAdminContracts
// resolver so both layers honour the same admin-bypass set per
// (viewer, contract) — required by the access/visibility symmetry
// invariant in REDACTION_SPEC.md.
//
// When wired (via RedactionEngine.SetAdminContractsResolver) the
// redactor uses the returned map to bypass the deny-when-no-ABI gate
// (RD-889) for admin viewers — exactly as rbac.FilterEventLogs does
// at the RPC layer with its isAdminByContract input.
//
// Implementations MUST be org-scoped: a contract C in Org B's
// ownership must NOT appear admin-true for a viewer who is admin only
// in Org A, even if both orgs ever held the same address (defense in
// depth against migration 035 ever weakening). Unregistered or
// lookup-failed addresses are silently omitted (admin = false).
type AdminContractsResolver interface {
	Resolve(ctx context.Context, viewerDID string, addresses []string) map[string]bool
}

// VisibleToUnlockResolver returns the subset of supplied contract
// addresses where the per-contract `allow_visibleto_unlock` flag is set
// AND the viewer is eligible for the unlock — both gates from RD-874.
// The map is consumed by Phase 4 of RedactLogs along with the
// ListedTxHashes opt: when both the contract is unlockable AND the
// log's tx hash is one the viewer is genuinely listed on, the log passes unredacted
// (bypasses event_rules, param_rules, and the deny-when-no-ABI gate).
//
// Implementations MUST be org-scoped: a viewer who is in another org
// must never appear unlock-eligible for a contract whose owning org
// they are not a member of. Same defence as AdminContractsResolver.
//
// This resolver mirrors the JSON-RPC layer's
// `buildVisibleToUnlockableMap` so both layers honour the same unlock
// set per (viewer, contract) — required by the access/visibility
// symmetry invariant in REDACTION_SPEC.md.
type VisibleToUnlockResolver interface {
	Resolve(ctx context.Context, viewerDID string, addresses []string) map[string]bool
}

// DynamicPayloadAllowedResolver returns, for a batch of contract
// addresses, the subset whose operator has explicitly opted out of the
// M15 dynamic-payload drop gate (`events_allow_dynamic_payload = true`).
// Mirrors the JSON-RPC layer's storeABIProvider.IsEventsAllowDynamicPayload
// so both layers honour the same operator attestation per contract —
// required by the access/visibility symmetry invariant in
// REDACTION_SPEC.md.
//
// Returns a lowercase-address → bool map. Missing or false entries
// mean "drop dynamic-payload events for non-Full viewers" (close-by-
// default). True means "operator attests the dynamic payload is safe;
// pass through" — used for standard ERC-20 / ERC-721 contracts where
// `string symbol` / `bytes metadata` cannot contain foreign-org address
// material.
//
// Implementations MUST scope reads to the canonical contracts table by
// address; cross-org leakage is impossible here because the gate is a
// contract-level attestation, not a viewer-level one.
type DynamicPayloadAllowedResolver interface {
	Resolve(ctx context.Context, addresses []string) map[string]bool
}

// ParticipantEventSlots is the canonical map of "events that name participants
// by indexed address topics" → which 1-based topic slots are address-typed.
// Used by LogParticipantResolver implementations and by RedactTransactions
// to recognise a viewer as a tx participant via event-log evidence (RD-939).
//
// Why an explicit list rather than "any indexed address in any event":
// over-broad inference (e.g. accepting a third-party operator address as a
// participant signal for everyone in that log) would cause false-positive
// reveals — the inverse of the bug we're fixing here. The signatures below
// are the ERC-standard events whose slot semantics are unambiguously
// "from / to / operator / owner / spender" (i.e. a counterparty), so the
// viewer-on-topic test is sound by construction.
//
// Topic0 hashes (keccak256 of the canonical signature):
//
//	Transfer(address,address,uint256)
//	   0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
//	Approval(address,address,uint256)
//	   0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925
//	ApprovalForAll(address,address,bool)
//	   0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31
//	TransferSingle(address,address,address,uint256,uint256)
//	   0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62
//	TransferBatch(address,address,address,uint256[],uint256[])
//	   0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb
//	Deposit(address,uint256)      (WETH)
//	   0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c
//	Withdrawal(address,uint256)   (WETH)
//	   0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65
var ParticipantEventSlots = map[string][]int{
	"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": {1, 2},    // Transfer
	"0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925": {1, 2},    // Approval
	"0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31": {1, 2},    // ApprovalForAll
	"0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62": {1, 2, 3}, // TransferSingle
	"0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb": {1, 2, 3}, // TransferBatch
	"0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c": {1},       // Deposit (WETH)
	"0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65": {1},       // Withdrawal (WETH)
}

// LogParticipantStore returns the subset of tx hashes where the viewer is
// a participant via event-log evidence. A viewer counts as a log
// participant when one of their linked ETH addresses appears in any of the
// address-typed indexed topic slots of an accepted ParticipantEventSlots
// signature on a log emitted by that tx.
//
// This is the participant signal that catches token mints to the viewer,
// approvals granted to/by the viewer, ERC-1155 batch transfers, and
// WETH-style wrappers — none of which surface in tx.from / tx.to and most
// of which are missed by the (legacy, hardcoded) calldata heuristic when
// the contract uses a non-standard function selector. See RD-939 for the
// origin bug (custom mint(address,…,…) calldata + Transfer event log,
// viewer was dropped).
//
// Implementations MUST filter on ParticipantEventSlots only — accepting any
// indexed address in any event would falsely flag uninvolved bystanders
// (operator-of-someone-else's-transfer). Returns lowercase tx hashes.
type LogParticipantStore interface {
	FindLogParticipantTxs(ctx context.Context, viewerAddrs []string, txHashes []string) (map[string]bool, error)
}

// RedactionEngine handles the bulk redaction of explorer data based on user grants
type RedactionEngine struct {
	store                         ContractStore
	db                            Database // The main Open Privacy Suite DB for RBAC checks
	eventRuleChecker              EventRuleChecker
	abiResolver                   ABIResolver
	adminContractsResolver        AdminContractsResolver
	visibleToUnlockResolver       VisibleToUnlockResolver
	dynamicPayloadAllowedResolver DynamicPayloadAllowedResolver
	logParticipantStore           LogParticipantStore
	pseudonymKey                  []byte // RD-1164 #8: HMAC key for address pseudonyms (nil = unkeyed HMAC, still non-reversible)
}

// Database interface for the methods RedactionEngine needs from the main DB
type Database interface {
	GetBatchVisibility(ctx context.Context, viewerDID string, addresses []string) (VisibilityMap, error)
	GetBatchVisibilityDetailed(ctx context.Context, viewerDID string, addresses []string) (map[string]AddressVisibility, error)
	// GetLinkedAddresses returns the lowercase ETH addresses linked to a DID.
	GetLinkedAddresses(ctx context.Context, did string) ([]string, error)
	// GetBatchEventAccess checks which contracts the viewer has event/log access to.
	// Returns a map of lowercase contract address -> bool (true = has event access).
	// A viewer has event access if they are an org admin or have a contract_grant
	// with non-empty event_rules (event_rules IS NOT NULL AND event_rules != '[]').
	GetBatchEventAccess(ctx context.Context, viewerDID string, contractAddresses []string) (map[string]bool, error)
}

func NewRedactionEngine(store ContractStore, db Database) *RedactionEngine {
	return &RedactionEngine{
		store: store,
		db:    db,
	}
}

// SetEventRuleChecker sets an optional event rule checker for log-level filtering.
func (r *RedactionEngine) SetEventRuleChecker(checker EventRuleChecker) {
	r.eventRuleChecker = checker
}

// SetAdminContractsResolver wires the unified admin-contracts resolver
// (RD-890 — closes the tier-3 admin bypass asymmetry between RPC and
// explorer). When set:
//   - Phase 4 computes a per-call admin map for the contracts emitting
//     logs in this batch.
//   - Admin viewers bypass the deny-when-no-ABI gate (RD-889) for those
//     specific contracts — mirroring rbac.FilterEventLogs's
//     isAdminByContract bypass at the RPC layer.
//
// Without this resolver wired, admins fall through to the regular gates
// — strictly fail-closed but creates UX surprise for tier-3 admins
// (logs visible via eth_getLogs but not via the explorer endpoint).
// Production server startup wires it.
func (r *RedactionEngine) SetAdminContractsResolver(resolver AdminContractsResolver) {
	r.adminContractsResolver = resolver
}

// SetVisibleToUnlockResolver wires the per-contract visibleTo unlock
// resolver (RD-874). When set, Phase 4 of RedactLogs treats logs from
// unlock-eligible contracts as fully visible for the duration of any
// transaction the viewer is listed in via visibleTo — bypassing
// event_rules, param_rules, and the deny-when-no-ABI gate for that
// specific tx. Without the resolver wired the unlock branch is
// disabled and the redactor falls back to the additive visibleTo
// behaviour. Production server startup wires it.
func (r *RedactionEngine) SetVisibleToUnlockResolver(resolver VisibleToUnlockResolver) {
	r.visibleToUnlockResolver = resolver
}

// SetDynamicPayloadAllowedResolver wires the M15 per-contract opt-out
// resolver. When set, Phase 4 of RedactLogs drops logs whose matching
// event declares any dynamic non-indexed parameter for contracts where
// the operator has NOT opted out — close-by-default. Mirrors the
// JSON-RPC layer's storeABIProvider.IsEventsAllowDynamicPayload so both
// layers agree per contract.
//
// Without this resolver wired, the M15 drop gate stays disabled —
// dynamic-payload events pass through unredacted. Production server
// startup MUST wire it; legacy tests without explicit M15 coverage skip
// the gate.
func (r *RedactionEngine) SetDynamicPayloadAllowedResolver(resolver DynamicPayloadAllowedResolver) {
	r.dynamicPayloadAllowedResolver = resolver
}

// SetABIResolver wires the unified ABI resolver (RD-889 / Stage 2 of the
// RPC↔explorer redaction unification, RD-887). When set:
//   - Phase 3 (data-field address scanning) consults the resolver instead
//     of the explorer's local ContractStore — gives the explorer access
//     to the built-in ABI registry (ERC-20 / ERC-721 from
//     metadata.token_type) that was previously RPC-layer-only.
//   - Phase 4 applies the deny-when-no-ABI gate: logs from a contract
//     with no resolvable ABI are dropped, mirroring rbac.FilterEventLogs
//     at the RPC layer (RD-875 / decisions.md §2 G5).
//
// Without this resolver wired, the redactor falls back to the
// pre-RD-889 ContractStore-based ABI lookup and skips the deny gate —
// keeping legacy tests passing. Production server startup MUST wire it.
func (r *RedactionEngine) SetABIResolver(resolver ABIResolver) {
	r.abiResolver = resolver
}

// SetPseudonymKey wires the HMAC key used to derive address pseudonyms
// (RD-1164 #8). With a key set, pseudonyms are non-reversible AND
// non-enumerable; with nil they are still non-reversible (HMAC) but a
// candidate address can be recomputed. Production server startup wires
// cfg.ExplorerPseudonymKey via wireExplorerRedactor.
func (r *RedactionEngine) SetPseudonymKey(key []byte) {
	r.pseudonymKey = key
}

// SetLogParticipantStore wires the log-based participant detector (RD-939
// Stage A). Without this resolver the redactor falls back to tx.from /
// tx.to and the legacy hardcoded calldata heuristic, which misses
// participants reached only via event-log topics (the original Dave bug:
// custom-selector mint with viewer in Transfer's `to` topic).
//
// Production server startup MUST wire it; tests that don't care can leave
// it unset (RedactTransactions degrades gracefully — no log signal, but
// the other paths still fire).
func (r *RedactionEngine) SetLogParticipantStore(store LogParticipantStore) {
	r.logParticipantStore = store
}

// resolveContractABI returns the resolved ABI JSON for an address, or
// json.RawMessage(nil) when no ABI is resolvable. Prefers the unified
// ABIResolver (covers built-in registry fallback); falls back to the
// explorer's ContractStore for legacy callers that haven't wired the
// resolver. Pre-RD-889 the only path was ContractStore.
func (r *RedactionEngine) resolveContractABI(ctx context.Context, address string) json.RawMessage {
	if r.abiResolver != nil {
		if abi := r.abiResolver.Resolve(ctx, address); abi != "" {
			return json.RawMessage(abi)
		}
		return nil
	}
	if r.store != nil {
		contract, err := r.store.GetContract(ctx, address)
		if err != nil || contract == nil {
			return nil
		}
		return contract.ABI
	}
	return nil
}

// extractUniqueAddresses gets all unique from/to addresses from a list of transactions
func extractUniqueAddresses(txs []Transaction) []string {
	addrMap := make(map[string]bool)
	for _, tx := range txs {
		if tx.From != "" {
			addrMap[strings.ToLower(tx.From)] = true
		}
		if tx.HasRecipient() {
			addrMap[strings.ToLower(*tx.To)] = true
		}
		// RD-1143: include the deployed-contract address on CREATE receipts so
		// its visibility is resolved in the same batch and it can be field-level
		// redacted below. Nil for non-CREATE txs and factory/CREATE2 deploys
		// (the receipt only carries contractAddress for a top-level CREATE).
		if tx.ContractAddress != nil && *tx.ContractAddress != "" {
			addrMap[strings.ToLower(*tx.ContractAddress)] = true
		}
	}

	var addrs []string
	for addr := range addrMap {
		addrs = append(addrs, addr)
	}
	return addrs
}

// isViewerInCalldata checks if any of the viewer's addresses appear as an
// address parameter in the transaction's input data. This detects participation
// in contract calls where the actual counterparty is encoded in calldata rather
// than in the tx-level "to" field (e.g., ERC20 transfer(address,uint256)).
//
// Supported function selectors:
//   - ERC-20  0xa9059cbb: transfer(address to, uint256 amount)
//   - ERC-20  0x23b872dd: transferFrom(address from, address to, uint256 amount)
//   - ERC-20  0x095ea7b3: approve(address spender, uint256 amount)
//   - ERC-721 0x42842e0e: safeTransferFrom(address from, address to, uint256 tokenId)
//   - ERC-721 0xb88d4fde: safeTransferFrom(address from, address to, uint256 tokenId, bytes data)
//   - ERC-721 0xa22cb465: setApprovalForAll(address operator, bool approved)
//   - ERC-1155 0xf242432a: safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes data)
//   - ERC-1155 0x2eb2c2d6: safeBatchTransferFrom(address from, address to, uint256[] ids, uint256[] amounts, bytes data)
//
// M14: pre-fix this covered only the three ERC-20 selectors. Viewers
// who were encoded recipients of ERC-721 / ERC-1155 transfers silently
// lost the participant override — they saw [PRIVATE] for transactions
// where they were the actual counterparty.
func isViewerInCalldata(inputData string, viewerAddrs map[string]bool) bool {
	if len(viewerAddrs) == 0 || len(inputData) < 8 {
		return false
	}

	data := strings.ToLower(inputData)
	// Normalize: strip 0x prefix if present so selector is always at [0:8]
	if strings.HasPrefix(data, "0x") {
		data = data[2:]
	}
	if len(data) < 8 {
		return false
	}
	selector := "0x" + data[:8]

	// Each address param is 32 bytes (64 hex chars), zero-padded on the left.
	// Address is in the last 20 bytes: offset 24 hex chars from param start.
	extractAddr := func(offset int) string {
		start := 8 + offset*64 // 8 = selector length after stripping 0x
		end := start + 64
		if len(data) < end {
			return ""
		}
		// Address is last 20 bytes of 32-byte word
		return "0x" + data[start+24:end]
	}

	switch selector {
	// ERC-20
	case "0xa9059cbb": // transfer(address,uint256) — param 0 is recipient
		return viewerAddrs[extractAddr(0)]
	case "0x23b872dd": // transferFrom(address,address,uint256) — params 0,1
		return viewerAddrs[extractAddr(0)] || viewerAddrs[extractAddr(1)]
	case "0x095ea7b3": // approve(address,uint256) — param 0 is spender
		return viewerAddrs[extractAddr(0)]
	// ERC-721 (same shape; from/to at params 0,1)
	case "0x42842e0e", "0xb88d4fde":
		return viewerAddrs[extractAddr(0)] || viewerAddrs[extractAddr(1)]
	case "0xa22cb465": // setApprovalForAll(address,bool)
		return viewerAddrs[extractAddr(0)]
	// ERC-1155 (from/to at params 0,1)
	case "0xf242432a", "0x2eb2c2d6":
		return viewerAddrs[extractAddr(0)] || viewerAddrs[extractAddr(1)]
	}
	return false
}

// isViewerInCalldataABI is the RD-939 Stage B successor to the hardcoded
// `isViewerInCalldata` selector switch. It decodes the calldata against
// the called contract's registered ABI (resolved via abiResolver — the
// same path EventRuleChecker uses) and returns true when any decoded
// address-typed argument matches one of the viewer's linked addresses.
//
// Posture:
//   - Requires both abiResolver wired AND an ABI resolvable for tx.To.
//     When ABI is absent we return false rather than guess — same
//     fail-closed stance as RD-889 for log decoding. The log-based
//     participant signal (Stage A) covers most missing-ABI cases.
//   - Walks composite arg types (slice / array / single struct embed)
//     down to single addresses. Catches multi-recipient batch calls
//     where one of the recipients is the viewer.
//   - Returns false on any parse error rather than panicking — calldata
//     can be malformed or use a different ABI than the registered one
//     (e.g. proxy patterns); we never want a decoder error to redact
//     incorrectly.
//
// Why a method on RedactionEngine rather than a free function: it needs
// access to r.abiResolver, which is configured per engine. The legacy
// free `isViewerInCalldata` stays free because it's a fixed heuristic.
func (r *RedactionEngine) isViewerInCalldataABI(ctx context.Context, tx Transaction, viewerAddrs map[string]bool) bool {
	if r.abiResolver == nil || len(viewerAddrs) == 0 {
		return false
	}
	if !tx.HasRecipient() {
		return false // CREATE — no callee, no ABI to resolve.
	}
	abiJSON := r.abiResolver.Resolve(ctx, strings.ToLower(*tx.To))
	if abiJSON == "" {
		return false
	}
	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return false
	}
	data := strings.TrimPrefix(strings.ToLower(tx.InputData), "0x")
	if len(data) < 8 {
		return false
	}
	raw, err := hex.DecodeString(data)
	if err != nil {
		return false
	}
	method, err := parsedABI.MethodById(raw[:4])
	if err != nil {
		return false // Selector unknown to ABI (proxy/upgrade mismatch) — fail-closed.
	}
	args, err := method.Inputs.Unpack(raw[4:])
	if err != nil {
		return false
	}
	for _, arg := range args {
		if anyAddressMatches(arg, viewerAddrs) {
			return true
		}
	}
	return false
}

// anyAddressMatches recursively walks an unpacked ABI value looking for
// any common.Address that matches an entry in viewerAddrs (keys are
// lowercase hex, with 0x prefix). Handles single addresses, []address,
// and arbitrary nesting of slices/arrays. Other concrete types (uint,
// bool, string, bytes) are ignored — only address-typed slots count.
//
// Struct fields are not walked because go-ethereum's ABI decoder
// surfaces struct args as map[string]any only for events with named
// non-indexed fields, not for function inputs. Function struct inputs
// come back as anonymous structs at the type level but the reflect
// path below covers them too.
func anyAddressMatches(v any, viewerAddrs map[string]bool) bool {
	switch x := v.(type) {
	case common.Address:
		return viewerAddrs[strings.ToLower(x.Hex())]
	case []common.Address:
		for _, a := range x {
			if viewerAddrs[strings.ToLower(a.Hex())] {
				return true
			}
		}
		return false
	case []any:
		for _, e := range x {
			if anyAddressMatches(e, viewerAddrs) {
				return true
			}
		}
		return false
	}
	// Fallback via reflect: covers fixed arrays ([N]common.Address) and
	// struct-typed inputs. We walk every exported field / element and
	// recurse.
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Array, reflect.Slice:
		for i := 0; i < rv.Len(); i++ {
			if anyAddressMatches(rv.Index(i).Interface(), viewerAddrs) {
				return true
			}
		}
	case reflect.Struct:
		for i := 0; i < rv.NumField(); i++ {
			if !rv.Field(i).CanInterface() {
				continue
			}
			if anyAddressMatches(rv.Field(i).Interface(), viewerAddrs) {
				return true
			}
		}
	}
	return false
}

// RedactOpts provides optional overrides for transaction redaction.
type RedactOpts struct {
	// VisibleTxHashes is the set of tx hashes whose rows are always kept for
	// the viewer: genuine visibleTo shares plus the RD-1009
	// transfer-participant union. Membership alone only keeps the row; the
	// addresses are revealed only for hashes also in ListedTxHashes (a
	// genuine share) — the union never reveals an identity (RD-1316).
	VisibleTxHashes map[string]bool

	// ListedTxHashes is the set of tx hashes whose visibleTo row genuinely
	// lists the viewer (tx_visible_to only — never the RD-1009
	// transfer-participant union that also feeds VisibleTxHashes). It is the
	// only input the redactors accept for "the sender listed this viewer on
	// this tx": the address reveal on tx, transfer and internal rows (RD-1316),
	// and the RD-874 visibleTo log unlock and ordinary param-rule fallback
	// (RD-1307). A nil map lists nothing (fail-closed).
	ListedTxHashes map[string]bool

	// ParentParticipants are the parent transaction's from/to addresses,
	// threaded into RedactInternalTransactions by the single-hash handler
	// (/transactions/:hash/internal). Used ONLY for the RD-1122 per-side
	// reveal: when one of the viewer's linked EOAs is a parent participant,
	// the parent's two parties (already shown at the tx/Overview level) are
	// revealed across nested trace frames so the originator's direct
	// counterparty isn't over-redacted. Empty for the block- and
	// address-scoped internal-tx handlers, which have no single parent tx.
	ParentParticipants []string

	// ViewerIsAdmin indicates the viewer has admin-level access (org admin
	// or admin claim). Admins see all contract activity including txs from
	// private users — G10 non-participant drop does not apply to admins.
	ViewerIsAdmin bool

	// OrgAdminViewUserTxs gates the elevated admin audit view. It is the
	// per-request mirror of config.OrgAdminViewUserTxs. When true AND the
	// viewer is an admin, user↔user rows that are otherwise dropped
	// (both sides non-identifiable, deploys from private EOAs, internal
	// txs between private EOAs) are kept and their value/amount is
	// preserved. Counterparty addresses still render as [PRIVATE] — this is
	// a volume/timing audit view, not real-address visibility. Default false
	// reproduces the strict privacy behaviour exactly.
	OrgAdminViewUserTxs bool

	// Stats, when non-nil, accumulates redaction outcomes the caller cares
	// about. It is mutated through the pointer so it survives RedactOpts
	// being passed by value. Used to drive per-request audit logging.
	Stats *RedactStats
}

// RedactStats accumulates side-channel counts from a redaction pass so the
// caller can react (e.g. emit an audit-log entry) without re-deriving them.
type RedactStats struct {
	// AdminUserTxsRevealed counts rows the elevated org-admin audit view
	// (OrgAdminViewUserTxs) exposed: rows strict privacy would have dropped,
	// and union-kept rows with both sides (or the deployer) private, whose
	// value only the audit view reveals (RD-1316).
	AdminUserTxsRevealed int
	// GrantFullReveals counts rows where a Full disclosure grant on one
	// party caused the counterparty's effective level to be promoted above
	// its base — i.e. a regulatory-subpoena reveal of an otherwise-private
	// counterparty address. Each increment is audit-logged by the handler
	// (see auditAdminUserTxView and auditGrantFullReveal) so the compliance
	// trail captures who saw which counterparty under which grant. Strict
	// privacy (no Full grants in this pass) keeps this at zero — the
	// counter is only meaningful for grant-driven reveals.
	GrantFullReveals int
}

// adminAuditView reports whether the elevated org-admin audit view applies
// for this redaction pass.
func (o RedactOpts) adminAuditView() bool {
	return o.ViewerIsAdmin && o.OrgAdminViewUserTxs
}

// recordAdminReveal bumps the reveal counter when stats tracking is enabled.
func (o RedactOpts) recordAdminReveal() {
	if o.Stats != nil {
		o.Stats.AdminUserTxsRevealed++
	}
}

// recordGrantFullReveal bumps the grant-driven counterparty reveal counter when
// stats tracking is enabled.
func (o RedactOpts) recordGrantFullReveal() {
	if o.Stats != nil {
		o.Stats.GrantFullReveals++
	}
}

// counterpartyLensLevel implements the per-grant-level counterparty rendering
// rule from /docs/security/privacy-requirements §"Disclosure Levels":
//
//   - Full grant     → counterparty rendered at Full (real address). If the
//     counterparty's base level was lower (Hidden / Redacted / Pseudonymous)
//     this is a regulatory-subpoena reveal — promoted == true so the caller
//     can bump GrantFullReveals for the audit log.
//   - Pseudonymous   → counterparty rendered at Pseudonymous (Address-XXXX).
//     Demotion when base was Full (PR #282), promotion-to-pseudonym when
//     base was Hidden/Redacted. Either way the auditor sees a consistent
//     `Address-XXXX` lens across the tx — never the real hex.
//     promoted == false because the address material itself is not revealed.
//   - Redacted       → counterparty rendered as [PRIVATE] regardless of its
//     base level. Proof-of-activity lens — the row stays visible to the
//     auditor (timing/value preserved by the redactor downstream) but no
//     party's real address is disclosed. promoted == false.
//
// Returns the new level and a bool indicating whether the change constitutes
// a Full-level counterparty reveal (the only class that requires per-row
// audit logging). The legacy own-grant-level behaviour (granted target
// renders at the grant level) is unaffected — that's handled by the
// VisibilityMap layer.
func counterpartyLensLevel(grantLevel, counterpartyLevel VisibilityLevel) (VisibilityLevel, bool) {
	switch grantLevel {
	case VisibilityFull:
		if counterpartyLevel != VisibilityFull {
			return VisibilityFull, true
		}
		return counterpartyLevel, false
	case VisibilityPseudonymous:
		if counterpartyLevel != VisibilityPseudonymous {
			return VisibilityPseudonymous, false
		}
		return counterpartyLevel, false
	case VisibilityRedacted:
		if counterpartyLevel != VisibilityRedacted {
			return VisibilityRedacted, false
		}
		return counterpartyLevel, false
	default:
		return counterpartyLevel, false
	}
}

// disclosureGrantLevel returns (level, true) when the address's visibility
// metadata indicates an active disclosure grant; (Hidden, false) otherwise.
// Used by the redactor to compute counterparty lens behaviour:
//   - Full grant     → promote counterparty to Full (regulatory subpoena reveal,
//     audit-logged by the handler)
//   - Pseudonymous   → demote counterparty to Pseudonymous (limited audit lens,
//     RD-original / PR #282 behaviour preserved)
//   - Redacted       → counterparty rendered as [PRIVATE], row survives
//     (proof-of-activity audit lens)
//
// The grant signal is `Reason == ReasonDisclosureGrant`; the level is the
// grant's resolved disclosure_level. Centralising the predicate keeps the
// three redactors (transactions / transfers / internal-txs) in lock-step on
// the matrix in /docs/security/privacy-requirements §"Disclosure Levels".
func disclosureGrantLevel(v AddressVisibility) (VisibilityLevel, bool) {
	if v.Reason != ReasonDisclosureGrant {
		return VisibilityHidden, false
	}
	return v.Level, true
}

// RedactTransactions applies privacy rules to a list of transactions.
// Optional RedactOpts can override drop behavior for visibleTo transactions.
func (r *RedactionEngine) RedactTransactions(ctx context.Context, txs []Transaction, viewerDID string, opts ...RedactOpts) ([]Transaction, error) {
	if len(txs) == 0 {
		return txs, nil
	}

	var ropts RedactOpts
	if len(opts) > 0 {
		ropts = opts[0]
	}
	visibleHashes := ropts.VisibleTxHashes
	viewerIsAdmin := ropts.ViewerIsAdmin
	adminAuditView := ropts.adminAuditView()

	// 1. Extract unique addresses
	uniqueAddrs := extractUniqueAddresses(txs)

	// 2. Get batch visibility. GetBatchVisibilityDetailed is an exact superset
	// of GetBatchVisibility (same levels + reason metadata), so we issue ONE
	// query and project the level-only map out of it (RD-1123). The detailed
	// map drives the disclosure-grant lens / AddressMetadata below; the plain
	// map drives base level resolution — both from the same fetch.
	visibilityMapDetailed, err := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, uniqueAddrs)
	if err != nil {
		return nil, err
	}
	visibilityMap := visibilityMapFromDetailed(visibilityMapDetailed)

	// 2b. Get the viewer's linked addresses for participant visibility.
	// If the viewer is a participant (from or to) in a transaction, the counterparty
	// address should be visible in that specific transaction — the viewer already
	// knows who they sent to / received from via their own wallet.
	viewerAddrs := make(map[string]bool)
	if viewerDID != "" {
		linked, err := r.db.GetLinkedAddresses(ctx, viewerDID)
		if err != nil {
			return nil, err
		}
		for _, a := range linked {
			viewerAddrs[strings.ToLower(a)] = true
		}
	}

	// 2c. (RD-939 Stage A) Resolve log-based participant signals for this
	// batch in a single store call. A viewer is a log participant in a tx
	// when one of their linked addresses appears in an indexed address
	// topic of any ParticipantEventSlots event emitted by that tx — the
	// only signal that catches custom-selector mints to the viewer,
	// approvals, ERC-1155 transfers, WETH wrappers, etc. (See
	// LogParticipantStore docstring for the closed list and rationale.)
	//
	// Degrades gracefully: if the store isn't wired (legacy tests), if the
	// viewer has no linked addresses, or if the query errors out, we just
	// skip the log signal — tx.from/to and the legacy calldata heuristic
	// still apply.
	logParticipantTxs := make(map[string]bool)
	if r.logParticipantStore != nil && len(viewerAddrs) > 0 && len(txs) > 0 {
		addrSlice := make([]string, 0, len(viewerAddrs))
		for a := range viewerAddrs {
			addrSlice = append(addrSlice, a)
		}
		hashes := make([]string, 0, len(txs))
		for i := range txs {
			hashes = append(hashes, strings.ToLower(txs[i].Hash))
		}
		if found, err := r.logParticipantStore.FindLogParticipantTxs(ctx, addrSlice, hashes); err == nil {
			logParticipantTxs = found
		}
	}

	// 3. Apply redactions
	var redactedTxs []Transaction
	for _, tx := range txs {
		// Determine whether the viewer is a participant in this transaction.
		// Four orthogonal signals; any one is sufficient.
		//   1. tx-level from / to (the basic case).
		//   2. Legacy hardcoded ERC-20/721/1155 calldata recipient
		//      (isViewerInCalldata) — kept as cheap fast-path for
		//      contracts without a registered ABI.
		//   3. (RD-939 Stage B) ABI-decoded calldata: when the called
		//      contract has a resolvable ABI, decode and check every
		//      address-typed input arg. Catches custom selectors
		//      (the original RD-939 mint(address,…) reproducer).
		//   4. (RD-939 Stage A) Event-log topic appearance: viewer in
		//      any indexed address slot of an accepted event signature.
		//      Authoritative — the EVM emitted it.
		viewerIsFrom := tx.From != "" && viewerAddrs[strings.ToLower(tx.From)]
		viewerIsTo := tx.HasRecipient() && viewerAddrs[strings.ToLower(*tx.To)]
		viewerIsCalldataLegacy := isViewerInCalldata(tx.InputData, viewerAddrs)
		viewerIsCalldataABI := r.isViewerInCalldataABI(ctx, tx, viewerAddrs)
		viewerIsLogParticipant := logParticipantTxs[strings.ToLower(tx.Hash)]
		viewerIsParticipant := viewerIsFrom || viewerIsTo ||
			viewerIsCalldataLegacy || viewerIsCalldataABI || viewerIsLogParticipant

		// Resolve base visibility from the shared map.
		baseFromLevel := VisibilityFull
		if tx.From != "" {
			baseFromLevel = visibilityMap[strings.ToLower(tx.From)]
		}
		baseToLevel := VisibilityFull
		if tx.HasRecipient() {
			baseToLevel = visibilityMap[strings.ToLower(*tx.To)]
		}

		// visibleTo override: if this tx was shared with the viewer via the
		// visibleTo param, upgrade both addresses to full visibility — the
		// sender explicitly chose to share this transaction with the viewer.
		// RD-1316: only a genuine tx_visible_to listing (ListedTxHashes)
		// reveals. A hash that is in VisibleTxHashes without a listing came
		// from the RD-1009 transfer-participant union: it keeps the row
		// (txKeptByUnion) but every address renders at the viewer's own level.
		txVisibleToViewer := ropts.ListedTxHashes[strings.ToLower(tx.Hash)]
		txKeptByUnion := visibleHashes[strings.ToLower(tx.Hash)] && !txVisibleToViewer

		// Participant override: the counterparty address is revealed (so we don't
		// replace it with [PRIVATE]), but sensitive metadata like nonce is still
		// stripped based on the BASE visibility — the participant override only
		// makes the address visible, not the sender's activity metadata.
		fromLevel := baseFromLevel
		toLevel := baseToLevel
		if viewerIsParticipant || txVisibleToViewer {
			if fromLevel == VisibilityHidden || fromLevel == VisibilityRedacted {
				fromLevel = VisibilityFull
			}
			if toLevel == VisibilityHidden || toLevel == VisibilityRedacted {
				toLevel = VisibilityFull
			}
		}

		// Disclosure-grant lens: when this tx is visible to the viewer via a
		// disclosure grant on one party, the counterparty's effective render
		// is determined by the grant's level — never by the counterparty's
		// own (privacy-default Hidden) base visibility. The /docs/security/
		// privacy-requirements §"Disclosure Levels" matrix is the source of
		// truth; this block applies all three cells (full / pseudonymous /
		// redacted) symmetrically. Pre-fix only the pseudonymous demotion
		// existed (PR #282); full was missing — counterparty leaked as
		// [PRIVATE] — and redacted dropped the row via G10 / bothHidden.
		//
		// Participant-override wins: if the viewer is a direct participant
		// in the tx (their own linked address is from / to / log-participant /
		// in calldata), they already know the counterparty, so the grant's
		// lens is moot. visibleTo (explicit share via hash) wins for the
		// same reason.
		//
		// txVisibleViaGrant flag drives the row-survival bypass below
		// (G10 / bothHidden / deployHidden) — the spec keeps the row for
		// every grant level; only field-level rendering differs. Field
		// rendering remains via the standard applyRedaction path on the
		// resolved fromLevel / toLevel, so Full → real address,
		// Pseudonymous → Address-XXXX, Redacted → [PRIVATE].
		txVisibleViaGrant := false
		if !viewerIsParticipant && !txVisibleToViewer {
			fromVis := visibilityMapDetailed[strings.ToLower(tx.From)]
			var toVis AddressVisibility
			if tx.HasRecipient() {
				toVis = visibilityMapDetailed[strings.ToLower(*tx.To)]
			}
			fromGrantLvl, fromIsGrant := disclosureGrantLevel(fromVis)
			toGrantLvl, toIsGrant := disclosureGrantLevel(toVis)
			txVisibleViaGrant = fromIsGrant || toIsGrant

			// Counterparty rendering — apply the grant's lens level to the
			// non-granted side. Full PROMOTES the counterparty (reveals the
			// real address — regulatory subpoena reveal, audit-logged below
			// via GrantFullReveals); Pseudonymous DEMOTES Full counterparties
			// (existing PR #282 behaviour, preserved); Redacted SETS the
			// counterparty to Redacted so it renders as [PRIVATE] while the
			// row stays visible (proof-of-activity audit lens).
			revealedCounterpartyByFullGrant := false
			if fromIsGrant && tx.HasRecipient() {
				if newLvl, promoted := counterpartyLensLevel(fromGrantLvl, toLevel); newLvl != toLevel {
					toLevel = newLvl
					if promoted {
						revealedCounterpartyByFullGrant = true
					}
				}
			}
			if toIsGrant {
				if newLvl, promoted := counterpartyLensLevel(toGrantLvl, fromLevel); newLvl != fromLevel {
					fromLevel = newLvl
					if promoted {
						revealedCounterpartyByFullGrant = true
					}
				}
			}
			if revealedCounterpartyByFullGrant {
				ropts.recordGrantFullReveal()
			}
		}

		// If BOTH participants are non-identifiable to the viewer (hidden or
		// redacted after participant override), the row is dropped under strict
		// privacy — showing "[PRIVATE] → [PRIVATE]" leaks transaction existence
		// and timing. The elevated org-admin audit view (gated by the
		// ORG_ADMIN_VIEW_USER_TXS deployment flag) keeps it instead: the admin
		// needs to audit user activity, and the row stays address-private (both
		// sides remain [PRIVATE]); only value/timing are revealed below. Each
		// such reveal is counted so the handler can audit-log the access.
		//
		// Grant override: when the tx is visible via a disclosure grant
		// (txVisibleViaGrant), the row is kept by the grant's authority
		// regardless of bothHidden. The redacted-grant cell of the matrix
		// is the canonical reproducer: counterparty is private to the
		// viewer (Hidden) and the granted party renders as [PRIVATE] under
		// the redacted lens — both sides non-identifiable, yet the row
		// must survive per the matrix ("proof of activity" audit lens).
		//
		// Union override (RD-1316): a row kept by the transfer-participant
		// union survives with both sides [PRIVATE]. Under the audit view its
		// value is revealed below, so that reveal is counted too.
		bothHidden := isNonIdentifiable(fromLevel) && isNonIdentifiable(toLevel)
		if bothHidden && !txVisibleViaGrant {
			if !adminAuditView && !txKeptByUnion {
				continue
			}
			if adminAuditView {
				ropts.recordAdminReveal()
			}
		}

		// Contract creation transactions: if the deployer is non-identifiable,
		// the row is dropped under strict privacy ("[PRIVATE] → Contract" leaks
		// deployment activity, timing, and the resulting contract address). The
		// elevated admin audit view keeps it (same gating + audit as above).
		// Skip the re-count when bothHidden already counted this row.
		//
		// Grant override mirrors the bothHidden block above: the granted
		// party may have deployed a contract and the viewer is entitled to
		// see it under the grant's lens — keep the row. A union-kept deploy
		// survives the same way as a union-kept bothHidden row above.
		deployHidden := tx.IsContractCreation() && isNonIdentifiable(fromLevel)
		if deployHidden && !bothHidden && !txVisibleViaGrant {
			if !adminAuditView && !txKeptByUnion {
				continue
			}
			if adminAuditView {
				ropts.recordAdminReveal()
			}
		}

		// G10 fix: Non-participant, non-visibleTo txs where one side is hidden
		// are dropped. This aligns explorer visibility with the RPC layer.
		// Exceptions:
		// - Admins see all contract activity (they need to audit the network)
		// - Both sides Full = both identifiable, no information leak
		// - txVisibleViaGrant: a disclosure grant on either party authorises
		//   the row regardless of the counterparty's own (Hidden/Redacted)
		//   level. Field-level rendering still applies via applyRedaction —
		//   the flag only affects row-survival.
		if !viewerIsParticipant && !txVisibleToViewer && !viewerIsAdmin && !txVisibleViaGrant && !txKeptByUnion {
			if isNonIdentifiable(fromLevel) || isNonIdentifiable(toLevel) {
				continue
			}
		}

		redactedTx := tx
		redactedTx.AddressMetadata = make(map[string]VisibilityReason)
		setMeta := func(addr string, baseLvl VisibilityLevel) {
			aLower := strings.ToLower(addr)
			if viewerIsParticipant && isNonIdentifiable(baseLvl) {
				redactedTx.AddressMetadata[aLower] = ReasonParticipantOverride
			} else if txVisibleToViewer && isNonIdentifiable(baseLvl) {
				redactedTx.AddressMetadata[aLower] = ReasonVisibleToGrant
			} else if meta, ok := visibilityMapDetailed[aLower]; ok {
				redactedTx.AddressMetadata[aLower] = meta.Reason
			}
		}

		// RD-1143: redact the deployed-contract address on a CREATE receipt. It
		// is a first-class address field and must follow the same field-level
		// redaction as from/to — keyed on the CONTRACT's own resolved visibility
		// (it is registered to the deployer's org via the deploy auto-grant, so it
		// resolves to Redacted/Hidden for outsiders and Full for the deployer /
		// org members). The participant/visibleTo override reveals it to the
		// deployer (who is the `from` participant of their own CREATE). The
		// elevated admin audit view deliberately does NOT reveal it: per
		// /docs/security/privacy-requirements the flag reveals existence + value
		// (row survival) but never counterparty/contract addresses. Fail-closed:
		// only the two identifiable levels reveal; Hidden/Redacted AND any
		// unknown level render [PRIVATE]. Runs before the branch split so it
		// applies on every surviving row regardless of from/to outcome.
		if tx.ContractAddress != nil && *tx.ContractAddress != "" {
			caBase := visibilityMap[strings.ToLower(*tx.ContractAddress)]
			caLevel := caBase
			if (viewerIsParticipant || txVisibleToViewer) && isNonIdentifiable(caLevel) {
				caLevel = VisibilityFull
			}
			if caLevel == VisibilityFull || caLevel == VisibilityPseudonymous {
				red := r.applyRedaction(*tx.ContractAddress, caLevel)
				redactedTx.ContractAddress = &red
				setMeta(*tx.ContractAddress, caBase)
			} else {
				p := "[PRIVATE]"
				redactedTx.ContractAddress = &p
			}
		}

		// If one side is non-identifiable (hidden or redacted) but the other is
		// identifiable, replace the non-identifiable side with [PRIVATE] and strip
		// financial data (value, input, error).
		if isNonIdentifiable(fromLevel) || isNonIdentifiable(toLevel) {
			if isNonIdentifiable(fromLevel) {
				redactedTx.From = "[PRIVATE]"
				// Zero out nonce: it reveals the transaction count of a private account,
				// and sequential nonces across [PRIVATE] transactions could link them to the same account.
				redactedTx.Nonce = nil
			} else {
				redactedTx.From = r.applyRedaction(tx.From, fromLevel)
				setMeta(tx.From, baseFromLevel)
			}
			if isNonIdentifiable(toLevel) {
				p := "[PRIVATE]"
				redactedTx.To = &p
			} else if tx.HasRecipient() {
				redacted := r.applyRedaction(*tx.To, toLevel)
				redactedTx.To = &redacted
				setMeta(*tx.To, baseToLevel)
			}
			// Under the elevated admin audit view, preserve value so the row is
			// informative and consistent with the Transfer event the admin can
			// already read (RD-751). InputData stays stripped (calldata embeds
			// addresses) and nonce stays nil (it links a private account's txs) —
			// the view reveals volume/timing, never identity.
			//
			// txVisibleViaGrant: per /docs/security/privacy-requirements
			// §"Disclosure Levels" line 141, redacted-grant rows MUST
			// preserve value (timing-only audit explicitly preserves it).
			// This is the proof-of-activity lens — the auditor sees that a
			// tx of amount X happened to/from the granted target with both
			// addresses [PRIVATE]. Same treatment for pseudonymous grants
			// where the lens dropped a counterparty below Full. InputData
			// stays stripped for both because calldata can embed addresses.
			if !adminAuditView && !txVisibleViaGrant {
				redactedTx.Value = JSONString("")
			}
			redactedTx.InputData = ""
			redactedTx.Error = nil
			redactedTx.RevertReason = nil
			redactedTxs = append(redactedTxs, redactedTx)
			continue
		}

		// Neither side is hidden or redacted — apply normal redaction
		if tx.From != "" {
			redactedTx.From = r.applyRedaction(tx.From, fromLevel)
			setMeta(tx.From, baseFromLevel)
		}
		if tx.HasRecipient() {
			redacted := r.applyRedaction(*tx.To, toLevel)
			redactedTx.To = &redacted
			setMeta(*tx.To, baseToLevel)
		}

		// Participant override: even when the counterparty address is revealed,
		// strip the sender's nonce if the sender is base-level private. The nonce
		// reveals their lifetime tx count — the receiver doesn't need that.
		if viewerIsParticipant && (baseFromLevel == VisibilityHidden || baseFromLevel == VisibilityRedacted) {
			redactedTx.Nonce = nil
		}

		redactedTxs = append(redactedTxs, redactedTx)
	}

	// Strip token transfer info from transactions where the viewer lacks event access
	// to the target contract. Token transfers are derived from Transfer event logs,
	// so they should only be visible when the viewer has event/log access.
	if !viewerIsAdmin {
		tokenContractAddrs := make(map[string]bool)
		for i := range redactedTxs {
			if redactedTxs[i].TokenTransferCount > 0 && redactedTxs[i].HasRecipient() {
				tokenContractAddrs[strings.ToLower(*redactedTxs[i].To)] = true
			}
		}
		if len(tokenContractAddrs) > 0 {
			addrs := make([]string, 0, len(tokenContractAddrs))
			for a := range tokenContractAddrs {
				addrs = append(addrs, a)
			}
			eventAccess, err := r.db.GetBatchEventAccess(ctx, viewerDID, addrs)
			if err != nil {
				return nil, err
			}
			for i := range redactedTxs {
				if redactedTxs[i].TokenTransferCount > 0 && redactedTxs[i].HasRecipient() {
					toAddr := strings.ToLower(*redactedTxs[i].To)
					if !eventAccess[toAddr] {
						redactedTxs[i].TokenTransferCount = 0
						redactedTxs[i].TxCategories = removeCategory(redactedTxs[i].TxCategories, "token_transfer")
						// If stripping "token_transfer" left no categories, restore
						// "contract_call" — the tx still called a contract.
						// Note: can't check InputData here because it may have been
						// stripped by the redaction loop above.
						if len(redactedTxs[i].TxCategories) == 0 && redactedTxs[i].HasRecipient() {
							redactedTxs[i].TxCategories = []string{"contract_call"}
						}
					}
				}
			}
		}
	}

	return redactedTxs, nil
}

func removeCategory(cats []string, remove string) []string {
	var result []string
	for _, c := range cats {
		if c != remove {
			result = append(result, c)
		}
	}
	return result
}

// RedactTransfers applies privacy rules to a list of token transfers.
// Like RedactTransactions, participants (viewer is sender or receiver) get a
// visibility override so they can see the transfer amount and counterparty.
func (r *RedactionEngine) RedactTransfers(ctx context.Context, transfers []TokenTransfer, viewerDID string, opts ...RedactOpts) ([]TokenTransfer, error) {
	if len(transfers) == 0 {
		return transfers, nil
	}

	addrMap := make(map[string]bool)
	for _, t := range transfers {
		if t.From != "" {
			addrMap[strings.ToLower(t.From)] = true
		}
		if t.To != "" {
			addrMap[strings.ToLower(t.To)] = true
		}
	}
	addrs := make([]string, 0, len(addrMap))
	for a := range addrMap {
		addrs = append(addrs, a)
	}

	// Single visibility fetch (RD-1123): the detailed map is a superset of the
	// plain one, so derive plain levels from it instead of querying twice.
	visMapDetailed, err := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, addrs)
	if err != nil {
		return nil, err
	}
	visMap := visibilityMapFromDetailed(visMapDetailed)

	// Get viewer's linked addresses for participant visibility override.
	viewerAddrs := make(map[string]bool)
	if viewerDID != "" {
		linked, err := r.db.GetLinkedAddresses(ctx, viewerDID)
		if err != nil {
			return nil, err
		}
		for _, a := range linked {
			viewerAddrs[strings.ToLower(a)] = true
		}
	}

	var ropts RedactOpts
	if len(opts) > 0 {
		ropts = opts[0]
	}
	viewerIsAdminT := ropts.ViewerIsAdmin
	adminAuditView := ropts.adminAuditView()

	var result []TokenTransfer
	for _, t := range transfers {
		viewerIsFrom := t.From != "" && viewerAddrs[strings.ToLower(t.From)]
		viewerIsTo := t.To != "" && viewerAddrs[strings.ToLower(t.To)]
		viewerIsParticipant := viewerIsFrom || viewerIsTo
		// RD-1316: only a genuine tx_visible_to listing reveals. The RD-1009
		// transfer-participant union (VisibleTxHashes) plays no part here: the
		// transfer that drove the union survives on its own (participant
		// override, grant lens, or the admin G10 exemption), and keying the
		// union on the parent hash would keep every sibling transfer of that
		// tx, including third-party rows that strict privacy drops.
		txVisibleToViewer := ropts.ListedTxHashes[strings.ToLower(t.TxHash)]

		baseFromLevel := visMap[strings.ToLower(t.From)]
		baseToLevel := visMap[strings.ToLower(t.To)]
		// The EVM zero address is a protocol constant used for ERC-20 mints and
		// burns, never an identity that privacy policy can protect. Treat it as
		// public so a visible counterparty does not lose the derived transfer
		// row (or see a misleading [PRIVATE] sender/recipient).
		if isZeroEVMAddress(t.From) {
			baseFromLevel = VisibilityFull
		}
		if isZeroEVMAddress(t.To) {
			baseToLevel = VisibilityFull
		}
		fromLevel := baseFromLevel
		toLevel := baseToLevel

		// Participant or visibleTo override
		if viewerIsParticipant || txVisibleToViewer {
			if isNonIdentifiable(fromLevel) {
				fromLevel = VisibilityFull
			}
			if isNonIdentifiable(toLevel) {
				toLevel = VisibilityFull
			}
		}

		// Disclosure-grant lens (same shape as RedactTransactions, see the
		// matching block there for the full rationale). Applies the matrix
		// in /docs/security/privacy-requirements §"Disclosure Levels"
		// uniformly: Full promotes the counterparty (regulatory reveal,
		// audit-logged), Pseudonymous demotes a Full counterparty (PR #282
		// behaviour preserved), Redacted sets the counterparty to Redacted
		// so the row stays with [PRIVATE] addresses (proof-of-activity).
		// Participant / visibleTo overrides win.
		txVisibleViaGrant := false
		if !viewerIsParticipant && !txVisibleToViewer {
			fromVis := visMapDetailed[strings.ToLower(t.From)]
			toVis := visMapDetailed[strings.ToLower(t.To)]
			fromGrantLvl, fromIsGrant := disclosureGrantLevel(fromVis)
			toGrantLvl, toIsGrant := disclosureGrantLevel(toVis)
			txVisibleViaGrant = fromIsGrant || toIsGrant

			revealedCounterpartyByFullGrant := false
			if fromIsGrant {
				if newLvl, promoted := counterpartyLensLevel(fromGrantLvl, toLevel); newLvl != toLevel {
					toLevel = newLvl
					if promoted {
						revealedCounterpartyByFullGrant = true
					}
				}
			}
			if toIsGrant {
				if newLvl, promoted := counterpartyLensLevel(toGrantLvl, fromLevel); newLvl != fromLevel {
					fromLevel = newLvl
					if promoted {
						revealedCounterpartyByFullGrant = true
					}
				}
			}
			if revealedCounterpartyByFullGrant {
				ropts.recordGrantFullReveal()
			}
		}

		// Drop if both sides are non-identifiable. Under strict privacy this
		// keeps the surrounding transferCount aggregate out of sync with the
		// rows, but that is the conservative default. The elevated org-admin
		// audit view (ORG_ADMIN_VIEW_USER_TXS) keeps the row instead — addresses
		// stay [PRIVATE], only the amount/timing are revealed (below) — and the
		// reveal is counted for audit logging.
		//
		// Grant override: a disclosure grant on either party authorises the
		// row even when bothHidden — covers the redacted-grant cell of the
		// matrix where both sides render as [PRIVATE] but the row must
		// survive (proof-of-activity audit lens).
		if isNonIdentifiable(fromLevel) && isNonIdentifiable(toLevel) && !txVisibleViaGrant {
			if !adminAuditView {
				continue
			}
			ropts.recordAdminReveal()
		}

		// G10: non-participant, non-visibleTo, non-admin, one side hidden → drop.
		// Grant override: a disclosure grant on either party bypasses G10 —
		// see RedactTransactions for the symmetry rationale.
		if !viewerIsParticipant && !txVisibleToViewer && !viewerIsAdminT && !txVisibleViaGrant {
			if isNonIdentifiable(fromLevel) || isNonIdentifiable(toLevel) {
				continue
			}
		}

		redacted := t
		redacted.AddressMetadata = make(map[string]VisibilityReason)
		setMeta := func(addr string, baseLvl VisibilityLevel) {
			aLower := strings.ToLower(addr)
			if viewerIsParticipant && isNonIdentifiable(baseLvl) {
				redacted.AddressMetadata[aLower] = ReasonParticipantOverride
			} else if txVisibleToViewer && isNonIdentifiable(baseLvl) {
				redacted.AddressMetadata[aLower] = ReasonVisibleToGrant
			} else if meta, ok := visMapDetailed[aLower]; ok {
				redacted.AddressMetadata[aLower] = meta.Reason
			}
		}

		// If one side is non-identifiable, replace with [PRIVATE] and strip amount
		if isNonIdentifiable(fromLevel) || isNonIdentifiable(toLevel) {
			if isNonIdentifiable(fromLevel) {
				redacted.From = "[PRIVATE]"
			} else {
				redacted.From = r.applyRedaction(t.From, fromLevel)
				setMeta(t.From, baseFromLevel)
			}
			if isNonIdentifiable(toLevel) {
				redacted.To = "[PRIVATE]"
			} else {
				redacted.To = r.applyRedaction(t.To, toLevel)
				setMeta(t.To, baseToLevel)
			}
			// Elevated admin audit view preserves the transfer amount (consistent
			// with the Transfer log the admin can already read); addresses remain
			// [PRIVATE]. txVisibleViaGrant similarly preserves the amount per
			// the matrix line 141 (timing-only audit preserves value for
			// redacted grants; pseudonymous-lens transfers always preserve
			// amount because the auditor's expectation is to see the volume).
			if !adminAuditView && !txVisibleViaGrant {
				redacted.Value = JSONString("")
			}
			if isZeroEVMAddress(t.From) {
				redacted.From = t.From
			}
			if isZeroEVMAddress(t.To) {
				redacted.To = t.To
			}
			result = append(result, redacted)
			continue
		}

		// Neither side hidden or redacted — apply normal redaction
		redacted.From = r.applyRedaction(t.From, fromLevel)
		setMeta(t.From, baseFromLevel)
		redacted.To = r.applyRedaction(t.To, toLevel)
		setMeta(t.To, baseToLevel)

		result = append(result, redacted)
	}

	// Strip transfers where the viewer lacks event access to the token contract.
	if !viewerIsAdminT && len(result) > 0 {
		tokenAddrs := make(map[string]bool)
		for _, t := range result {
			if t.TokenAddress != "" {
				tokenAddrs[strings.ToLower(t.TokenAddress)] = true
			}
		}
		if len(tokenAddrs) > 0 {
			addrs := make([]string, 0, len(tokenAddrs))
			for a := range tokenAddrs {
				addrs = append(addrs, a)
			}
			eventAccess, err := r.db.GetBatchEventAccess(ctx, viewerDID, addrs)
			if err != nil {
				return nil, err
			}
			var filtered []TokenTransfer
			for _, t := range result {
				if eventAccess[strings.ToLower(t.TokenAddress)] {
					filtered = append(filtered, t)
				}
			}
			result = filtered
		}
	}

	return result, nil
}

// RedactInternalTransactions applies privacy rules to a list of internal transactions.
// Like RedactTransactions, participants get a visibility override.
func (r *RedactionEngine) RedactInternalTransactions(ctx context.Context, itxs []InternalTransaction, viewerDID string, opts ...RedactOpts) ([]InternalTransaction, error) {
	if len(itxs) == 0 {
		return itxs, nil
	}

	var ropts RedactOpts
	if len(opts) > 0 {
		ropts = opts[0]
	}
	visibleHashes := ropts.VisibleTxHashes
	adminAuditView := ropts.adminAuditView()

	addrMap := make(map[string]bool)
	for _, t := range itxs {
		if t.From != "" {
			addrMap[strings.ToLower(t.From)] = true
		}
		if t.To != nil && *t.To != "" {
			addrMap[strings.ToLower(*t.To)] = true
		}
	}
	addrs := make([]string, 0, len(addrMap))
	for a := range addrMap {
		addrs = append(addrs, a)
	}

	// Single visibility fetch (RD-1123): derive plain levels from the detailed
	// superset rather than querying GetBatchVisibility separately.
	visMapDetailed, err := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, addrs)
	if err != nil {
		return nil, err
	}
	visMap := visibilityMapFromDetailed(visMapDetailed)

	// Get viewer's linked addresses for participant visibility override.
	viewerAddrs := make(map[string]bool)
	if viewerDID != "" {
		linked, err := r.db.GetLinkedAddresses(ctx, viewerDID)
		if err != nil {
			return nil, err
		}
		for _, a := range linked {
			viewerAddrs[strings.ToLower(a)] = true
		}
	}

	// RD-1122: parent-tx participants, threaded from the single-hash handler.
	// The viewer is a "parent participant" iff one of their linked EOAs is the
	// parent tx's from or to — computed ONCE (mirrors RedactLogs' isParticipant).
	// This is intentionally restricted to linked-EOA participation: disclosure-
	// grant / visibleTo viewers are handled by the existing per-frame lens paths
	// below, and must NOT trigger the parent-participant reveal (doing so would
	// surface the parent's real counterparty under a pseudonymous lens — the
	// RD-1079 leak class).
	parentParticipantSet := make(map[string]bool, len(ropts.ParentParticipants))
	for _, pa := range ropts.ParentParticipants {
		if pa != "" {
			parentParticipantSet[strings.ToLower(pa)] = true
		}
	}
	viewerIsParentParticipant := false
	for pa := range parentParticipantSet {
		if viewerAddrs[pa] {
			viewerIsParentParticipant = true
			break
		}
	}

	var result []InternalTransaction
	for _, t := range itxs {
		viewerIsFrom := t.From != "" && viewerAddrs[strings.ToLower(t.From)]
		viewerIsTo := t.To != nil && *t.To != "" && viewerAddrs[strings.ToLower(*t.To)]
		viewerIsParticipant := viewerIsFrom || viewerIsTo

		// RD-1122 per-side parent-participant flags: a frame side qualifies for
		// reveal ONLY when its own address is itself one of the parent's two
		// parties. NEVER blanket-reveal a frame — a frame's `to` is the
		// CALL/STATICCALL/DELEGATECALL target and is attacker-influenceable, so
		// revealing the non-parent side of a `parentParty -> foreignOrgContract`
		// frame would leak a foreign-org private address. Revealing exactly the
		// parent's parties discloses nothing new (they are already shown at the
		// tx/Overview level by the existing top-frame participant override).
		fromIsParentParty := viewerIsParentParticipant && t.From != "" && parentParticipantSet[strings.ToLower(t.From)]
		toIsParentParty := viewerIsParentParticipant && t.To != nil && *t.To != "" && parentParticipantSet[strings.ToLower(*t.To)]

		// visibleTo override: an internal tx inherits its parent's allowlist
		// membership. When the parent tx is in VisibleTxHashes (either because
		// the sender explicitly shared the hash, or because RD-1009's
		// transfer-participant union added it), the internal tx must survive
		// — otherwise /transactions/:hash/internal would drop a row whose
		// parent /transactions and /transfers feeds just rendered. Same
		// cross-surface row-survival bug class as RD-1009; same fix shape
		// (parent-tx allowlist threaded into the drop predicate).
		//
		// RD-1316: only the explicit share (ListedTxHashes) also reveals the
		// frame addresses. A union-only parent keeps its frames but renders
		// each side at the viewer's own level — a frame's target can be any
		// org's private contract (the RD-1122 / RD-1223 concern).
		txVisibleToViewer := ropts.ListedTxHashes[strings.ToLower(t.TxHash)]
		txKeptByUnion := visibleHashes[strings.ToLower(t.TxHash)] && !txVisibleToViewer

		baseFromLevel := visMap[strings.ToLower(t.From)]
		baseToLevel := VisibilityFull
		if t.To != nil && *t.To != "" {
			baseToLevel = visMap[strings.ToLower(*t.To)]
		}
		fromLevel := baseFromLevel
		toLevel := baseToLevel

		// Participant or visibleTo override: reveal counterparty. A genuine
		// share mirrors RedactTransactions/RedactTransfers — the sender chose
		// to show this tx to the viewer, so its frames are revealed too.
		if viewerIsParticipant || txVisibleToViewer {
			if isNonIdentifiable(fromLevel) {
				fromLevel = VisibilityFull
			}
			if isNonIdentifiable(toLevel) {
				toLevel = VisibilityFull
			}
		}

		// RD-1122 per-side parent-participant reveal. Reveal ONLY the side whose
		// address is itself a parent party (see fromIsParentParty/toIsParentParty
		// above). Strictly narrower than the both-sides override above: it never
		// promotes the non-parent side of a frame, so a deep
		// `parentParty -> foreignOrgContract` frame keeps the foreign contract at
		// its standing (Redacted/Hidden) level — no cross-org leak.
		if fromIsParentParty && isNonIdentifiable(fromLevel) {
			fromLevel = VisibilityFull
		}
		if toIsParentParty && isNonIdentifiable(toLevel) {
			toLevel = VisibilityFull
		}

		// Disclosure-grant lens (same shape as RedactTransactions, see the
		// matching block there for the full matrix-spec rationale).
		// Participant and visibleTo overrides win.
		txVisibleViaGrant := false
		if !viewerIsParticipant && !txVisibleToViewer {
			fromVis := visMapDetailed[strings.ToLower(t.From)]
			var toVis AddressVisibility
			if t.To != nil && *t.To != "" {
				toVis = visMapDetailed[strings.ToLower(*t.To)]
			}
			fromGrantLvl, fromIsGrant := disclosureGrantLevel(fromVis)
			toGrantLvl, toIsGrant := disclosureGrantLevel(toVis)
			txVisibleViaGrant = fromIsGrant || toIsGrant

			hasTo := t.To != nil && *t.To != ""
			revealedCounterpartyByFullGrant := false
			if fromIsGrant && hasTo {
				if newLvl, promoted := counterpartyLensLevel(fromGrantLvl, toLevel); newLvl != toLevel {
					toLevel = newLvl
					if promoted {
						revealedCounterpartyByFullGrant = true
					}
				}
			}
			if toIsGrant {
				if newLvl, promoted := counterpartyLensLevel(toGrantLvl, fromLevel); newLvl != fromLevel {
					fromLevel = newLvl
					if promoted {
						revealedCounterpartyByFullGrant = true
					}
				}
			}
			if revealedCounterpartyByFullGrant {
				ropts.recordGrantFullReveal()
			}
		}

		// Drop if both sides are non-identifiable. The elevated org-admin audit
		// view (ORG_ADMIN_VIEW_USER_TXS) keeps the row — addresses stay
		// [PRIVATE], value/timing revealed below — and counts the reveal. This
		// mirrors RedactTransactions/RedactTransfers so internal-tx lists do not
		// contradict the surrounding count for the admin under the flag.
		//
		// txVisibleToViewer above already upgraded fromLevel/toLevel to Full
		// when the parent tx is genuinely shared, so the bothHidden branch
		// cannot fire for those. A union-only parent (txKeptByUnion) is not
		// promoted, so it is exempted here explicitly — the frame survives
		// with both sides [PRIVATE] (RD-1009 coherence, RD-1316).
		//
		// Grant override mirrors RedactTransactions: a disclosure grant on
		// either party keeps the row regardless of bothHidden — required
		// for the redacted-grant cell of the matrix.
		bothHidden := isNonIdentifiable(fromLevel) && isNonIdentifiable(toLevel)
		if bothHidden && !txVisibleViaGrant {
			if !adminAuditView && !txKeptByUnion {
				continue
			}
			if adminAuditView {
				ropts.recordAdminReveal()
			}
		}

		redacted := t
		redacted.AddressMetadata = make(map[string]VisibilityReason)
		setMeta := func(addr string, baseLvl VisibilityLevel) {
			aLower := strings.ToLower(addr)
			if viewerIsParticipant && isNonIdentifiable(baseLvl) {
				redacted.AddressMetadata[aLower] = ReasonParticipantOverride
			} else if viewerIsParentParticipant && parentParticipantSet[aLower] && isNonIdentifiable(baseLvl) {
				// RD-1122: revealed because it is a party of the parent tx the
				// viewer participated in (already shown at the tx/Overview level).
				redacted.AddressMetadata[aLower] = ReasonParticipantOverride
			} else if txVisibleToViewer && isNonIdentifiable(baseLvl) {
				redacted.AddressMetadata[aLower] = ReasonVisibleToGrant
			} else if meta, ok := visMapDetailed[aLower]; ok {
				redacted.AddressMetadata[aLower] = meta.Reason
			}
		}

		// If one side is non-identifiable, replace with [PRIVATE] and strip financial data
		if isNonIdentifiable(fromLevel) || isNonIdentifiable(toLevel) {
			if isNonIdentifiable(fromLevel) {
				redacted.From = "[PRIVATE]"
			} else {
				redacted.From = r.applyRedaction(t.From, fromLevel)
				setMeta(t.From, baseFromLevel)
			}
			if isNonIdentifiable(toLevel) {
				p := "[PRIVATE]"
				redacted.To = &p
			} else if t.To != nil && *t.To != "" {
				r2 := r.applyRedaction(*t.To, toLevel)
				redacted.To = &r2
				setMeta(*t.To, baseToLevel)
			}
			// Elevated admin audit view preserves value; Input/Output stay nil
			// (they can embed addresses / decoded private data).
			// txVisibleViaGrant preserves value per the matrix (line 141):
			// redacted/pseudonymous-grant rows keep volume/timing.
			if !adminAuditView && !txVisibleViaGrant {
				redacted.Value = JSONString("")
			}
			redacted.Input = nil
			redacted.Output = nil
			// Strip the trace error: a revert string can embed the hidden
			// counterparty's address or a private reason (e.g. "execution
			// reverted: caller 0xABCD... not authorized"). Top-level
			// RedactTransactions already nils Error on its one-side-hidden
			// branch; this closes the matching gap for internal txs.
			// (REDACTION_SPEC G4 / RD-1177 F2)
			redacted.Error = nil
			result = append(result, redacted)
			continue
		}

		// Neither side hidden or redacted — apply normal redaction
		redacted.From = r.applyRedaction(t.From, fromLevel)
		setMeta(t.From, baseFromLevel)
		if t.To != nil && *t.To != "" {
			r2 := r.applyRedaction(*t.To, toLevel)
			redacted.To = &r2
			setMeta(*t.To, baseToLevel)
		}

		result = append(result, redacted)
	}
	return result, nil
}

// extractTopicAddress checks if a 32-byte topic hex string encodes an address
// collectLogTopics flattens an explorer.Log's separate Topic0..Topic3
// pointers into the contiguous topics[0..N] slice that
// rbac.MatchesEventParamRules expects. Trailing nils stop the slice —
// once a Topic_i is nil, deeper Topic_(i+1)..Topic_3 are not appended,
// matching how the RPC layer's logEntry.Topics is shaped (only as
// long as the actual indexed-topic count for the event).
func collectLogTopics(l Log) []string {
	if l.Topic0 == nil {
		return nil
	}
	out := []string{*l.Topic0}
	if l.Topic1 == nil {
		return out
	}
	out = append(out, *l.Topic1)
	if l.Topic2 == nil {
		return out
	}
	out = append(out, *l.Topic2)
	if l.Topic3 == nil {
		return out
	}
	out = append(out, *l.Topic3)
	return out
}

// using the standard zero-padding convention (12 zero bytes = 24 zero hex chars prefix after "0x").
// Returns the lowercase "0x"-prefixed address and true if the pattern matches, otherwise "", false.
func extractTopicAddress(topic string) (string, bool) {
	t := strings.ToLower(topic)
	// Topics are 66 chars: "0x" + 64 hex. Address occupies the last 40 chars.
	if len(t) != 66 || !strings.HasPrefix(t, "0x") {
		return "", false
	}
	prefix := t[2:26] // 24 hex chars = 12 zero bytes of padding
	if strings.Trim(prefix, "0") != "" {
		return "", false
	}
	return "0x" + t[26:], true
}

// redactTopicAddress converts a visibility-redacted embedded address back into a
// zero-padded 32-byte topic value.
func redactTopicAddress(addr string, level VisibilityLevel) string {
	switch level {
	case VisibilityFull:
		a := strings.ToLower(strings.TrimPrefix(addr, "0x"))
		return "0x" + strings.Repeat("0", 24) + a
	case VisibilityPseudonymous:
		// GeneratePseudonym returns a human-readable string, not a hex address.
		// We cannot zero-pad it into a valid 32-byte hex topic, so zero the slot instead.
		return "0x" + strings.Repeat("0", 64)
	default: // VisibilityRedacted, VisibilityHidden
		return "0x" + strings.Repeat("0", 64)
	}
}

// RedactLogAddressFields zeroes every embedded address in a log's topics and
// ABI-decoded non-indexed data that is NOT VisibilityFull for the viewer, per
// visMap. It is the single field-level redaction primitive shared by the
// explorer redactor (RedactionEngine.RedactLogsWithOpts) and the RPC log filter
// (server.FilterLogsWithEventRules), so both layers hide EXACTLY the same
// embedded addresses for a given (viewer, log) — symmetry by construction
// (RD-1214, completing RD-887).
//
// It performs NO admission decision (that is rbac.DecideLogEmitter,
// resolved upstream) and NO metadata emission (explorer-only, and only for the
// addresses this primitive leaves visible). Both callers resolve visMap from the
// SAME source — db.GetBatchVisibilityDetailed — so the per-address verdict is
// identical on the two layers by construction.
//
// topics is topic0..topicN in slot order (nil entries preserved in place). data
// is the raw hex data field; contractABI + topic0 drive the non-indexed data
// scan (a no-op when either is absent — the caller's deny-when-no-ABI gate has
// already run, so an admitted log always has a resolvable ABI in production).
func RedactLogAddressFields(topics []*string, data string, contractABI json.RawMessage, topic0 *string, visMap VisibilityMap) ([]*string, string) {
	redTopics := make([]*string, len(topics))
	for i, t := range topics {
		redTopics[i] = redactTopicField(t, visMap)
	}
	redData := redactLogData(data, contractABI, topic0, visMap)
	return redTopics, redData
}

// ExtractLogAddresses returns every embedded address (indexed topics +
// ABI-decoded non-indexed data), lowercased and de-duplicated, in a log. It is
// the companion to RedactLogAddressFields: a caller collects these addresses,
// resolves their visibility (db.GetBatchVisibilityDetailed), builds a visMap,
// then calls RedactLogAddressFields. Sharing this extractor means the RPC log
// filter and the explorer redactor consider the SAME address set (RD-1214).
func ExtractLogAddresses(topics []*string, data string, contractABI json.RawMessage, topic0 *string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(a string) {
		if _, ok := seen[a]; ok {
			return
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	for _, t := range topics {
		if t == nil {
			continue
		}
		if a, ok := extractTopicAddress(*t); ok {
			add(a)
		}
	}
	if data != "" && topic0 != nil && len(contractABI) > 0 {
		for _, a := range extractDataAddresses(data, contractABI, topic0) {
			add(a)
		}
	}
	return out
}

// redactTopicField redacts a single topic field if it embeds a private address.
// If the topic does not embed a recognised address pattern it is returned unchanged.
func redactTopicField(topic *string, visMap VisibilityMap) *string {
	if topic == nil {
		return nil
	}
	addr, ok := extractTopicAddress(*topic)
	if !ok {
		return topic
	}
	level := visMap[addr]
	if level == VisibilityFull {
		return topic
	}
	redacted := redactTopicAddress(addr, level)
	return &redacted
}

// eventHasDynamicNonIndexedParam mirrors rbac.eventHasDynamicNonIndexedParam:
// reports whether the event matching topic0 in contractABI declares any
// non-indexed parameter of a dynamically-sized ABI type (`bytes`,
// `string`, dynamic arrays / fixed arrays of dynamic types, or tuples
// containing any dynamic field).
//
// Drives the M15 drop gate (security audit follow-up to RD-915). When
// true, the redactor drops the entire log for non-Full viewers (unless
// the contract is opted out via DynamicPayloadAllowedResolver, or the
// viewer has an admin / participant / visibleTo bypass — those resolve
// before this check).
//
// Conservatively returns false on ABI parse failure or unknown topic0
// — at that point the deny-when-no-ABI gate (RD-889) has already taken
// over.
func eventHasDynamicNonIndexedParam(contractABI json.RawMessage, topic0 string) bool {
	if len(contractABI) == 0 || topic0 == "" {
		return false
	}
	parsed, err := abi.JSON(strings.NewReader(string(contractABI)))
	if err != nil {
		return false
	}
	topic0Lower := strings.ToLower(topic0)
	var matched *abi.Event
	for _, ev := range parsed.Events {
		sig := "0x" + hex.EncodeToString(crypto.Keccak256([]byte(ev.Sig)))
		if strings.ToLower(sig) == topic0Lower {
			ev := ev
			matched = &ev
			break
		}
	}
	if matched == nil {
		return false
	}
	for _, inp := range matched.Inputs {
		if inp.Indexed {
			continue
		}
		if isDynamicABIType(inp.Type) {
			return true
		}
	}
	return false
}

// isDynamicABIType mirrors rbac.isDynamicABIType — bytes / string /
// slice / array-of-dynamic / tuple-with-any-dynamic are dynamic; fixed
// types (bytesN, intN, uintN, bool, address, function, hash) are static.
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

// extractDataAddresses parses the ABI-encoded Data field of a log and returns the lowercase
// "0x"-prefixed addresses found in any non-indexed address-typed parameter slots.
// Returns nil if the ABI cannot be parsed, the event is not found, or no address params exist.
func extractDataAddresses(data string, contractABI json.RawMessage, topic0 *string) []string {
	if data == "" || len(contractABI) == 0 || topic0 == nil {
		return nil
	}
	parsedABI, err := abi.JSON(strings.NewReader(string(contractABI)))
	if err != nil {
		return nil
	}
	// Find the event matching topic0 (keccak256 of its signature).
	topic0Lower := strings.ToLower(*topic0)
	var matchedEvent *abi.Event
	for _, ev := range parsedABI.Events {
		sig := "0x" + hex.EncodeToString(crypto.Keccak256([]byte(ev.Sig)))
		if strings.ToLower(sig) == topic0Lower {
			ev := ev // capture
			matchedEvent = &ev
			break
		}
	}
	if matchedEvent == nil {
		return nil
	}
	// Collect non-indexed inputs in declaration order.
	var nonIndexed []abi.Argument
	for _, inp := range matchedEvent.Inputs {
		if !inp.Indexed {
			nonIndexed = append(nonIndexed, inp)
		}
	}
	if len(nonIndexed) == 0 {
		return nil
	}

	// Decode the hex data.
	dataHex := strings.TrimPrefix(data, "0x")
	dataBytes, err := hex.DecodeString(dataHex)
	if err != nil {
		return nil
	}
	// Each non-indexed param occupies a 32-byte slot (for value types).
	if len(dataBytes) < len(nonIndexed)*32 {
		return nil
	}

	var addrs []string
	for i, inp := range nonIndexed {
		if inp.Type.T != abi.AddressTy {
			continue
		}
		slot := dataBytes[i*32 : (i+1)*32]
		// Addresses are right-aligned in a 32-byte slot (12 zero bytes of padding on the left).
		prefix := slot[:12]
		allZero := true
		for _, b := range prefix {
			if b != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			continue
		}
		addr := common.BytesToAddress(slot[12:]).Hex()
		addrs = append(addrs, strings.ToLower(addr))
	}
	return addrs
}

// redactLogData scans the ABI-encoded Data field of a log for non-indexed address parameters
// and zeros any slot whose address is private (non-Full visibility).
// Returns the original data unchanged if no ABI is registered, the event is not found,
// no address fields exist, or the data cannot be decoded.
func redactLogData(data string, contractABI json.RawMessage, topic0 *string, visMap VisibilityMap) string {
	if data == "" || len(contractABI) == 0 || topic0 == nil {
		return data
	}
	parsedABI, err := abi.JSON(strings.NewReader(string(contractABI)))
	if err != nil {
		return data
	}
	topic0Lower := strings.ToLower(*topic0)
	var matchedEvent *abi.Event
	for _, ev := range parsedABI.Events {
		sig := "0x" + hex.EncodeToString(crypto.Keccak256([]byte(ev.Sig)))
		if strings.ToLower(sig) == topic0Lower {
			ev := ev
			matchedEvent = &ev
			break
		}
	}
	if matchedEvent == nil {
		return data
	}
	var nonIndexed []abi.Argument
	for _, inp := range matchedEvent.Inputs {
		if !inp.Indexed {
			nonIndexed = append(nonIndexed, inp)
		}
	}
	if len(nonIndexed) == 0 {
		return data
	}

	dataHex := strings.TrimPrefix(data, "0x")
	dataBytes, err := hex.DecodeString(dataHex)
	if err != nil {
		return data
	}
	if len(dataBytes) < len(nonIndexed)*32 {
		return data
	}

	modified := false
	for i, inp := range nonIndexed {
		// M15 / G23 (security audit follow-up to RD-915): pre-fix this
		// loop only scanned slots whose ABI type was AddressTy. A field
		// declared as bytes32 with an address right-aligned in the slot
		// — a common pattern for "addresses passed as bytes32 for
		// historical / cross-contract reasons" — leaked the address
		// verbatim. Now also scan FixedBytesTy slots of size 32 (bytes32):
		// the address pattern (first 12 bytes zero, last 20 = address)
		// is detectable with the same heuristic as AddressTy.
		//
		// Dynamic bytes/string are NOT scanned: the static slot at
		// position i contains the offset into the tail, not the value
		// itself; following the offset would require modelling the full
		// dynamic-encoding layout. Tracked as a follow-up to G23.
		//
		// uint256 / int256 are NOT scanned because legitimate small
		// numeric values (e.g. a uint256 = 123) have the first 12 bytes
		// zero and would false-positive as a hidden address (0x..0007b),
		// silently zeroing event values. Contract authors who encode
		// addresses in uint256 must declare the field as `address`
		// instead — that's an ABI-level signal we honour today.
		eligible := inp.Type.T == abi.AddressTy ||
			(inp.Type.T == abi.FixedBytesTy && inp.Type.Size == 32)
		if !eligible {
			continue
		}
		slot := dataBytes[i*32 : (i+1)*32]
		prefix := slot[:12]
		allZero := true
		for _, b := range prefix {
			if b != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			continue
		}
		addr := strings.ToLower(common.BytesToAddress(slot[12:]).Hex())
		level := visMap[addr]
		if level == VisibilityFull {
			continue
		}
		// Zero out the entire 32-byte slot.
		for j := i * 32; j < (i+1)*32; j++ {
			dataBytes[j] = 0
		}
		modified = true
	}
	if !modified {
		return data
	}
	prefix := ""
	if strings.HasPrefix(data, "0x") || strings.HasPrefix(data, "0X") {
		prefix = "0x"
	}
	return prefix + hex.EncodeToString(dataBytes)
}

// RedactLogs applies privacy rules to event logs.
// The log Address field is the contract that emitted the event.
// Hidden contracts are dropped; pseudonymous/redacted contracts have their address masked
// and topic/data stripped to prevent correlation.
// For logs from visible contracts, each topic is additionally scanned for embedded EOA/contract
// addresses (zero-padded 32-byte form). Any embedded address that is private is zeroed out.
// When the emitting contract has a registered ABI, the non-indexed Data field is also scanned
// for address-typed parameters and any private addresses are zeroed.
// RedactLogs applies privacy rules to transaction logs. If participantAddrs
// contains the viewer's addresses (e.g. from the parent tx's from/to), logs
// from Redacted contracts are kept (with topics/data intact) instead of being
// stripped — the viewer is a direct participant and already knows the contract.
func (r *RedactionEngine) RedactLogs(ctx context.Context, logs []Log, viewerDID string, participantAddrs ...string) ([]Log, error) {
	return r.RedactLogsWithOpts(ctx, logs, viewerDID, nil, participantAddrs...)
}

// RedactLogsWithOpts is RedactLogs with visibleTo support.
func (r *RedactionEngine) RedactLogsWithOpts(ctx context.Context, logs []Log, viewerDID string, opts *RedactOpts, participantAddrs ...string) ([]Log, error) {
	var visibleTxHashes, listedTxHashes map[string]bool
	if opts != nil {
		visibleTxHashes = opts.VisibleTxHashes
		listedTxHashes = opts.ListedTxHashes
	}
	if len(logs) == 0 {
		return logs, nil
	}

	// Build set of viewer's own linked addresses. Propagate DB errors —
	// silently treating a lookup failure as "no linked addresses" was
	// the pre-fix behaviour and would quietly disable the participant
	// override and the "self" param-rule constraint, leaving the viewer
	// with strictly less access than the policy says they should have.
	// Better to fail the request than to over- or under-redact silently.
	viewerAddrs := make(map[string]bool)
	if viewerDID != "" {
		linked, err := r.db.GetLinkedAddresses(ctx, viewerDID)
		if err != nil {
			return nil, err
		}
		for _, a := range linked {
			viewerAddrs[strings.ToLower(a)] = true
		}
	}

	// Phase 1: collect emitting contract addresses and do an initial batch lookup.
	addrMap := make(map[string]bool)
	for _, l := range logs {
		if l.Address != "" {
			addrMap[strings.ToLower(l.Address)] = true
		}
	}
	addrs := make([]string, 0, len(addrMap))
	for a := range addrMap {
		addrs = append(addrs, a)
	}

	// Single visibility fetch (RD-1123): the detailed map carries both the
	// level (for visMap) and the reason (for masterMeta), so one query replaces
	// the previous GetBatchVisibility + GetBatchVisibilityDetailed pair.
	visMapDetailed, err := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, addrs)
	if err != nil {
		return nil, err
	}
	visMap := visibilityMapFromDetailed(visMapDetailed)
	masterMeta := make(map[string]VisibilityReason)
	for k, v := range visMapDetailed {
		masterMeta[k] = v.Reason
	}

	// Check if viewer is actually a participant in the parent tx.
	isParticipant := false
	for _, pa := range participantAddrs {
		if pa != "" && viewerAddrs[strings.ToLower(pa)] {
			isParticipant = true
			break
		}
	}

	// Phase 2: for logs that will be kept (full/pseudonymous or participant override),
	// scan topics for embedded addresses not yet in visMap.
	extraAddrMap := make(map[string]bool)
	for _, l := range logs {
		level := visMap[strings.ToLower(l.Address)]
		// Redacted/hidden contracts are scanned if viewer is a participant
		// or the tx is in the viewer's visibleTo set.
		logVisibleTo := visibleTxHashes[strings.ToLower(l.TxHash)]
		if (level == VisibilityHidden || level == VisibilityRedacted) && !isParticipant && !logVisibleTo {
			continue
		}
		for _, t := range []*string{l.Topic0, l.Topic1, l.Topic2, l.Topic3} {
			if t == nil {
				continue
			}
			addr, ok := extractTopicAddress(*t)
			if !ok {
				continue
			}
			if _, alreadyKnown := visMap[addr]; !alreadyKnown {
				extraAddrMap[addr] = true
			}
		}
	}

	if len(extraAddrMap) > 0 {
		extraAddrs := make([]string, 0, len(extraAddrMap))
		for a := range extraAddrMap {
			extraAddrs = append(extraAddrs, a)
		}
		// Single fetch (RD-1123): derive level + reason from the detailed map.
		extraVisMapDetailed, err := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, extraAddrs)
		if err != nil {
			return nil, err
		}
		for k, v := range extraVisMapDetailed {
			visMap[k] = v.Level
			masterMeta[k] = v.Reason
		}
	}

	// Phase 3: ABI-based data scanning for logs from visible/pseudonymous contracts.
	// Fetch ABIs for each unique emitter, extract address-typed non-indexed params from
	// the Data field, and resolve their visibility so they can be zeroed if private.
	//
	// ABI source (RD-889 / Stage 2): when SetABIResolver has been called, the
	// resolver is consulted — that path includes the built-in registry
	// fallback (ERC-20 / ERC-721 from metadata.token_type) so the explorer
	// agrees with the RPC layer's storeABIProvider on "is this contract's
	// ABI resolvable?". When the resolver is not wired, fall back to the
	// pre-RD-889 ContractStore lookup so legacy tests keep working.
	contractABIs := make(map[string]json.RawMessage) // address → ABI (nil if not found)
	if r.store != nil || r.abiResolver != nil {
		abiDataAddrMap := make(map[string]bool)
		for _, l := range logs {
			level := visMap[strings.ToLower(l.Address)]
			if level == VisibilityHidden || level == VisibilityRedacted || l.Data == "" || l.Topic0 == nil {
				continue
			}
			addrKey := strings.ToLower(l.Address)
			if _, cached := contractABIs[addrKey]; !cached {
				contractABIs[addrKey] = r.resolveContractABI(ctx, addrKey)
			}
			if len(contractABIs[addrKey]) == 0 {
				continue
			}
			for _, a := range extractDataAddresses(l.Data, contractABIs[addrKey], l.Topic0) {
				if _, alreadyKnown := visMap[a]; !alreadyKnown {
					abiDataAddrMap[a] = true
				}
			}
		}
		if len(abiDataAddrMap) > 0 {
			abiDataAddrs := make([]string, 0, len(abiDataAddrMap))
			for a := range abiDataAddrMap {
				abiDataAddrs = append(abiDataAddrs, a)
			}
			// Single fetch (RD-1123): derive level + reason from the detailed map.
			abiVisMapDetailed, err2 := r.db.GetBatchVisibilityDetailed(ctx, viewerDID, abiDataAddrs)
			if err2 != nil {
				return nil, err2
			}
			for k, v := range abiVisMapDetailed {
				visMap[k] = v.Level
				masterMeta[k] = v.Reason
			}
		}
	}

	// Phase 3b: resolve event rules for each unique emitting contract (if checker is set).
	eventRulesMap := make(map[string]EventRulesResolution) // address -> tri-state resolution
	eventRulesResolved := make(map[string]bool)            // true once we've called the checker for an address
	if r.eventRuleChecker != nil && viewerDID != "" {
		for addr := range addrMap {
			eventRulesMap[addr] = r.eventRuleChecker.GetEventRulesForContract(ctx, viewerDID, addr)
			eventRulesResolved[addr] = true
		}
	}

	// Phase 3c (RD-890): resolve admin-equivalent privileges per emitting
	// contract for the viewer. Mirrors rbac.FilterEventLogs's
	// isAdminByContract input — admins bypass the deny-when-no-ABI gate
	// below (admin already has full access in the contract's owning org;
	// withholding logs because the operator hasn't uploaded an ABI is
	// a UX-only restriction at that level, not a security one).
	//
	// Resolved once per call (one DB pass) rather than per-log to keep
	// the hot path cheap. When the resolver is not wired, this stays an
	// empty map and the bypass simply doesn't fire.
	adminContracts := map[string]bool{}
	if r.adminContractsResolver != nil && viewerDID != "" && len(addrMap) > 0 {
		uniqueAddrs := make([]string, 0, len(addrMap))
		for a := range addrMap {
			uniqueAddrs = append(uniqueAddrs, a)
		}
		adminContracts = r.adminContractsResolver.Resolve(ctx, viewerDID, uniqueAddrs)
	}

	// Phase 3d (RD-874): resolve the per-contract visibleTo unlock map.
	// True for contracts where (a) `allow_visibleto_unlock` is set in the
	// DB AND (b) the viewer is unlock-eligible there (rbac.UnlockableContracts
	// — the same helper the RPC's buildVisibleToUnlockableMap calls). Combined
	// with the per-tx ListedTxHashes check below, this drives the unlock
	// branch in Phase 4, so RPC and explorer agree on the (viewer, contract,
	// tx) triple.
	unlockableContracts := map[string]bool{}
	// The unlock only fires on a tx the viewer is listed on, so skip the
	// eligibility lookups entirely when this page has no listed tx.
	if r.visibleToUnlockResolver != nil && viewerDID != "" && len(addrMap) > 0 && len(listedTxHashes) > 0 {
		uniqueAddrs := make([]string, 0, len(addrMap))
		for a := range addrMap {
			uniqueAddrs = append(uniqueAddrs, a)
		}
		unlockableContracts = r.visibleToUnlockResolver.Resolve(ctx, viewerDID, uniqueAddrs)
	}

	// Phase 3e (M15): resolve the per-contract dynamic-payload opt-out
	// flag for emitting contracts. Drives the drop gate in Phase 4:
	// events whose ABI declares any dynamic non-indexed param are
	// dropped for non-Full viewers unless the contract is opted out
	// (close-by-default). One DB pass per call.
	allowDynamicPayload := map[string]bool{}
	if r.dynamicPayloadAllowedResolver != nil && len(addrMap) > 0 {
		uniqueAddrs := make([]string, 0, len(addrMap))
		for a := range addrMap {
			uniqueAddrs = append(uniqueAddrs, a)
		}
		allowDynamicPayload = r.dynamicPayloadAllowedResolver.Resolve(ctx, uniqueAddrs)
	}

	// Per-call memo of the ABI resolver (uncached DB lookup), so resolving the
	// ABI fact for every candidate log costs one lookup per emitter.
	abiByContract := make(map[string]string)
	resolveABIOnce := func(addr string) string {
		if r.abiResolver == nil {
			return ""
		}
		if v, ok := abiByContract[addr]; ok {
			return v
		}
		// Phase 3 already asked the same resolver (resolveContractABI prefers
		// it when wired), including for emitters that have no ABI.
		if raw, ok := contractABIs[addr]; ok {
			abiByContract[addr] = string(raw)
			return string(raw)
		}
		v := r.abiResolver.Resolve(ctx, addr)
		abiByContract[addr] = v
		return v
	}

	// Phase 4: apply redactions.
	var result []Log
	for _, l := range logs {
		contractAddrLower := strings.ToLower(l.Address)

		level := visMap[contractAddrLower]
		contractAddr := contractAddrLower

		// Hard floor: a Hidden emitter (unregistered address / EOA, or a
		// foreign-org contract) is dropped unconditionally — before any bypass,
		// including admin. This is defence-in-depth: even if a resolver bug
		// wrongly flags such an emitter as admin/unlockable, a truly
		// inaccessible contract's logs must never surface. (The engine's shared
		// policy handles the grant/rules/participant decision for in-scope
		// emitters below; this floor is the explorer's visibility-level
		// pre-filter, with no RPC equivalent needed — isAdminByContract there
		// can never be set for an unregistered contract.)
		if level == VisibilityHidden {
			continue
		}

		// Resolve the per-log facts and defer the admit/deny verdict to the
		// shared decision engine (rbac.DecideLogEmitter, RD-1214/RD-1300) — the
		// SAME function the RPC filter (rbac.FilterEventLogs) uses, so the two
		// layers reach identical verdicts and cannot drift. The engine owns the
		// gate order; this block only resolves the facts from the explorer's
		// data model, and the rendering below turns an admit into structured
		// output.
		facts := rbac.LogEmitterFacts{
			// RD-890 admin bypass (per-contract, org-scoped).
			IsAdmin: adminContracts[contractAddr],
			// RD-874 visibleTo unlock — the only standalone-grant path. Keyed on
			// the viewer's genuine listing for THIS tx (ListedTxHashes), never on
			// the RD-1009 transfer-participant union in VisibleTxHashes (RD-1307).
			Unlocked: unlockableContracts[contractAddr] && listedTxHashes[strings.ToLower(l.TxHash)],
			// Grant eligibility: a contract grant resolves the emitter to Full
			// for this viewer (GetBatchVisibilityDetailed). No grant → Redacted
			// (registered) or Hidden (unregistered/EOA). Load-bearing (RD-1208).
			HasGrant: level == VisibilityFull,
			// RD-1162 participant/sender (grant-bounded inside the engine).
			IsParticipant: isParticipant,
			// Ordinary visibleTo — additive param-rule fallback only. Like the
			// unlock, keyed on the genuine listing, never the RD-1009 union
			// (RD-1307) — matching the RPC's tx_visible_to check.
			InVisibleTo: listedTxHashes[strings.ToLower(l.TxHash)],
			HasTopic0:   l.Topic0 != nil,
		}

		// Fast drop for emitters with no possible admit path (no admin, no
		// unlock, no grant → Hidden or Redacted/ReasonNoAccess). The engine
		// returns false for all of these; short-circuiting here enforces the
		// grant boundary up front and avoids the (uncached) ABI-resolver DB
		// call for foreign-org logs — the pre-engine early Hidden drop
		// generalised to the full no-grant case (RD-1208/RD-1214).
		if !facts.IsAdmin && !facts.Unlocked && !facts.HasGrant {
			continue
		}

		// RD-889 deny-when-no-ABI + M15 dynamic-payload — the embedded-address
		// protections. Resolved for EVERY candidate log, admin and unlock
		// included, exactly as rbac.FilterEventLogs does: the engine admits
		// admin/unlock before reading these facts, but a policy profile that
		// switches the unlock off falls back to the ordinary verdict, which
		// must then see the real ABI/M15 facts rather than permissive defaults.
		// Without a resolvable ABI, non-indexed address params in `data` can't
		// be decoded/redacted.
		resolvedABI := resolveABIOnce(contractAddr)
		facts.ABIResolvable = r.abiResolver == nil || resolvedABI != ""
		if l.Topic0 != nil {
			var abiForCheck json.RawMessage
			if raw, ok := contractABIs[contractAddr]; ok && len(raw) > 0 {
				abiForCheck = raw
			} else if resolvedABI != "" {
				abiForCheck = json.RawMessage(resolvedABI)
			}
			if len(abiForCheck) > 0 && !allowDynamicPayload[contractAddr] &&
				eventHasDynamicNonIndexedParam(abiForCheck, *l.Topic0) {
				facts.DynamicPayloadDropped = true
			}
		}

		// event_rules resolution (RD-888). When no checker is wired (legacy
		// callers / tests) the gate is disabled — treat as wildcard; the grant
		// gate above still applies. visibleTo extends the param-rule fallback.
		if eventRulesResolved[contractAddr] {
			res := eventRulesMap[contractAddr]
			switch {
			case res.Wildcard:
				facts.Rules = rbac.LogEventRulesWildcard
			case len(res.Rules) == 0:
				facts.Rules = rbac.LogEventRulesDeny
			default:
				facts.Rules = rbac.LogEventRulesAllowlist
				if l.Topic0 != nil {
					topic0Lower := strings.ToLower(*l.Topic0)
					for _, rule := range res.Rules {
						if rule.Topic0 != topic0Lower {
							continue
						}
						facts.Topic0Allowlisted = true
						if len(rule.ParamRules) == 0 {
							facts.EventAllowed = true
							break
						}
						var abiJSON string
						if raw, ok := contractABIs[contractAddr]; ok {
							abiJSON = string(raw)
						}
						if rbac.MatchesEventParamRules(
							rbac.EventLogInputs{
								ContractAddress: contractAddr,
								Topics:          collectLogTopics(l),
								Data:            l.Data,
							},
							rule.ParamRules,
							viewerAddrs,
							abiJSON,
						) {
							facts.EventAllowed = true
							break
						}
					}
				}
			}
		} else {
			facts.Rules = rbac.LogEventRulesWildcard
		}

		decision := rbac.DecideLogEmitter(facts)
		if !decision.Admit {
			continue
		}

		// Payload policy from the shared decision (RD-1300) — the SAME value the
		// RPC renderer consumes. LogPayloadFull (the RD-874 visibleTo unlock:
		// the contract owner opted in via allow_visibleto_unlock and the sender
		// listed this viewer on this tx) is a full reveal with no field
		// redaction; everything else is masked below.
		if decision.Payload == rbac.LogPayloadFull {
			redacted := l
			redacted.AddressMetadata = make(map[string]VisibilityReason)
			result = append(result, redacted)
			continue
		}

		redacted := l
		redacted.AddressMetadata = make(map[string]VisibilityReason)

		setMeta := func(addr string, baseLvl VisibilityLevel) {
			// Emit a metadata reason ONLY for an address that remains
			// IDENTIFIABLE in the rendered log — i.e. VisibilityFull. That is
			// the sole level whose real address survives redaction: topics/data
			// carrying a Redacted, Hidden or Pseudonymous embedded address are
			// zeroed (redactTopicAddress / redactLogData). Writing a reason for
			// such an address keys AddressMetadata by the very address the
			// zeroing hid, handing it back to the viewer in the clear —
			// the RD-1214 metadata-key leak. A zeroed address gets no entry.
			//
			// Note: a participant's counterparty is not revealed here — logs
			// zero all non-Full embedded addresses regardless of participation,
			// so there is no identifiable address to annotate. Per-address
			// counterparty reveal (unified with the RPC field-redaction) is the
			// remaining RD-1214 work; until then the fail-closed posture holds.
			if baseLvl != VisibilityFull {
				return
			}
			aLower := strings.ToLower(addr)
			if reason, ok := masterMeta[aLower]; ok {
				redacted.AddressMetadata[aLower] = reason
			}
		}

		redacted.Address = r.applyRedaction(l.Address, level)
		setMeta(l.Address, visMap[strings.ToLower(l.Address)])

		if level == VisibilityRedacted {
			redacted.Topic0 = nil
			redacted.Topic1 = nil
			redacted.Topic2 = nil
			redacted.Topic3 = nil
			redacted.Data = ""
		} else {
			// Contract is visible — zero every embedded private address in the
			// topics and ABI-decoded data via the SHARED field-redaction
			// primitive (RD-1214). The RPC log filter calls the same
			// RedactLogAddressFields with a visMap resolved from the same
			// GetBatchVisibilityDetailed, so the two layers zero identical
			// addresses by construction.
			topicABI := contractABIs[strings.ToLower(l.Address)]
			redTopics, redData := RedactLogAddressFields(
				[]*string{l.Topic0, l.Topic1, l.Topic2, l.Topic3},
				l.Data, topicABI, l.Topic0, visMap,
			)
			redacted.Topic0, redacted.Topic1, redacted.Topic2, redacted.Topic3 =
				redTopics[0], redTopics[1], redTopics[2], redTopics[3]
			redacted.Data = redData

			// Annotate the embedded addresses that remain visible (setMeta emits
			// a reason only for VisibilityFull addresses — the ones the primitive
			// left intact — so a zeroed address is never keyed into metadata;
			// see the RD-1214 leak fix on setMeta above).
			for _, t := range []*string{l.Topic0, l.Topic1, l.Topic2, l.Topic3} {
				if t == nil {
					continue
				}
				if a, ok := extractTopicAddress(*t); ok {
					setMeta(a, visMap[a])
				}
			}
			if l.Data != "" && l.Topic0 != nil && len(topicABI) > 0 {
				for _, a := range extractDataAddresses(l.Data, topicABI, l.Topic0) {
					setMeta(a, visMap[a])
				}
			}
		}

		result = append(result, redacted)
	}
	return result, nil
}

// RedactAddress redacts a single address based on visibility for the viewer.
func (r *RedactionEngine) RedactAddress(ctx context.Context, address string, viewerDID string) (string, error) {
	visMap, err := r.db.GetBatchVisibility(ctx, viewerDID, []string{strings.ToLower(address)})
	if err != nil {
		return "[REDACTED]", err
	}
	level := visMap[strings.ToLower(address)]
	return r.applyRedaction(address, level), nil
}

// RedactTokenHolders applies privacy rules to token holder list.
// Holders with hidden addresses are dropped; others have their address masked.
func (r *RedactionEngine) RedactTokenHolders(ctx context.Context, holders []TokenHolder, viewerDID string) ([]TokenHolder, error) {
	if len(holders) == 0 {
		return holders, nil
	}

	addrMap := make(map[string]bool)
	for _, h := range holders {
		if h.Address != "" {
			addrMap[strings.ToLower(h.Address)] = true
		}
	}
	addrs := make([]string, 0, len(addrMap))
	for a := range addrMap {
		addrs = append(addrs, a)
	}

	visMap, err := r.db.GetBatchVisibility(ctx, viewerDID, addrs)
	if err != nil {
		return nil, err
	}

	var result []TokenHolder
	for _, h := range holders {
		level := visMap[strings.ToLower(h.Address)]
		if level == VisibilityHidden {
			continue
		}
		h.Address = r.applyRedaction(h.Address, level)
		if level == VisibilityRedacted {
			// Strip balance and percentage: they reveal financial position even when the address is masked.
			h.Balance = JSONString("")
			h.Percentage = 0
		}
		result = append(result, h)
	}
	return result, nil
}

// isNonIdentifiable returns true if the visibility level means the viewer
// cannot identify the address — it will render as "[PRIVATE]" either way.
func isNonIdentifiable(level VisibilityLevel) bool {
	return level == VisibilityHidden || level == VisibilityRedacted
}

// isZeroEVMAddress reports whether addr is the canonical EVM zero address.
// It is a protocol constant, never a private identity.
func isZeroEVMAddress(addr string) bool {
	normalized := strings.TrimPrefix(strings.ToLower(addr), "0x")
	return len(normalized) == 40 && strings.Trim(normalized, "0") == ""
}

// applyRedaction modifies an address string based on its visibility level
func (r *RedactionEngine) applyRedaction(address string, level VisibilityLevel) string {
	switch level {
	case VisibilityFull:
		return address
	case VisibilityPseudonymous:
		return GeneratePseudonym(address, r.pseudonymKey)
	case VisibilityRedacted:
		return "[PRIVATE]"
	case VisibilityHidden:
		return "[PRIVATE]"
	default:
		return "[PRIVATE]" // Fail safe
	}
}
