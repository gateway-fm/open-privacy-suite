package rbac

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
)

// ReadMethods classifies read-only RPC methods.
// These methods only read blockchain state and don't modify it.
// Note: No longer used for claim gating — retained for AllAllowedMethods() and reference.
var ReadMethods = map[string]bool{
	// Chain/Network info
	"eth_chainId":        true,
	"eth_blockNumber":    true,
	"net_version":        true,
	"net_listening":      true,
	"net_peerCount":      true,
	"web3_clientVersion": true,
	"web3_sha3":          true,
	"eth_syncing":        true,
	"eth_accounts":       true,

	// Account/Balance queries
	"eth_getBalance":          true,
	"eth_getCode":             true,
	"eth_getStorageAt":        true,
	"eth_getTransactionCount": true,

	// Block queries
	"eth_getBlockByHash":                   true,
	"eth_getBlockByNumber":                 true,
	"eth_getBlockTransactionCountByHash":   true,
	"eth_getBlockTransactionCountByNumber": true,

	// Transaction queries
	"eth_getTransactionByHash":                true,
	"eth_getTransactionReceipt":               true,
	"eth_getTransactionByBlockHashAndIndex":   true,
	"eth_getTransactionByBlockNumberAndIndex": true,

	// Contract calls (read-only)
	"eth_call":        true,
	"eth_estimateGas": true,

	// Gas price queries
	"eth_gasPrice":             true,
	"eth_maxPriorityFeePerGas": true,
	"eth_feeHistory":           true,

	// Logs
	"eth_getLogs": true,

	// Filter methods (used for event polling)
	"eth_newFilter":                   true,
	"eth_newBlockFilter":              true,
	"eth_newPendingTransactionFilter": true,
	"eth_getFilterChanges":            true,
	"eth_getFilterLogs":               true,
	"eth_uninstallFilter":             true,
}

// WriteMethods classifies state-modifying RPC methods.
// Note: No longer used for claim gating — retained for AllAllowedMethods() and reference.
var WriteMethods = map[string]bool{
	"eth_sendTransaction":    true,
	"eth_sendRawTransaction": true,
	"eth_sign":               true,
	"eth_signTransaction":    true,
	"personal_sign":          true,
	"eth_signTypedData":      true,
	"eth_signTypedData_v4":   true,
}

// TraceMethods are the runtime trace RPC methods. They are valid entries in a
// group's allowed_methods (and are included in the "*" all-methods expansion),
// but — as of RD-1121 — they are NOT coupled to any operational claim. Tracing
// is gated by the method allowlist like every other named method (runtime gate
// in jsonrpc_processor.processDebugTrace), and cross-org leakage is prevented by
// the TraceValidator content gate. The map name is kept generic to reflect that
// these are simply allowlist-eligible methods, not claim-bearing ones.
var TraceMethods = map[string]bool{
	"debug_traceTransaction": true,
	"debug_traceCall":        true,
}

// DeployMethods is the legacy name for the trace-method set, retained as an
// alias because external references use it. Tracing no longer requires the
// deploy claim — see TraceMethods and RD-1121.
var DeployMethods = TraceMethods

// canonicalMethodByLower maps the lowercased form of every built-in standard
// RPC method to its canonical camelCase spelling. Built once from the static
// Read/Write/Trace method sets. Operator-configured ExtraMethods (e.g. linea_*)
// are intentionally excluded — their canonical form is operator-defined and they
// pass through verbatim.
var canonicalMethodByLower = func() map[string]string {
	m := make(map[string]string, len(ReadMethods)+len(WriteMethods)+len(TraceMethods)+len(canonicalExtraMethods))
	for _, set := range []map[string]bool{ReadMethods, WriteMethods, TraceMethods} {
		for name := range set {
			m[strings.ToLower(name)] = name
		}
	}
	for _, name := range canonicalExtraMethods {
		m[strings.ToLower(name)] = name
	}
	return m
}()

// canonicalExtraMethods are built-in methods granted only by exact name.
// They use the same method-name normalization as the Read/Write/Trace sets.
// eth_getProof and eth_createAccessList have per-address access checks;
// eth_getBlockReceipts has a response filter (REDACTION_SPEC section 3.8).
var canonicalExtraMethods = []string{
	"eth_getProof",
	"eth_createAccessList",
	"eth_getBlockReceipts",
}

// CanonicalizeMethod normalizes built-in method names for internal dispatch
// and access checks (RD-1180). Operator method names retain their spelling.
func CanonicalizeMethod(method string) string {
	if canon, ok := canonicalMethodByLower[strings.ToLower(method)]; ok {
		return canon
	}
	return method
}

// GetClaimForMethod returns the claim required for a given RPC method.
//
// As of RD-1121, NO standard RPC method requires a claim at the allowlist level:
// read/write methods were always allowlist-gated, and debug_trace* is now gated
// by the allowlist too (it is not deploying). This returns "" for every method;
// operational claims (deploy/upgrade/admin) are still enforced for the
// operations that actually need them (contract deployment, proxy upgrade,
// admin) inside CheckAccess via ClassifyOperation, not here.
func GetClaimForMethod(method string) Claim {
	return ""
}

// IsReadMethod returns true for read-only RPC methods (gated by method allowlist, not claims).
func IsReadMethod(method string) bool {
	return ReadMethods[method]
}

// IsWriteMethod returns true for state-modifying RPC methods (gated by method allowlist, not claims).
func IsWriteMethod(method string) bool {
	return WriteMethods[method]
}

// ValidateMethodsMatchClaims checks that all provided methods have their
// required claims in the claims list.
//
// As of RD-1121 no standard RPC method (including debug_trace*) requires a claim
// to appear in a group's allowed_methods — method access is gated by the
// allowlist alone, and the deploy/upgrade/admin claims gate the privileged
// OPERATIONS (deployment, proxy upgrade, admin) at runtime, not the listing of a
// method. The function is retained (it still rejects any future claim-bearing
// method GetClaimForMethod might report) so callers and the config-time
// validation contract stay stable.
func ValidateMethodsMatchClaims(methods []string, claims []Claim) error {
	// Build a set of available claims
	hasClaim := make(map[Claim]bool)
	for _, c := range claims {
		hasClaim[c] = true
	}

	// Check each method — only deploy methods need a claim
	for _, method := range methods {
		requiredClaim := GetClaimForMethod(method)
		if requiredClaim != "" && !hasClaim[requiredClaim] {
			return &MethodClaimMismatchError{
				Method:        method,
				RequiredClaim: requiredClaim,
			}
		}
	}

	return nil
}

// MethodClaimMismatchError is returned when a method requires a claim
// that is not present in the claims list.
type MethodClaimMismatchError struct {
	Method        string
	RequiredClaim Claim
}

func (e *MethodClaimMismatchError) Error() string {
	return "method " + e.Method + " requires " + string(e.RequiredClaim) + " claim"
}

// GetAllReadMethods returns a slice of all read method names.
func GetAllReadMethods() []string {
	methods := make([]string, 0, len(ReadMethods))
	for method := range ReadMethods {
		methods = append(methods, method)
	}
	return methods
}

// GetAllWriteMethods returns a slice of all write method names.
func GetAllWriteMethods() []string {
	methods := make([]string, 0, len(WriteMethods))
	for method := range WriteMethods {
		methods = append(methods, method)
	}
	return methods
}

// GetAllDeployMethods returns a slice of all deploy method names.
func GetAllDeployMethods() []string {
	methods := make([]string, 0, len(DeployMethods))
	for method := range DeployMethods {
		methods = append(methods, method)
	}
	return methods
}

// ExtraMethods holds every operator-configured method name (e.g. linea_*),
// both aliased and passthrough entries. Populated at startup via
// RegisterExtraNamespaces.
var ExtraMethods = map[string]bool{}

// ExtraNamespaces holds the structured namespace→method names mapping from
// config. Used by the status API to expose available methods to the frontend.
var ExtraNamespaces map[string][]string

// MethodAliases maps chain-specific methods to their standard equivalents
// for access control purposes (e.g. "linea_estimateGas" → "eth_estimateGas").
// Methods with aliases inherit the same contract access checks, storage slot
// tiering, historical-state guard, deployment detection, and function selector
// extraction as their target. Targets are canonicalized at config load.
// An alias whose target is not a catalog method inherits nothing, so
// it is not forwardable (IsForwardableMethod).
var MethodAliases = map[string]string{}

// PassthroughMethods holds the operator-configured methods that are forwarded
// to the node by exact name WITHOUT any proxy model: no per-address gate, no
// response filter, no tracing. The operator takes responsibility for what they
// return (logged at startup). They are reachable only by a group that lists
// them explicitly — never through "*" and never anonymously.
var PassthroughMethods = map[string]bool{}

// methodRegistriesArmed flips to true once server startup finishes registering
// namespaces (ArmMethodRegistries). The registries above are read lock-free on
// the request hot path (ResolveMethodAlias, IsForwardableMethod,
// AllAllowedMethods), so mutating them after the server starts serving would
// be a data race. The flag turns that startup-only convention into an enforced
// invariant (RD-1262).
var methodRegistriesArmed atomic.Bool

// ArmMethodRegistries marks startup registration as complete: any subsequent
// RegisterExtraNamespaces call panics. Called by server initialization after
// the (optional) namespace registration; idempotent.
func ArmMethodRegistries() {
	methodRegistriesArmed.Store(true)
}

// SnapshotMethodRegistriesForTest deep-copies the four method registries and
// the armed flag, and returns a function that restores all of them. Test-only:
// production registers namespaces once at startup and never restores. Tests
// that mutate ExtraMethods/ExtraNamespaces/MethodAliases/PassthroughMethods
// should `defer SnapshotMethodRegistriesForTest()()` instead of hand-rolling
// the save/restore (the hand-rolled version restores map *pointers*, which
// does not undo in-place mutations of the original maps).
func SnapshotMethodRegistriesForTest() (restore func()) {
	extraMethods := maps.Clone(ExtraMethods)
	aliases := maps.Clone(MethodAliases)
	passthrough := maps.Clone(PassthroughMethods)
	var namespaces map[string][]string
	if ExtraNamespaces != nil {
		namespaces = make(map[string][]string, len(ExtraNamespaces))
		for ns, methods := range ExtraNamespaces {
			namespaces[ns] = slices.Clone(methods)
		}
	}
	armed := methodRegistriesArmed.Load()
	return func() {
		ExtraMethods = extraMethods
		MethodAliases = aliases
		PassthroughMethods = passthrough
		ExtraNamespaces = namespaces
		methodRegistriesArmed.Store(armed)
	}
}

// IsStandardMethod identifies reserved built-in RPC names independently of
// the supported method catalog. Config and registration use it to keep those
// names separate from operator-defined methods. The match is case-insensitive.
func IsStandardMethod(method string) bool {
	lower := strings.ToLower(strings.TrimSpace(method))
	if _, ok := canonicalMethodByLower[lower]; ok {
		return true
	}
	// Methods classified in ReadOpsMap / WriteOpsMap but not in the canonical
	// set (includes the response-filtered eth_getBlockReceipts).
	return ReadOpsMap[lower] || WriteOpsMap[lower]
}

// reservedExtraPrefixes are owned by the built-in catalog or the node's
// consensus API and cannot contain operator-defined extra methods.
var reservedExtraPrefixes = []string{"eth_", "net_", "web3_", "engine_"}

// specialDispatchMethods are the catalog methods whose protection is selected
// by the literal method name: a dedicated request path (raw-transaction
// decode + sender link + trace, send-side trace + travel rule + visibleTo +
// CREATE pre-registration, trace validation) or a rewrite of the forwarded
// body (full transaction objects for the block participant filter, a block
// fetch in place of a transaction count). An alias to one of them would be
// dispatched by its own name and skip that protection, so they cannot be
// alias targets.
var specialDispatchMethods = map[string]bool{
	"eth_sendTransaction":                  true,
	"eth_sendRawTransaction":               true,
	"debug_traceTransaction":               true,
	"debug_traceCall":                      true,
	"eth_getBlockByHash":                   true,
	"eth_getBlockByNumber":                 true,
	"eth_getBlockTransactionCountByHash":   true,
	"eth_getBlockTransactionCountByNumber": true,
}

// ValidateExtraMethod checks the name of one operator-configured method entry
// (aliased or passthrough). Names are exact (no wildcard characters), must not
// shadow a catalog method under any casing (a shadowing alias would re-route
// the catalog method's own gate, a shadowing passthrough would strip it), must
// not sit in a reserved namespace, and must not be globally blocked.
func ValidateExtraMethod(method string) error {
	if strings.TrimSpace(method) != method || method == "" {
		return fmt.Errorf("method %q: name must be non-empty with no surrounding whitespace", method)
	}
	if strings.Contains(method, "*") {
		return fmt.Errorf("method %q: wildcards are not supported; list each method by its exact name", method)
	}
	if IsStandardMethod(method) {
		return fmt.Errorf("method %q: shadows a built-in RPC method", method)
	}
	lower := strings.ToLower(method)
	for _, prefix := range reservedExtraPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return fmt.Errorf("method %q: the %s namespace is reserved; only built-in methods are served there", method, prefix)
		}
	}
	if IsMethodBlocked(method) {
		return fmt.Errorf("method %q: globally blocked", method)
	}
	return nil
}

// ValidateAliasTarget checks an alias target: it must be a catalog method in
// its canonical spelling (the alias inherits that method's gate and response
// filter; any other target leaves the alias with no protection) and must not
// be a special-dispatch method (see specialDispatchMethods).
func ValidateAliasTarget(method, target string) error {
	if !IsCatalogMethod(target) {
		return fmt.Errorf("method %q: alias %q is not a built-in RPC method (check the exact spelling)", method, target)
	}
	if specialDispatchMethods[target] {
		return fmt.Errorf("method %q: %q cannot be an alias target — its protection runs in a dedicated request path an alias would skip", method, target)
	}
	return nil
}

// RegisterExtraNamespaces registers operator-configured chain-specific methods:
// methodNames is the namespace→method display mapping (aliased and passthrough
// entries alike), aliases maps aliased methods to their catalog target, and
// passthrough lists the methods forwarded unfiltered by exact name. Every
// entry is validated (ValidateExtraMethod, ValidateAliasTarget); an invalid
// entry fails startup and registers nothing. Called once at startup from
// server initialization, strictly before ArmMethodRegistries; calling it
// afterwards panics.
func RegisterExtraNamespaces(methodNames map[string][]string, aliases map[string]string, passthrough []string) error {
	if methodRegistriesArmed.Load() {
		panic("rbac: RegisterExtraNamespaces called after startup — the method registries are read lock-free on the request hot path, so runtime registration is a data race; register all namespaces before ArmMethodRegistries (RD-1262)")
	}
	isPassthrough := make(map[string]bool, len(passthrough))
	for _, m := range passthrough {
		if _, aliased := aliases[m]; aliased {
			return fmt.Errorf("method %q: an entry is either aliased or passthrough, not both", m)
		}
		if err := ValidateExtraMethod(m); err != nil {
			return err
		}
		isPassthrough[m] = true
	}
	for method, target := range aliases {
		if err := ValidateExtraMethod(method); err != nil {
			return err
		}
		if err := ValidateAliasTarget(method, target); err != nil {
			return err
		}
	}
	for _, methods := range methodNames {
		for _, m := range methods {
			if _, aliased := aliases[m]; !aliased && !isPassthrough[m] {
				return fmt.Errorf("method %q: needs an alias to a built-in method or \"passthrough\": true", m)
			}
		}
	}

	ExtraNamespaces = methodNames
	for _, methods := range methodNames {
		for _, m := range methods {
			ExtraMethods[m] = true
		}
	}
	for method, alias := range aliases {
		MethodAliases[method] = alias
	}
	for m := range isPassthrough {
		ExtraMethods[m] = true
		PassthroughMethods[m] = true
	}
	return nil
}

// ResolveMethodAlias returns the standard method name that a chain-specific method
// should be treated as for access control. Returns the method itself if no alias
// is registered (which is the case for catalog and passthrough methods).
func ResolveMethodAlias(method string) string {
	if alias, ok := MethodAliases[method]; ok {
		return alias
	}
	return method
}

// IsCatalogMethod reports whether method is a built-in RPC method the proxy
// models — one with a defined access gate and response story — in its
// canonical spelling, and not globally blocked. The catalog is ReadMethods ∪
// WriteMethods ∪ TraceMethods ∪ canonicalExtraMethods. The match is exact:
// callers canonicalize first (CanonicalizeMethod).
func IsCatalogMethod(method string) bool {
	canon, ok := canonicalMethodByLower[strings.ToLower(method)]
	return ok && canon == method && !IsMethodBlocked(method)
}

// IsPassthroughMethod reports whether method is an operator-configured
// passthrough method (exact name).
func IsPassthroughMethod(method string) bool {
	return PassthroughMethods[method]
}

// IsForwardableMethod is the default-deny method gate: the proxy forwards a
// method to the node only if it is a catalog method, an operator alias whose
// target is a valid alias target (a catalog method outside the
// special-dispatch set — the alias then runs under the target's gate and
// response filter), or an operator passthrough method. Everything else has no
// gate, no response filter and no tracing, and is never forwarded.
func IsForwardableMethod(method string) bool {
	if IsCatalogMethod(method) || PassthroughMethods[method] {
		return true
	}
	if target, ok := MethodAliases[method]; ok {
		return ValidateAliasTarget(method, target) == nil
	}
	return false
}

// inBuiltinWildcardSet reports whether method is one of the built-in methods a
// "*" entry expands to: ReadMethods ∪ WriteMethods ∪ TraceMethods.
// canonicalExtraMethods are grantable by exact name only.
func inBuiltinWildcardSet(method string) bool {
	return ReadMethods[method] || WriteMethods[method] || TraceMethods[method]
}

// InWildcardExpansion reports whether a "*" entry in allowed_methods grants
// method: the built-in Read/Write/Trace methods and the operator aliases whose
// target is one of them, minus globally blocked methods. Passthrough methods
// are never granted through "*" — they must be listed by name. This is exactly
// the set AllAllowedMethods returns.
func InWildcardExpansion(method string) bool {
	if IsMethodBlocked(method) || PassthroughMethods[method] {
		return false
	}
	if inBuiltinWildcardSet(method) {
		return true
	}
	if ExtraMethods[method] {
		// An alias joins "*" only when it is forwardable and its target is
		// itself in "*": an alias to an exact-name-only catalog method
		// (eth_getProof) stays exact-name-only.
		target, ok := MethodAliases[method]
		return ok && IsForwardableMethod(method) && inBuiltinWildcardSet(target)
	}
	return false
}

// AllAllowedMethods returns the explicit method list a "*" entry expands to
// (see InWildcardExpansion), sorted. Used to expand "*" before an
// allowed_methods list is stored, so the database never holds "*".
func AllAllowedMethods() []string {
	seen := make(map[string]bool)
	var methods []string
	for _, set := range []map[string]bool{ReadMethods, WriteMethods, TraceMethods, ExtraMethods} {
		for method := range set {
			if !seen[method] && InWildcardExpansion(method) {
				seen[method] = true
				methods = append(methods, method)
			}
		}
	}
	sort.Strings(methods)
	return methods
}

// IsAssignableMethod reports whether method may be stored in a group's
// allowed_methods: exactly the forwardable methods. Names the proxy would
// never forward — unknown methods, aliases to invalid targets, globs — are
// rejected at write time rather than stored as dead or dangerous entries.
func IsAssignableMethod(method string) bool {
	return IsForwardableMethod(method)
}

// SupportedMethods returns every assignable method, sorted: the catalog plus
// the forwardable operator methods. The admin UI uses it to tell a stored
// entry it can keep from one the proxy no longer supports.
func SupportedMethods() []string {
	seen := make(map[string]bool)
	var methods []string
	add := func(m string) {
		if !seen[m] && IsAssignableMethod(m) {
			seen[m] = true
			methods = append(methods, m)
		}
	}
	for _, m := range canonicalMethodByLower {
		add(m)
	}
	for m := range ExtraMethods {
		add(m)
	}
	sort.Strings(methods)
	return methods
}

// ExpandWildcardMethods replaces a wildcard "*" entry in the given method list
// with the explicit set from AllAllowedMethods(), keeping the list's other
// entries (an exact-name-only or passthrough method listed next to "*" stays
// granted). Result is deduplicated and sorted. If no "*" is present, the
// input is returned unchanged.
func ExpandWildcardMethods(methods []string) []string {
	if !slices.Contains(methods, "*") {
		return methods
	}
	seen := make(map[string]bool)
	var out []string
	for _, m := range append(AllAllowedMethods(), methods...) {
		if m != "*" && !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}
