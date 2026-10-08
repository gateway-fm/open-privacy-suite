package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetClaimForMethod(t *testing.T) {
	tests := []struct {
		name   string
		method string
		want   Claim
	}{
		// Read methods no longer require a claim — gated by method allowlist
		{name: "eth_call has no claim", method: "eth_call", want: ""},
		{name: "eth_getBalance has no claim", method: "eth_getBalance", want: ""},
		{name: "eth_chainId has no claim", method: "eth_chainId", want: ""},
		{name: "eth_blockNumber has no claim", method: "eth_blockNumber", want: ""},
		{name: "eth_estimateGas has no claim", method: "eth_estimateGas", want: ""},
		{name: "eth_getLogs has no claim", method: "eth_getLogs", want: ""},
		{name: "eth_getTransactionReceipt has no claim", method: "eth_getTransactionReceipt", want: ""},
		{name: "eth_getCode has no claim", method: "eth_getCode", want: ""},
		{name: "net_version has no claim", method: "net_version", want: ""},
		{name: "web3_clientVersion has no claim", method: "web3_clientVersion", want: ""},
		{name: "eth_newFilter has no claim", method: "eth_newFilter", want: ""},
		{name: "eth_getFilterChanges has no claim", method: "eth_getFilterChanges", want: ""},

		// Write methods no longer require a claim — gated by method allowlist
		{name: "eth_sendTransaction has no claim", method: "eth_sendTransaction", want: ""},
		{name: "eth_sendRawTransaction has no claim", method: "eth_sendRawTransaction", want: ""},
		{name: "eth_sign has no claim", method: "eth_sign", want: ""},
		{name: "eth_signTransaction has no claim", method: "eth_signTransaction", want: ""},
		{name: "personal_sign has no claim", method: "personal_sign", want: ""},
		{name: "eth_signTypedData has no claim", method: "eth_signTypedData", want: ""},
		{name: "eth_signTypedData_v4 has no claim", method: "eth_signTypedData_v4", want: ""},

		// RD-1121: debug_trace* no longer requires a claim — it is gated by the
		// method allowlist like every other named method (tracing != deploying).
		{name: "debug_traceCall has no claim", method: "debug_traceCall", want: ""},
		{name: "debug_traceTransaction has no claim", method: "debug_traceTransaction", want: ""},

		// Unknown/uncategorized methods
		{name: "unknown method returns empty", method: "unknown_method", want: ""},
		{name: "admin method returns empty", method: "admin_peers", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetClaimForMethod(tt.method)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsReadMethod(t *testing.T) {
	assert.True(t, IsReadMethod("eth_call"))
	assert.True(t, IsReadMethod("eth_getBalance"))
	assert.True(t, IsReadMethod("eth_chainId"))
	assert.False(t, IsReadMethod("eth_sendTransaction"))
	assert.False(t, IsReadMethod("unknown_method"))
}

func TestIsWriteMethod(t *testing.T) {
	assert.True(t, IsWriteMethod("eth_sendTransaction"))
	assert.True(t, IsWriteMethod("eth_sendRawTransaction"))
	assert.True(t, IsWriteMethod("eth_sign"))
	assert.False(t, IsWriteMethod("eth_call"))
	assert.False(t, IsWriteMethod("unknown_method"))
}

func TestValidateMethodsMatchClaims(t *testing.T) {
	tests := []struct {
		name    string
		methods []string
		claims  []Claim
		wantErr bool
		errMsg  string
	}{
		{
			name:    "read methods need no claims",
			methods: []string{"eth_call", "eth_getBalance", "eth_chainId"},
			claims:  []Claim{},
			wantErr: false,
		},
		{
			name:    "write methods need no claims",
			methods: []string{"eth_sendTransaction", "eth_sendRawTransaction"},
			claims:  []Claim{},
			wantErr: false,
		},
		{
			name:    "mixed read+write methods need no claims",
			methods: []string{"eth_call", "eth_sendTransaction", "eth_getBalance"},
			claims:  []Claim{},
			wantErr: false,
		},
		{
			name:    "trace method with deploy claim is fine",
			methods: []string{"debug_traceTransaction"},
			claims:  []Claim{ClaimDeploy},
			wantErr: false,
		},
		{
			// RD-1121: trace is allowlist-gated, not claim-coupled. A group may
			// list debug_trace* in allowed_methods without holding any claim.
			name:    "trace method without any claim is allowed (RD-1121)",
			methods: []string{"debug_traceTransaction"},
			claims:  []Claim{},
			wantErr: false,
		},
		{
			name:    "trace method with admin claim is fine",
			methods: []string{"debug_traceCall"},
			claims:  ExpandClaims([]Claim{ClaimAdmin}),
			wantErr: false,
		},
		{
			name:    "empty methods list",
			methods: []string{},
			claims:  []Claim{},
			wantErr: false,
		},
		{
			name:    "unknown methods don't require claims",
			methods: []string{"some_unknown_method"},
			claims:  []Claim{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMethodsMatchClaims(tt.methods, tt.claims)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Equal(t, tt.errMsg, err.Error())
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMethodClaimMismatchError(t *testing.T) {
	err := &MethodClaimMismatchError{
		Method:        "debug_traceTransaction",
		RequiredClaim: ClaimDeploy,
	}
	assert.Equal(t, "method debug_traceTransaction requires deploy claim", err.Error())
}

func TestGetAllReadMethods(t *testing.T) {
	methods := GetAllReadMethods()
	assert.NotEmpty(t, methods)

	// Check that all returned methods are actually read methods
	for _, m := range methods {
		assert.True(t, IsReadMethod(m), "method %s should be a read method", m)
	}

	// Check that the count matches the map
	assert.Equal(t, len(ReadMethods), len(methods))
}

func TestGetAllWriteMethods(t *testing.T) {
	methods := GetAllWriteMethods()
	assert.NotEmpty(t, methods)

	// Check that all returned methods are actually write methods
	for _, m := range methods {
		assert.True(t, IsWriteMethod(m), "method %s should be a write method", m)
	}

	// Check that the count matches the map
	assert.Equal(t, len(WriteMethods), len(methods))
}

func TestGetAllDeployMethods(t *testing.T) {
	methods := GetAllDeployMethods()
	assert.NotEmpty(t, methods)

	for _, m := range methods {
		assert.True(t, DeployMethods[m], "method %s should be a deploy method", m)
	}

	assert.Equal(t, len(DeployMethods), len(methods))
}

func TestAllAllowedMethods(t *testing.T) {
	methods := AllAllowedMethods()
	assert.NotEmpty(t, methods)

	// Every returned method must NOT be globally blocked
	for _, m := range methods {
		assert.False(t, IsMethodBlocked(m), "method %s is globally blocked and should not be in AllAllowedMethods()", m)
	}

	// Every returned method must come from ReadMethods, WriteMethods, or DeployMethods
	for _, m := range methods {
		inRead := ReadMethods[m]
		inWrite := WriteMethods[m]
		inDeploy := DeployMethods[m]
		assert.True(t, inRead || inWrite || inDeploy,
			"method %s is not in ReadMethods, WriteMethods, or DeployMethods", m)
	}

	// The list should be sorted
	for i := 1; i < len(methods); i++ {
		assert.True(t, methods[i-1] < methods[i],
			"AllAllowedMethods() not sorted: %s >= %s", methods[i-1], methods[i])
	}

	// Verify no duplicates
	seen := make(map[string]bool, len(methods))
	for _, m := range methods {
		assert.False(t, seen[m], "duplicate method %s in AllAllowedMethods()", m)
		seen[m] = true
	}

	// Sanity: known allowed methods should be present
	assert.Contains(t, methods, "eth_call")
	assert.Contains(t, methods, "eth_getBalance")
	assert.Contains(t, methods, "eth_blockNumber")
	assert.Contains(t, methods, "eth_sendRawTransaction")
	assert.Contains(t, methods, "debug_traceTransaction")
	assert.Contains(t, methods, "debug_traceCall")

	// Sanity: globally blocked methods should NOT be present
	assert.NotContains(t, methods, "admin_peers")
	assert.NotContains(t, methods, "debug_dumpblock")
	assert.NotContains(t, methods, "miner_start")
	assert.NotContains(t, methods, "txpool_content")
}

func TestExpandWildcardMethods(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expanded bool // true if we expect expansion to AllAllowedMethods()
	}{
		{
			name:     "wildcard alone",
			input:    []string{"*"},
			expanded: true,
		},
		{
			name:     "wildcard with methods already in the expansion",
			input:    []string{"eth_call", "*", "eth_getBalance"},
			expanded: true,
		},
		{
			name:     "no wildcard",
			input:    []string{"eth_call", "eth_getBalance"},
			expanded: false,
		},
		{
			name:     "empty list",
			input:    []string{},
			expanded: false,
		},
		{
			name:     "nil list",
			input:    nil,
			expanded: false,
		},
	}

	allMethods := AllAllowedMethods()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExpandWildcardMethods(tt.input)
			if tt.expanded {
				assert.Equal(t, allMethods, result)
				// Verify none of the expanded methods are globally blocked
				for _, m := range result {
					assert.False(t, IsMethodBlocked(m), "expanded method %s is globally blocked", m)
				}
			} else {
				assert.Equal(t, tt.input, result)
			}
		})
	}
}

func TestRegisterExtraNamespaces(t *testing.T) {
	// Extra methods are package-level state — snapshot and restore.
	defer SnapshotMethodRegistriesForTest()()

	// Reset state
	ExtraMethods = map[string]bool{}
	ExtraNamespaces = nil
	MethodAliases = map[string]string{}
	PassthroughMethods = map[string]bool{}

	namespaces := map[string][]string{
		"Linea": {"linea_estimateGas", "linea_getProof"},
		"Trace": {"trace_block", "trace_transaction"},
	}
	aliases := map[string]string{
		"linea_estimateGas": "eth_estimateGas",
		"linea_getProof":    "eth_getProof",
	}

	require.NoError(t, RegisterExtraNamespaces(namespaces, aliases, []string{"trace_block", "trace_transaction"}))

	// Verify ExtraMethods populated
	assert.True(t, ExtraMethods["linea_estimateGas"])
	assert.True(t, ExtraMethods["linea_getProof"])
	assert.True(t, ExtraMethods["trace_block"])
	assert.True(t, ExtraMethods["trace_transaction"])
	assert.False(t, ExtraMethods["eth_call"]) // standard method not in ExtraMethods

	// Verify ExtraNamespaces stored
	assert.Equal(t, namespaces, ExtraNamespaces)

	// Verify aliases stored and resolved
	assert.Equal(t, "eth_estimateGas", ResolveMethodAlias("linea_estimateGas"))
	assert.Equal(t, "eth_getProof", ResolveMethodAlias("linea_getProof"))
	assert.Equal(t, "trace_block", ResolveMethodAlias("trace_block")) // passthrough = returns self
	assert.Equal(t, "eth_call", ResolveMethodAlias("eth_call"))       // standard method = returns self

	// Passthrough registry
	assert.True(t, IsPassthroughMethod("trace_block"))
	assert.False(t, IsPassthroughMethod("linea_estimateGas"))

	// "*" expansion: built-in methods plus aliases whose target is itself in
	// the expansion. Passthrough methods and aliases to exact-name-only
	// catalog methods (eth_getProof) are never granted through "*".
	all := AllAllowedMethods()
	assert.Contains(t, all, "linea_estimateGas", "alias to a '*' method joins the expansion")
	assert.Contains(t, all, "eth_call")
	assert.NotContains(t, all, "linea_getProof", "alias to an exact-name-only method stays exact-name-only")
	assert.NotContains(t, all, "trace_block", "passthrough methods are never granted through '*'")
	assert.NotContains(t, all, "trace_transaction")
	assert.Equal(t, all, ExpandWildcardMethods([]string{"*"}))
}

// An exact-name-only method listed next to "*" stays granted: the expansion
// is a union with the list's other entries, not a replacement.
func TestExpandWildcardMethods_KeepsEntriesOutsideTheExpansion(t *testing.T) {
	got := ExpandWildcardMethods([]string{"*", "eth_getProof", "eth_call"})
	assert.Contains(t, got, "eth_getProof")
	assert.NotContains(t, got, "*")
	assert.Equal(t, len(AllAllowedMethods())+1, len(got), "deduplicated")
	assert.IsIncreasing(t, got)
}

// TestRegisterExtraNamespaces_RejectsInvalidEntries pins the operator-config
// rules: exact names only, no shadowing of built-in methods, no passthrough in
// the reserved standard namespaces or for globally blocked names, and every
// entry is either aliased or passthrough. A rejected config registers nothing.
func TestRegisterExtraNamespaces_RejectsInvalidEntries(t *testing.T) {
	tests := []struct {
		name        string
		namespaces  map[string][]string
		aliases     map[string]string
		passthrough []string
	}{
		{"glob passthrough", map[string][]string{"L": {"linea_*"}}, nil, []string{"linea_*"}},
		{"glob alias", map[string][]string{"L": {"linea_*"}}, map[string]string{"linea_*": "eth_call"}, nil},
		{"passthrough shadows catalog", map[string][]string{"X": {"eth_getLogs"}}, nil, []string{"eth_getLogs"}},
		{"passthrough shadows catalog in another case", map[string][]string{"X": {"ETH_GETLOGS"}}, nil, []string{"ETH_GETLOGS"}},
		{"alias shadows catalog", map[string][]string{"X": {"eth_getLogs"}}, map[string]string{"eth_getLogs": "eth_blockNumber"}, nil},
		{"alias shadows catalog in another case", map[string][]string{"X": {"Eth_Call"}}, map[string]string{"Eth_Call": "eth_blockNumber"}, nil},
		{"passthrough in eth_ namespace", map[string][]string{"X": {"eth_getRawTransactionByHash"}}, nil, []string{"eth_getRawTransactionByHash"}},
		{"passthrough send-sync", map[string][]string{"X": {"eth_sendRawTransactionSync"}}, nil, []string{"eth_sendRawTransactionSync"}},
		{"passthrough in net_ namespace", map[string][]string{"X": {"net_foo"}}, nil, []string{"net_foo"}},
		{"passthrough in web3_ namespace", map[string][]string{"X": {"WEB3_foo"}}, nil, []string{"WEB3_foo"}},
		{"passthrough globally blocked", map[string][]string{"X": {"debug_getRawBlock"}}, nil, []string{"debug_getRawBlock"}},
		{"passthrough blocked prefix", map[string][]string{"X": {"admin_nodeInfo"}}, nil, []string{"admin_nodeInfo"}},
		{"passthrough engine API", map[string][]string{"X": {"engine_forkchoiceUpdatedV3"}}, nil, []string{"engine_forkchoiceUpdatedV3"}},
		// Alias names are held to the same namespace rules: an eth_ alias
		// would dress an unmodelled standard method as a modelled one whose
		// response filter does not match its shape.
		{"alias in eth_ namespace", map[string][]string{"X": {"eth_getRawTransactionByHash"}}, map[string]string{"eth_getRawTransactionByHash": "eth_getTransactionByHash"}, nil},
		{"alias blocked name", map[string][]string{"X": {"txpool_contentFrom"}}, map[string]string{"txpool_contentFrom": "eth_getTransactionByHash"}, nil},
		// Alias targets must be catalog methods with no dedicated request
		// path: anything else would leave the alias without its target's
		// protection.
		{"alias to unmodelled target", map[string][]string{"L": {"linea_raw"}}, map[string]string{"linea_raw": "eth_getRawTransactionByHash"}, nil},
		{"alias to mis-cased target", map[string][]string{"L": {"linea_call"}}, map[string]string{"linea_call": "ETH_CALL"}, nil},
		{"alias to blocked target", map[string][]string{"L": {"linea_filter"}}, map[string]string{"linea_filter": "eth_newFilter"}, nil},
		{"alias to eth_sendRawTransaction", map[string][]string{"L": {"linea_sendRawTransaction"}}, map[string]string{"linea_sendRawTransaction": "eth_sendRawTransaction"}, nil},
		{"alias to eth_sendTransaction", map[string][]string{"L": {"linea_sendTransaction"}}, map[string]string{"linea_sendTransaction": "eth_sendTransaction"}, nil},
		{"alias to debug_traceCall", map[string][]string{"L": {"linea_traceCall"}}, map[string]string{"linea_traceCall": "debug_traceCall"}, nil},
		{"alias to debug_traceTransaction", map[string][]string{"L": {"linea_traceTx"}}, map[string]string{"linea_traceTx": "debug_traceTransaction"}, nil},
		// Block readers whose forwarded body is rewritten by literal name
		// (full tx objects for the participant filter, count → block fetch).
		{"alias to eth_getBlockByNumber", map[string][]string{"L": {"linea_block"}}, map[string]string{"linea_block": "eth_getBlockByNumber"}, nil},
		{"alias to eth_getBlockByHash", map[string][]string{"L": {"linea_blockByHash"}}, map[string]string{"linea_blockByHash": "eth_getBlockByHash"}, nil},
		{"alias to eth_getBlockTransactionCountByNumber", map[string][]string{"L": {"linea_count"}}, map[string]string{"linea_count": "eth_getBlockTransactionCountByNumber"}, nil},
		{"alias to eth_getBlockTransactionCountByHash", map[string][]string{"L": {"linea_countByHash"}}, map[string]string{"linea_countByHash": "eth_getBlockTransactionCountByHash"}, nil},
		// Typed-data signing with node keys is globally blocked, so it is
		// neither a valid alias target nor a passthrough name.
		{"alias to eth_signTypedData_v4", map[string][]string{"L": {"linea_signTyped"}}, map[string]string{"linea_signTyped": "eth_signTypedData_v4"}, nil},
		{"both alias and passthrough", map[string][]string{"L": {"linea_x"}}, map[string]string{"linea_x": "eth_call"}, []string{"linea_x"}},
		{"neither alias nor passthrough", map[string][]string{"L": {"linea_x"}}, nil, nil},
		{"empty name", map[string][]string{"L": {""}}, nil, []string{""}},
		{"surrounding whitespace", map[string][]string{"L": {" linea_x"}}, nil, []string{" linea_x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer SnapshotMethodRegistriesForTest()()
			ExtraMethods = map[string]bool{}
			ExtraNamespaces = nil
			MethodAliases = map[string]string{}
			PassthroughMethods = map[string]bool{}

			err := RegisterExtraNamespaces(tt.namespaces, tt.aliases, tt.passthrough)
			require.Error(t, err)
			assert.Empty(t, ExtraMethods, "a rejected config must register nothing")
			assert.Empty(t, MethodAliases)
			assert.Empty(t, PassthroughMethods)
			assert.Nil(t, ExtraNamespaces)
		})
	}
}

// TestIsForwardableMethod pins the default-deny method gate: only catalog
// methods, operator aliases whose target is a catalog method, and operator
// passthrough methods are forwarded. Exact match — callers canonicalize.
func TestIsForwardableMethod(t *testing.T) {
	defer SnapshotMethodRegistriesForTest()()
	ExtraMethods = map[string]bool{"linea_estimateGas": true, "custom_getRaw": true, "trace_block": true, "linea_sendRaw": true, "linea_trace": true}
	MethodAliases = map[string]string{
		"linea_estimateGas": "eth_estimateGas",
		"custom_getRaw":     "eth_getRawTransactionByHash",
		"linea_sendRaw":     "eth_sendRawTransaction",
		"linea_trace":       "debug_traceCall",
	}
	PassthroughMethods = map[string]bool{"trace_block": true}

	forwardable := []string{
		"eth_call", "eth_getLogs", "eth_sendTransaction", "eth_sendRawTransaction", "debug_traceCall",
		"eth_getProof", "eth_createAccessList", "eth_getBlockReceipts", "eth_feeHistory", "net_peerCount",
		"linea_estimateGas", "trace_block",
	}
	for _, m := range forwardable {
		assert.Truef(t, IsForwardableMethod(m), "%s must be forwardable", m)
	}
	refused := []string{
		"eth_getRawTransactionByHash", "eth_getRawTransactionByBlockHashAndIndex", "eth_getRawTransactionByBlockNumberAndIndex",
		"eth_getTransactionBySenderAndNonce", "eth_getAccount", "eth_simulateV1", "eth_callMany", "eth_sendRawTransactionSync",
		"eth_getUncleByBlockNumberAndIndex", "eth_protocolVersion",
		"trace_transaction", "trace_call", "ots_getTransactionBySenderAndNonce", "erigon_getLogs", "parity_listStorageKeys",
		"custom_getRaw",                // alias to an unmodelled target
		"linea_sendRaw", "linea_trace", // aliases to special-dispatch methods
		"ETH_CALL", "Eth_GetLogs", // non-canonical spelling (callers canonicalize first)
		"eth_newFilter", "personal_sign", // catalog-listed but globally blocked
		"debug_getRawBlock", "admin_peers",
		"*", "linea_*", "eth_*", "",
	}
	for _, m := range refused {
		assert.Falsef(t, IsForwardableMethod(m), "%s must not be forwardable", m)
	}
}

func TestIsCatalogMethod(t *testing.T) {
	defer SnapshotMethodRegistriesForTest()()
	PassthroughMethods = map[string]bool{"trace_block": true}
	MethodAliases = map[string]string{"linea_estimateGas": "eth_estimateGas"}

	assert.True(t, IsCatalogMethod("eth_call"))
	assert.True(t, IsCatalogMethod("eth_getBlockReceipts"))
	assert.False(t, IsCatalogMethod("ETH_CALL"), "exact canonical spelling only")
	assert.False(t, IsCatalogMethod("trace_block"), "passthrough is not catalog")
	assert.False(t, IsCatalogMethod("linea_estimateGas"), "an alias is not catalog")
	assert.False(t, IsCatalogMethod("eth_uninstallFilter"), "globally blocked")
	assert.False(t, IsCatalogMethod("eth_sendRawTransactionSync"))
}

func TestAccessCheckRequest_EffectiveMethod(t *testing.T) {
	t.Run("returns AccessMethod when set", func(t *testing.T) {
		req := &AccessCheckRequest{
			Method:       "linea_estimateGas",
			AccessMethod: "eth_estimateGas",
		}
		assert.Equal(t, "eth_estimateGas", req.EffectiveMethod())
	})

	t.Run("returns Method when AccessMethod empty", func(t *testing.T) {
		req := &AccessCheckRequest{
			Method: "eth_call",
		}
		assert.Equal(t, "eth_call", req.EffectiveMethod())
	})
}

// TestRegisterExtraNamespaces_PanicsAfterArm pins the RD-1262 invariant: the
// method registries are read lock-free on the request hot path, so
// registration is startup-only. Once ArmMethodRegistries has run (end of
// server construction), a late RegisterExtraNamespaces call must fail loud —
// a panic at the registration site — instead of silently racing readers.
func TestRegisterExtraNamespaces_PanicsAfterArm(t *testing.T) {
	defer SnapshotMethodRegistriesForTest()()

	// Pre-arm registration is the normal startup path and must work.
	require.NoError(t, RegisterExtraNamespaces(
		map[string][]string{"Linea": {"linea_estimateGas"}},
		map[string]string{"linea_estimateGas": "eth_estimateGas"},
		nil,
	))
	assert.True(t, ExtraMethods["linea_estimateGas"], "pre-arm registration must succeed")

	ArmMethodRegistries()

	assert.Panics(t, func() {
		_ = RegisterExtraNamespaces(
			map[string][]string{"Late": {"late_method"}},
			nil,
			[]string{"late_method"},
		)
	}, "post-arm registration must panic, not race hot-path readers")
}

// TestSnapshotMethodRegistriesForTest verifies the deep-copy semantics the
// helper promises: in-place mutations of the live maps (what tests actually
// do) are undone by restore, not just pointer reassignments — and the armed
// flag is restored too.
func TestSnapshotMethodRegistriesForTest(t *testing.T) {
	// Outer snapshot so this test itself leaves no trace.
	defer SnapshotMethodRegistriesForTest()()

	ExtraMethods = map[string]bool{"keep_me": true, "pass_me": true}
	ExtraNamespaces = map[string][]string{"NS": {"keep_me", "pass_me"}}
	MethodAliases = map[string]string{"keep_me": "eth_call"}
	PassthroughMethods = map[string]bool{"pass_me": true}

	restore := SnapshotMethodRegistriesForTest()

	// Mutate in place AND reassign — both must be undone.
	ExtraMethods["intruder"] = true
	ExtraNamespaces["NS"] = append(ExtraNamespaces["NS"], "intruder")
	MethodAliases["intruder"] = "eth_call"
	PassthroughMethods["intruder"] = true
	ArmMethodRegistries()

	restore()

	assert.Equal(t, map[string]bool{"keep_me": true, "pass_me": true}, ExtraMethods)
	assert.Equal(t, map[string][]string{"NS": {"keep_me", "pass_me"}}, ExtraNamespaces)
	assert.Equal(t, map[string]string{"keep_me": "eth_call"}, MethodAliases)
	assert.Equal(t, map[string]bool{"pass_me": true}, PassthroughMethods)
	assert.NotPanics(t, func() {
		_ = RegisterExtraNamespaces(map[string][]string{"Again": {"again_m"}}, nil, []string{"again_m"})
	}, "restore must disarm (this test started un-armed)")
}

// TestIsStandardMethod covers reserved names used by config loading.
func TestIsStandardMethod(t *testing.T) {
	for m, want := range map[string]bool{
		"eth_getStorageAt":                true,
		"ETH_SENDTRANSACTION":             true,
		" eth_call ":                      true,
		"eth_getProof":                    true, // canonicalized extra standard method
		"eth_createAccessList":            true,
		"eth_getBlockReceipts":            true, // response-filtered by name
		"eth_getUncleByBlockHashAndIndex": true,
		"debug_traceCall":                 true,
		"linea_getProof":                  false,
		"trace_block":                     false,
		"":                                false,
	} {
		if got := IsStandardMethod(m); got != want {
			t.Errorf("IsStandardMethod(%q) = %v, want %v", m, got, want)
		}
	}
}

// TestIsStandardMethod_CoversClassifiedMethods pins that every classified
// method is reserved; in practice it catches a non-lowercase key in
// ReadOpsMap / WriteOpsMap, which the lowercased lookup would miss.
func TestIsStandardMethod_CoversClassifiedMethods(t *testing.T) {
	for _, set := range []map[string]bool{ReadOpsMap, WriteOpsMap, ReadMethods, WriteMethods, TraceMethods} {
		for m := range set {
			if !IsStandardMethod(m) {
				t.Errorf("%q is classified by the proxy but not refused as an alias key", m)
			}
		}
	}
}

// TestIsStandardMethod_CoversNameKeyedMethods pins the methods that gates or
// response filters currently key on by name (mostly through the alias
// target), so a reserved method cannot drop out of the reserved set
// unnoticed. Add any new name-keyed method here.
func TestIsStandardMethod_CoversNameKeyedMethods(t *testing.T) {
	for _, m := range []string{
		MethodGetTransactionByHash, MethodGetTransactionReceipt,
		MethodGetTransactionByBlockHashAndIndex, MethodGetTransactionByBlockNumberAndIndex,
		MethodGetBlockByHash, MethodGetBlockByNumber, MethodGetBlockReceipts,
		MethodGetLogs,
		MethodNewFilter, MethodNewBlockFilter, MethodNewPendingTransactionFilter,
		MethodGetFilterLogs, MethodGetFilterChanges, MethodUninstallFilter,
		MethodGetStorageAt, MethodGetCode, MethodGetBalance, MethodGetTransactionCount, MethodGetProof,
		MethodCall, MethodEstimateGas, MethodSendTransaction, MethodSendRawTransaction,
		"eth_getBlockTransactionCountByHash", "eth_getBlockTransactionCountByNumber",
		"eth_createAccessList", "debug_traceCall", "debug_traceTransaction",
	} {
		if !IsStandardMethod(m) {
			t.Errorf("%q is checked or filtered by name but not reserved from alias keys", m)
		}
	}
}

// TestSupportedMethods is the assignable set the admin UI receives: the catalog
// plus forwardable operator methods, never unmodelled or blocked names.
func TestSupportedMethods(t *testing.T) {
	defer SnapshotMethodRegistriesForTest()()
	ExtraMethods = map[string]bool{"linea_estimateGas": true, "custom_getRaw": true, "trace_block": true}
	MethodAliases = map[string]string{"linea_estimateGas": "eth_estimateGas", "custom_getRaw": "eth_getRawTransactionByHash"}
	PassthroughMethods = map[string]bool{"trace_block": true}

	got := SupportedMethods()
	assert.IsIncreasing(t, got)
	for _, m := range []string{"eth_call", "eth_getProof", "eth_getBlockReceipts", "debug_traceCall", "linea_estimateGas", "trace_block"} {
		assert.Contains(t, got, m)
	}
	for _, m := range []string{"custom_getRaw", "eth_newFilter", "personal_sign", "eth_sign", "eth_sendRawTransactionSync"} {
		assert.NotContains(t, got, m)
	}
	for _, m := range got {
		assert.True(t, IsAssignableMethod(m), m)
	}
}

// Typed-data signing asks the node to sign with one of its own keys: no
// signer-vs-caller check, nothing to filter. It is blocked like eth_sign and
// eth_signTransaction, so it is never forwarded and never part of "*".
func TestSignTypedData_IsBlocked(t *testing.T) {
	for _, m := range []string{"eth_signTypedData", "eth_signTypedData_v4", "ETH_SIGNTYPEDDATA_V4"} {
		assert.Truef(t, IsMethodBlocked(m), "%s must be globally blocked", m)
		assert.Falsef(t, IsForwardableMethod(CanonicalizeMethod(m)), "%s must not be forwardable", m)
	}
	assert.NotContains(t, AllAllowedMethods(), "eth_signTypedData")
	assert.NotContains(t, AllAllowedMethods(), "eth_signTypedData_v4")
}
