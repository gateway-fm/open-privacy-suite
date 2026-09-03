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
			name:     "wildcard with other methods",
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
	Wildcards = nil

	namespaces := map[string][]string{
		"Linea": {"linea_estimateGas", "linea_getProof"},
		"Trace": {"trace_block", "trace_transaction"},
	}
	aliases := map[string]string{
		"linea_estimateGas": "eth_estimateGas",
		"linea_getProof":    "eth_getProof",
	}

	RegisterExtraNamespaces(namespaces, aliases, nil)

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
	assert.Equal(t, "trace_block", ResolveMethodAlias("trace_block")) // no alias = returns self
	assert.Equal(t, "eth_call", ResolveMethodAlias("eth_call"))       // standard method = returns self

	// Verify AllAllowedMethods includes extras
	all := AllAllowedMethods()
	allSet := make(map[string]bool)
	for _, m := range all {
		allSet[m] = true
	}
	assert.True(t, allSet["linea_estimateGas"], "extra method should be in AllAllowedMethods")
	assert.True(t, allSet["trace_block"], "extra method should be in AllAllowedMethods")
	assert.True(t, allSet["eth_call"], "standard method should still be in AllAllowedMethods")

	// Verify wildcard expansion includes extras
	expanded := ExpandWildcardMethods([]string{"*"})
	expandedSet := make(map[string]bool)
	for _, m := range expanded {
		expandedSet[m] = true
	}
	assert.True(t, expandedSet["linea_estimateGas"], "extra method should be in wildcard expansion")
	assert.True(t, expandedSet["trace_transaction"], "extra method should be in wildcard expansion")
}

// TestMatchWildcard exercises the prefix-wildcard passthrough matcher: prefix
// match, deny-glob override, and namespaces with no wildcard.
func TestMatchWildcard(t *testing.T) {
	defer SnapshotMethodRegistriesForTest()()

	Wildcards = []*WildcardNamespace{
		{
			Namespace: "Linea",
			Prefix:    "linea_",
			Deny:      []string{"linea_sendTransaction", "linea_sendRawTransaction", "linea_sign*"},
		},
		{
			Namespace: "Trace",
			Prefix:    "trace_",
			Deny:      nil,
		},
	}

	tests := []struct {
		name     string
		method   string
		expectNS string // empty = expect nil match
	}{
		{"linea unknown method matches", "linea_brandNewMethod", "Linea"},
		{"linea explicit also matches", "linea_estimateGas", "Linea"},
		{"linea deny exact match", "linea_sendTransaction", ""},
		{"linea deny suffix glob", "linea_signTypedData", ""},
		{"linea deny suffix glob exact", "linea_sign", ""},
		{"unrelated prefix", "eth_call", ""},
		{"trace any method passes (no deny list)", "trace_anything", "Trace"},
		{"empty method", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchWildcard(tt.method)
			if tt.expectNS == "" {
				assert.Nil(t, got, "expected no wildcard match for %q", tt.method)
				return
			}
			require.NotNil(t, got, "expected wildcard match for %q", tt.method)
			assert.Equal(t, tt.expectNS, got.Namespace)
		})
	}
}

// TestHasWildcardForPrefix is the lookup that GroupAccess.HasMethod uses to
// validate that a "<prefix>*" entry in a group's allowed_methods binds to a
// real registered wildcard. Groups can't invent prefixes the operator hasn't
// enabled globally.
func TestHasWildcardForPrefix(t *testing.T) {
	defer SnapshotMethodRegistriesForTest()()

	Wildcards = []*WildcardNamespace{
		{Namespace: "Linea", Prefix: "linea_"},
	}

	assert.True(t, HasWildcardForPrefix("linea_"))
	assert.False(t, HasWildcardForPrefix("zksync_"))
	assert.False(t, HasWildcardForPrefix(""))
}

// TestRegisterExtraNamespaces_WithWildcards verifies that wildcards passed to
// RegisterExtraNamespaces are stored alongside the explicit-method registry,
// and that explicit methods continue to win for alias resolution (a method can
// be both explicit and covered by a wildcard prefix).
func TestRegisterExtraNamespaces_WithWildcards(t *testing.T) {
	defer SnapshotMethodRegistriesForTest()()
	ExtraMethods = map[string]bool{}
	ExtraNamespaces = nil
	MethodAliases = map[string]string{}
	Wildcards = nil

	RegisterExtraNamespaces(
		map[string][]string{"Linea": {"linea_estimateGas"}},
		map[string]string{"linea_estimateGas": "eth_estimateGas"},
		[]*WildcardNamespace{{Namespace: "Linea", Prefix: "linea_", Deny: []string{"linea_sign*"}}},
	)

	// Explicit method has its alias.
	assert.Equal(t, "eth_estimateGas", ResolveMethodAlias("linea_estimateGas"))
	// Wildcard-only method passes through (no alias).
	assert.Equal(t, "linea_brandNew", ResolveMethodAlias("linea_brandNew"))
	// Wildcard match returns the namespace for both explicit-also-matched and unknown methods.
	require.NotNil(t, MatchWildcard("linea_estimateGas"))
	require.NotNil(t, MatchWildcard("linea_brandNew"))
	// Deny still wins.
	assert.Nil(t, MatchWildcard("linea_signFoo"))
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
	RegisterExtraNamespaces(
		map[string][]string{"Linea": {"linea_estimateGas"}},
		map[string]string{"linea_estimateGas": "eth_estimateGas"},
		nil,
	)
	assert.True(t, ExtraMethods["linea_estimateGas"], "pre-arm registration must succeed")

	ArmMethodRegistries()

	assert.Panics(t, func() {
		RegisterExtraNamespaces(
			map[string][]string{"Late": {"late_method"}},
			nil,
			nil,
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

	ExtraMethods = map[string]bool{"keep_me": true}
	ExtraNamespaces = map[string][]string{"NS": {"keep_me"}}
	MethodAliases = map[string]string{"keep_me": "eth_call"}
	Wildcards = []*WildcardNamespace{{Namespace: "NS", Prefix: "ns_", Deny: []string{"ns_deny"}}}

	restore := SnapshotMethodRegistriesForTest()

	// Mutate in place AND reassign — both must be undone. Wildcard elements
	// are pointers, so in-place struct/deny mutation is the sharpest case.
	ExtraMethods["intruder"] = true
	ExtraNamespaces["NS"] = append(ExtraNamespaces["NS"], "intruder")
	MethodAliases["intruder"] = "eth_call"
	Wildcards[0].Prefix = "mutated_"
	Wildcards[0].Deny[0] = "mutated_deny"
	ArmMethodRegistries()

	restore()

	assert.Equal(t, map[string]bool{"keep_me": true}, ExtraMethods)
	assert.Equal(t, map[string][]string{"NS": {"keep_me"}}, ExtraNamespaces)
	assert.Equal(t, map[string]string{"keep_me": "eth_call"}, MethodAliases)
	if assert.Len(t, Wildcards, 1) {
		assert.Equal(t, "ns_", Wildcards[0].Prefix)
		assert.Equal(t, []string{"ns_deny"}, Wildcards[0].Deny)
	}
	assert.NotPanics(t, func() {
		RegisterExtraNamespaces(map[string][]string{"Again": {"again_m"}}, nil, nil)
	}, "restore must disarm (this test started un-armed)")
}
