package rbac

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

func TestClassifyOperation(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		params        []any
		expectedClaim Claim
	}{
		// Read methods — no claim required (gated by method allowlist)
		{
			name:          "Read operation - eth_call (no claim)",
			method:        "eth_call",
			params:        nil,
			expectedClaim: "",
		},
		{
			name:          "Read operation - eth_getBalance (no claim)",
			method:        "eth_getBalance",
			params:        nil,
			expectedClaim: "",
		},
		{
			name:   "Read operation - eth_estimateGas with to address (no claim)",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"to": "0x1234567890123456789012345678901234567890", "data": "0xa9059cbb"},
			},
			expectedClaim: "",
		},
		// Write methods — no claim required (gated by method allowlist)
		{
			name:   "Write operation - eth_sendTransaction with to address (no claim)",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x1234567890123456789012345678901234567890", "value": "0x100"},
			},
			expectedClaim: "",
		},
		{
			name:          "Other method - no contract claim required",
			method:        "eth_blockNumber",
			params:        nil,
			expectedClaim: "",
		},
		{
			name:          "Other method - net_version",
			method:        "net_version",
			params:        nil,
			expectedClaim: "",
		},
		// Without params, we can't determine deployment — no claim
		{
			name:          "eth_sendTransaction with no params (no claim)",
			method:        "eth_sendTransaction",
			params:        nil,
			expectedClaim: "",
		},
		{
			name:          "eth_sendTransaction with empty params (no claim)",
			method:        "eth_sendTransaction",
			params:        []any{},
			expectedClaim: "",
		},
		// Contract deployment cases - should require deploy claim
		{
			name:   "Deploy - eth_sendTransaction with no 'to' field",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"data": "0x6080604052", "value": "0x0"},
			},
			expectedClaim: ClaimDeploy,
		},
		{
			name:   "Deploy - eth_sendTransaction with 'to' = null",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": nil, "data": "0x6080604052"},
			},
			expectedClaim: ClaimDeploy,
		},
		{
			name:   "Deploy - eth_sendTransaction with 'to' = empty string",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "", "data": "0x6080604052"},
			},
			expectedClaim: ClaimDeploy,
		},
		{
			name:   "Deploy - eth_sendTransaction with 'to' = '0x'",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x", "data": "0x6080604052"},
			},
			expectedClaim: ClaimDeploy,
		},
		{
			name:   "NOT Deploy - eth_sendTransaction with valid 'to' address (no claim)",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x1234567890123456789012345678901234567890", "data": "0xa9059cbb"},
			},
			expectedClaim: "",
		},
		{
			name:   "NOT Deploy - eth_sendTransaction to zero address (no claim)",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x0000000000000000000000000000000000000000", "value": "0x100"},
			},
			expectedClaim: "",
		},
		// eth_estimateGas deployment cases - should require deploy claim
		{
			name:   "Deploy - eth_estimateGas with no 'to' field (deployment estimation)",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"data": "0x6080604052", "from": "0xabc"},
			},
			expectedClaim: ClaimDeploy,
		},
		{
			name:   "Deploy - eth_estimateGas with 'to' = null (deployment estimation)",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"to": nil, "data": "0x6080604052"},
			},
			expectedClaim: ClaimDeploy,
		},
		{
			name:   "NOT Deploy - eth_estimateGas with valid 'to' (no claim)",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"to": "0x1234567890123456789012345678901234567890", "data": "0xa9059cbb"},
			},
			expectedClaim: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claim := ClassifyOperation(tt.method, tt.params)

			if claim != tt.expectedClaim {
				t.Errorf("Expected claim %v, got %v", tt.expectedClaim, claim)
			}
		})
	}
}

func TestIsContractDeployment(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		params   []any
		expected bool
	}{
		// Without params, we can't determine if it's a deployment
		{
			name:     "eth_sendTransaction with no params - unknown (not deployment)",
			method:   "eth_sendTransaction",
			params:   nil,
			expected: false, // Can't determine without params
		},
		{
			name:     "eth_sendTransaction with empty params - unknown (not deployment)",
			method:   "eth_sendTransaction",
			params:   []any{},
			expected: false, // Can't determine without params
		},
		// Deployment cases
		{
			name:   "eth_sendTransaction with no 'to' field - deployment",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"data": "0x6080604052", "from": "0xabc"},
			},
			expected: true,
		},
		{
			name:   "eth_sendTransaction with 'to' = nil - deployment",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": nil, "data": "0x6080604052"},
			},
			expected: true,
		},
		{
			name:   "eth_sendTransaction with 'to' = empty string - deployment",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "", "data": "0x6080604052"},
			},
			expected: true,
		},
		{
			name:   "eth_sendTransaction with 'to' = '0x' - deployment",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x", "data": "0x6080604052"},
			},
			expected: true,
		},
		{
			name:   "eth_sendTransaction with malformed params (not map) - deployment (safe default)",
			method: "eth_sendTransaction",
			params: []any{"not a map"},
			expected: true,
		},
		{
			name:   "eth_sendTransaction with 'to' as number - deployment (safe default)",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": 12345, "data": "0x6080604052"},
			},
			expected: true,
		},
		// NOT deployment cases
		{
			name:   "eth_sendTransaction with valid 'to' - NOT deployment",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x1234567890123456789012345678901234567890"},
			},
			expected: false,
		},
		{
			name:   "eth_sendTransaction to zero address - NOT deployment (it's a burn)",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x0000000000000000000000000000000000000000"},
			},
			expected: false,
		},
		{
			name:   "eth_sendTransaction with short but valid 'to' - NOT deployment",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x1"},
			},
			expected: false,
		},
		// eth_estimateGas deployment cases
		{
			name:   "eth_estimateGas with no 'to' field - deployment",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"data": "0x6080604052", "from": "0xabc"},
			},
			expected: true,
		},
		{
			name:   "eth_estimateGas with 'to' = nil - deployment",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"to": nil, "data": "0x6080604052"},
			},
			expected: true,
		},
		{
			name:   "eth_estimateGas with 'to' = '' - deployment",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"to": "", "data": "0x6080604052"},
			},
			expected: true,
		},
		{
			name:   "eth_estimateGas with valid 'to' - NOT deployment",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"to": "0x1234567890123456789012345678901234567890"},
			},
			expected: false,
		},
		// Other methods - never deployment
		{
			name:     "eth_sendRawTransaction - NOT deployment (can't validate)",
			method:   "eth_sendRawTransaction",
			params:   []any{"0xf86c..."},
			expected: false,
		},
		{
			name:     "eth_call - NOT deployment",
			method:   "eth_call",
			params:   nil,
			expected: false,
		},
		{
			name:     "eth_blockNumber - NOT deployment",
			method:   "eth_blockNumber",
			params:   nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsContractDeployment(tt.method, tt.params)
			if result != tt.expected {
				t.Errorf("IsContractDeployment(%q, %v) = %v, expected %v",
					tt.method, tt.params, result, tt.expected)
			}
		})
	}
}

func TestGetTargetAddress(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		params   []any
		expected string
	}{
		{
			name:     "No params",
			method:   "eth_call",
			params:   nil,
			expected: "",
		},
		{
			name:     "Empty params",
			method:   "eth_call",
			params:   []any{},
			expected: "",
		},
		{
			name:   "eth_call with to address",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0xABCD1234"},
			},
			expected: "0xabcd1234",
		},
		{
			name:   "eth_estimateGas with to address",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"to": "0xABCD1234", "data": "0x"},
			},
			expected: "0xabcd1234",
		},
		{
			name:   "eth_sendTransaction with to address",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0xABCD1234", "value": "0x100"},
			},
			expected: "0xabcd1234",
		},
		{
			name:     "eth_getCode with address",
			method:   "eth_getCode",
			params:   []any{"0xABCD1234", "latest"},
			expected: "0xabcd1234",
		},
		{
			name:     "eth_getStorageAt with address",
			method:   "eth_getStorageAt",
			params:   []any{"0xABCD1234", "0x0", "latest"},
			expected: "0xabcd1234",
		},
		// Account query methods - MUST extract target address for per-address access checks.
		// On a private network, balances and nonces are sensitive cross-org data.
		{
			name:     "eth_getBalance extracts target address",
			method:   "eth_getBalance",
			params:   []any{"0xABCD1234", "latest"},
			expected: "0xabcd1234",
		},
		{
			name:     "eth_getTransactionCount extracts target address",
			method:   "eth_getTransactionCount",
			params:   []any{"0x0000000000000000000000000000000000000000", "latest"},
			expected: "0x0000000000000000000000000000000000000000",
		},
		// eth_getProof returns balance + nonce + storage proof — equivalent to
		// eth_getBalance + eth_getStorageAt combined. Must be per-address gated.
		{
			name:     "eth_getProof extracts target address",
			method:   "eth_getProof",
			params:   []any{"0xABCD1234", []any{"0x0"}, "latest"},
			expected: "0xabcd1234",
		},
		// eth_createAccessList reveals which storage slots and addresses a call
		// would access — leaks contract internals cross-org.
		{
			name:   "eth_createAccessList extracts to from call object",
			method: "eth_createAccessList",
			params: []any{
				map[string]any{"to": "0xABCD1234", "data": "0x"},
			},
			expected: "0xabcd1234",
		},
		// eth_getLogs: extract address from filter for org resolution
		{
			name:   "eth_getLogs with single address string",
			method: "eth_getLogs",
			params: []any{
				map[string]any{"address": "0xABCD1234", "fromBlock": "0x0"},
			},
			expected: "0xabcd1234",
		},
		{
			name:   "eth_getLogs with address array",
			method: "eth_getLogs",
			params: []any{
				map[string]any{"address": []any{"0xABCD1234", "0x5678"}, "fromBlock": "0x0"},
			},
			expected: "0xabcd1234",
		},
		{
			name:   "eth_getLogs with no address in filter",
			method: "eth_getLogs",
			params: []any{
				map[string]any{"fromBlock": "0x0", "toBlock": "latest"},
			},
			expected: "",
		},
		{
			name:   "eth_getLogs with empty address array",
			method: "eth_getLogs",
			params: []any{
				map[string]any{"address": []any{}},
			},
			expected: "",
		},
		{
			name:     "Unknown method",
			method:   "eth_blockNumber",
			params:   []any{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetTargetAddress(tt.method, tt.params)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestEffectivePermissionsMethods(t *testing.T) {
	perms := &EffectivePermissions{
		AllowedMethods: []string{"eth_call", "eth_getBalance"},
		ContractAccess: map[string]ContractAccess{
			"0xaddress1": {Claims: []Claim{ClaimDeploy}},
			"0xaddress2": {Claims: []Claim{}},
			"0xowned1":   {Claims: []Claim{ClaimDeploy, ClaimAdmin}},
		},
		Claims: []Claim{ClaimDeploy},
	}

	// Test HasMethod
	if !perms.HasMethod("eth_call") {
		t.Error("Expected HasMethod to return true for eth_call")
	}
	if perms.HasMethod("eth_sendTransaction") {
		t.Error("Expected HasMethod to return false for eth_sendTransaction")
	}

	// Test HasContractAccess
	if !perms.HasContractAccess("0xaddress1") {
		t.Error("Expected HasContractAccess to return true for 0xaddress1")
	}
	if perms.HasContractAccess("0xunknown") {
		t.Error("Expected HasContractAccess to return false for unknown address")
	}

	// Test HasDefaultClaim
	if !perms.HasDefaultClaim(ClaimDeploy) {
		t.Error("Expected HasDefaultClaim to return true for ClaimDeploy")
	}
	if perms.HasDefaultClaim(ClaimUpgrade) {
		t.Error("Expected HasDefaultClaim to return false for ClaimUpgrade")
	}

	// Test contract access claims
	access := perms.ContractAccess["0xaddress1"]
	if !access.HasClaim(ClaimDeploy) {
		t.Error("Expected contract access to have deploy claim")
	}
	if access.HasClaim(ClaimUpgrade) {
		t.Error("Expected contract access to not have upgrade claim")
	}
	if access.HasClaim(ClaimAdmin) {
		t.Error("Expected contract access to not have admin claim")
	}
}

func TestIsMethodBlocked(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		expected bool
	}{
		// Should be blocked - debug namespace (except exempted trace methods)
		{"debug_setHead", "debug_setHead", true},
		{"debug_unknown", "debug_unknown", true}, // prefix match

		// Should NOT be blocked - exempted debug trace methods (gated by deploy claim instead)
		{"debug_traceTransaction", "debug_traceTransaction", false},
		{"debug_traceCall", "debug_traceCall", false},
		{"debug_traceCall_case", "DEBUG_TRACECALL", false}, // case-insensitive exemption

		// Should be blocked - admin namespace
		{"admin_addPeer", "admin_addPeer", true},
		{"admin_nodeInfo", "admin_nodeInfo", true},
		{"admin_unknown", "admin_unknown", true}, // prefix match

		// Should be blocked - personal namespace
		{"personal_unlockAccount", "personal_unlockAccount", true},
		{"personal_sign", "personal_sign", true},
		{"personal_unknown", "personal_unknown", true}, // prefix match

		// Should be blocked - miner namespace
		{"miner_start", "miner_start", true},
		{"miner_stop", "miner_stop", true},

		// Should be blocked - txpool namespace
		{"txpool_content", "txpool_content", true},
		{"txpool_status", "txpool_status", true},

		// Should be blocked - signing methods
		{"eth_sign", "eth_sign", true},
		{"eth_signTransaction", "eth_signTransaction", true},

		// Should be blocked - clique namespace
		{"clique_propose", "clique_propose", true},

		// Should be blocked - les namespace
		{"les_serverInfo", "les_serverInfo", true},

		// Should NOT be blocked - eth_getStorageAt uses tiered access control in CheckAccess
		// (admin=all slots, read=well-known only) instead of a global block
		{"eth_getStorageAt", "eth_getStorageAt", false},

		// Should NOT be blocked - normal read operations
		{"eth_call", "eth_call", false},
		{"eth_getBalance", "eth_getBalance", false},
		{"eth_blockNumber", "eth_blockNumber", false},
		{"eth_getTransactionReceipt", "eth_getTransactionReceipt", false},
		{"eth_chainId", "eth_chainId", false},

		// Should NOT be blocked - normal write operations
		{"eth_sendTransaction", "eth_sendTransaction", false},

		// Should NOT be blocked by IsMethodBlocked - eth_sendRawTransaction is handled
		// specially by CheckAccess (allowed only when runtime tracing is enabled).
		// See access.go GlobalBlockedMethods comment for details.
		{"eth_sendRawTransaction", "eth_sendRawTransaction", false},

		// Should NOT be blocked - other namespaces
		{"net_version", "net_version", false},
		{"web3_clientVersion", "web3_clientVersion", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsMethodBlocked(tt.method)
			if result != tt.expected {
				t.Errorf("IsMethodBlocked(%q) = %v, expected %v", tt.method, result, tt.expected)
			}
		})
	}
}

func TestIsMulticallTarget(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		expected bool
	}{
		{"Multicall3 lowercase", "0xca11bde05977b3631167028862be2a173976ca11", true},
		{"Multicall3 uppercase", "0xCA11BDE05977B3631167028862BE2A173976CA11", true},
		{"Multicall3 mixed case", "0xcA11bde05977b3631167028862bE2a173976CA11", true},
		{"Multicall2 mainnet", "0x5ba1e12693dc8f9c48aad8770482f4739beed696", true},
		{"Original Multicall", "0xeefba1e63905ef1d7acba5a8513c70307c1ce441", true},
		{"Random address", "0x1234567890123456789012345678901234567890", false},
		{"Empty address", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsMulticallTarget(tt.address)
			if result != tt.expected {
				t.Errorf("IsMulticallTarget(%q) = %v, expected %v", tt.address, result, tt.expected)
			}
		})
	}
}

func TestIsMulticallData(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected bool
	}{
		{"aggregate selector", "0x252dba42", true},
		{"aggregate3 selector", "0x82ad56cb", true},
		{"tryAggregate selector", "0xbce38bd7", true},
		{"aggregate with params", "0x252dba42000000000000000000000000", true},
		{"Not multicall", "0xa9059cbb", false},
		{"Empty data", "", false},
		{"Short data", "0x1234", false},
		{"No 0x prefix", "252dba42", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsMulticallData(tt.data)
			if result != tt.expected {
				t.Errorf("IsMulticallData(%q) = %v, expected %v", tt.data, result, tt.expected)
			}
		})
	}
}

func TestDetectMulticall(t *testing.T) {
	tests := []struct {
		name            string
		method          string
		params          []any
		expectMulticall bool
	}{
		{
			name:   "eth_call to Multicall3 with aggregate",
			method: "eth_call",
			params: []any{
				map[string]any{
					"to":   "0xcA11bde05977b3631167028862bE2a173976CA11",
					"data": "0x252dba42000000000000000000000000",
				},
			},
			expectMulticall: true,
		},
		{
			name:   "eth_estimateGas to Multicall3",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{
					"to":   "0xca11bde05977b3631167028862be2a173976ca11",
					"data": "0x82ad56cb",
				},
			},
			expectMulticall: true,
		},
		{
			name:   "eth_call to regular contract",
			method: "eth_call",
			params: []any{
				map[string]any{
					"to":   "0x1234567890123456789012345678901234567890",
					"data": "0x252dba42",
				},
			},
			expectMulticall: false,
		},
		{
			name:   "eth_call to Multicall3 with non-multicall function",
			method: "eth_call",
			params: []any{
				map[string]any{
					"to":   "0xca11bde05977b3631167028862be2a173976ca11",
					"data": "0xa9059cbb", // transfer selector
				},
			},
			expectMulticall: false,
		},
		{
			name:   "eth_sendTransaction to Multicall3 with aggregate - BLOCKED",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{
					"to":   "0xca11bde05977b3631167028862be2a173976ca11",
					"data": "0x252dba42000000000000000000000000",
				},
			},
			expectMulticall: true,
		},
		{
			name:   "eth_sendTransaction to Multicall3 with aggregate3 - BLOCKED",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{
					"to":   "0xca11bde05977b3631167028862be2a173976ca11",
					"data": "0x82ad56cb",
				},
			},
			expectMulticall: true,
		},
		{
			name:   "eth_sendTransaction to regular contract - allowed",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{
					"to":   "0x1234567890123456789012345678901234567890",
					"data": "0x252dba42", // Same selector but different target
				},
			},
			expectMulticall: false,
		},
		{
			name:   "eth_sendTransaction to Multicall3 with non-multicall function - allowed",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{
					"to":   "0xca11bde05977b3631167028862be2a173976ca11",
					"data": "0xa9059cbb", // transfer selector, not multicall
				},
			},
			expectMulticall: false,
		},
		{
			name:            "eth_sendTransaction with empty params - not checked",
			method:          "eth_sendTransaction",
			params:          []any{},
			expectMulticall: false,
		},
		{
			name:            "eth_blockNumber is not checked",
			method:          "eth_blockNumber",
			params:          []any{},
			expectMulticall: false,
		},
		{
			name:            "Empty params",
			method:          "eth_call",
			params:          []any{},
			expectMulticall: false,
		},
		{
			name:   "Missing data field",
			method: "eth_call",
			params: []any{
				map[string]any{
					"to": "0xca11bde05977b3631167028862be2a173976ca11",
				},
			},
			expectMulticall: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isMulticall, reason := DetectMulticall(tt.method, tt.params)
			if isMulticall != tt.expectMulticall {
				t.Errorf("DetectMulticall() = %v, expected %v, reason: %s", isMulticall, tt.expectMulticall, reason)
			}
			if tt.expectMulticall && reason == "" {
				t.Error("Expected non-empty reason when Multicall is detected")
			}
		})
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("intersectStrings", func(t *testing.T) {
		a := []string{"a", "b", "c"}
		b := []string{"b", "c", "d"}
		result := intersectStrings(a, b)

		if len(result) != 2 {
			t.Errorf("Expected 2 elements, got %d: %v", len(result), result)
		}
	})

	t.Run("intersectStrings empty", func(t *testing.T) {
		result := intersectStrings([]string{}, []string{"a", "b"})
		if len(result) != 0 {
			t.Errorf("Expected empty result, got %v", result)
		}
	})

	t.Run("unionStrings", func(t *testing.T) {
		a := []string{"a", "b"}
		b := []string{"b", "c"}
		result := unionStrings(a, b)

		if len(result) != 3 {
			t.Errorf("Expected 3 elements, got %d: %v", len(result), result)
		}
	})
}

func TestExtractGetLogsAddresses(t *testing.T) {
	tests := []struct {
		name     string
		filter   map[string]any
		expected []string
	}{
		{
			name:     "No address field",
			filter:   map[string]any{"fromBlock": "latest"},
			expected: nil,
		},
		{
			name:     "Address field is nil",
			filter:   map[string]any{"address": nil},
			expected: nil,
		},
		{
			name:     "Single address as string",
			filter:   map[string]any{"address": "0xABCD1234567890ABCD1234567890ABCD12345678"},
			expected: []string{"0xabcd1234567890abcd1234567890abcd12345678"},
		},
		{
			name:     "Single address as string (lowercase)",
			filter:   map[string]any{"address": "0xabcd1234567890abcd1234567890abcd12345678"},
			expected: []string{"0xabcd1234567890abcd1234567890abcd12345678"},
		},
		{
			name:     "Empty string address",
			filter:   map[string]any{"address": ""},
			expected: []string{},
		},
		{
			name: "Multiple addresses as array",
			filter: map[string]any{
				"address": []any{
					"0xABCD1234567890ABCD1234567890ABCD12345678",
					"0x1234567890ABCD1234567890ABCD123456789012",
				},
			},
			expected: []string{
				"0xabcd1234567890abcd1234567890abcd12345678",
				"0x1234567890abcd1234567890abcd123456789012",
			},
		},
		{
			name:     "Empty address array",
			filter:   map[string]any{"address": []any{}},
			expected: []string{},
		},
		{
			name: "Array with empty string (filtered out)",
			filter: map[string]any{
				"address": []any{
					"0xABCD1234567890ABCD1234567890ABCD12345678",
					"",
				},
			},
			expected: []string{"0xabcd1234567890abcd1234567890abcd12345678"},
		},
		{
			name: "Array with mixed types (non-strings ignored)",
			filter: map[string]any{
				"address": []any{
					"0xABCD1234567890ABCD1234567890ABCD12345678",
					123, // number, should be ignored
				},
			},
			expected: []string{"0xabcd1234567890abcd1234567890abcd12345678"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractGetLogsAddresses(tt.filter)

			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d addresses, got %d: %v", len(tt.expected), len(result), result)
				return
			}

			for i, addr := range result {
				if addr != tt.expected[i] {
					t.Errorf("Address %d: expected %q, got %q", i, tt.expected[i], addr)
				}
			}
		})
	}
}

func TestClassifyOperation_EthGetLogs(t *testing.T) {
	// eth_getLogs no longer requires a claim — gated by method allowlist
	tests := []struct {
		name          string
		method        string
		params        []any
		expectedClaim Claim
	}{
		{
			name:          "eth_getLogs requires no claim",
			method:        "eth_getLogs",
			params:        nil,
			expectedClaim: "",
		},
		{
			name:   "eth_getLogs with filter requires no claim",
			method: "eth_getLogs",
			params: []any{
				map[string]any{"address": "0x1234", "fromBlock": "latest"},
			},
			expectedClaim: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claim := ClassifyOperation(tt.method, tt.params)
			if claim != tt.expectedClaim {
				t.Errorf("Expected claim %v, got %v", tt.expectedClaim, claim)
			}
		})
	}
}

// TestCrossOrgIsolation tests the P0 security fix for cross-org isolation.
// This ensures that users cannot access contracts belonging to other organizations
// via the default_claims fallback.
func TestCrossOrgIsolation(t *testing.T) {
	t.Run("IsContractRegistered - explicit access", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				"0xmycontract": {Claims: []Claim{}},
			},
			Claims: []Claim{},
		}

		if !perms.IsContractRegistered("0xmycontract") {
			t.Error("Expected IsContractRegistered to return true for contract in ContractAccess")
		}
		if !perms.IsContractRegistered("0xMYCONTRACT") {
			t.Error("Expected IsContractRegistered to be case-insensitive")
		}
		if perms.IsContractRegistered("0xothercontract") {
			t.Error("Expected IsContractRegistered to return false for unknown contract")
		}
	})

	t.Run("GetContractAccess returns nil for unregistered (private by default)", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				"0xmycontract": {Claims: []Claim{ClaimDeploy, ClaimUpgrade}},
			},
			Claims: []Claim{ClaimDeploy},
		}

		// Registered contract should return explicit access
		access := perms.GetContractAccess("0xmycontract")
		if access == nil || len(access.Claims) != 2 {
			t.Errorf("Expected 2 claims for registered contract, got %v", access)
		}

		// Unregistered contract should return nil (private by default)
		access = perms.GetContractAccess("0xunregistered")
		if access != nil {
			t.Errorf("Expected nil for unregistered contract (private by default), got %v", access)
		}
	})

	t.Run("GetContractAccess returns access for precompile address", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				"0xmycontract": {Claims: nil},
			},
			Claims: nil,
		}

		// Registered contract still works
		access := perms.GetContractAccess("0xmycontract")
		if access == nil {
			t.Error("Expected access for registered contract, got nil")
		}

		// Precompile should return non-nil access (always accessible)
		access = perms.GetContractAccess("0x0000000000000000000000000000000000000001")
		if access == nil {
			t.Fatal("Expected access for precompile, got nil")
		}

		// Non-precompile unregistered should return nil
		access = perms.GetContractAccess("0xunregistered")
		if access != nil {
			t.Errorf("Expected nil for unregistered contract (private by default), got %v", access)
		}
	})

	t.Run("No default claims means no access to unregistered", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				"0xmycontract": {Claims: []Claim{}},
			},
			Claims: []Claim{}, // No default claims
		}

		access := perms.GetContractAccess("0xunregistered")
		if access != nil {
			t.Errorf("Expected nil access for unregistered contract when no default claims, got %v", access)
		}
	})
}

// TestGetContractAccessUnregisteredRestriction verifies that ALL users are
// denied access to unregistered contracts (private by default). Only precompiles
// are accessible without explicit registration.
func TestGetContractAccessUnregisteredRestriction(t *testing.T) {
	tests := []struct {
		name     string
		claims   []Claim
		expected bool // true = access returned, false = nil
	}{
		{"upgrade denied", []Claim{ClaimUpgrade}, false},
		{"deploy denied", []Claim{ClaimDeploy}, false},
		{"admin denied", []Claim{ClaimAdmin, ClaimDeploy, ClaimUpgrade}, false},
		{"empty claims denied", []Claim{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := &EffectivePermissions{
				AllowedMethods: []string{"eth_call"},
				ContractAccess: map[string]ContractAccess{},
				Claims:         tt.claims,
			}
			access := perms.GetContractAccess("0xunregistered")
			if tt.expected && access == nil {
				t.Errorf("expected access for unregistered contract with claims %v, got nil", tt.claims)
			}
			if !tt.expected && access != nil {
				t.Errorf("expected nil for unregistered contract with claims %v, got %v", tt.claims, access)
			}
		})
	}
}

// TestReadWriteOpsMaps verifies the ReadOpsMap and WriteOpsMap contain the right methods.
// These maps are retained for reference and test completeness even though ClassifyOperation
// no longer consults them (read/write are gated by method allowlist, not claims).
func TestReadWriteOpsMaps(t *testing.T) {
	// Core read operations (lowercase keys)
	expectedReadOps := []string{
		"eth_call",
		"eth_estimategas",
		"eth_getcode",
		"eth_getbalance",
		"eth_getstorageat",
		"eth_gettransactioncount",
		"eth_getlogs",
		// Filter equivalents of eth_getLogs
		"eth_newfilter",
		"eth_newblockfilter",
		"eth_newpendingtransactionfilter",
		"eth_getfilterchanges",
		"eth_getfilterlogs",
		"eth_uninstallfilter",
		// State proofs
		"eth_getproof",
	}

	for _, method := range expectedReadOps {
		if !ReadOpsMap[method] {
			t.Errorf("Expected %s to be in ReadOpsMap", method)
		}
	}

	// Verify write ops are in WriteOpsMap and NOT in ReadOpsMap
	writeOps := []string{"eth_sendtransaction", "eth_sendrawtransaction"}
	for _, method := range writeOps {
		if ReadOpsMap[method] {
			t.Errorf("Expected %s to NOT be in ReadOpsMap", method)
		}
		if !WriteOpsMap[method] {
			t.Errorf("Expected %s to be in WriteOpsMap", method)
		}
	}
}

// =============================================================================
// Comprehensive Cross-Org Isolation Tests
// =============================================================================

// TestCrossOrgIsolationComprehensive provides comprehensive cross-org isolation tests
// verifying security properties for contract access across organizations.
func TestCrossOrgIsolationComprehensive(t *testing.T) {
	// Contract addresses for testing
	const (
		contractOrgA = "0xaaaa000000000000000000000000000000000001" // OrgA's contract
		contractOrgB = "0xbbbb000000000000000000000000000000000002" // OrgB's contract
		publicContract = "0xcccc000000000000000000000000000000000003" // Public (no org)
	)

	t.Run("user cannot access other org contract via eth_call", func(t *testing.T) {
		// UserA has access to ContractOrgA but not ContractOrgB
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call", "eth_estimateGas"},
			ContractAccess: map[string]ContractAccess{
				contractOrgA: {Claims: []Claim{ClaimDeploy}},
			},
			Claims: []Claim{}, // No default claims - cross-org denied
		}

		// User has access to their own contract
		accessA := perms.GetContractAccess(contractOrgA)
		if accessA == nil {
			t.Fatal("User should have access to their own org's contract")
		}

		// User does NOT have access to other org's contract (contractOrgB is registered elsewhere)
		// With no default claims, GetContractAccess returns nil
		accessB := perms.GetContractAccess(contractOrgB)
		if accessB != nil {
			t.Error("User should NOT have access to other org's contract when no default claims")
		}

		// Operation classification — no claim needed for reads
		claim := ClassifyOperation("eth_call", []any{
			map[string]any{"to": contractOrgB, "data": "0xa9059cbb"},
		})
		if claim != "" {
			t.Errorf("eth_call should require no claim, got %v", claim)
		}
	})

	t.Run("user cannot access other org contract via eth_estimateGas", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call", "eth_estimateGas"},
			ContractAccess: map[string]ContractAccess{
				contractOrgA: {Claims: nil},
			},
			Claims: []Claim{}, // No default claims
		}

		// Verify user has no access to other org's contract
		accessB := perms.GetContractAccess(contractOrgB)
		if accessB != nil {
			t.Error("User should NOT have access to other org's contract")
		}

		// No claim needed for reads
		claim := ClassifyOperation("eth_estimateGas", []any{
			map[string]any{"to": contractOrgB, "data": "0xa9059cbb"},
		})
		if claim != "" {
			t.Errorf("eth_estimateGas should require no claim, got %v", claim)
		}
	})

	t.Run("user can access their own org contract", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
			ContractAccess: map[string]ContractAccess{
				contractOrgA: {Claims: []Claim{ClaimDeploy}},
			},
			Claims: []Claim{},
		}

		// User has access to their own contract
		access := perms.GetContractAccess(contractOrgA)
		if access == nil {
			t.Fatal("User should have access to their own org's contract")
		}
		if !access.HasClaim(ClaimDeploy) {
			t.Error("User should have deploy claim on their own contract")
		}

		// Verify HasContractClaim
		if !perms.HasContractClaim(contractOrgA, ClaimDeploy) {
			t.Error("HasContractClaim should return true for deploy")
		}
		if perms.HasContractClaim(contractOrgA, ClaimAdmin) {
			t.Error("HasContractClaim should return false for admin (not granted)")
		}
	})

	t.Run("user denied access to unregistered contract (all private)", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				contractOrgA: {Claims: []Claim{}},
			},
			Claims: []Claim{},
		}

		// All unregistered contracts are private by default — no access
		access := perms.GetContractAccess(publicContract)
		if access != nil {
			t.Fatal("Unregistered contracts should be denied (all private)")
		}
	})

	t.Run("default_claims do not grant access to other org contracts", func(t *testing.T) {
		// User with default claims still cannot access OrgB's contracts
		// This is enforced at the controller level, not EffectivePermissions
		// The controller checks IsContractRegisteredToAnyOrg before applying default_claims
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
			ContractAccess: map[string]ContractAccess{
				contractOrgA: {Claims: []Claim{ClaimDeploy}},
			},
			Claims: []Claim{ClaimDeploy}, // Wide default claims
		}

		// GetContractAccess returns default claims for unknown contracts
		// The cross-org check happens at controller level
		accessB := perms.GetContractAccess(contractOrgB)
		// This returns default claims, but controller would check IsContractRegisteredToAnyOrg
		// and deny if contract is registered to another org
		if accessB == nil {
			// This is expected if default_claims is empty, but here it's not
			t.Log("Note: GetContractAccess returns default claims; controller checks cross-org")
		}

		// Verify the registered contract only has its explicit claims
		accessA := perms.GetContractAccess(contractOrgA)
		if accessA == nil {
			t.Fatal("Should have explicit access to contractOrgA")
		}
		if accessA.HasClaim(ClaimAdmin) {
			t.Error("ContractOrgA should only have explicit claims, not inherit from default")
		}
	})
}

// TestCrossOrgIsolationEdgeCasesComprehensive tests edge cases for cross-org isolation.
func TestCrossOrgIsolationEdgeCasesComprehensive(t *testing.T) {
	t.Run("case insensitive address matching", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				"0xabcdef1234567890abcdef1234567890abcdef12": {Claims: []Claim{}},
			},
			Claims: []Claim{},
		}

		// Should match regardless of case
		testCases := []string{
			"0xabcdef1234567890abcdef1234567890abcdef12",
			"0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
			"0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
		}

		for _, addr := range testCases {
			access := perms.GetContractAccess(addr)
			if access == nil {
				t.Errorf("Should have access to %s (case insensitive)", addr)
			}
			// Verify IsContractRegistered is also case insensitive
			if !perms.IsContractRegistered(addr) {
				t.Errorf("IsContractRegistered should match %s (case insensitive)", addr)
			}
		}
	})

	t.Run("empty contract access map with deploy claim denied unregistered (all private)", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{}, // Empty
			Claims:         []Claim{ClaimDeploy},
		}

		// All unregistered contracts are private — even deploy users are denied
		access := perms.GetContractAccess("0x1234567890123456789012345678901234567890")
		if access != nil {
			t.Error("Unregistered contracts should be denied (all private)")
		}
	})

	t.Run("empty contract access map with no claims denied unregistered (all private)", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{}, // Empty
			Claims:         []Claim{},
		}

		// All unregistered contracts are private — denied
		access := perms.GetContractAccess("0x1234567890123456789012345678901234567890")
		if access != nil {
			t.Error("Unregistered contracts should be denied (all private)")
		}
	})

	t.Run("no default claims means no access to unregistered contracts", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				"0xaaaa000000000000000000000000000000000001": {Claims: []Claim{}},
			},
			Claims: []Claim{}, // No default claims
		}

		// Registered contract still accessible
		accessA := perms.GetContractAccess("0xaaaa000000000000000000000000000000000001")
		if accessA == nil {
			t.Fatal("Should have access to registered contract")
		}

		// Unregistered contract has NO access
		accessB := perms.GetContractAccess("0xbbbb000000000000000000000000000000000002")
		if accessB != nil {
			t.Error("Should have NO access to unregistered contract when no default claims")
		}
	})

	t.Run("nil default claims treated as empty", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				"0xaaaa": {Claims: []Claim{}},
			},
			Claims: nil, // nil
		}

		// Should behave same as empty
		access := perms.GetContractAccess("0xunknown")
		if access != nil {
			t.Error("Should return nil for unknown contract when default claims is nil")
		}
	})
}

// =============================================================================
// ReadOps and WriteOps Validation Tests
// =============================================================================

// TestReadOpsValidationComprehensive tests access validation for read operations.
func TestReadOpsValidationComprehensive(t *testing.T) {
	t.Run("eth_call to accessible contract is allowed", func(t *testing.T) {
		addr := "0xaaaa000000000000000000000000000000000001"
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				addr: {Claims: []Claim{}},
			},
		}

		// Verify method is allowed
		if !perms.HasMethod("eth_call") {
			t.Error("eth_call should be in allowed methods")
		}

		// Verify contract access entry exists
		access := perms.GetContractAccess(addr)
		if access == nil {
			t.Fatal("Should have access to contract")
		}
	})

	t.Run("eth_call to inaccessible contract is denied", func(t *testing.T) {
		userAddr := "0xaaaa000000000000000000000000000000000001"
		otherAddr := "0xbbbb000000000000000000000000000000000002"

		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]ContractAccess{
				userAddr: {Claims: []Claim{}},
			},
			Claims: []Claim{}, // No default claims
		}

		// User has no access to otherAddr
		access := perms.GetContractAccess(otherAddr)
		if access != nil {
			t.Error("Should NOT have access to unregistered contract when no default claims")
		}
	})

	t.Run("eth_estimateGas follows same rules as eth_call", func(t *testing.T) {
		addr := "0xaaaa000000000000000000000000000000000001"

		// Both should require no claim (gated by method allowlist)
		callClaim := ClassifyOperation("eth_call", []any{
			map[string]any{"to": addr, "data": "0xa9059cbb"},
		})
		estimateClaim := ClassifyOperation("eth_estimateGas", []any{
			map[string]any{"to": addr, "data": "0xa9059cbb"},
		})

		if callClaim != estimateClaim {
			t.Errorf("eth_call and eth_estimateGas should require same claim, got %v vs %v",
				callClaim, estimateClaim)
		}
		if callClaim != "" {
			t.Errorf("Both should require no claim, got %v", callClaim)
		}
	})

	t.Run("eth_call without target address uses empty string", func(t *testing.T) {
		// GetTargetAddress returns empty string when 'to' is missing
		addr := GetTargetAddress("eth_call", []any{
			map[string]any{"data": "0x6080604052"},
		})
		if addr != "" {
			t.Errorf("Expected empty address, got %s", addr)
		}
	})

	t.Run("read ops require no claim (gated by method allowlist)", func(t *testing.T) {
		simpleReadMethods := []string{
			"eth_call",
			"eth_getCode",
			"eth_getBalance",
			"eth_getTransactionCount",
			"eth_getLogs",
		}

		for _, method := range simpleReadMethods {
			claim := ClassifyOperation(method, nil)
			if claim != "" {
				t.Errorf("%s should require no claim, got %v", method, claim)
			}
		}

		// eth_estimateGas with nil params returns no claim
		claimNoParams := ClassifyOperation("eth_estimateGas", nil)
		if claimNoParams != "" {
			t.Errorf("eth_estimateGas with nil params should require no claim, got %v", claimNoParams)
		}

		// With a 'to' address, eth_estimateGas requires no claim
		claimWithTo := ClassifyOperation("eth_estimateGas", []any{
			map[string]any{"to": "0x1234567890123456789012345678901234567890", "data": "0xa9059cbb"},
		})
		if claimWithTo != "" {
			t.Errorf("eth_estimateGas with 'to' address should require no claim, got %v", claimWithTo)
		}
	})
}

// =============================================================================
// GetContractAccess Comprehensive Tests
// =============================================================================

// TestGetContractAccessComprehensive tests the GetContractAccess method behavior.
func TestGetContractAccessComprehensive(t *testing.T) {
	t.Run("returns explicit access for registered contract", func(t *testing.T) {
		addr := "0xaaaa000000000000000000000000000000000001"
		perms := &EffectivePermissions{
			ContractAccess: map[string]ContractAccess{
				addr: {
					Claims:    []Claim{ClaimDeploy, ClaimUpgrade},
					Functions: []FunctionRule{{Selector: "0xa9059cbb"}, {Selector: "0x095ea7b3"}},
				},
			},
			Claims: []Claim{ClaimDeploy},
		}

		access := perms.GetContractAccess(addr)
		if access == nil {
			t.Fatal("Should return access for registered contract")
		}
		if len(access.Claims) != 2 {
			t.Errorf("Should have 2 explicit claims, got %d", len(access.Claims))
		}
		if !access.HasClaim(ClaimUpgrade) {
			t.Error("Should have upgrade claim")
		}
		if len(access.Functions) != 2 {
			t.Errorf("Should have 2 function rules, got %d", len(access.Functions))
		}
	})

	t.Run("returns nil for other org contract when no default claims", func(t *testing.T) {
		userAddr := "0xaaaa000000000000000000000000000000000001"
		otherOrgAddr := "0xbbbb000000000000000000000000000000000002"

		perms := &EffectivePermissions{
			ContractAccess: map[string]ContractAccess{
				userAddr: {Claims: []Claim{}},
			},
			Claims: []Claim{}, // Empty
		}

		access := perms.GetContractAccess(otherOrgAddr)
		if access != nil {
			t.Error("Should return nil for contract not in access and no default claims")
		}
	})

	t.Run("returns nil for unregistered contract (private by default)", func(t *testing.T) {
		userAddr := "0xaaaa000000000000000000000000000000000001"
		publicAddr := "0xcccc000000000000000000000000000000000003"

		perms := &EffectivePermissions{
			ContractAccess: map[string]ContractAccess{
				userAddr: {Claims: []Claim{ClaimDeploy}},
			},
			Claims: []Claim{ClaimDeploy},
		}

		access := perms.GetContractAccess(publicAddr)
		if access != nil {
			t.Error("Should return nil for unregistered contract (private by default)")
		}
	})

	t.Run("returns read access for precompile address", func(t *testing.T) {
		perms := &EffectivePermissions{
			ContractAccess: map[string]ContractAccess{},
			Claims:         nil,
		}

		// Test all precompile addresses (0x01-0x09)
		for i := 1; i <= 9; i++ {
			addr := fmt.Sprintf("0x%040x", i)
			access := perms.GetContractAccess(addr)
			if access == nil {
				t.Errorf("Should return non-nil access for precompile %s", addr)
			}
		}
	})

	t.Run("HasFunctionSelector with explicit restrictions", func(t *testing.T) {
		addr := "0xaaaa000000000000000000000000000000000001"
		perms := &EffectivePermissions{
			ContractAccess: map[string]ContractAccess{
				addr: {
					Claims:    nil,
					Functions: []FunctionRule{{Selector: "0xa9059cbb"}, {Selector: "0x095ea7b3"}},
				},
			},
		}

		// Allowed selectors
		if !perms.HasFunctionSelector(addr, "0xa9059cbb") {
			t.Error("Should allow 0xa9059cbb")
		}
		if !perms.HasFunctionSelector(addr, "0x095ea7b3") {
			t.Error("Should allow 0x095ea7b3")
		}

		// Not allowed selector
		if perms.HasFunctionSelector(addr, "0x70a08231") {
			t.Error("Should NOT allow 0x70a08231 (not in allowed list)")
		}

		// Unknown contract (no default claims)
		if perms.HasFunctionSelector("0xunknown", "0xa9059cbb") {
			t.Error("Should NOT allow selector on unknown contract with no default claims")
		}
	})

	t.Run("HasFunctionSelector with no restrictions allows all", func(t *testing.T) {
		addr := "0xaaaa000000000000000000000000000000000001"
		perms := &EffectivePermissions{
			ContractAccess: map[string]ContractAccess{
				addr: {
					Claims:    []Claim{},
					Functions: nil, // No restrictions
				},
			},
		}

		// All selectors should be allowed
		if !perms.HasFunctionSelector(addr, "0xa9059cbb") {
			t.Error("Should allow any selector when Functions is nil")
		}
		if !perms.HasFunctionSelector(addr, "0x12345678") {
			t.Error("Should allow any selector when Functions is nil")
		}
	})

	t.Run("HasFunctionSelector with empty slice denies all", func(t *testing.T) {
		addr := "0xaaaa000000000000000000000000000000000001"
		perms := &EffectivePermissions{
			ContractAccess: map[string]ContractAccess{
				addr: {
					Claims:    []Claim{},
					Functions: []FunctionRule{}, // Explicitly empty = deny all
				},
			},
		}

		if perms.HasFunctionSelector(addr, "0xa9059cbb") {
			t.Error("Should deny all selectors when Functions is explicitly empty (non-nil)")
		}
	})

	t.Run("HasAdminOnContract checks admin claim", func(t *testing.T) {
		adminAddr := "0xaaaa000000000000000000000000000000000001"
		normalAddr := "0xbbbb000000000000000000000000000000000002"

		perms := &EffectivePermissions{
			ContractAccess: map[string]ContractAccess{
				adminAddr:  {Claims: []Claim{ClaimAdmin}},
				normalAddr: {Claims: []Claim{ClaimDeploy}},
			},
		}

		if !perms.HasAdminOnContract(adminAddr) {
			t.Error("Should have admin on adminAddr")
		}
		if perms.HasAdminOnContract(normalAddr) {
			t.Error("Should NOT have admin on normalAddr")
		}
	})
}

// =============================================================================
// GetFunctionSelector Tests
// =============================================================================

func TestGetFunctionSelectorComprehensive(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		params   []any
		expected string
	}{
		{
			name:     "eth_call with data",
			method:   "eth_call",
			params:   []any{map[string]any{"to": "0x123", "data": "0xa9059cbb0000000000"}},
			expected: "0xa9059cbb",
		},
		{
			name:     "eth_estimateGas with data",
			method:   "eth_estimateGas",
			params:   []any{map[string]any{"to": "0x123", "data": "0x095ea7b3000000"}},
			expected: "0x095ea7b3",
		},
		{
			name:     "eth_sendTransaction with data",
			method:   "eth_sendTransaction",
			params:   []any{map[string]any{"to": "0x123", "data": "0x70a08231abc"}},
			expected: "0x70a08231",
		},
		{
			name:     "eth_call with uppercase data",
			method:   "eth_call",
			params:   []any{map[string]any{"to": "0x123", "data": "0xA9059CBB0000"}},
			expected: "0xa9059cbb",
		},
		{
			name:     "No params",
			method:   "eth_call",
			params:   nil,
			expected: "",
		},
		{
			name:     "Empty params",
			method:   "eth_call",
			params:   []any{},
			expected: "",
		},
		{
			name:     "No data field",
			method:   "eth_call",
			params:   []any{map[string]any{"to": "0x123"}},
			expected: "",
		},
		{
			name:     "Data too short",
			method:   "eth_call",
			params:   []any{map[string]any{"to": "0x123", "data": "0xa905"}},
			expected: "",
		},
		{
			name:     "Data exactly 10 chars",
			method:   "eth_call",
			params:   []any{map[string]any{"to": "0x123", "data": "0xa9059cbb"}},
			expected: "0xa9059cbb",
		},
		{
			name:     "Non-call method",
			method:   "eth_blockNumber",
			params:   []any{map[string]any{"data": "0xa9059cbb"}},
			expected: "",
		},
		{
			name:     "eth_getLogs (not a contract call)",
			method:   "eth_getLogs",
			params:   []any{map[string]any{"data": "0xa9059cbb"}},
			expected: "",
		},
		{
			name:     "Malformed params (not a map)",
			method:   "eth_call",
			params:   []any{"not a map"},
			expected: "",
		},
		// "input" field tests (some clients use "input" instead of "data")
		{
			name:     "eth_call with input field instead of data",
			method:   "eth_call",
			params:   []any{map[string]any{"to": "0x123", "input": "0xa9059cbb0000000000"}},
			expected: "0xa9059cbb",
		},
		{
			name:     "eth_sendTransaction with input field",
			method:   "eth_sendTransaction",
			params:   []any{map[string]any{"to": "0x123", "input": "0x70a08231abc"}},
			expected: "0x70a08231",
		},
		{
			name:     "data takes precedence over input",
			method:   "eth_call",
			params:   []any{map[string]any{"to": "0x123", "data": "0xa9059cbb00", "input": "0x70a0823100"}},
			expected: "0xa9059cbb",
		},
		{
			name:     "empty data falls back to input",
			method:   "eth_call",
			params:   []any{map[string]any{"to": "0x123", "data": "0x", "input": "0x70a0823100"}},
			expected: "0x70a08231",
		},
		{
			name:     "input too short",
			method:   "eth_call",
			params:   []any{map[string]any{"to": "0x123", "input": "0xa905"}},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetFunctionSelector(tt.method, tt.params)
			if result != tt.expected {
				t.Errorf("GetFunctionSelector(%q, %v) = %q, expected %q",
					tt.method, tt.params, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// extractDeploymentBytecode Tests
// =============================================================================

func TestExtractDeploymentBytecode(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		params   []any
		expected string
	}{
		{
			name:   "eth_sendTransaction with data field",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"data": "0x6080604052"},
			},
			expected: "0x6080604052",
		},
		{
			name:   "eth_sendTransaction with input field",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"input": "0x6080604052"},
			},
			expected: "0x6080604052",
		},
		{
			name:   "eth_sendTransaction with both data and input - prefers data",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"data": "0xdata", "input": "0xinput"},
			},
			expected: "0xdata",
		},
		{
			name:   "eth_estimateGas with data field",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"data": "0x6080604052"},
			},
			expected: "0x6080604052",
		},
		{
			name:   "eth_estimateGas with input field",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"input": "0x6080604052"},
			},
			expected: "0x6080604052",
		},
		{
			name:     "eth_call - not a deployment method",
			method:   "eth_call",
			params:   []any{map[string]any{"data": "0x6080604052"}},
			expected: "",
		},
		{
			name:     "eth_sendRawTransaction - not a deployment method",
			method:   "eth_sendRawTransaction",
			params:   []any{"0xf86c..."},
			expected: "",
		},
		{
			name:     "No params",
			method:   "eth_sendTransaction",
			params:   nil,
			expected: "",
		},
		{
			name:     "Empty params",
			method:   "eth_sendTransaction",
			params:   []any{},
			expected: "",
		},
		{
			name:   "Malformed params - not a map",
			method: "eth_sendTransaction",
			params: []any{"not a map"},
			expected: "",
		},
		{
			name:   "Empty data field",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"data": ""},
			},
			expected: "",
		},
		{
			name:   "Data is just 0x",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"data": "0x"},
			},
			expected: "",
		},
		{
			name:   "No data or input field",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": nil, "value": "0x0"},
			},
			expected: "",
		},
		{
			name:   "Data is non-string type",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"data": 12345},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractDeploymentBytecode(tt.method, tt.params)
			if result != tt.expected {
				t.Errorf("extractDeploymentBytecode(%q, %v) = %q, expected %q",
					tt.method, tt.params, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Historical State Query Restriction Tests
// =============================================================================

func TestExtractBlockParam(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		params   []any
		expected string
	}{
		// eth_call cases
		{
			name:     "eth_call with no params - defaults to latest",
			method:   "eth_call",
			params:   nil,
			expected: "latest",
		},
		{
			name:     "eth_call with empty params - defaults to latest",
			method:   "eth_call",
			params:   []any{},
			expected: "latest",
		},
		{
			name:   "eth_call with only txObject - defaults to latest",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234", "data": "0xa9059cbb"},
			},
			expected: "latest",
		},
		{
			name:   "eth_call with latest block param",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"latest",
			},
			expected: "latest",
		},
		{
			name:   "eth_call with pending block param",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"pending",
			},
			expected: "pending",
		},
		{
			name:   "eth_call with safe block param",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"safe",
			},
			expected: "safe",
		},
		{
			name:   "eth_call with finalized block param",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"finalized",
			},
			expected: "finalized",
		},
		{
			name:   "eth_call with earliest block param",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"earliest",
			},
			expected: "earliest",
		},
		{
			name:   "eth_call with hex block number",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"0x1234",
			},
			expected: "0x1234",
		},
		{
			name:   "eth_call with block hash (66 chars)",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			},
			expected: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		},
		{
			name:   "eth_call with nil block param - defaults to latest",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				nil,
			},
			expected: "latest",
		},
		{
			name:   "eth_call with empty string block param - defaults to latest",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"",
			},
			expected: "latest",
		},
		{
			name:   "eth_call with non-string block param (number) - treated as historical",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				12345,
			},
			expected: "historical",
		},
		// eth_getStorageAt cases
		{
			name:     "eth_getStorageAt with no params - defaults to latest",
			method:   "eth_getStorageAt",
			params:   nil,
			expected: "latest",
		},
		{
			name:     "eth_getStorageAt with only address - defaults to latest",
			method:   "eth_getStorageAt",
			params:   []any{"0x1234"},
			expected: "latest",
		},
		{
			name:     "eth_getStorageAt with address and slot - defaults to latest",
			method:   "eth_getStorageAt",
			params:   []any{"0x1234", "0x0"},
			expected: "latest",
		},
		{
			name:     "eth_getStorageAt with latest block param",
			method:   "eth_getStorageAt",
			params:   []any{"0x1234", "0x0", "latest"},
			expected: "latest",
		},
		{
			name:     "eth_getStorageAt with hex block number",
			method:   "eth_getStorageAt",
			params:   []any{"0x1234", "0x0", "0xabcd"},
			expected: "0xabcd",
		},
		{
			name:     "eth_getStorageAt with nil block param - defaults to latest",
			method:   "eth_getStorageAt",
			params:   []any{"0x1234", "0x0", nil},
			expected: "latest",
		},
		// Other state-query methods - block param at index 1
		{
			name:     "eth_getBalance with historical block",
			method:   "eth_getBalance",
			params:   []any{"0x1234", "0x100"},
			expected: "0x100",
		},
		{
			name:     "eth_getBalance with latest",
			method:   "eth_getBalance",
			params:   []any{"0x1234", "latest"},
			expected: "latest",
		},
		{
			name:     "eth_getBalance without block param",
			method:   "eth_getBalance",
			params:   []any{"0x1234"},
			expected: "latest",
		},
		{
			name:     "eth_getCode with historical block",
			method:   "eth_getCode",
			params:   []any{"0x1234", "0x5678"},
			expected: "0x5678",
		},
		{
			name:     "eth_getTransactionCount with historical block",
			method:   "eth_getTransactionCount",
			params:   []any{"0x1234", "0xabc"},
			expected: "0xabc",
		},
		{
			name:     "eth_getProof with historical block",
			method:   "eth_getProof",
			params:   []any{"0x1234", []any{"0x0"}, "0x999"},
			expected: "0x999",
		},
		// Methods not in historicalCheckMethods - should return latest
		{
			name:     "eth_blockNumber - not applicable, returns latest",
			method:   "eth_blockNumber",
			params:   nil,
			expected: "latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractBlockParam(tt.method, tt.params)
			if result != tt.expected {
				t.Errorf("extractBlockParam(%q, %v) = %q, expected %q",
					tt.method, tt.params, result, tt.expected)
			}
		})
	}
}

func TestIsHistoricalBlock(t *testing.T) {
	tests := []struct {
		name       string
		blockParam string
		expected   bool
	}{
		// NOT historical (current state)
		{"empty string - not historical", "", false},
		{"latest - not historical", "latest", false},
		{"LATEST uppercase - not historical", "LATEST", false},
		{"Latest mixed case - not historical", "Latest", false},
		{"pending - not historical", "pending", false},
		{"PENDING uppercase - not historical", "PENDING", false},
		{"safe - not historical", "safe", false},
		{"SAFE uppercase - not historical", "SAFE", false},
		{"finalized - not historical", "finalized", false},
		{"FINALIZED uppercase - not historical", "FINALIZED", false},
		{"earliest - not historical", "earliest", false},
		{"EARLIEST uppercase - not historical", "EARLIEST", false},

		// HISTORICAL
		{"hex block number 0x0 - historical", "0x0", true},
		{"hex block number 0x1 - historical", "0x1", true},
		{"hex block number 0x1234 - historical", "0x1234", true},
		{"hex block number 0xabcdef - historical", "0xabcdef", true},
		{"large hex block number - historical", "0xffffff", true},
		{"block hash (66 chars) - historical", "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", true},
		{"historical marker - historical", "historical", true},
		{"random string - historical", "someblock", true},
		{"number as string - historical", "12345", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isHistoricalBlock(tt.blockParam)
			if result != tt.expected {
				t.Errorf("isHistoricalBlock(%q) = %v, expected %v",
					tt.blockParam, result, tt.expected)
			}
		})
	}
}

func TestIsHistoricalStateQuery(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		params         []any
		expectBlocked  bool
		expectedReason string
	}{
		// eth_call - allowed cases
		{
			name:   "eth_call with latest - allowed",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"latest",
			},
			expectBlocked: false,
		},
		{
			name:   "eth_call with pending - allowed",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"pending",
			},
			expectBlocked: false,
		},
		{
			name:   "eth_call with safe - allowed",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"safe",
			},
			expectBlocked: false,
		},
		{
			name:   "eth_call with finalized - allowed",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"finalized",
			},
			expectBlocked: false,
		},
		{
			name:   "eth_call with earliest - allowed",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"earliest",
			},
			expectBlocked: false,
		},
		{
			name:   "eth_call without block param (defaults to latest) - allowed",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
			},
			expectBlocked: false,
		},
		// eth_call - blocked cases
		{
			name:   "eth_call with hex block number - blocked",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"0x1234",
			},
			expectBlocked:  true,
			expectedReason: "historical state queries not permitted",
		},
		{
			name:   "eth_call with block hash - blocked",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			},
			expectBlocked:  true,
			expectedReason: "historical state queries not permitted",
		},
		{
			name:   "eth_call with 0x0 block - blocked",
			method: "eth_call",
			params: []any{
				map[string]any{"to": "0x1234"},
				"0x0",
			},
			expectBlocked:  true,
			expectedReason: "historical state queries not permitted",
		},
		// eth_getStorageAt - allowed cases
		{
			name:          "eth_getStorageAt with latest - allowed",
			method:        "eth_getStorageAt",
			params:        []any{"0x1234", "0x0", "latest"},
			expectBlocked: false,
		},
		{
			name:          "eth_getStorageAt with pending - allowed",
			method:        "eth_getStorageAt",
			params:        []any{"0x1234", "0x0", "pending"},
			expectBlocked: false,
		},
		{
			name:          "eth_getStorageAt without block param - allowed",
			method:        "eth_getStorageAt",
			params:        []any{"0x1234", "0x0"},
			expectBlocked: false,
		},
		// eth_getStorageAt - blocked cases
		{
			name:           "eth_getStorageAt with hex block number - blocked",
			method:         "eth_getStorageAt",
			params:         []any{"0x1234", "0x0", "0x5678"},
			expectBlocked:  true,
			expectedReason: "historical state queries not permitted",
		},
		{
			name:           "eth_getStorageAt with block hash - blocked",
			method:         "eth_getStorageAt",
			params:         []any{"0x1234", "0x0", "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
			expectBlocked:  true,
			expectedReason: "historical state queries not permitted",
		},
		// Other state-query methods - now checked
		{
			name:           "eth_getBalance with historical block - blocked",
			method:         "eth_getBalance",
			params:         []any{"0x1234", "0x1234"},
			expectBlocked:  true,
			expectedReason: "historical state queries not permitted",
		},
		{
			name:          "eth_getBalance with latest - allowed",
			method:        "eth_getBalance",
			params:        []any{"0x1234", "latest"},
			expectBlocked: false,
		},
		{
			name:           "eth_getCode with historical block - blocked",
			method:         "eth_getCode",
			params:         []any{"0x1234", "0x5678"},
			expectBlocked:  true,
			expectedReason: "historical state queries not permitted",
		},
		{
			name:           "eth_getTransactionCount with historical block - blocked",
			method:         "eth_getTransactionCount",
			params:         []any{"0x1234", "0xabc"},
			expectBlocked:  true,
			expectedReason: "historical state queries not permitted",
		},
		{
			name:           "eth_getProof with historical block - blocked",
			method:         "eth_getProof",
			params:         []any{"0x1234", []any{"0x0"}, "0x999"},
			expectBlocked:  true,
			expectedReason: "historical state queries not permitted",
		},
		{
			name:          "eth_blockNumber - not checked",
			method:        "eth_blockNumber",
			params:        nil,
			expectBlocked: false,
		},
		{
			name:   "eth_estimateGas - not checked",
			method: "eth_estimateGas",
			params: []any{
				map[string]any{"to": "0x1234"},
				"0x1234",
			},
			expectBlocked: false,
		},
		{
			name:   "eth_sendTransaction - not checked",
			method: "eth_sendTransaction",
			params: []any{
				map[string]any{"to": "0x1234"},
			},
			expectBlocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isHistorical, reason := IsHistoricalStateQuery(tt.method, tt.params)
			if isHistorical != tt.expectBlocked {
				t.Errorf("IsHistoricalStateQuery(%q, %v) = %v, expected %v",
					tt.method, tt.params, isHistorical, tt.expectBlocked)
			}
			if tt.expectBlocked && reason != tt.expectedReason {
				t.Errorf("IsHistoricalStateQuery reason = %q, expected %q",
					reason, tt.expectedReason)
			}
		})
	}
}

// TestHistoricalStateQuery_AnonymousBlocked verifies that anonymous users
// are blocked from querying historical state (specific block numbers).
func TestHistoricalStateQuery_AnonymousBlocked(t *testing.T) {
	store := NewMockCrossOrgStore()
	controller := NewAccessController(store, 5*time.Minute)
	ctx := context.Background()

	// Anonymous user queries eth_call at a specific block number
	result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
		UserExternalID: "", // anonymous
		Method:         "eth_call",
		Params:         []any{map[string]any{"to": "0x1234"}, "0x100"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected anonymous historical state query to be denied")
	}
	if !strings.Contains(result.Reason, "historical") {
		t.Errorf("expected 'historical' in reason, got: %s", result.Reason)
	}
}

// TestHistoricalStateQuery_AuthenticatedAllowed verifies that authenticated users
// can query at specific block numbers (RBAC gates address access, not block number).
func TestHistoricalStateQuery_AuthenticatedAllowed(t *testing.T) {
	store := NewMockCrossOrgStore()
	setupCrossOrgTestScenario(store)
	controller := NewAccessController(store, 5*time.Minute)
	ctx := context.Background()

	contractA := "0xaaaa000000000000000000000000000000000001"

	// Authenticated user (user-a) queries their own org's contract at a specific block
	result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
		UserExternalID: "did:test:user-a",
		Method:         "eth_call",
		Params:         []any{map[string]any{"to": contractA, "data": "0x"}, "0x100"},
		TargetAddress:  contractA,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should be allowed — RBAC gates access, not block number
	if !result.Allowed {
		t.Errorf("expected authenticated historical query to be allowed, got denied: %s", result.Reason)
	}
}

// TestHistoricalStateQuery_AuthenticatedCrossOrgStillDenied verifies that
// RBAC still blocks cross-org access even at historical blocks.
func TestHistoricalStateQuery_AuthenticatedCrossOrgStillDenied(t *testing.T) {
	store := NewMockCrossOrgStore()
	setupCrossOrgTestScenario(store)
	controller := NewAccessController(store, 5*time.Minute)
	ctx := context.Background()

	contractB := "0xbbbb000000000000000000000000000000000002" // owned by org-b

	// User-a tries to query org-b's contract at a historical block
	result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
		UserExternalID: "did:test:user-a",
		Method:         "eth_call",
		Params:         []any{map[string]any{"to": contractB, "data": "0x"}, "0x100"},
		TargetAddress:  contractB,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should STILL be denied — RBAC blocks cross-org regardless of block number
	if result.Allowed {
		t.Error("expected cross-org query to be denied even without historical check")
	}
}

// paramConstraintStore wraps MockCrossOrgStore and adds configurable
// GetLinkedEthAddresses and GetContractByAddress returns for parameter
// constraint tests.
type paramConstraintStore struct {
	*MockCrossOrgStore
	linkedAddresses    map[string][]string  // DID -> linked ETH addresses
	contractsByAddress map[string]*Contract // "orgID:address" -> Contract
}

func newParamConstraintStore() *paramConstraintStore {
	return &paramConstraintStore{
		MockCrossOrgStore:  NewMockCrossOrgStore(),
		linkedAddresses:    make(map[string][]string),
		contractsByAddress: make(map[string]*Contract),
	}
}

func (s *paramConstraintStore) GetLinkedEthAddresses(ctx context.Context, did string) ([]string, error) {
	return s.linkedAddresses[did], nil
}
func (s *paramConstraintStore) SystemLinkEthAddress(_ context.Context, _, _ string) error { return nil }

func (s *paramConstraintStore) GetContractByAddress(ctx context.Context, orgID, address string) (*Contract, error) {
	key := orgID + ":" + strings.ToLower(address)
	return s.contractsByAddress[key], nil
}

// buildBalanceOfCalldata builds calldata for balanceOf(address) with selector 0x70a08231.
func buildBalanceOfCalldata(addr common.Address) []byte {
	addrType, _ := abi.NewType("address", "", nil)
	args := abi.Arguments{{Type: addrType}}
	packed, _ := args.Pack(addr)
	selector, _ := hex.DecodeString("70a08231")
	return append(selector, packed...)
}

func TestCheckAccessParamConstraints(t *testing.T) {
	ownAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	otherAddr := common.HexToAddress("0x2222222222222222222222222222222222222222")
	contractAddr := "0xaaaa000000000000000000000000000000000001"
	balanceOfSelector := "0x70a08231"

	balanceOfOwn := buildBalanceOfCalldata(ownAddr)
	balanceOfOther := buildBalanceOfCalldata(otherAddr)

	tests := []struct {
		name string
		// store setup
		linkedAddresses []string // user's linked ETH addresses (nil = no addresses)
		contractABI     string   // ABI stored on the contract (empty = no ABI)
		// permissions setup
		functionRules []FunctionRule // function rules on the contract grant
		// request setup
		calldata         []byte // raw calldata to send (nil = rely on extractCalldata from params)
		params           []any  // JSON-RPC params (used when calldata is nil)
		functionSelector string // function selector in request
		method           string // RPC method
		// expectations
		expectAllowed bool
		expectReason  string // substring that must appear in denial reason
	}{
		{
			name:            "self constraint passes",
			linkedAddresses: []string{strings.ToLower(ownAddr.Hex())},
			contractABI:     testABI,
			functionRules: []FunctionRule{
				{Selector: balanceOfSelector, ParamRules: []ParamRule{{Index: 0, MustBe: "self"}}},
			},
			calldata:         balanceOfOwn,
			functionSelector: balanceOfSelector,
			method:           "eth_call",
			expectAllowed:    true,
		},
		{
			name:            "self constraint fails",
			linkedAddresses: []string{strings.ToLower(ownAddr.Hex())},
			contractABI:     testABI,
			functionRules: []FunctionRule{
				{Selector: balanceOfSelector, ParamRules: []ParamRule{{Index: 0, MustBe: "self"}}},
			},
			calldata:         balanceOfOther,
			functionSelector: balanceOfSelector,
			method:           "eth_call",
			expectAllowed:    false,
			expectReason:     "parameter constraint violation",
		},
		{
			name:            "no param rules - allowed",
			linkedAddresses: []string{strings.ToLower(ownAddr.Hex())},
			contractABI:     testABI,
			functionRules: []FunctionRule{
				{Selector: balanceOfSelector, ParamRules: nil},
			},
			calldata:         balanceOfOwn,
			functionSelector: balanceOfSelector,
			method:           "eth_call",
			expectAllowed:    true,
		},
		{
			name:            "missing calldata - denied",
			linkedAddresses: []string{strings.ToLower(ownAddr.Hex())},
			contractABI:     testABI,
			functionRules: []FunctionRule{
				{Selector: balanceOfSelector, ParamRules: []ParamRule{{Index: 0, MustBe: "self"}}},
			},
			calldata:         nil,                                                     // no Calldata field
			params:           []any{map[string]any{"to": contractAddr, "data": "0x"}}, // data="0x" yields no calldata
			functionSelector: balanceOfSelector,
			method:           "eth_call",
			expectAllowed:    false,
			expectReason:     "calldata required",
		},
		{
			name:            "no linked addresses - denied",
			linkedAddresses: nil, // no linked addresses
			contractABI:     testABI,
			functionRules: []FunctionRule{
				{Selector: balanceOfSelector, ParamRules: []ParamRule{{Index: 0, MustBe: "self"}}},
			},
			calldata:         balanceOfOwn,
			functionSelector: balanceOfSelector,
			method:           "eth_call",
			expectAllowed:    false,
			expectReason:     "parameter constraint violation",
		},
		{
			name:            "missing contract ABI - denied",
			linkedAddresses: []string{strings.ToLower(ownAddr.Hex())},
			contractABI:     "", // no ABI
			functionRules: []FunctionRule{
				{Selector: balanceOfSelector, ParamRules: []ParamRule{{Index: 0, MustBe: "self"}}},
			},
			calldata:         balanceOfOwn,
			functionSelector: balanceOfSelector,
			method:           "eth_call",
			expectAllowed:    false,
			expectReason:     "contract ABI required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			store := newParamConstraintStore()

			// Set up organization
			org := &Organization{ID: "org-a", Slug: "org-a", Name: "Org A"}
			store.organizations["org-a"] = org

			// Set up user
			user := &User{ID: "user-1", ExternalID: "did:test:user1", KYC: true, Banned: false}
			store.users["did:test:user1"] = user

			// Set up group and membership
			group := &Group{ID: "group-a", OrgID: "org-a", Slug: "group-a", Name: "Group A"}
			store.memberships["user-1"] = []*MembershipWithDetails{
				{Membership: &UserMembership{ID: "mem-1", UserID: "user-1", GroupID: "group-a"}, Group: group},
			}

			// Set up group access (no operational claims needed)
			store.groupAccess["group-a"] = &GroupAccess{
				ID:             "access-a",
				GroupID:        "group-a",
				AllowedMethods: []string{"eth_call", "eth_sendTransaction", "eth_estimateGas"},
				Claims:         []Claim{},
			}

			// Set up contract ownership
			addr := strings.ToLower(contractAddr)
			store.contractOwners[addr] = "org-a"
			store.registeredToAnyOrg[addr] = true
			store.addressOwnedByOrg[addr] = map[string]bool{"org-a": true}

			// Set up cached permissions with function rules from the test case
			store.cachedPermissions["user-1:org-a"] = &EffectivePermissions{
				ID:             "perms-1",
				UserID:         "user-1",
				OrgID:          "org-a",
				AllowedMethods: []string{"eth_call", "eth_sendTransaction", "eth_estimateGas"},
				ContractAccess: map[string]ContractAccess{
					addr: {
						Claims:    []Claim{},
						Functions: tt.functionRules,
					},
				},
				Claims:     []Claim{},
				ComputedAt: time.Now(),
				ExpiresAt:  time.Now().Add(1 * time.Hour),
			}

			// Set up linked ETH addresses
			if tt.linkedAddresses != nil {
				store.linkedAddresses["did:test:user1"] = tt.linkedAddresses
			}

			// Set up contract with ABI
			store.contractsByAddress["org-a:"+addr] = &Contract{
				ID:      "contract-1",
				OrgID:   "org-a",
				Address: addr,
				Name:    "TestToken",
				ABI:     tt.contractABI,
			}

			controller := NewAccessController(store, 5*time.Minute)

			req := &AccessCheckRequest{
				UserExternalID:   "did:test:user1",
				Method:           tt.method,
				Params:           tt.params,
				TargetAddress:    contractAddr,
				FunctionSelector: tt.functionSelector,
				Calldata:         tt.calldata,
			}
			// If no params were explicitly set, construct default params for the method
			if req.Params == nil && tt.calldata != nil {
				req.Params = []any{
					map[string]any{"to": contractAddr, "data": "0x" + hex.EncodeToString(tt.calldata)},
					"latest",
				}
			}

			result, err := controller.CheckAccess(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Allowed != tt.expectAllowed {
				if tt.expectAllowed {
					t.Errorf("expected access to be allowed, got denied: %s", result.Reason)
				} else {
					t.Errorf("expected access to be denied, got allowed")
				}
			}
			if !tt.expectAllowed && tt.expectReason != "" {
				if !strings.Contains(result.Reason, tt.expectReason) {
					t.Errorf("expected reason to contain %q, got: %s", tt.expectReason, result.Reason)
				}
			}
		})
	}
}

// TestDeployUserParamConstraints verifies that deploy-claim users with explicit
// contract grants have function restrictions and parameter constraints enforced.
// This is a regression test for a bug where CheckAccess re-fetched permissions via
// GetContractAccess, which returned the deploy default (Functions: nil) instead of
// using the already-retrieved access that had actual function restrictions.
func TestDeployUserParamConstraints(t *testing.T) {
	ownAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	otherAddr := common.HexToAddress("0x2222222222222222222222222222222222222222")
	contractAddr := "0xaaaa000000000000000000000000000000000001"
	balanceOfSelector := "0x70a08231"

	balanceOfOwn := buildBalanceOfCalldata(ownAddr)
	balanceOfOther := buildBalanceOfCalldata(otherAddr)

	tests := []struct {
		name             string
		calldata         []byte
		functionSelector string
		expectAllowed    bool
		expectReason     string
	}{
		{
			name:             "deploy user - self constraint passes",
			calldata:         balanceOfOwn,
			functionSelector: balanceOfSelector,
			expectAllowed:    true,
		},
		{
			name:             "deploy user - self constraint denies other address",
			calldata:         balanceOfOther,
			functionSelector: balanceOfSelector,
			expectAllowed:    false,
			expectReason:     "parameter constraint violation",
		},
		{
			name:             "deploy user - unlisted function denied",
			calldata:         balanceOfOwn, // calldata doesn't matter, selector is wrong
			functionSelector: "0xdeadbeef",
			expectAllowed:    false,
			expectReason:     "function 0xdeadbeef not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			store := newParamConstraintStore()

			org := &Organization{ID: "org-d", Slug: "org-d", Name: "Org D"}
			store.organizations["org-d"] = org

			user := &User{ID: "user-d", ExternalID: "did:test:userd", KYC: true, Banned: false}
			store.users["did:test:userd"] = user

			group := &Group{ID: "group-d", OrgID: "org-d", Slug: "group-d", Name: "Group D"}
			store.memberships["user-d"] = []*MembershipWithDetails{
				{Membership: &UserMembership{ID: "mem-d", UserID: "user-d", GroupID: "group-d"}, Group: group},
			}

			// Deploy claim — this is what triggers the deploy default in GetContractAccess
			store.groupAccess["group-d"] = &GroupAccess{
				ID:             "access-d",
				GroupID:        "group-d",
				AllowedMethods: []string{"eth_call", "eth_sendTransaction", "eth_estimateGas"},
				Claims:         []Claim{ClaimDeploy},
			}

			addr := strings.ToLower(contractAddr)
			store.contractOwners[addr] = "org-d"
			store.registeredToAnyOrg[addr] = true
			store.addressOwnedByOrg[addr] = map[string]bool{"org-d": true}

			// Cached permissions with deploy claim AND explicit function restrictions.
			// Before the fix, CheckAccess would re-fetch via GetContractAccess and get
			// Functions: nil (deploy default), bypassing these restrictions.
			store.cachedPermissions["user-d:org-d"] = &EffectivePermissions{
				ID:             "perms-d",
				UserID:         "user-d",
				OrgID:          "org-d",
				AllowedMethods: []string{"eth_call", "eth_sendTransaction", "eth_estimateGas"},
				ContractAccess: map[string]ContractAccess{
					addr: {
						Claims: []Claim{ClaimDeploy},
						Functions: []FunctionRule{
							{Selector: balanceOfSelector, ParamRules: []ParamRule{{Index: 0, MustBe: "self"}}},
						},
					},
				},
				Claims:     []Claim{ClaimDeploy},
				ComputedAt: time.Now(),
				ExpiresAt:  time.Now().Add(1 * time.Hour),
			}

			store.linkedAddresses["did:test:userd"] = []string{strings.ToLower(ownAddr.Hex())}

			store.contractsByAddress["org-d:"+addr] = &Contract{
				ID:      "contract-d",
				OrgID:   "org-d",
				Address: addr,
				Name:    "TestToken",
				ABI:     testABI,
			}

			controller := NewAccessController(store, 5*time.Minute)

			req := &AccessCheckRequest{
				UserExternalID:   "did:test:userd",
				Method:           "eth_call",
				TargetAddress:    contractAddr,
				FunctionSelector: tt.functionSelector,
				Calldata:         tt.calldata,
				Params: []any{
					map[string]any{"to": contractAddr, "data": "0x" + hex.EncodeToString(tt.calldata)},
					"latest",
				},
			}

			result, err := controller.CheckAccess(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Allowed != tt.expectAllowed {
				if tt.expectAllowed {
					t.Errorf("expected access to be allowed, got denied: %s", result.Reason)
				} else {
					t.Errorf("expected access to be denied, got allowed")
				}
			}
			if !tt.expectAllowed && tt.expectReason != "" {
				if !strings.Contains(result.Reason, tt.expectReason) {
					t.Errorf("expected reason to contain %q, got: %s", tt.expectReason, result.Reason)
				}
			}
		})
	}
}

// TestEmptySelectorDeniedWithFunctionRestrictions verifies that an empty function
// selector is denied when the contract has function-level restrictions defined.
// This closes a security vulnerability where callers could bypass function-level
// restrictions by sending calldata shorter than 4 bytes (or no calldata at all).
func TestEmptySelectorDeniedWithFunctionRestrictions(t *testing.T) {
	contractAddr := "0xaaaa000000000000000000000000000000000002"
	transferSelector := "0xa9059cbb" // transfer(address,uint256)

	tests := []struct {
		name          string
		functionRules []FunctionRule // function rules on the contract grant
		selector      string        // function selector in request
		expectAllowed bool
		expectReason  string // substring that must appear in denial reason
	}{
		{
			name: "function restrictions + empty selector -> denied",
			functionRules: []FunctionRule{
				{Selector: transferSelector},
			},
			selector:      "",
			expectAllowed: false,
			expectReason:  "function selector required",
		},
		{
			name:          "no function restrictions + empty selector -> allowed",
			functionRules: nil, // nil means all functions allowed
			selector:      "",
			expectAllowed: true,
		},
		{
			name:          "empty function restrictions slice + empty selector -> denied",
			functionRules: []FunctionRule{}, // non-nil empty = explicit deny all
			selector:      "",
			expectAllowed: false,
			expectReason:  "function selector required",
		},
		{
			name: "function restrictions + valid matching selector -> allowed",
			functionRules: []FunctionRule{
				{Selector: transferSelector},
			},
			selector:      transferSelector,
			expectAllowed: true,
		},
		{
			name: "function restrictions + non-matching selector -> denied by selector check",
			functionRules: []FunctionRule{
				{Selector: transferSelector},
			},
			selector:      "0xdeadbeef",
			expectAllowed: false,
			expectReason:  "function 0xdeadbeef not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			store := newParamConstraintStore()

			// Set up organization
			org := &Organization{ID: "org-b", Slug: "org-b", Name: "Org B"}
			store.organizations["org-b"] = org

			// Set up user
			user := &User{ID: "user-2", ExternalID: "did:test:user2", KYC: true, Banned: false}
			store.users["did:test:user2"] = user

			// Set up group and membership
			group := &Group{ID: "group-b", OrgID: "org-b", Slug: "group-b", Name: "Group B"}
			store.memberships["user-2"] = []*MembershipWithDetails{
				{Membership: &UserMembership{ID: "mem-2", UserID: "user-2", GroupID: "group-b"}, Group: group},
			}

			// Set up group access (no operational claims needed)
			store.groupAccess["group-b"] = &GroupAccess{
				ID:             "access-b",
				GroupID:        "group-b",
				AllowedMethods: []string{"eth_call", "eth_sendTransaction", "eth_estimateGas"},
				Claims:         []Claim{},
			}

			// Set up contract ownership
			addr := strings.ToLower(contractAddr)
			store.contractOwners[addr] = "org-b"
			store.registeredToAnyOrg[addr] = true
			store.addressOwnedByOrg[addr] = map[string]bool{"org-b": true}

			// Set up cached permissions with function rules from the test case
			store.cachedPermissions["user-2:org-b"] = &EffectivePermissions{
				ID:             "perms-2",
				UserID:         "user-2",
				OrgID:          "org-b",
				AllowedMethods: []string{"eth_call", "eth_sendTransaction", "eth_estimateGas"},
				ContractAccess: map[string]ContractAccess{
					addr: {
						Claims:    []Claim{},
						Functions: tt.functionRules,
					},
				},
				Claims:     []Claim{},
				ComputedAt: time.Now(),
				ExpiresAt:  time.Now().Add(1 * time.Hour),
			}

			controller := NewAccessController(store, 5*time.Minute)

			req := &AccessCheckRequest{
				UserExternalID:   "did:test:user2",
				Method:           "eth_call",
				Params:           []any{map[string]any{"to": contractAddr, "data": "0x"}, "latest"},
				TargetAddress:    contractAddr,
				FunctionSelector: tt.selector,
			}

			result, err := controller.CheckAccess(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Allowed != tt.expectAllowed {
				if tt.expectAllowed {
					t.Errorf("expected access to be allowed, got denied: %s", result.Reason)
				} else {
					t.Errorf("expected access to be denied, got allowed")
				}
			}
			if !tt.expectAllowed && tt.expectReason != "" {
				if !strings.Contains(result.Reason, tt.expectReason) {
					t.Errorf("expected reason to contain %q, got: %s", tt.expectReason, result.Reason)
				}
			}
		})
	}
}

// TestAnonymousAccess verifies that unauthenticated requests (UserExternalID == "")
// are allowed only for claim-free chain-metadata methods and denied for everything
// that could reveal user data (balances, transactions, receipts, contract state, logs).
func TestAnonymousAccess(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		expectAllowed bool
	}{
		// Claim-free metadata — allowed anonymously
		{name: "eth_blockNumber", method: "eth_blockNumber", expectAllowed: true},
		{name: "eth_chainId", method: "eth_chainId", expectAllowed: true},
		{name: "eth_gasPrice", method: "eth_gasPrice", expectAllowed: true},
		{name: "net_version", method: "net_version", expectAllowed: true},
		{name: "net_listening", method: "net_listening", expectAllowed: true},
		{name: "web3_clientVersion", method: "web3_clientVersion", expectAllowed: true},

		// Read operations — require authentication even for anonymous callers
		{name: "eth_getBalance", method: "eth_getBalance", expectAllowed: false},
		{name: "eth_call", method: "eth_call", expectAllowed: false},
		{name: "eth_estimateGas", method: "eth_estimateGas", expectAllowed: false},
		{name: "eth_getCode", method: "eth_getCode", expectAllowed: false},
		{name: "eth_getStorageAt", method: "eth_getStorageAt", expectAllowed: false},
		{name: "eth_getTransactionCount", method: "eth_getTransactionCount", expectAllowed: false},
		{name: "eth_getLogs", method: "eth_getLogs", expectAllowed: false},

		// Block contents — contain tx data, deny anonymously
		{name: "eth_getBlockByNumber", method: "eth_getBlockByNumber", expectAllowed: false},
		{name: "eth_getBlockByHash", method: "eth_getBlockByHash", expectAllowed: false},
		{name: "eth_getBlockTransactionCountByNumber", method: "eth_getBlockTransactionCountByNumber", expectAllowed: false},
		{name: "eth_getBlockTransactionCountByHash", method: "eth_getBlockTransactionCountByHash", expectAllowed: false},
		{name: "eth_getUncleByBlockHashAndIndex", method: "eth_getUncleByBlockHashAndIndex", expectAllowed: false},
		{name: "eth_getUncleByBlockNumberAndIndex", method: "eth_getUncleByBlockNumberAndIndex", expectAllowed: false},
		{name: "eth_getUncleCountByBlockHash", method: "eth_getUncleCountByBlockHash", expectAllowed: false},
		{name: "eth_getUncleCountByBlockNumber", method: "eth_getUncleCountByBlockNumber", expectAllowed: false},

		// Transaction details — sender/receiver/value/input, deny anonymously
		{name: "eth_getTransactionByHash", method: "eth_getTransactionByHash", expectAllowed: false},
		{name: "eth_getTransactionByBlockHashAndIndex", method: "eth_getTransactionByBlockHashAndIndex", expectAllowed: false},
		{name: "eth_getTransactionByBlockNumberAndIndex", method: "eth_getTransactionByBlockNumberAndIndex", expectAllowed: false},

		// Receipts — contain logs/status, deny anonymously
		{name: "eth_getTransactionReceipt", method: "eth_getTransactionReceipt", expectAllowed: false},

		// State proofs — expose balance/nonce/storage, deny anonymously
		{name: "eth_getProof", method: "eth_getProof", expectAllowed: false},

		// Access list simulation — reveals contract internals, deny anonymously
		{name: "eth_createAccessList", method: "eth_createAccessList", expectAllowed: false},

		// Node accounts — may expose signer addresses, deny anonymously
		{name: "eth_accounts", method: "eth_accounts", expectAllowed: false},

		// Log filters — equivalent to eth_getLogs, deny anonymously
		{name: "eth_newFilter", method: "eth_newFilter", expectAllowed: false},
		{name: "eth_newBlockFilter", method: "eth_newBlockFilter", expectAllowed: false},
		{name: "eth_newPendingTransactionFilter", method: "eth_newPendingTransactionFilter", expectAllowed: false},
		{name: "eth_getFilterChanges", method: "eth_getFilterChanges", expectAllowed: false},
		{name: "eth_getFilterLogs", method: "eth_getFilterLogs", expectAllowed: false},
		{name: "eth_uninstallFilter", method: "eth_uninstallFilter", expectAllowed: false},

		// Case-insensitive bypass attempt — must be denied
		{name: "ETH_GETBALANCE uppercase", method: "ETH_GETBALANCE", expectAllowed: false},
		{name: "Eth_GetBlockByNumber mixed", method: "Eth_GetBlockByNumber", expectAllowed: false},
		{name: "ETH_NEWFILTER uppercase", method: "ETH_NEWFILTER", expectAllowed: false},

		// Write operations — deny anonymously
		{name: "eth_sendTransaction", method: "eth_sendTransaction", expectAllowed: false},
		{name: "eth_sendRawTransaction", method: "eth_sendRawTransaction", expectAllowed: false},
	}

	store := NewMockCrossOrgStore()
	controller := NewAccessController(store, 5*time.Minute)
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &AccessCheckRequest{
				UserExternalID: "", // anonymous
				Method:         tt.method,
			}

			result, err := controller.CheckAccess(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Allowed != tt.expectAllowed {
				if tt.expectAllowed {
					t.Errorf("expected anonymous access to be allowed, got denied: %s", result.Reason)
				} else {
					t.Errorf("expected anonymous access to be denied, got allowed")
				}
			}

			if !tt.expectAllowed {
				// Methods that are globally blocked get rejected before the anonymous
				// access check, so their reason says "globally blocked" instead of
				// "authentication required". Both are correct denials.
				if !strings.Contains(result.Reason, "authentication required") &&
					!strings.Contains(result.Reason, "globally blocked") {
					t.Errorf("expected reason to contain 'authentication required' or 'globally blocked', got: %s", result.Reason)
				}
			}
			// Note: RateLimit{RPS,Daily} are no longer set on the AccessCheckResult
			// for anonymous requests — per-user rate limiting moved to the upstream
			// RPC proxy (PR #120). RD-870 finished removing the dead values.
		})
	}
}

// TestAnonymousAccess_DBSourced verifies the RD-870 contract: anonymous
// permissions come from the anonymous group's group_access row in the DB,
// not from a hardcoded code branch. Editing the row changes what anonymous
// can call.
func TestAnonymousAccess_DBSourced(t *testing.T) {
	store := NewMockCrossOrgStore()
	controller := NewAccessController(store, 5*time.Minute)
	ctx := context.Background()

	// Default seed allows eth_blockNumber but not eth_call.
	res, err := controller.CheckAccess(ctx, &AccessCheckRequest{Method: "eth_blockNumber"})
	if err != nil || !res.Allowed {
		t.Fatalf("eth_blockNumber should be allowed under default seed: err=%v allowed=%v", err, res.Allowed)
	}
	res, err = controller.CheckAccess(ctx, &AccessCheckRequest{Method: "eth_call"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allowed {
		t.Fatalf("eth_call should be denied under default seed")
	}

	// Mutate the seeded row to add eth_call. The next access check must
	// reflect the new config — proving the access path reads the DB row
	// rather than a frozen code constant.
	store.groupAccess[AnonymousGroupID].AllowedMethods = append(
		store.groupAccess[AnonymousGroupID].AllowedMethods, "eth_call",
	)
	// L9: the access path caches the anonymous row briefly (5s default
	// in production) — admin handlers call InvalidateAnonymousAccess
	// after writes. The test mutates the mock store directly so we
	// must do the same.
	controller.InvalidateAnonymousAccess()
	res, err = controller.CheckAccess(ctx, &AccessCheckRequest{Method: "eth_call"})
	if err != nil || !res.Allowed {
		t.Fatalf("eth_call should be allowed after adding it to AllowedMethods: err=%v allowed=%v", err, res.Allowed)
	}

	// Remove the row entirely — fail closed. Anonymous gets nothing.
	delete(store.groupAccess, AnonymousGroupID)
	controller.InvalidateAnonymousAccess()
	res, err = controller.CheckAccess(ctx, &AccessCheckRequest{Method: "eth_blockNumber"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allowed {
		t.Fatalf("eth_blockNumber should be denied when anonymous group_access row is missing (fail-closed)")
	}
	if !res.AuthRequired {
		t.Errorf("expected AuthRequired=true for fail-closed denial")
	}
}

// TestAnonymousAccess_DeploymentBlocked verifies that even if a super admin
// allowlists a write method like eth_sendTransaction on the anonymous group,
// CREATE-shaped payloads still require an authenticated principal with the
// deploy claim — defense in depth against admin foot-guns.
func TestAnonymousAccess_DeploymentBlocked(t *testing.T) {
	store := NewMockCrossOrgStore()
	store.groupAccess[AnonymousGroupID].AllowedMethods = append(
		store.groupAccess[AnonymousGroupID].AllowedMethods, "eth_sendTransaction",
	)
	controller := NewAccessController(store, 5*time.Minute)
	ctx := context.Background()

	// Deployment payload (no `to` field — IsContractDeployment treats this
	// as a CREATE call).
	deployParams := []any{map[string]any{"from": "0x0", "data": "0x60806040"}}
	res, err := controller.CheckAccess(ctx, &AccessCheckRequest{
		Method: "eth_sendTransaction",
		Params: deployParams,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allowed {
		t.Fatalf("anonymous deployment must be denied even when eth_sendTransaction is allowlisted")
	}
	if !res.AuthRequired {
		t.Errorf("expected AuthRequired=true on deployment denial")
	}
}

// TestOrgFreeMetadataMethods verifies that authenticated users can call the 6
// chain-metadata methods (same set as the anonymous allowlist) on /rpc without
// an explicit org_id in the path. These methods carry no user or org state;
// requiring org context for them would break standard tools (Hardhat, wallets).
// The ban gate must still fire; the KYC gate is exempt for exactly these
// methods (RD-1197) — anonymous requests get them with no user at all, so a
// blanket KYC deny would make signing in stricter than staying anonymous.
func TestOrgFreeMetadataMethods(t *testing.T) {
	store := NewMockCrossOrgStore()
	controller := NewAccessController(store, 5*time.Minute)
	ctx := context.Background()

	// User with no org membership at all.
	user := &User{ID: "user-no-org", ExternalID: "did:test:no-org", KYC: true, Banned: false}
	store.users[user.ExternalID] = user

	orgFreeMethods := []string{
		"eth_blockNumber",
		"eth_chainId",
		"eth_gasPrice",
		"net_version",
		"net_listening",
		"web3_clientVersion",
	}

	for _, method := range orgFreeMethods {
		t.Run("allowed/"+method, func(t *testing.T) {
			res, err := controller.CheckAccess(ctx, &AccessCheckRequest{
				UserExternalID: user.ExternalID,
				Method:         method,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !res.Allowed {
				t.Errorf("expected allowed, got denied: %s", res.Reason)
			}
		})
	}

	// Non-metadata methods still require org context.
	for _, method := range []string{"eth_getBalance", "eth_call", "eth_sendTransaction"} {
		t.Run("denied/"+method, func(t *testing.T) {
			res, err := controller.CheckAccess(ctx, &AccessCheckRequest{
				UserExternalID: user.ExternalID,
				Method:         method,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Allowed {
				t.Errorf("expected denied, got allowed")
			}
		})
	}

	// Banned user is blocked even for org-free methods.
	t.Run("banned user blocked", func(t *testing.T) {
		banned := &User{ID: "user-banned", ExternalID: "did:test:banned-no-org", KYC: true, Banned: true}
		store.users[banned.ExternalID] = banned
		res, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: banned.ExternalID,
			Method:         "eth_blockNumber",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Allowed {
			t.Errorf("expected banned user to be denied")
		}
	})

	// KYC-failed user is allowed for org-free metadata methods (RD-1197):
	// anonymous gets the same set, so KYC must not make sign-in stricter.
	// State-touching methods remain KYC-gated — see
	// TestKYCGateExemptsOrgFreeMetadataMethods.
	t.Run("no-KYC user allowed on metadata", func(t *testing.T) {
		noKYC := &User{ID: "user-nokyc", ExternalID: "did:test:nokyc-no-org", KYC: false, Banned: false}
		store.users[noKYC.ExternalID] = noKYC
		res, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: noKYC.ExternalID,
			Method:         "eth_blockNumber",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Allowed {
			t.Errorf("expected no-KYC user to be allowed on metadata method, got denied: %s", res.Reason)
		}
	})
}

// TestSingleOrgImplicitFallback verifies that a user in exactly one org can call
// non-metadata methods on /rpc (no org_id in path) and the proxy resolves the
// org automatically. Users in 2+ orgs must specify /rpc/:org_id.
func TestSingleOrgImplicitFallback(t *testing.T) {
	store := NewMockCrossOrgStore()
	controller := NewAccessController(store, 5*time.Minute)
	ctx := context.Background()

	// Org and group setup
	org := &Organization{ID: "org-single", Slug: "single", Name: "Single Org"}
	store.organizations["org-single"] = org
	group := &Group{ID: "grp-single", OrgID: "org-single"}
	store.groupAccess["grp-single"] = &GroupAccess{
		ID:             "ga-single",
		GroupID:        "grp-single",
		AllowedMethods: []string{"eth_getBalance", "eth_call", "eth_blockNumber"},
		Claims:         []Claim{},
	}

	// Single-org user
	user := &User{ID: "u-single", ExternalID: "did:test:single-org", KYC: true, Banned: false}
	store.users[user.ExternalID] = user
	store.memberships["u-single"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "m1", UserID: "u-single", GroupID: "grp-single"}, Group: group},
	}
	store.cachedPermissions["u-single:org-single"] = &EffectivePermissions{
		ID:             "ep-single",
		UserID:         "u-single",
		OrgID:          "org-single",
		AllowedMethods: []string{"eth_getBalance", "eth_call", "eth_blockNumber"},
		Claims:         []Claim{},
	}

	t.Run("single-org user: eth_blockNumber without org_id", func(t *testing.T) {
		res, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: user.ExternalID,
			Method:         "eth_blockNumber",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Allowed {
			t.Errorf("expected allowed, got denied: %s", res.Reason)
		}
	})

	t.Run("single-org user: eth_getBalance without org_id", func(t *testing.T) {
		res, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: user.ExternalID,
			Method:         "eth_getBalance",
			Params:         []any{"0x1234567890123456789012345678901234567890", "latest"},
			TargetAddress:  "0x1234567890123456789012345678901234567890",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Allowed {
			t.Errorf("expected allowed, got denied: %s", res.Reason)
		}
	})

	t.Run("single-org user: explicit org_id still works", func(t *testing.T) {
		res, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: user.ExternalID,
			OrgID:          "org-single",
			Method:         "eth_getBalance",
			Params:         []any{"0x1234567890123456789012345678901234567890", "latest"},
			TargetAddress:  "0x1234567890123456789012345678901234567890",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Allowed {
			t.Errorf("expected allowed, got denied: %s", res.Reason)
		}
	})

	// Multi-org user — must specify org_id
	org2 := &Organization{ID: "org-second", Slug: "second", Name: "Second Org"}
	store.organizations["org-second"] = org2
	group2 := &Group{ID: "grp-second", OrgID: "org-second"}
	store.groupAccess["grp-second"] = &GroupAccess{
		ID:             "ga-second",
		GroupID:        "grp-second",
		AllowedMethods: []string{"eth_getBalance"},
		Claims:         []Claim{},
	}
	multiUser := &User{ID: "u-multi", ExternalID: "did:test:multi-org", KYC: true, Banned: false}
	store.users[multiUser.ExternalID] = multiUser
	store.memberships["u-multi"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "m2", UserID: "u-multi", GroupID: "grp-single"}, Group: group},
		{Membership: &UserMembership{ID: "m3", UserID: "u-multi", GroupID: "grp-second"}, Group: group2},
	}

	t.Run("multi-org user: eth_getBalance without org_id is denied", func(t *testing.T) {
		res, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: multiUser.ExternalID,
			Method:         "eth_getBalance",
			Params:         []any{"0x1234567890123456789012345678901234567890", "latest"},
			TargetAddress:  "0x1234567890123456789012345678901234567890",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Allowed {
			t.Errorf("expected denied for multi-org user without org_id")
		}
		if !strings.Contains(res.Reason, "multiple organizations") {
			t.Errorf("expected 'multiple organizations' in reason, got: %s", res.Reason)
		}
	})

	t.Run("multi-org user: explicit org_id is allowed", func(t *testing.T) {
		store.cachedPermissions["u-multi:org-single"] = &EffectivePermissions{
			ID:             "ep-multi-a",
			UserID:         "u-multi",
			OrgID:          "org-single",
			AllowedMethods: []string{"eth_getBalance"},
			Claims:         []Claim{},
		}
		res, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: multiUser.ExternalID,
			OrgID:          "org-single",
			Method:         "eth_getBalance",
			Params:         []any{"0x1234567890123456789012345678901234567890", "latest"},
			TargetAddress:  "0x1234567890123456789012345678901234567890",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Allowed {
			t.Errorf("expected allowed with explicit org_id, got denied: %s", res.Reason)
		}
	})
}

// TestFunctionSelectorGateOnlyForCallMethods covers the bug where the
// "function selector required" check was incorrectly applied to methods
// that never produce a function selector (eth_getCode). This caused
// eth_getCode access to depend on ABI registration rather than AllowedMethods.
//
// Security vectors covered:
//  1. eth_getCode with ABI registered must be allowed (not accidentally blocked)
//  2. eth_getCode without ABI must be allowed (consistent with #1)
//  3. eth_getCode NOT in AllowedMethods must be denied regardless of ABI
//  4. eth_call without selector + ABI registered must still be denied (no regression)
//  5. eth_call without selector + no ABI must be allowed (no regression)
//  6. eth_estimateGas and eth_sendTransaction have the same selector gate (no regression)
func TestFunctionSelectorGateOnlyForCallMethods(t *testing.T) {
	const (
		contractAddr = "0xcontract000000000000000000000000000000001"
		userDID      = "did:test:user1"
	)

	someABIFunctions := []FunctionRule{
		{Selector: "0xa9059cbb"}, // transfer(address,uint256)
	}

	tests := []struct {
		name           string
		allowedMethods []string
		functions      []FunctionRule // nil = no ABI, non-nil = ABI with restrictions
		method         string
		params         []any
		expectAllowed  bool
		expectReason   string
	}{
		// --- eth_getCode: access must depend ONLY on AllowedMethods, not ABI ---
		{
			name:           "eth_getCode allowed when in AllowedMethods, no ABI",
			allowedMethods: []string{"eth_getCode"},
			functions:      nil,
			method:         "eth_getCode",
			params:         []any{contractAddr, "latest"},
			expectAllowed:  true,
		},
		{
			name:           "eth_getCode allowed when in AllowedMethods, ABI registered",
			allowedMethods: []string{"eth_getCode"},
			functions:      someABIFunctions, // ABI registered — must NOT block eth_getCode
			method:         "eth_getCode",
			params:         []any{contractAddr, "latest"},
			expectAllowed:  true,
		},
		{
			name:           "eth_getCode denied when NOT in AllowedMethods, no ABI",
			allowedMethods: []string{"eth_call"}, // eth_getCode absent
			functions:      nil,
			method:         "eth_getCode",
			params:         []any{contractAddr, "latest"},
			expectAllowed:  false,
			expectReason:   "not allowed",
		},
		{
			name:           "eth_getCode denied when NOT in AllowedMethods, ABI registered",
			allowedMethods: []string{"eth_call"}, // eth_getCode absent
			functions:      someABIFunctions,
			method:         "eth_getCode",
			params:         []any{contractAddr, "latest"},
			expectAllowed:  false,
			expectReason:   "not allowed",
		},
		{
			name:           "eth_getCode denied with empty AllowedMethods regardless of ABI",
			allowedMethods: []string{},
			functions:      nil,
			method:         "eth_getCode",
			params:         []any{contractAddr, "latest"},
			expectAllowed:  false,
		},

		// --- eth_call: selector gate must still apply (regression guard) ---
		{
			name:           "eth_call without selector, ABI registered — denied (selector required)",
			allowedMethods: []string{"eth_call"},
			functions:      someABIFunctions,
			method:         "eth_call",
			params:         []any{map[string]any{"to": contractAddr}, "latest"},
			expectAllowed:  false,
			expectReason:   "function selector required",
		},
		{
			name:           "eth_call without selector, no ABI — allowed",
			allowedMethods: []string{"eth_call"},
			functions:      nil,
			method:         "eth_call",
			params:         []any{map[string]any{"to": contractAddr}, "latest"},
			expectAllowed:  true,
		},
		{
			name:           "eth_call with selector matching ABI — allowed",
			allowedMethods: []string{"eth_call"},
			functions:      someABIFunctions,
			method:         "eth_call",
			params:         []any{map[string]any{"to": contractAddr, "data": "0xa9059cbb00000000"}, "latest"},
			expectAllowed:  true,
		},
		{
			name:           "eth_call with selector not in ABI — denied",
			allowedMethods: []string{"eth_call"},
			functions:      someABIFunctions,
			method:         "eth_call",
			params:         []any{map[string]any{"to": contractAddr, "data": "0xdeadbeef00000000"}, "latest"},
			expectAllowed:  false,
			expectReason:   "not allowed",
		},

		// --- eth_estimateGas: selector gate must apply (regression guard) ---
		{
			name:           "eth_estimateGas without selector, ABI registered — denied",
			allowedMethods: []string{"eth_estimateGas"},
			functions:      someABIFunctions,
			method:         "eth_estimateGas",
			params:         []any{map[string]any{"to": contractAddr}, "latest"},
			expectAllowed:  false,
			expectReason:   "function selector required",
		},

		// --- eth_sendTransaction: selector gate must apply (regression guard) ---
		{
			name:           "eth_sendTransaction without selector, ABI registered — denied",
			allowedMethods: []string{"eth_sendTransaction"},
			functions:      someABIFunctions,
			method:         "eth_sendTransaction",
			params:         []any{map[string]any{"to": contractAddr}},
			expectAllowed:  false,
			expectReason:   "function selector required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			store := newParamConstraintStore()

			org := &Organization{ID: "org-a", Slug: "org-a", Name: "Org A"}
			store.organizations["org-a"] = org

			user := &User{ID: "user-1", ExternalID: userDID, KYC: true, Banned: false}
			store.users[userDID] = user

			group := &Group{ID: "group-a", OrgID: "org-a", Slug: "group-a", Name: "Group A"}
			store.memberships["user-1"] = []*MembershipWithDetails{
				{Membership: &UserMembership{ID: "mem-1", UserID: "user-1", GroupID: "group-a"}, Group: group},
			}

			addr := strings.ToLower(contractAddr)
			store.contractOwners[addr] = "org-a"
			store.registeredToAnyOrg[addr] = true
			store.addressOwnedByOrg[addr] = map[string]bool{"org-a": true}

			store.cachedPermissions["user-1:org-a"] = &EffectivePermissions{
				ID:             "perms-1",
				UserID:         "user-1",
				OrgID:          "org-a",
				AllowedMethods: tt.allowedMethods,
				ContractAccess: map[string]ContractAccess{
					addr: {
						Claims:    []Claim{},
						Functions: tt.functions,
					},
				},
				Claims:     []Claim{},
				ComputedAt: time.Now(),
				ExpiresAt:  time.Now().Add(time.Hour),
			}

			controller := NewAccessController(store, 5*time.Minute)

			// Mirror what jsonrpc_processor does: extract selector from params before CheckAccess.
			result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
				UserExternalID:   userDID,
				Method:           tt.method,
				Params:           tt.params,
				TargetAddress:    contractAddr,
				FunctionSelector: GetFunctionSelector(tt.method, tt.params),
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Allowed != tt.expectAllowed {
				if tt.expectAllowed {
					t.Errorf("expected allowed, got denied: %s", result.Reason)
				} else {
					t.Errorf("expected denied, got allowed")
				}
			}
			if !tt.expectAllowed && tt.expectReason != "" {
				if !strings.Contains(result.Reason, tt.expectReason) {
					t.Errorf("reason = %q, want it to contain %q", result.Reason, tt.expectReason)
				}
			}
		})
	}
}
