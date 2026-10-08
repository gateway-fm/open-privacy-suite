package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEffectivePermissions_HasMethod pins the default-deny allowlist: a method
// is granted only if the proxy would forward it (catalog, alias to a catalog
// method, operator passthrough) AND the group lists it by exact name, or holds
// a legacy "*" entry and the method is in the "*" expansion. Globs grant
// nothing; passthrough methods are never granted through "*".
func TestEffectivePermissions_HasMethod(t *testing.T) {
	defer SnapshotMethodRegistriesForTest()()
	ExtraMethods = map[string]bool{"linea_estimateGas": true, "linea_getProof": true, "custom_getRaw": true, "trace_block": true}
	MethodAliases = map[string]string{
		"linea_estimateGas": "eth_estimateGas",
		"linea_getProof":    "eth_getProof",
		"custom_getRaw":     "eth_getRawTransactionByHash",
	}
	PassthroughMethods = map[string]bool{"trace_block": true}

	tests := []struct {
		name           string
		allowedMethods []string
		method         string
		want           bool
	}{
		{"exact catalog method", []string{"eth_call"}, "eth_call", true},
		{"unlisted catalog method", []string{"eth_call"}, "eth_getLogs", false},
		{"exact alias to catalog method", []string{"linea_estimateGas"}, "linea_estimateGas", true},
		{"exact passthrough method", []string{"trace_block"}, "trace_block", true},
		{"exact-name-only catalog method listed", []string{"eth_getProof"}, "eth_getProof", true},

		{"star grants built-in methods", []string{"*"}, "eth_sendTransaction", true},
		{"star grants trace methods", []string{"*"}, "debug_traceCall", true},
		{"star grants alias to a star method", []string{"*"}, "linea_estimateGas", true},
		{"star does not grant exact-name-only catalog methods", []string{"*"}, "eth_getProof", false},
		{"star does not grant alias to exact-name-only method", []string{"*"}, "linea_getProof", false},
		{"star does not grant passthrough", []string{"*"}, "trace_block", false},
		{"star does not grant unmodelled method", []string{"*"}, "eth_getRawTransactionByHash", false},
		{"star does not grant unmodelled namespace", []string{"*"}, "trace_transaction", false},
		{"star does not grant send-sync", []string{"*"}, "eth_sendRawTransactionSync", false},
		{"star does not grant alias to unmodelled target", []string{"*"}, "custom_getRaw", false},
		{"star does not grant globally blocked", []string{"*"}, "eth_newFilter", false},

		{"explicit unmodelled name grants nothing", []string{"eth_getRawTransactionByHash"}, "eth_getRawTransactionByHash", false},
		{"explicit alias to unmodelled target grants nothing", []string{"custom_getRaw"}, "custom_getRaw", false},
		{"explicit globally blocked grants nothing", []string{"eth_newFilter"}, "eth_newFilter", false},
		{"glob grants nothing", []string{"linea_*"}, "linea_estimateGas", false},
		{"glob grants nothing for catalog prefix", []string{"eth_*"}, "eth_call", false},
		{"non-canonical spelling grants nothing", []string{"ETH_CALL"}, "ETH_CALL", false},
		{"empty entry grants nothing", []string{""}, "eth_call", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := &EffectivePermissions{AllowedMethods: tt.allowedMethods}
			got := perms.HasMethod(tt.method)
			assert.Equal(t, tt.want, got, "method=%q allowed=%v", tt.method, tt.allowedMethods)
		})
	}
}
