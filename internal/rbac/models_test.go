package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEffectivePermissions_HasMethod_Glob covers the v2 wildcard binding path:
// a "<prefix>*" entry in allowed_methods matches a method only when a
// registered global WildcardNamespace covers it (deny list checked there).
func TestEffectivePermissions_HasMethod_Glob(t *testing.T) {
	defer SnapshotMethodRegistriesForTest()()

	Wildcards = []*WildcardNamespace{
		{
			Namespace: "Linea",
			Prefix:    "linea_",
			Deny:      []string{"linea_sendTransaction", "linea_sign*"},
		},
	}

	tests := []struct {
		name           string
		allowedMethods []string
		method         string
		want           bool
	}{
		{"explicit exact match still wins", []string{"linea_estimateGas"}, "linea_estimateGas", true},
		{"glob covers unknown method via registered wildcard", []string{"linea_*"}, "linea_brandNew", true},
		{"glob does NOT cover deny-listed method", []string{"linea_*"}, "linea_sendTransaction", false},
		{"glob does NOT cover deny-glob match", []string{"linea_*"}, "linea_signTypedData", false},
		{"unrelated prefix glob without registered wildcard is ignored", []string{"zksync_*"}, "zksync_anyMethod", false},
		{"bare * still allows anything not in any wildcard Deny", []string{"*"}, "linea_anything", true},
		{"empty glob entry is ignored", []string{""}, "linea_brandNew", false},
		// M8 (security audit): a wildcard's Deny list is a hard floor —
		// even bare "*" in allowed_methods cannot override it. Pre-fix
		// this case returned true, allowing tier-1/2 admins to bypass an
		// operator-configured per-namespace deny by listing "*" or the
		// method explicitly.
		{"wildcard Deny is hard floor even against *", []string{"*"}, "linea_sendTransaction", false},
		{"glob entry alongside explicits — explicit wins for explicit method", []string{"linea_estimateGas", "linea_*"}, "linea_estimateGas", true},
		{"glob entry alongside explicits — glob covers other methods", []string{"linea_estimateGas", "linea_*"}, "linea_getProof", true},
		{"no glob, unknown method denied", []string{"linea_estimateGas"}, "linea_brandNew", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := &EffectivePermissions{AllowedMethods: tt.allowedMethods}
			got := perms.HasMethod(tt.method)
			assert.Equal(t, tt.want, got, "method=%q allowed=%v", tt.method, tt.allowedMethods)
		})
	}
}

// TestEffectivePermissions_HasMethod_NoWildcardsRegistered confirms that v1
// behavior is identical when no wildcards are configured: glob entries simply
// don't match anything (no operator opt-in → no surface).
func TestEffectivePermissions_HasMethod_NoWildcardsRegistered(t *testing.T) {
	defer SnapshotMethodRegistriesForTest()()
	Wildcards = nil

	perms := &EffectivePermissions{AllowedMethods: []string{"eth_call", "linea_*"}}
	assert.True(t, perms.HasMethod("eth_call"), "exact match still works")
	assert.False(t, perms.HasMethod("linea_estimateGas"), "glob without registered wildcard is inert")
}
