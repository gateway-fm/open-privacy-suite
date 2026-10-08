package rbac

import (
	"testing"
)

func TestIsWellKnownStorageSlot(t *testing.T) {
	tests := []struct {
		name string
		slot string
		want bool
	}{
		// EIP-1967 implementation slot
		{
			name: "EIP-1967 implementation slot",
			slot: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
			want: true,
		},
		// EIP-1967 admin slot
		{
			name: "EIP-1967 admin slot",
			slot: "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
			want: true,
		},
		// EIP-1967 beacon slot
		{
			name: "EIP-1967 beacon slot",
			slot: "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
			want: true,
		},
		// Diamond storage slot (EIP-2535)
		{
			name: "Diamond storage slot (EIP-2535)",
			slot: "0xc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c",
			want: true,
		},
		// Without 0x prefix
		{
			name: "EIP-1967 implementation without 0x prefix",
			slot: "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
			want: true,
		},
		{
			name: "EIP-1967 admin without 0x prefix",
			slot: "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
			want: true,
		},
		{
			name: "Diamond slot without 0x prefix",
			slot: "c8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c",
			want: true,
		},
		// Uppercase hex (case insensitive)
		{
			name: "EIP-1967 implementation uppercase",
			slot: "0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC",
			want: true,
		},
		{
			name: "Diamond slot mixed case",
			slot: "0xC8FCAD8DB84D3CC18B4C41D551EA0EE66DD599CDE068D998E57D5E09332C131C",
			want: true,
		},
		// Fail-closed: empty string
		{
			name: "empty string returns false",
			slot: "",
			want: false,
		},
		// Arbitrary slots that are NOT well-known
		{
			name: "slot zero",
			slot: "0x0000000000000000000000000000000000000000000000000000000000000000",
			want: false,
		},
		{
			name: "short slot 0x1",
			slot: "0x1",
			want: false,
		},
		{
			name: "random 32-byte hex",
			slot: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			want: false,
		},
		// Off-by-one from EIP-1967 implementation slot (last byte changed)
		{
			name: "implementation slot off-by-one (last byte)",
			slot: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbd",
			want: false,
		},
		// Off-by-one from Diamond slot (first byte after 0x changed)
		{
			name: "Diamond slot off-by-one (first byte)",
			slot: "0xd8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c",
			want: false,
		},
		// Off-by-one from admin slot
		{
			name: "admin slot off-by-one",
			slot: "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6104",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsWellKnownStorageSlot(tt.slot)
			if got != tt.want {
				t.Errorf("IsWellKnownStorageSlot(%q) = %v, want %v", tt.slot, got, tt.want)
			}
		})
	}
}

func TestExtractStorageSlot(t *testing.T) {
	tests := []struct {
		name   string
		params []any
		want   string
	}{
		{
			name:   "normal params with address, slot, and block tag",
			params: []any{"0x1234567890abcdef1234567890abcdef12345678", "0x0", "latest"},
			want:   "0x0",
		},
		{
			name:   "missing slot (only address)",
			params: []any{"0x1234567890abcdef1234567890abcdef12345678"},
			want:   "",
		},
		{
			name:   "empty params",
			params: []any{},
			want:   "",
		},
		{
			name:   "nil params",
			params: nil,
			want:   "",
		},
		{
			name:   "non-string slot (integer)",
			params: []any{"0x1234567890abcdef1234567890abcdef12345678", 123},
			want:   "",
		},
		{
			name:   "non-string slot (bool)",
			params: []any{"0x1234567890abcdef1234567890abcdef12345678", true},
			want:   "",
		},
		{
			name:   "non-string slot (nil)",
			params: []any{"0x1234567890abcdef1234567890abcdef12345678", nil},
			want:   "",
		},
		{
			name: "slot with extra params (ignored)",
			params: []any{
				"0x1234567890abcdef1234567890abcdef12345678",
				"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
				"latest",
				"extra",
			},
			want: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
		},
		{
			name:   "EIP-1967 implementation slot extracted correctly",
			params: []any{"0xcontract", "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", "latest"},
			want:   "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractStorageSlot(tt.params)
			if got != tt.want {
				t.Errorf("extractStorageSlot(%v) = %q, want %q", tt.params, got, tt.want)
			}
		})
	}
}

// The private-storage probe must sit outside the infrastructure allowlist, or
// the storage-slot tier would grant it to every viewer with contract access.
func TestPrivateStorageSlotIsNotInfrastructure(t *testing.T) {
	if IsWellKnownStorageSlot(PrivateStorageSlot) {
		t.Fatalf("PrivateStorageSlot %q must not be a well-known infrastructure slot", PrivateStorageSlot)
	}
}
