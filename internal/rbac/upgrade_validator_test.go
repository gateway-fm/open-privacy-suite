package rbac

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
)

// MockUpgradeStore implements the Store interface for upgrade validator tests
type MockUpgradeStore struct {
	MockStore
	ownedAddresses map[string]map[string]bool // orgID -> address -> owned
}

func NewMockUpgradeStore() *MockUpgradeStore {
	return &MockUpgradeStore{
		MockStore:      *NewMockStore(),
		ownedAddresses: make(map[string]map[string]bool),
	}
}

func (m *MockUpgradeStore) IsAddressOwnedByOrg(ctx context.Context, address string, orgID string) (bool, error) {
	addr := strings.ToLower(address)
	if orgAddrs, ok := m.ownedAddresses[orgID]; ok {
		return orgAddrs[addr], nil
	}
	return false, nil
}

func (m *MockUpgradeStore) GetContractOwnerOrgID(ctx context.Context, address string) (string, error) {
	addr := strings.ToLower(address)
	for orgID, addrs := range m.ownedAddresses {
		if addrs[addr] {
			return orgID, nil
		}
	}
	return "", nil
}

func (m *MockUpgradeStore) AddOwnedAddress(orgID, address string) {
	addr := strings.ToLower(address)
	if m.ownedAddresses[orgID] == nil {
		m.ownedAddresses[orgID] = make(map[string]bool)
	}
	m.ownedAddresses[orgID][addr] = true
}

func (m *MockUpgradeStore) GrantContractToDeployerGroup(ctx context.Context, orgID, contractID, deployerUserID string) error {
	return nil
}
func (m *MockUpgradeStore) RegisterDeployedContract(ctx context.Context, contract *Contract, deployerUserID string) (bool, error) {
	return true, nil
}

func TestIsUpgradeSelector(t *testing.T) {
	tests := []struct {
		name     string
		selector string
		expected bool
	}{
		{"upgradeTo", "0x3659cfe6", true},
		{"upgradeToAndCall", "0x4f1ef286", true},
		{"setImplementation", "0xd784d426", true},
		{"upgrade (proxy admin)", "0x99a88ec4", true},
		{"upgradeAndCall (proxy admin)", "0x9623609d", true},
		{"random selector", "0xabcdef12", false},
		{"without 0x prefix", "3659cfe6", true},
		{"uppercase", "0x3659CFE6", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsUpgradeSelector(tt.selector)
			if result != tt.expected {
				t.Errorf("IsUpgradeSelector(%s) = %v, want %v", tt.selector, result, tt.expected)
			}
		})
	}
}

func TestGetUpgradeFunctionName(t *testing.T) {
	tests := []struct {
		selector string
		expected string
	}{
		{"0x3659cfe6", "upgradeTo(address)"},
		{"0x4f1ef286", "upgradeToAndCall(address,bytes)"},
		{"0xd784d426", "setImplementation(address)"},
		{"0x99a88ec4", "upgrade(address,address)"},
		{"0x9623609d", "upgradeAndCall(address,address,bytes)"},
		{"0xabcdef12", ""},
	}

	for _, tt := range tests {
		t.Run(tt.selector, func(t *testing.T) {
			result := GetUpgradeFunctionName(tt.selector)
			if result != tt.expected {
				t.Errorf("GetUpgradeFunctionName(%s) = %q, want %q", tt.selector, result, tt.expected)
			}
		})
	}
}

func TestValidateUpgrade(t *testing.T) {
	ctx := context.Background()

	// Build test calldata for upgradeTo(0x1234567890123456789012345678901234567890)
	newImplAddr := "0x1234567890123456789012345678901234567890"
	upgradeToCalldata := buildUpgradeToCalldata(newImplAddr)

	tests := []struct {
		name            string
		setupStore      func(*MockUpgradeStore)
		proxyAddress    string
		calldata        []byte
		orgID           string
		expectAllowed   bool
		expectIsUpgrade bool
		expectReason    string
	}{
		{
			name:            "Non-upgrade call passes through",
			setupStore:      func(s *MockUpgradeStore) {},
			proxyAddress:    "0xproxy",
			calldata:        []byte{0xab, 0xcd, 0xef, 0x12, 0x00, 0x00}, // Random selector
			orgID:           "org1",
			expectAllowed:   true,
			expectIsUpgrade: false,
		},
		{
			name:            "Short calldata passes through",
			setupStore:      func(s *MockUpgradeStore) {},
			proxyAddress:    "0xproxy",
			calldata:        []byte{0x36, 0x59}, // Too short
			orgID:           "org1",
			expectAllowed:   true,
			expectIsUpgrade: false,
		},
		{
			name: "Upgrade with unowned implementation denied",
			setupStore: func(s *MockUpgradeStore) {
				// New implementation is NOT owned by org
			},
			proxyAddress:    "0xproxy",
			calldata:        upgradeToCalldata,
			orgID:           "org1",
			expectAllowed:   false,
			expectIsUpgrade: true,
			expectReason:    "not owned by the organization",
		},
		{
			name: "Valid upgrade allowed",
			setupStore: func(s *MockUpgradeStore) {
				s.AddOwnedAddress("org1", newImplAddr)
			},
			proxyAddress:    "0xproxy",
			calldata:        upgradeToCalldata,
			orgID:           "org1",
			expectAllowed:   true,
			expectIsUpgrade: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMockUpgradeStore()
			tt.setupStore(store)

			validator := NewUpgradeValidator(store)
			result, err := validator.ValidateUpgrade(ctx, tt.orgID, tt.proxyAddress, tt.calldata)
			if err != nil {
				t.Fatalf("ValidateUpgrade failed: %v", err)
			}

			if result.IsUpgradeCall != tt.expectIsUpgrade {
				t.Errorf("IsUpgradeCall = %v, want %v", result.IsUpgradeCall, tt.expectIsUpgrade)
			}

			if result.Allowed != tt.expectAllowed {
				t.Errorf("Allowed = %v, want %v (reason: %s)", result.Allowed, tt.expectAllowed, result.Reason)
			}

			if tt.expectReason != "" && !strings.Contains(result.Reason, tt.expectReason) {
				t.Errorf("Reason = %q, want to contain %q", result.Reason, tt.expectReason)
			}
		})
	}
}

func TestExtractImplementationAddress(t *testing.T) {
	tests := []struct {
		name          string
		selector      string
		buildCalldata func(string) []byte
		expectedAddr  string
	}{
		{
			name:     "upgradeTo extracts address",
			selector: SelectorUpgradeTo,
			buildCalldata: func(addr string) []byte {
				return buildUpgradeToCalldata(addr)
			},
			expectedAddr: "0x1234567890123456789012345678901234567890",
		},
		{
			name:     "upgradeToAndCall extracts address",
			selector: SelectorUpgradeToAndCall,
			buildCalldata: func(addr string) []byte {
				return buildUpgradeToAndCallCalldata(addr)
			},
			expectedAddr: "0x1234567890123456789012345678901234567890",
		},
		{
			name:     "upgrade (proxy admin) extracts second address",
			selector: SelectorProxyAdminUpgrade,
			buildCalldata: func(addr string) []byte {
				return buildProxyAdminUpgradeCalldata("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", addr)
			},
			expectedAddr: "0x1234567890123456789012345678901234567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calldata := tt.buildCalldata(tt.expectedAddr)
			result, err := extractImplementationAddress(tt.selector, calldata)
			if err != nil {
				t.Fatalf("extractImplementationAddress failed: %v", err)
			}

			if strings.ToLower(result) != strings.ToLower(tt.expectedAddr) {
				t.Errorf("extractImplementationAddress = %s, want %s", result, tt.expectedAddr)
			}
		})
	}
}

// Helper functions to build calldata

func buildUpgradeToCalldata(implAddr string) []byte {
	// selector (4 bytes) + address (32 bytes, zero-padded)
	selector, _ := hex.DecodeString(SelectorUpgradeTo)
	addrBytes := addressToBytes32(implAddr)
	return append(selector, addrBytes...)
}

func buildUpgradeToAndCallCalldata(implAddr string) []byte {
	// selector (4 bytes) + address (32 bytes) + offset (32 bytes) + length (32 bytes) + data
	selector, _ := hex.DecodeString(SelectorUpgradeToAndCall)
	addrBytes := addressToBytes32(implAddr)
	// Just add minimal bytes data encoding
	offset := make([]byte, 32)
	offset[31] = 0x40 // offset to data
	length := make([]byte, 32)
	// Empty data
	result := append(selector, addrBytes...)
	result = append(result, offset...)
	result = append(result, length...)
	return result
}

func buildProxyAdminUpgradeCalldata(proxyAddr, implAddr string) []byte {
	// selector (4 bytes) + proxy address (32 bytes) + impl address (32 bytes)
	selector, _ := hex.DecodeString(SelectorProxyAdminUpgrade)
	proxyBytes := addressToBytes32(proxyAddr)
	implBytes := addressToBytes32(implAddr)
	result := append(selector, proxyBytes...)
	result = append(result, implBytes...)
	return result
}

func addressToBytes32(addr string) []byte {
	// Remove 0x prefix
	addr = strings.TrimPrefix(addr, "0x")
	// Decode hex
	addrBytes, _ := hex.DecodeString(addr)
	// Zero-pad to 32 bytes
	result := make([]byte, 32)
	copy(result[32-len(addrBytes):], addrBytes)
	return result
}
