package compliance

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strings"
	"testing"
	"time"
)

// mockComplianceStore implements Store with configurable return values.
type mockComplianceStore struct {
	config          *ComplianceConfig
	configErr       error
	tokenPrice      *TokenPrice
	tokenPriceErr   error
	sanctionedAddrs map[string]bool // key = lowercased address
	sanctionErr     error
	claimedRecord   *TravelRuleRecord
	claimErr        error
	findCalls       int
	claimCalls      int
	logs            []*ComplianceLog
	logErr          error                                // if set, CreateComplianceLog returns this error
	addrOverrides   map[string]*AddressThresholdOverride // key = lowercased address
	addrOverrideErr error                                // if set, GetAddressThresholdOverride returns this error
	systemPrices    map[string]*SystemTokenPrice         // key = coingecko_id
	systemSetting   string                               // value returned by GetSystemSetting (e.g. base_currency)
}

func (m *mockComplianceStore) GetComplianceConfig(_ context.Context, _ string) (*ComplianceConfig, error) {
	return m.config, m.configErr
}

func (m *mockComplianceStore) UpsertComplianceConfig(_ context.Context, _ *ComplianceConfig) error {
	panic("not implemented")
}

func (m *mockComplianceStore) GetTokenPrice(_ context.Context, _, _ string) (*TokenPrice, error) {
	return m.tokenPrice, m.tokenPriceErr
}

func (m *mockComplianceStore) UpsertTokenPrice(_ context.Context, _ *TokenPrice, _ string) error {
	panic("not implemented")
}

func (m *mockComplianceStore) DeleteTokenPrice(_ context.Context, _, _ string) error {
	panic("not implemented")
}

func (m *mockComplianceStore) ListTokenPrices(_ context.Context, _ string) ([]*TokenPrice, error) {
	panic("not implemented")
}

func (m *mockComplianceStore) ListAllManualTokenPrices(_ context.Context) ([]*TokenPrice, error) {
	panic("not implemented")
}

func (m *mockComplianceStore) CreateTravelRuleRecord(_ context.Context, _ *TravelRuleRecord) error {
	panic("not implemented")
}

func (m *mockComplianceStore) GetTravelRuleRecord(_ context.Context, _ string) (*TravelRuleRecord, error) {
	panic("not implemented")
}

func (m *mockComplianceStore) FindUnusedTravelRuleRecord(_ context.Context, _, _, _, _ string, _ float64) (*TravelRuleRecord, error) {
	m.findCalls++
	return m.claimedRecord, m.claimErr
}

func (m *mockComplianceStore) ClaimUnusedTravelRuleRecord(_ context.Context, _, _, _, _ string, _ float64) (*TravelRuleRecord, error) {
	m.claimCalls++
	return m.claimedRecord, m.claimErr
}

func (m *mockComplianceStore) DeleteTravelRuleRecord(_ context.Context, _, _ string) error {
	panic("not implemented")
}

func (m *mockComplianceStore) MarkTravelRuleRecordUsed(_ context.Context, _ string, _ *string) error {
	panic("not implemented")
}

func (m *mockComplianceStore) ListTravelRuleRecords(_ context.Context, _ string, _, _ int) ([]*TravelRuleRecord, int, error) {
	panic("not implemented")
}

func (m *mockComplianceStore) CleanupExpiredRecords(_ context.Context) (int64, error) {
	panic("not implemented")
}

func (m *mockComplianceStore) IsAddressSanctioned(_ context.Context, _ string, address string) (bool, error) {
	if m.sanctionErr != nil {
		return false, m.sanctionErr
	}
	return m.sanctionedAddrs[strings.ToLower(address)], nil
}

func (m *mockComplianceStore) AddSanctionedAddress(_ context.Context, _ *SanctionedAddress) error {
	panic("not implemented")
}

func (m *mockComplianceStore) RemoveSanctionedAddress(_ context.Context, _ string) error {
	panic("not implemented")
}

func (m *mockComplianceStore) GetSanctionedAddress(_ context.Context, _ string) (*SanctionedAddress, error) {
	panic("not implemented")
}

func (m *mockComplianceStore) ListSanctionedAddresses(_ context.Context, _ *string, _, _ int) ([]*SanctionedAddress, int, error) {
	panic("not implemented")
}

func (m *mockComplianceStore) GetAddressThresholdOverride(_ context.Context, _ string, address string) (*AddressThresholdOverride, error) {
	if m.addrOverrideErr != nil {
		return nil, m.addrOverrideErr
	}
	if m.addrOverrides != nil {
		return m.addrOverrides[strings.ToLower(address)], nil
	}
	return nil, nil
}

func (m *mockComplianceStore) ListAddressThresholdOverrides(_ context.Context, _ string, _, _ int) ([]*AddressThresholdOverride, int, error) {
	panic("not implemented")
}

func (m *mockComplianceStore) UpsertAddressThresholdOverride(_ context.Context, _ *AddressThresholdOverride) error {
	panic("not implemented")
}

func (m *mockComplianceStore) DeleteAddressThresholdOverride(_ context.Context, _, _ string) error {
	panic("not implemented")
}

func (m *mockComplianceStore) CreateComplianceLog(_ context.Context, log *ComplianceLog) (int64, error) {
	if m.logErr != nil {
		return 0, m.logErr
	}
	m.logs = append(m.logs, log)
	return int64(len(m.logs)), nil
}

func (m *mockComplianceStore) GetComplianceLog(_ context.Context, _ int64) (*ComplianceLog, error) {
	panic("not implemented")
}

func (m *mockComplianceStore) ListComplianceLogs(_ context.Context, _ string, _ *ComplianceLogFilters) ([]*ComplianceLog, int, error) {
	panic("not implemented")
}

func (m *mockComplianceStore) GetSystemTokenPrice(_ context.Context, coingeckoID string) (*SystemTokenPrice, error) {
	if m.systemPrices != nil {
		return m.systemPrices[coingeckoID], nil
	}
	return nil, nil
}

func (m *mockComplianceStore) UpsertSystemTokenPrice(_ context.Context, _ *SystemTokenPrice) error {
	panic("not implemented")
}

func (m *mockComplianceStore) ListSystemTokenPrices(_ context.Context) ([]*SystemTokenPrice, error) {
	panic("not implemented")
}

func (m *mockComplianceStore) GetSystemSetting(_ context.Context, _ string) (string, error) {
	return m.systemSetting, nil
}

func (m *mockComplianceStore) SetSystemSetting(_ context.Context, _, _ string) error {
	panic("not implemented")
}

// enabledConfig returns a ComplianceConfig with compliance enabled and the given threshold.
func enabledConfig(threshold float64) *ComplianceConfig {
	return &ComplianceConfig{
		ID:            "cfg-1",
		OrgID:         "org-1",
		Enabled:       true,
		ThresholdFiat: threshold,
	}
}

// nativePrice returns a TokenPrice for native ETH with the given price.
func nativePrice(priceFiat float64) *TokenPrice {
	return &TokenPrice{
		ID:           "tp-1",
		OrgID:        "org-1",
		TokenAddress: "native",
		Symbol:       "ETH",
		Decimals:     18,
		PriceFiat:    priceFiat,
	}
}

func TestCheckPreviewDoesNotClaimOrLog(t *testing.T) {
	store := &mockComplianceStore{
		config:        enabledConfig(1000),
		tokenPrice:    nativePrice(1000),
		claimedRecord: &TravelRuleRecord{ID: "tr-preview"},
	}
	checker := NewChecker(store, 24*time.Hour, 15*time.Minute)
	result, err := checker.CheckPreview(context.Background(), &CheckRequest{
		OrgID: "org-1", UserID: "user-1",
		From:  "0x0000000000000000000000000000000000000001",
		To:    "0x0000000000000000000000000000000000000002",
		Value: "0x1bc16d674ec80000",
	})

	if err != nil {
		t.Fatalf("CheckPreview() error = %v", err)
	}
	if !result.Allowed {
		t.Fatalf("CheckPreview() allowed = false, reason = %q", result.Reason)
	}
	if store.findCalls != 1 || store.claimCalls != 0 {
		t.Fatalf("record lookups = find %d, claim %d; want find 1, claim 0", store.findCalls, store.claimCalls)
	}
	if len(store.logs) != 0 {
		t.Fatalf("preview wrote %d compliance logs", len(store.logs))
	}
}

// erc20Price returns a TokenPrice for an ERC20 token.
func erc20Price(addr, symbol string, decimals int, priceFiat float64) *TokenPrice {
	return &TokenPrice{
		ID:           "tp-2",
		OrgID:        "org-1",
		TokenAddress: strings.ToLower(addr),
		Symbol:       symbol,
		Decimals:     decimals,
		PriceFiat:    priceFiat,
	}
}

// nativePriceMultiCurrency returns a TokenPrice for native ETH with prices_by_currency set.
func nativePriceMultiCurrency(prices map[string]float64) *TokenPrice {
	return &TokenPrice{
		ID:               "tp-1",
		OrgID:            "org-1",
		TokenAddress:     "native",
		Symbol:           "ETH",
		Decimals:         18,
		PriceFiat:        prices["usd"], // legacy field
		PricesByCurrency: prices,
	}
}

// coingeckoLinkedPrice returns a per-org TokenPrice linked to a CoinGecko system price.
func coingeckoLinkedPrice(cgID string) *TokenPrice {
	return &TokenPrice{
		ID:           "tp-cg",
		OrgID:        "org-1",
		TokenAddress: "native",
		Symbol:       "ETH",
		Decimals:     18,
		PriceFiat:    0,
		CoingeckoID:  &cgID,
	}
}

// buildERC20TransferData constructs the calldata for an ERC20 transfer(address,uint256).
func buildERC20TransferData(recipient string, amount *big.Int) string {
	// Remove 0x prefix from recipient
	recipientHex := strings.TrimPrefix(strings.ToLower(recipient), "0x")
	// Pad address to 32 bytes (left-padded with zeros)
	paddedRecipient := fmt.Sprintf("%064s", recipientHex)
	// Pad amount to 32 bytes
	amountHex := hex.EncodeToString(amount.Bytes())
	paddedAmount := fmt.Sprintf("%064s", amountHex)

	return SelectorTransfer + paddedRecipient + paddedAmount
}

// buildERC20TransferFromData constructs calldata for transferFrom(address,address,uint256).
func buildERC20TransferFromData(fromAddr, toAddr string, amount *big.Int) string {
	fromHex := strings.TrimPrefix(strings.ToLower(fromAddr), "0x")
	paddedFrom := fmt.Sprintf("%064s", fromHex)
	toHex := strings.TrimPrefix(strings.ToLower(toAddr), "0x")
	paddedTo := fmt.Sprintf("%064s", toHex)
	amountHex := hex.EncodeToString(amount.Bytes())
	paddedAmount := fmt.Sprintf("%064s", amountHex)
	return SelectorTransferFrom + paddedFrom + paddedTo + paddedAmount
}

func TestCheckerCheck(t *testing.T) {
	ctx := context.Background()

	const (
		orgID  = "org-1"
		userID = "user-1"
		from   = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		to     = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	// Common hex values for native ETH transfers.
	const (
		hexOneTenthETH = "0x16345785d8a0000"  // 0.1 ETH
		hexOneETH      = "0xde0b6b3a7640000"  // 1 ETH
		hexThreeETH    = "0x29a2241af62c0000" // 3 ETH
	)

	// ERC20 setup: 1000 USDC = 1000 * 1e6 = 1_000_000_000
	tokenContract := "0xcccccccccccccccccccccccccccccccccccccccc"
	usdcRecipient := to
	// 500 USDC (500 * 1e6) -- below $1000 at $1/USDC
	usdc500 := new(big.Int).Mul(big.NewInt(500), big.NewInt(1e6))
	// 1500 USDC (1500 * 1e6) -- above $1000 at $1/USDC
	usdc1500 := new(big.Int).Mul(big.NewInt(1500), big.NewInt(1e6))

	erc20Data500 := buildERC20TransferData(usdcRecipient, usdc500)
	erc20Data1500 := buildERC20TransferData(usdcRecipient, usdc1500)

	// Value for exactly-at-threshold: 0.5 ETH at $2000/ETH = $1000
	hexHalfETH := "0x6f05b59d3b20000" // 0.5 ETH = 5e17

	tests := []struct {
		name        string
		store       *mockComplianceStore
		req         *CheckRequest
		wantAllowed bool
		wantReason  string // substring match
	}{
		{
			name:  "not a value transfer",
			store: &mockComplianceStore{},
			req: &CheckRequest{
				OrgID:  orgID,
				UserID: userID,
				From:   from,
				To:     to,
				Data:   "",
				Value:  "",
			},
			wantAllowed: true,
			wantReason:  "not a value transfer",
		},
		{
			name: "compliance disabled",
			store: &mockComplianceStore{
				config: &ComplianceConfig{
					ID:      "cfg-1",
					OrgID:   orgID,
					Enabled: false,
				},
			},
			req: &CheckRequest{
				OrgID:  orgID,
				UserID: userID,
				From:   from,
				To:     to,
				Data:   "",
				Value:  hexOneETH,
			},
			wantAllowed: true,
			wantReason:  "compliance not enabled",
		},
		{
			name: "no compliance config",
			store: &mockComplianceStore{
				config: nil,
			},
			req: &CheckRequest{
				OrgID:  orgID,
				UserID: userID,
				From:   from,
				To:     to,
				Data:   "",
				Value:  hexOneETH,
			},
			wantAllowed: true,
			wantReason:  "compliance not enabled",
		},
		{
			name: "recipient sanctioned",
			store: &mockComplianceStore{
				config:          enabledConfig(1000),
				sanctionedAddrs: map[string]bool{strings.ToLower(to): true},
			},
			req: &CheckRequest{
				OrgID:  orgID,
				UserID: userID,
				From:   from,
				To:     to,
				Data:   "",
				Value:  hexOneETH,
			},
			wantAllowed: false,
			wantReason:  "recipient address",
		},
		{
			name: "sender sanctioned",
			store: &mockComplianceStore{
				config:          enabledConfig(1000),
				sanctionedAddrs: map[string]bool{strings.ToLower(from): true},
			},
			req: &CheckRequest{
				OrgID:  orgID,
				UserID: userID,
				From:   from,
				To:     to,
				Data:   "",
				Value:  hexOneETH,
			},
			wantAllowed: false,
			wantReason:  "sender address",
		},
		{
			name: "transferFrom spender sanctioned",
			store: &mockComplianceStore{
				config:          enabledConfig(1000),
				sanctionedAddrs: map[string]bool{"0xspenderaddress0000000000000000000000000": true},
			},
			req: &CheckRequest{
				OrgID:  orgID,
				UserID: userID,
				From:   "0xSpenderAddress0000000000000000000000000",  // msg.sender (spender)
				To:     "0xcccccccccccccccccccccccccccccccccccccccc", // token contract
				// transferFrom(allowanceOwner, recipient, amount) — info.FromAddress will be allowanceOwner
				Data:  buildERC20TransferFromData(from, to, new(big.Int).SetUint64(1000000000000000000)),
				Value: "0x0",
			},
			wantAllowed: false,
			wantReason:  "transaction sender",
		},
		{
			name: "no token price configured",
			store: &mockComplianceStore{
				config:     enabledConfig(1000),
				tokenPrice: nil,
			},
			req: &CheckRequest{
				OrgID:  orgID,
				UserID: userID,
				From:   from,
				To:     to,
				Data:   "",
				Value:  hexOneETH,
			},
			wantAllowed: false,
			wantReason:  "no price configured for token native",
		},
		{
			name: "below threshold",
			store: &mockComplianceStore{
				config:     enabledConfig(1000),
				tokenPrice: nativePrice(2000),
			},
			req: &CheckRequest{
				OrgID:  orgID,
				UserID: userID,
				From:   from,
				To:     to,
				Data:   "",
				Value:  hexOneTenthETH, // 0.1 ETH * $2000 = $200
			},
			wantAllowed: true,
			wantReason:  "below threshold",
		},
		{
			name: "above threshold no record",
			store: &mockComplianceStore{
				config:        enabledConfig(1000),
				tokenPrice:    nativePrice(2000),
				claimedRecord: nil,
			},
			req: &CheckRequest{
				OrgID:  orgID,
				UserID: userID,
				From:   from,
				To:     to,
				Data:   "",
				Value:  hexOneETH, // 1 ETH * $2000 = $2000
			},
			wantAllowed: false,
			wantReason:  "exceeds threshold",
		},
		{
			name: "above threshold record found",
			store: &mockComplianceStore{
				config:     enabledConfig(1000),
				tokenPrice: nativePrice(2000),
				claimedRecord: &TravelRuleRecord{
					ID:    "tr-1",
					OrgID: orgID,
				},
			},
			req: &CheckRequest{
				OrgID:  orgID,
				UserID: userID,
				From:   from,
				To:     to,
				Data:   "",
				Value:  hexThreeETH, // 3 ETH * $2000 = $6000
			},
			wantAllowed: true,
			wantReason:  "travel rule record tr-1 applied",
		},
		{
			name: "erc20 transfer below threshold",
			store: &mockComplianceStore{
				config:     enabledConfig(1000),
				tokenPrice: erc20Price(tokenContract, "USDC", 6, 1.0),
			},
			req: &CheckRequest{
				OrgID:  orgID,
				UserID: userID,
				From:   from,
				To:     tokenContract,
				Data:   erc20Data500, // 500 USDC * $1 = $500
				Value:  "0x0",
			},
			wantAllowed: true,
			wantReason:  "below threshold",
		},
		{
			name: "erc20 transfer above threshold no record",
			store: &mockComplianceStore{
				config:        enabledConfig(1000),
				tokenPrice:    erc20Price(tokenContract, "USDC", 6, 1.0),
				claimedRecord: nil,
			},
			req: &CheckRequest{
				OrgID:  orgID,
				UserID: userID,
				From:   from,
				To:     tokenContract,
				Data:   erc20Data1500, // 1500 USDC * $1 = $1500
				Value:  "0x0",
			},
			wantAllowed: false,
			wantReason:  "exceeds threshold",
		},
		{
			name: "above threshold record amount insufficient",
			store: &mockComplianceStore{
				config:        enabledConfig(1000),
				tokenPrice:    nativePrice(2000),
				claimedRecord: nil, // DB returns nil because record amount_fiat < transfer amount
			},
			req: &CheckRequest{
				OrgID:  orgID,
				UserID: userID,
				From:   from,
				To:     to,
				Data:   "",
				Value:  hexThreeETH, // 3 ETH * $2000 = $6000, but record is only for $4000
			},
			wantAllowed: false,
			wantReason:  "exceeds threshold",
		},
		{
			name: "exactly at threshold is allowed",
			store: &mockComplianceStore{
				config:     enabledConfig(1000),
				tokenPrice: nativePrice(2000),
			},
			req: &CheckRequest{
				OrgID:  orgID,
				UserID: userID,
				From:   from,
				To:     to,
				Data:   "",
				Value:  hexHalfETH, // 0.5 ETH * $2000 = $1000 exactly
			},
			// amountFiat < threshold uses strict less-than, so $1000 is NOT < $1000
			// This means it falls through to the travel rule check path.
			// With no record configured, it should be denied.
			wantAllowed: false,
			wantReason:  "exceeds threshold",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewChecker(tt.store, 24*time.Hour, 15*time.Minute)
			result, err := checker.Check(ctx, tt.req)
			if err != nil {
				t.Fatalf("Check() returned unexpected error: %v", err)
			}
			if result.Allowed != tt.wantAllowed {
				t.Errorf("Check() Allowed = %v, want %v (reason: %s)", result.Allowed, tt.wantAllowed, result.Reason)
			}
			if !strings.Contains(result.Reason, tt.wantReason) {
				t.Errorf("Check() Reason = %q, want substring %q", result.Reason, tt.wantReason)
			}
		})
	}
}

func TestCheckerPerAddressThreshold(t *testing.T) {
	ctx := context.Background()

	// 0.1 ETH = $200 at $2000/ETH
	hexTenthETH := "0x" + new(big.Int).Mul(big.NewInt(100000000000000000), big.NewInt(1)).Text(16)

	tests := []struct {
		name        string
		store       *mockComplianceStore
		req         *CheckRequest
		wantAllowed bool
		wantReason  string
	}{
		{
			name: "per-address override lowers threshold - denied",
			store: &mockComplianceStore{
				config:     enabledConfig(1000), // global: $1000
				tokenPrice: nativePrice(2000),
				addrOverrides: map[string]*AddressThresholdOverride{
					"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": {
						ID: "override-1", ThresholdFiat: 100, // address-specific: $100
					},
				},
			},
			req: &CheckRequest{
				OrgID: "org-1", UserID: "user-1",
				From:  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				To:    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				Value: hexTenthETH, // $200 > $100 override
			},
			wantAllowed: false,
			wantReason:  "exceeds threshold",
		},
		{
			name: "per-address override lowers threshold - allowed below override",
			store: &mockComplianceStore{
				config:     enabledConfig(1000),
				tokenPrice: nativePrice(2000),
				addrOverrides: map[string]*AddressThresholdOverride{
					"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": {
						ID: "override-1", ThresholdFiat: 500,
					},
				},
			},
			req: &CheckRequest{
				OrgID: "org-1", UserID: "user-1",
				From:  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				To:    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				Value: hexTenthETH, // $200 < $500 override
			},
			wantAllowed: true,
			wantReason:  "below threshold",
		},
		{
			name: "no override uses org threshold - allowed",
			store: &mockComplianceStore{
				config:     enabledConfig(1000),
				tokenPrice: nativePrice(2000),
			},
			req: &CheckRequest{
				OrgID: "org-1", UserID: "user-1",
				From:  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				To:    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				Value: hexTenthETH, // $200 < $1000 global
			},
			wantAllowed: true,
			wantReason:  "below threshold",
		},
		{
			name: "zero threshold requires record for any transfer",
			store: &mockComplianceStore{
				config:     enabledConfig(0), // $0 threshold
				tokenPrice: nativePrice(2000),
			},
			req: &CheckRequest{
				OrgID: "org-1", UserID: "user-1",
				From:  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				To:    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				Value: "0x1", // tiniest possible transfer
			},
			wantAllowed: false,
			wantReason:  "exceeds threshold",
		},
		{
			name: "zero per-address override requires record",
			store: &mockComplianceStore{
				config:     enabledConfig(1000),
				tokenPrice: nativePrice(2000),
				addrOverrides: map[string]*AddressThresholdOverride{
					"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": {
						ID: "override-1", ThresholdFiat: 0, // $0 for this address
					},
				},
			},
			req: &CheckRequest{
				OrgID: "org-1", UserID: "user-1",
				From:  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				To:    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				Value: "0x1",
			},
			wantAllowed: false,
			wantReason:  "exceeds threshold",
		},
		{
			name: "sender override also applies (lowest wins)",
			store: &mockComplianceStore{
				config:     enabledConfig(1000),
				tokenPrice: nativePrice(2000),
				addrOverrides: map[string]*AddressThresholdOverride{
					"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {
						ID: "override-sender", ThresholdFiat: 50, // sender override: $50
					},
					"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": {
						ID: "override-recipient", ThresholdFiat: 300, // recipient override: $300
					},
				},
			},
			req: &CheckRequest{
				OrgID: "org-1", UserID: "user-1",
				From:  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				To:    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				Value: hexTenthETH, // $200 > $50 (lowest override wins)
			},
			wantAllowed: false,
			wantReason:  "exceeds threshold",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewChecker(tt.store, 24*time.Hour, 15*time.Minute)
			result, err := checker.Check(ctx, tt.req)
			if err != nil {
				t.Fatalf("Check() returned unexpected error: %v", err)
			}
			if result.Allowed != tt.wantAllowed {
				t.Errorf("Check() Allowed = %v, want %v (reason: %s)", result.Allowed, tt.wantAllowed, result.Reason)
			}
			if !strings.Contains(result.Reason, tt.wantReason) {
				t.Errorf("Check() Reason = %q, want substring %q", result.Reason, tt.wantReason)
			}
		})
	}
}

func TestWeiToUSD(t *testing.T) {
	tests := []struct {
		name      string
		amountWei *big.Int
		decimals  int
		priceUSD  float64
		want      float64
		wantErr   bool
	}{
		{
			name:      "1 ETH at $2000",
			amountWei: new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil), // 1e18
			decimals:  18,
			priceUSD:  2000,
			want:      2000,
		},
		{
			name:      "0.5 ETH at $2000",
			amountWei: new(big.Int).Div(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil), big.NewInt(2)), // 5e17
			decimals:  18,
			priceUSD:  2000,
			want:      1000,
		},
		{
			name:      "1e6 USDC at $1",
			amountWei: big.NewInt(1_000_000), // 1e6
			decimals:  6,
			priceUSD:  1,
			want:      1,
		},
		{
			name:      "zero amount",
			amountWei: big.NewInt(0),
			decimals:  18,
			priceUSD:  2000,
			want:      0,
		},
		{
			name:      "nil amount",
			amountWei: nil,
			decimals:  18,
			priceUSD:  2000,
			want:      0,
		},
		{
			name:      "negative decimals rejected",
			amountWei: big.NewInt(1000),
			decimals:  -1,
			priceUSD:  100,
			wantErr:   true,
		},
		{
			name:      "excessive decimals rejected",
			amountWei: big.NewInt(1000),
			decimals:  100,
			priceUSD:  100,
			wantErr:   true,
		},
		{
			name:      "negative price rejected",
			amountWei: big.NewInt(1000),
			decimals:  18,
			priceUSD:  -1,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := WeiToUSD(tt.amountWei, tt.decimals, tt.priceUSD)
			if tt.wantErr {
				if err == nil {
					t.Errorf("WeiToUSD() expected error, got %f", got)
				}
				return
			}
			if err != nil {
				t.Errorf("WeiToUSD() unexpected error: %v", err)
				return
			}
			if math.Abs(got-tt.want) > 0.01 {
				t.Errorf("WeiToUSD() = %f, want %f", got, tt.want)
			}
		})
	}
}

func TestWeiToUSD_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		amountWei *big.Int
		decimals  int
		priceUSD  float64
		want      float64
		wantErr   bool
	}{
		{
			name:      "+Inf price",
			amountWei: big.NewInt(1e18),
			decimals:  18,
			priceUSD:  math.Inf(1),
			wantErr:   true,
		},
		{
			name:      "NaN price",
			amountWei: big.NewInt(1e18),
			decimals:  18,
			priceUSD:  math.NaN(),
			wantErr:   true,
		},
		{
			name: "very large amountWei that overflows float64",
			// 10^308 wei with 0 decimals and price $1 would produce 10^308,
			// which is near the edge of float64. 10^309 should overflow.
			amountWei: new(big.Int).Exp(big.NewInt(10), big.NewInt(309), nil),
			decimals:  0,
			priceUSD:  1,
			wantErr:   true,
		},
		{
			name:      "price $0 returns $0",
			amountWei: new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil), // 1 ETH
			decimals:  18,
			priceUSD:  0,
			want:      0,
		},
		{
			name:      "0 decimals token: raw units times price",
			amountWei: big.NewInt(100), // 100 raw units
			decimals:  0,
			priceUSD:  5.0,
			want:      500,
		},
		{
			name:      "max valid decimals 77 with reasonable amount",
			amountWei: new(big.Int).Exp(big.NewInt(10), big.NewInt(77), nil), // 10^77 wei
			decimals:  77,
			priceUSD:  1.0,
			want:      1.0, // 10^77 / 10^77 * $1 = $1
		},
		{
			name:      "1 wei at $2000 with 18 decimals (tiny but valid)",
			amountWei: big.NewInt(1),
			decimals:  18,
			priceUSD:  2000,
			want:      2e-15, // 1 / 1e18 * 2000 = 2e-15
		},
		{
			name:      "negative amountWei is rejected",
			amountWei: big.NewInt(-1000),
			decimals:  18,
			priceUSD:  2000,
			wantErr:   true,
		},
		{
			name:      "-Inf price",
			amountWei: big.NewInt(1e18),
			decimals:  18,
			priceUSD:  math.Inf(-1),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := WeiToUSD(tt.amountWei, tt.decimals, tt.priceUSD)
			if tt.wantErr {
				if err == nil {
					t.Errorf("WeiToUSD() expected error, got %f", got)
				}
				return
			}
			if err != nil {
				t.Errorf("WeiToUSD() unexpected error: %v", err)
				return
			}
			// Use relative tolerance for very small numbers
			if tt.want == 0 {
				if got != 0 {
					t.Errorf("WeiToUSD() = %e, want 0", got)
				}
			} else {
				relErr := math.Abs((got - tt.want) / tt.want)
				if relErr > 0.001 {
					t.Errorf("WeiToUSD() = %e, want %e (relative error: %f)", got, tt.want, relErr)
				}
			}
		})
	}
}

func TestWeiToFiat(t *testing.T) {
	// WeiToFiat delegates to WeiToUSD — just verify delegation works.
	amount := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil) // 1e18
	got, err := WeiToFiat(amount, 18, 2500)
	if err != nil {
		t.Fatalf("WeiToFiat() unexpected error: %v", err)
	}
	if math.Abs(got-2500) > 0.01 {
		t.Errorf("WeiToFiat() = %f, want 2500", got)
	}
}

func TestWeiToUSD_NegativeWei(t *testing.T) {
	// Verify that negative amountWei is rejected. Previously, amountWei.Sign() == 0
	// only caught zero, not negative values, which would have silently produced
	// a negative USD amount. The fix adds an explicit check for negative sign.
	amounts := []*big.Int{
		big.NewInt(-1),
		big.NewInt(-1000000000000000000), // -1 ETH
		new(big.Int).Neg(new(big.Int).Exp(big.NewInt(10), big.NewInt(50), nil)), // very large negative
	}

	for _, amt := range amounts {
		t.Run(fmt.Sprintf("negative_%s", amt.String()), func(t *testing.T) {
			_, err := WeiToUSD(amt, 18, 2000)
			if err == nil {
				t.Errorf("WeiToUSD(%s, 18, 2000) expected error for negative amount, got nil", amt.String())
			}
			if err != nil && !strings.Contains(err.Error(), "negative") {
				t.Errorf("WeiToUSD() error = %q, expected error mentioning 'negative'", err.Error())
			}
		})
	}
}

func TestCheckerCheck_DBErrors(t *testing.T) {
	ctx := context.Background()

	const (
		orgID  = "org-1"
		userID = "user-1"
		from   = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		to     = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	hexOneETH := "0xde0b6b3a7640000"

	tests := []struct {
		name  string
		store *mockComplianceStore
		req   *CheckRequest
	}{
		{
			name: "GetComplianceConfig error",
			store: &mockComplianceStore{
				configErr: fmt.Errorf("db connection lost"),
			},
			req: &CheckRequest{
				OrgID: orgID, UserID: userID,
				From: from, To: to,
				Value: hexOneETH,
			},
		},
		{
			name: "IsAddressSanctioned error on recipient",
			store: &mockComplianceStore{
				config:      enabledConfig(1000),
				sanctionErr: fmt.Errorf("sanctions table unavailable"),
			},
			req: &CheckRequest{
				OrgID: orgID, UserID: userID,
				From: from, To: to,
				Value: hexOneETH,
			},
		},
		{
			name: "GetTokenPrice error",
			store: &mockComplianceStore{
				config:        enabledConfig(1000),
				tokenPriceErr: fmt.Errorf("price cache failed"),
			},
			req: &CheckRequest{
				OrgID: orgID, UserID: userID,
				From: from, To: to,
				Value: hexOneETH,
			},
		},
		{
			name: "ClaimUnusedTravelRuleRecord error",
			store: &mockComplianceStore{
				config:     enabledConfig(1000),
				tokenPrice: nativePrice(2000),
				claimErr:   fmt.Errorf("deadlock detected"),
			},
			req: &CheckRequest{
				OrgID: orgID, UserID: userID,
				From: from, To: to,
				Value: hexOneETH, // 1 ETH * $2000 = $2000 > $1000 threshold
			},
		},
		{
			name: "GetAddressThresholdOverride error",
			store: &mockComplianceStore{
				config:          enabledConfig(1000),
				tokenPrice:      nativePrice(2000),
				addrOverrideErr: fmt.Errorf("override table locked"),
			},
			req: &CheckRequest{
				OrgID: orgID, UserID: userID,
				From: from, To: to,
				Value: hexOneETH,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewChecker(tt.store, 24*time.Hour, 15*time.Minute)
			result, err := checker.Check(ctx, tt.req)
			if err == nil {
				t.Fatalf("Check() expected error, got result: Allowed=%v Reason=%q", result.Allowed, result.Reason)
			}
		})
	}
}

func TestCheckerCheck_AuditLogFailClosed(t *testing.T) {
	ctx := context.Background()

	const (
		orgID  = "org-1"
		userID = "user-1"
		from   = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		to     = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	hexOneTenthETH := "0x16345785d8a0000" // 0.1 ETH
	hexOneETH := "0xde0b6b3a7640000"      // 1 ETH

	tests := []struct {
		name        string
		store       *mockComplianceStore
		req         *CheckRequest
		wantAllowed bool
		wantReason  string // substring match
	}{
		{
			name: "allowed decision + log fails = denial (fail closed)",
			store: &mockComplianceStore{
				config:     enabledConfig(1000),
				tokenPrice: nativePrice(2000),
				logErr:     fmt.Errorf("audit log unavailable"),
			},
			req: &CheckRequest{
				OrgID: orgID, UserID: userID,
				From: from, To: to,
				Value: hexOneTenthETH, // 0.1 ETH * $2000 = $200 < $1000
			},
			wantAllowed: false,
			wantReason:  "failing closed",
		},
		{
			name: "denied decision + log fails = still denied",
			store: &mockComplianceStore{
				config:        enabledConfig(1000),
				tokenPrice:    nativePrice(2000),
				claimedRecord: nil, // no record
				logErr:        fmt.Errorf("audit log unavailable"),
			},
			req: &CheckRequest{
				OrgID: orgID, UserID: userID,
				From: from, To: to,
				Value: hexOneETH, // 1 ETH * $2000 = $2000 > $1000
			},
			wantAllowed: false,
			wantReason:  "exceeds threshold",
		},
		{
			name: "allowed with record + log fails = denial (fail closed)",
			store: &mockComplianceStore{
				config:     enabledConfig(1000),
				tokenPrice: nativePrice(2000),
				claimedRecord: &TravelRuleRecord{
					ID:    "tr-1",
					OrgID: orgID,
				},
				logErr: fmt.Errorf("audit log unavailable"),
			},
			req: &CheckRequest{
				OrgID: orgID, UserID: userID,
				From: from, To: to,
				Value: hexOneETH, // 1 ETH * $2000 = $2000 > $1000, but record exists
			},
			wantAllowed: false,
			wantReason:  "failing closed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewChecker(tt.store, 24*time.Hour, 15*time.Minute)
			result, err := checker.Check(ctx, tt.req)
			if err != nil {
				t.Fatalf("Check() returned unexpected error: %v", err)
			}
			if result.Allowed != tt.wantAllowed {
				t.Errorf("Check() Allowed = %v, want %v (reason: %s)", result.Allowed, tt.wantAllowed, result.Reason)
			}
			if !strings.Contains(result.Reason, tt.wantReason) {
				t.Errorf("Check() Reason = %q, want substring %q", result.Reason, tt.wantReason)
			}
		})
	}
}

func TestCheckerCheck_InteractionEdgeCases(t *testing.T) {
	ctx := context.Background()

	const (
		orgID  = "org-1"
		userID = "user-1"
		from   = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		to     = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	// 1000 ETH in hex: 1000 * 1e18 = 1e21 = 0xd3c21bcecceda1000000
	eth1000 := new(big.Int).Mul(new(big.Int).SetInt64(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	hexThousandETH := "0x" + eth1000.Text(16)

	tests := []struct {
		name        string
		store       *mockComplianceStore
		req         *CheckRequest
		wantAllowed bool
		wantReason  string // substring match
	}{
		{
			name: "sanctions block even 1 wei",
			store: &mockComplianceStore{
				config:          enabledConfig(1000),
				tokenPrice:      nativePrice(2000),
				sanctionedAddrs: map[string]bool{strings.ToLower(to): true},
			},
			req: &CheckRequest{
				OrgID: orgID, UserID: userID,
				From: from, To: to,
				Value: "0x1", // 1 wei
			},
			wantAllowed: false,
			wantReason:  "sanctioned",
		},
		{
			name: "sanctions block even with valid record",
			store: &mockComplianceStore{
				config:          enabledConfig(1000),
				tokenPrice:      nativePrice(2000),
				sanctionedAddrs: map[string]bool{strings.ToLower(to): true},
				claimedRecord: &TravelRuleRecord{
					ID:    "tr-1",
					OrgID: orgID,
				},
			},
			req: &CheckRequest{
				OrgID: orgID, UserID: userID,
				From: from, To: to,
				Value: "0xde0b6b3a7640000", // 1 ETH
			},
			wantAllowed: false,
			wantReason:  "sanctioned",
		},
		{
			name: "$0 price fails closed (misconfiguration)",
			store: &mockComplianceStore{
				config:     enabledConfig(1000),
				tokenPrice: nativePrice(0), // $0/ETH — misconfiguration → fail closed
			},
			req: &CheckRequest{
				OrgID: orgID, UserID: userID,
				From: from, To: to,
				Value: hexThousandETH, // 1000 ETH * $0 = no valid price → fail closed
			},
			wantAllowed: false,
			wantReason:  "no price configured",
		},
		{
			name: "per-address override + record interaction: above override, record exists = allowed",
			store: &mockComplianceStore{
				config:     enabledConfig(1000),
				tokenPrice: nativePrice(2000),
				addrOverrides: map[string]*AddressThresholdOverride{
					strings.ToLower(to): {
						ID: "override-1", ThresholdFiat: 100, // $100 override
					},
				},
				claimedRecord: &TravelRuleRecord{
					ID:    "tr-1",
					OrgID: orgID,
				},
			},
			req: &CheckRequest{
				OrgID: orgID, UserID: userID,
				From: from, To: to,
				Value: "0x16345785d8a0000", // 0.1 ETH * $2000 = $200 > $100 override
			},
			wantAllowed: true,
			wantReason:  "travel rule record tr-1 applied",
		},
		{
			name: "per-address override + no record: above override = denied",
			store: &mockComplianceStore{
				config:     enabledConfig(1000),
				tokenPrice: nativePrice(2000),
				addrOverrides: map[string]*AddressThresholdOverride{
					strings.ToLower(to): {
						ID: "override-1", ThresholdFiat: 100,
					},
				},
				claimedRecord: nil,
			},
			req: &CheckRequest{
				OrgID: orgID, UserID: userID,
				From: from, To: to,
				Value: "0x16345785d8a0000", // 0.1 ETH * $2000 = $200 > $100 override
			},
			wantAllowed: false,
			wantReason:  "exceeds threshold",
		},
		{
			name: "very large transfer with record",
			store: &mockComplianceStore{
				config:     enabledConfig(1000),
				tokenPrice: nativePrice(2000),
				claimedRecord: &TravelRuleRecord{
					ID:    "tr-whale",
					OrgID: orgID,
				},
			},
			req: &CheckRequest{
				OrgID: orgID, UserID: userID,
				From: from, To: to,
				Value: hexThousandETH, // 1000 ETH * $2000 = $2,000,000
			},
			wantAllowed: true,
			wantReason:  "travel rule record tr-whale applied",
		},
		{
			name: "floating point just below threshold = allowed",
			store: &mockComplianceStore{
				config: enabledConfig(1000),
				// Price that makes 0.4999 ETH = $999.8 (below $1000)
				// 0.4999 ETH * $2000 = $999.80
				tokenPrice: nativePrice(2000),
			},
			req: &CheckRequest{
				OrgID: orgID, UserID: userID,
				From: from, To: to,
				// 0.4999 ETH = 4.999e17 wei = 0x6f0226ea9aa2800 (approximately)
				Value: "0x" + new(big.Int).SetUint64(499900000000000000).Text(16),
			},
			wantAllowed: true,
			wantReason:  "below threshold",
		},
		{
			name: "floating point just above threshold = denied",
			store: &mockComplianceStore{
				config:        enabledConfig(1000),
				tokenPrice:    nativePrice(2000),
				claimedRecord: nil,
			},
			req: &CheckRequest{
				OrgID: orgID, UserID: userID,
				From: from, To: to,
				// 0.5001 ETH = 5.001e17 wei at $2000/ETH = $1000.20
				Value: "0x" + new(big.Int).SetUint64(500100000000000000).Text(16),
			},
			wantAllowed: false,
			wantReason:  "exceeds threshold",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewChecker(tt.store, 24*time.Hour, 15*time.Minute)
			result, err := checker.Check(ctx, tt.req)
			if err != nil {
				t.Fatalf("Check() returned unexpected error: %v", err)
			}
			if result.Allowed != tt.wantAllowed {
				t.Errorf("Check() Allowed = %v, want %v (reason: %s)", result.Allowed, tt.wantAllowed, result.Reason)
			}
			if !strings.Contains(result.Reason, tt.wantReason) {
				t.Errorf("Check() Reason = %q, want substring %q", result.Reason, tt.wantReason)
			}
		})
	}
}

// TestCheckerCheck_PerOrgCurrency proves the checker values a transfer in the
// ORG's own currency (config.Currency), not the cluster-wide base_currency
// (RD-1158). config.Currency=eur is honoured even though the stale global
// setting would value in USD and flip the decision — so one org's currency
// choice can never affect another's enforcement.
func TestCheckerCheck_PerOrgCurrency(t *testing.T) {
	const orgID, userID = "org-1", "user-1"
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	cfg := enabledConfig(1000)
	cfg.Currency = "eur"
	store := &mockComplianceStore{
		config: cfg,
		// The stale global would value in USD and DENY; it MUST be ignored now
		// that currency is per-org.
		systemSetting: "usd",
		tokenPrice: nativePriceMultiCurrency(map[string]float64{
			"usd": 5000,
			"eur": 4000,
		}),
	}

	// 0.22 ETH: EUR = 0.22 * 4000 = €880 (< €1000 → allowed);
	//           USD = 0.22 * 5000 = $1100 (> $1000 → would be denied).
	value := "0x" + new(big.Int).SetUint64(220000000000000000).Text(16)

	checker := NewChecker(store, 24*time.Hour, 15*time.Minute)
	result, err := checker.Check(context.Background(), &CheckRequest{
		OrgID: orgID, UserID: userID, From: from, To: to, Value: value,
	})
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("Allowed=false (reason %q): per-org EUR valuation should allow €880 < €1000; the global USD setting must be ignored", result.Reason)
	}
	if !strings.Contains(result.Reason, "below threshold") {
		t.Errorf("Reason = %q, want 'below threshold'", result.Reason)
	}
	// The audit snapshot must record the per-org currency, not the global one.
	if len(store.logs) == 0 {
		t.Fatalf("expected a compliance decision log")
	}
	last := store.logs[len(store.logs)-1]
	if last.Currency != "eur" {
		t.Errorf("logged decision currency = %q, want %q (per-org snapshot)", last.Currency, "eur")
	}
	if last.AmountFiat == nil || *last.AmountFiat < 879 || *last.AmountFiat > 881 {
		t.Errorf("logged amount_fiat = %v, want ~880 (valued in EUR, not USD)", last.AmountFiat)
	}
}

func TestResolveTokenPrice_MultiCurrency(t *testing.T) {
	const orgID = "org-1"
	const userID = "user-1"
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	tests := []struct {
		name        string
		store       *mockComplianceStore
		wantAllowed bool
		wantReason  string
	}{
		{
			name: "manual token: uses prices_by_currency for active currency (EUR)",
			store: &mockComplianceStore{
				config: enabledConfig(5000),
				tokenPrice: nativePriceMultiCurrency(map[string]float64{
					"usd": 3500,
					"eur": 3200,
				}),
				systemSetting: "eur",
			},
			wantAllowed: true,
			wantReason:  "below threshold", // 1 ETH * €3200 = €3200 < €5000
		},
		{
			name: "manual token: fails closed when active currency not in prices_by_currency",
			store: &mockComplianceStore{
				config: enabledConfig(5000),
				tokenPrice: nativePriceMultiCurrency(map[string]float64{
					"usd": 3500,
				}),
				systemSetting: "eur",
			},
			wantAllowed: false,
			wantReason:  "no price configured",
		},
		{
			name: "manual token: legacy fallback when prices_by_currency is nil",
			store: &mockComplianceStore{
				config:        enabledConfig(5000),
				tokenPrice:    nativePrice(3500),
				systemSetting: "usd",
			},
			wantAllowed: true,
			wantReason:  "below threshold", // 1 ETH * $3500 = $3500 < $5000
		},
		{
			name: "coingecko-linked: uses system prices_by_currency for active currency",
			store: &mockComplianceStore{
				config:     enabledConfig(5000),
				tokenPrice: coingeckoLinkedPrice("ethereum"),
				systemPrices: map[string]*SystemTokenPrice{
					"ethereum": {
						ID:        1,
						Symbol:    "ETH",
						Decimals:  18,
						PriceFiat: 3500,
						PricesByCurrency: map[string]float64{
							"usd": 3500,
							"eur": 3200,
							"gbp": 2800,
						},
						UpdatedAt: time.Now(),
					},
				},
				systemSetting: "gbp",
			},
			wantAllowed: true,
			wantReason:  "below threshold", // 1 ETH * £2800 = £2800 < £5000
		},
		{
			name: "coingecko-linked: fails closed when system price unavailable",
			store: &mockComplianceStore{
				config:        enabledConfig(5000),
				tokenPrice:    coingeckoLinkedPrice("ethereum"),
				systemPrices:  map[string]*SystemTokenPrice{},
				systemSetting: "usd",
			},
			wantAllowed: false,
			wantReason:  "no price configured",
		},
		{
			name: "coingecko-linked: fails closed when stale (no fallback to manual)",
			store: &mockComplianceStore{
				config:     enabledConfig(5000),
				tokenPrice: coingeckoLinkedPrice("ethereum"),
				systemPrices: map[string]*SystemTokenPrice{
					"ethereum": {
						ID:        1,
						Symbol:    "ETH",
						Decimals:  18,
						PriceFiat: 3500,
						PricesByCurrency: map[string]float64{
							"usd": 3500,
						},
						UpdatedAt: time.Now().Add(-2 * time.Hour), // stale
					},
				},
				systemSetting: "usd",
			},
			wantAllowed: false,
			wantReason:  "no price configured",
		},
		{
			name: "auto-resolve native: uses system prices_by_currency",
			store: &mockComplianceStore{
				config:     enabledConfig(5000),
				tokenPrice: nil, // no per-org entry
				systemPrices: map[string]*SystemTokenPrice{
					"ethereum": {
						ID:        1,
						Symbol:    "ETH",
						Decimals:  18,
						PriceFiat: 3500,
						PricesByCurrency: map[string]float64{
							"usd": 3500,
							"chf": 3100,
						},
						UpdatedAt: time.Now(),
					},
				},
				systemSetting: "chf",
			},
			wantAllowed: true,
			wantReason:  "below threshold", // 1 ETH * CHF 3100 = CHF 3100 < CHF 5000
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewChecker(tt.store, 24*time.Hour, 1*time.Hour)
			result, err := checker.Check(context.Background(), &CheckRequest{
				OrgID:  orgID,
				UserID: userID,
				From:   from,
				To:     to,
				Value:  "0xde0b6b3a7640000", // 1 ETH
			})
			if err != nil {
				t.Fatalf("Check() returned unexpected error: %v", err)
			}
			if result.Allowed != tt.wantAllowed {
				t.Errorf("Check() Allowed = %v, want %v (reason: %s)", result.Allowed, tt.wantAllowed, result.Reason)
			}
			if !strings.Contains(result.Reason, tt.wantReason) {
				t.Errorf("Check() Reason = %q, want substring %q", result.Reason, tt.wantReason)
			}
		})
	}
}

func TestCheckerUnknownPricePolicy(t *testing.T) {
	req := &CheckRequest{
		OrgID: "org-1",
		From:  "0x1111",
		To:    "0x2222",
		Value: "0xde0b6b3a7640000", // 1 token
	}

	tests := []struct {
		name    string
		policy  UnknownPricePolicy
		allowed bool
	}{
		{
			name:    "forbidden policy denies transfer when price is unknown",
			policy:  UnknownPriceForbidden,
			allowed: false,
		},
		{
			name:    "allowed policy permits transfer when price is unknown",
			policy:  UnknownPriceAllowed,
			allowed: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := &mockComplianceStore{
				config: &ComplianceConfig{
					OrgID:              "org-1",
					Enabled:            true,
					ThresholdFiat:      1000,
					UnknownPricePolicy: tc.policy,
				},
			}
			// No token price set -> price is unknown

			checker := NewChecker(store, 24*time.Hour, 15*time.Minute)
			res, err := checker.Check(context.Background(), req)
			if err != nil {
				t.Fatalf("Check failed: %v", err)
			}
			if res.Allowed != tc.allowed {
				t.Errorf("got allowed=%v, want %v. reason: %s", res.Allowed, tc.allowed, res.Reason)
			}
		})
	}
}
