package policydsl

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

var (
	signerAddr = common.HexToAddress("0xAAAA000000000000000000000000000000000001")
	linkedAddr = common.HexToAddress("0xBBBB000000000000000000000000000000000002")
	strangerAd = common.HexToAddress("0xCCCC000000000000000000000000000000000003")
	libraryAd  = common.HexToAddress("0xDDDD000000000000000000000000000000000004")
)

// transferCalldata builds real calldata for transfer(address,uint256) so the
// evaluator is exercised against bytes an EVM would actually see.
func transferCalldata(t *testing.T, to common.Address, amount *big.Int) []byte {
	t.Helper()
	parsed, err := abi.JSON(strings.NewReader(vaultABI))
	if err != nil {
		t.Fatalf("fixture ABI does not parse: %v", err)
	}
	data, err := parsed.Pack("transfer", to, amount)
	if err != nil {
		t.Fatalf("packing transfer calldata: %v", err)
	}
	return data
}

func balanceOfCalldata(t *testing.T, owner common.Address) []byte {
	t.Helper()
	parsed, err := abi.JSON(strings.NewReader(vaultABI))
	if err != nil {
		t.Fatalf("fixture ABI does not parse: %v", err)
	}
	data, err := parsed.Pack("balanceOf", owner)
	if err != nil {
		t.Fatalf("packing balanceOf calldata: %v", err)
	}
	return data
}

// validatedWith builds a Validated from one binding's rules.
func validatedWith(t *testing.T, rules ...FrameRule) *Validated {
	t.Helper()
	p := &Policy{
		APIVersion:  APIVersion,
		Kind:        Kind,
		Org:         orgID,
		NestedCalls: NestedCallsRequireOwnRule,
		Bindings:    []Binding{{Group: groupID, Allow: rules}},
	}
	v, err := Validate(p, testCatalog(t))
	if err != nil {
		t.Fatalf("fixture policy failed validation: %v", err)
	}
	return v
}

func plainRule(t *testing.T, selector string, args ...ArgConstraint) FrameRule {
	t.Helper()
	return FrameRule{
		StorageAddress: vaultAddr,
		Selector:       selector,
		ABIDigest:      abiDigest(t, vaultABI),
		Args:           args,
	}
}

func memberCtx() Context {
	return Context{
		Groups:          []string{groupID},
		Signer:          signerAddr,
		LinkedAddresses: []common.Address{signerAddr, linkedAddr},
	}
}

func vaultCall(data []byte) Frame {
	return Frame{
		CallType:       CallTypeCall,
		StorageAddress: common.HexToAddress(vaultAddr),
		CodeAddress:    common.HexToAddress(vaultAddr),
		Calldata:       data,
	}
}

func TestEvaluate(t *testing.T) {
	hundred := "100"

	tests := []struct {
		name    string
		rules   []FrameRule
		ctx     Context
		frames  []Frame
		want    bool
		wantWhy string // substring required in the denial reason
	}{
		{
			name:   "permitted selector on a permitted contract",
			rules:  []FrameRule{plainRule(t, selTransfer)},
			ctx:    memberCtx(),
			frames: []Frame{vaultCall(transferCalldata(t, strangerAd, big.NewInt(1)))},
			want:   true,
		},
		{
			name:  "principal belongs to no bound group",
			rules: []FrameRule{plainRule(t, selTransfer)},
			ctx: Context{
				Groups: []string{"grp_other"},
				Signer: signerAddr,
			},
			frames:  []Frame{vaultCall(transferCalldata(t, strangerAd, big.NewInt(1)))},
			want:    false,
			wantWhy: "no rule",
		},
		{
			name:    "selector is not in the policy",
			rules:   []FrameRule{plainRule(t, selTransfer)},
			ctx:     memberCtx(),
			frames:  []Frame{vaultCall(balanceOfCalldata(t, signerAddr))},
			want:    false,
			wantWhy: "no rule",
		},
		{
			name:  "contract is not in the policy",
			rules: []FrameRule{plainRule(t, selTransfer)},
			ctx:   memberCtx(),
			frames: []Frame{{
				CallType:       CallTypeCall,
				StorageAddress: common.HexToAddress(relayAddr),
				CodeAddress:    common.HexToAddress(relayAddr),
				Calldata:       transferCalldata(t, strangerAd, big.NewInt(1)),
			}},
			want:    false,
			wantWhy: "no rule",
		},
		{
			name:   "staticcall is permitted by default",
			rules:  []FrameRule{plainRule(t, selBalanceOf)},
			ctx:    memberCtx(),
			frames: []Frame{{CallType: CallTypeStaticCall, StorageAddress: common.HexToAddress(vaultAddr), CodeAddress: common.HexToAddress(vaultAddr), Calldata: balanceOfCalldata(t, signerAddr)}},
			want:   true,
		},
		{
			name:    "delegatecall is not permitted by default",
			rules:   []FrameRule{plainRule(t, selTransfer)},
			ctx:     memberCtx(),
			frames:  []Frame{{CallType: CallTypeDelegateCall, StorageAddress: common.HexToAddress(vaultAddr), CodeAddress: libraryAd, Calldata: transferCalldata(t, strangerAd, big.NewInt(1))}},
			want:    false,
			wantWhy: "no rule",
		},
		{
			name: "delegatecall is permitted when the rule names the code address",
			rules: []FrameRule{{
				StorageAddress: vaultAddr,
				CodeAddress:    libraryAd.Hex(),
				Selector:       selTransfer,
				ABIDigest:      abiDigest(t, vaultABI),
				CallTypes:      []CallType{CallTypeDelegateCall},
			}},
			ctx:    memberCtx(),
			frames: []Frame{{CallType: CallTypeDelegateCall, StorageAddress: common.HexToAddress(vaultAddr), CodeAddress: libraryAd, Calldata: transferCalldata(t, strangerAd, big.NewInt(1))}},
			want:   true,
		},
		{
			name: "delegatecall through a different library is denied",
			rules: []FrameRule{{
				StorageAddress: vaultAddr,
				CodeAddress:    libraryAd.Hex(),
				Selector:       selTransfer,
				ABIDigest:      abiDigest(t, vaultABI),
				CallTypes:      []CallType{CallTypeDelegateCall},
			}},
			ctx:     memberCtx(),
			frames:  []Frame{{CallType: CallTypeDelegateCall, StorageAddress: common.HexToAddress(vaultAddr), CodeAddress: strangerAd, Calldata: transferCalldata(t, strangerAd, big.NewInt(1))}},
			want:    false,
			wantWhy: "no rule",
		},
		{
			name:   "address argument equals the signer",
			rules:  []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourceSigner}})},
			ctx:    memberCtx(),
			frames: []Frame{vaultCall(transferCalldata(t, signerAddr, big.NewInt(1)))},
			want:   true,
		},
		{
			name:    "address argument does not equal the signer",
			rules:   []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourceSigner}})},
			ctx:     memberCtx(),
			frames:  []Frame{vaultCall(transferCalldata(t, strangerAd, big.NewInt(1)))},
			want:    false,
			wantWhy: "argument 0",
		},
		{
			name:   "address argument matches one of the principal's linked addresses",
			rules:  []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourcePrincipalLinked}})},
			ctx:    memberCtx(),
			frames: []Frame{vaultCall(transferCalldata(t, linkedAddr, big.NewInt(1)))},
			want:   true,
		},
		{
			name:    "address argument matches none of the linked addresses",
			rules:   []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourcePrincipalLinked}})},
			ctx:     memberCtx(),
			frames:  []Frame{vaultCall(transferCalldata(t, strangerAd, big.NewInt(1)))},
			want:    false,
			wantWhy: "argument 0",
		},
		{
			name:    "principal has no linked addresses at all",
			rules:   []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourcePrincipalLinked}})},
			ctx:     Context{Groups: []string{groupID}, Signer: signerAddr},
			frames:  []Frame{vaultCall(transferCalldata(t, linkedAddr, big.NewInt(1)))},
			want:    false,
			wantWhy: "argument 0",
		},
		{
			name:   "address argument equals a literal",
			rules:  []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourceLiteral, Value: strangerAd.Hex()}})},
			ctx:    memberCtx(),
			frames: []Frame{vaultCall(transferCalldata(t, strangerAd, big.NewInt(1)))},
			want:   true,
		},
		{
			name:   "uint argument is below the bound",
			rules:  []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 1, UintAtMost: &hundred})},
			ctx:    memberCtx(),
			frames: []Frame{vaultCall(transferCalldata(t, strangerAd, big.NewInt(99)))},
			want:   true,
		},
		{
			name:   "uint argument is exactly at the bound",
			rules:  []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 1, UintAtMost: &hundred})},
			ctx:    memberCtx(),
			frames: []Frame{vaultCall(transferCalldata(t, strangerAd, big.NewInt(100)))},
			want:   true,
		},
		{
			name:    "uint argument is above the bound",
			rules:   []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 1, UintAtMost: &hundred})},
			ctx:     memberCtx(),
			frames:  []Frame{vaultCall(transferCalldata(t, strangerAd, big.NewInt(101)))},
			want:    false,
			wantWhy: "argument 1",
		},
		{
			name: "two constraints on one rule must both hold",
			rules: []FrameRule{plainRule(t, selTransfer,
				ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourceSigner}},
				ArgConstraint{Index: 1, UintAtMost: &hundred},
			)},
			ctx:     memberCtx(),
			frames:  []Frame{vaultCall(transferCalldata(t, signerAddr, big.NewInt(101)))},
			want:    false,
			wantWhy: "argument 1",
		},
		{
			name: "every nested frame needs its own rule",
			rules: []FrameRule{
				plainRule(t, selTransfer),
				plainRule(t, selBalanceOf),
			},
			ctx: memberCtx(),
			frames: []Frame{
				vaultCall(transferCalldata(t, strangerAd, big.NewInt(1))),
				vaultCall(balanceOfCalldata(t, signerAddr)),
			},
			want: true,
		},
		{
			name:  "one unpermitted nested frame denies the whole execution",
			rules: []FrameRule{plainRule(t, selTransfer)},
			ctx:   memberCtx(),
			frames: []Frame{
				vaultCall(transferCalldata(t, strangerAd, big.NewInt(1))),
				{
					CallType:       CallTypeCall,
					StorageAddress: common.HexToAddress(relayAddr),
					CodeAddress:    common.HexToAddress(relayAddr),
					Calldata:       transferCalldata(t, strangerAd, big.NewInt(1)),
				},
			},
			want:    false,
			wantWhy: "frame 1",
		},
		{
			name:    "an execution with no observed frames is denied",
			rules:   []FrameRule{plainRule(t, selTransfer)},
			ctx:     memberCtx(),
			frames:  nil,
			want:    false,
			wantWhy: "no frames",
		},
		{
			name:    "calldata too short to carry a selector",
			rules:   []FrameRule{plainRule(t, selTransfer)},
			ctx:     memberCtx(),
			frames:  []Frame{vaultCall([]byte{0x01, 0x02})},
			want:    false,
			wantWhy: "calldata",
		},
		{
			name:    "calldata arguments are truncated",
			rules:   []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourceSigner}})},
			ctx:     memberCtx(),
			frames:  []Frame{vaultCall(transferCalldata(t, signerAddr, big.NewInt(1))[:20])},
			want:    false,
			wantWhy: "decode",
		},
		{
			name:    "unknown call type on the frame",
			rules:   []FrameRule{plainRule(t, selTransfer)},
			ctx:     memberCtx(),
			frames:  []Frame{{CallType: "create", StorageAddress: common.HexToAddress(vaultAddr), CodeAddress: common.HexToAddress(vaultAddr), Calldata: transferCalldata(t, strangerAd, big.NewInt(1))}},
			want:    false,
			wantWhy: "no rule",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := validatedWith(t, tc.rules...)
			got := v.Evaluate(tc.ctx, tc.frames)

			if got.Allowed != tc.want {
				t.Fatalf("Allowed = %v, want %v (reason: %q)", got.Allowed, tc.want, got.Reason)
			}
			if tc.want {
				return
			}
			if got.Reason == "" {
				t.Fatal("a denial must carry a reason")
			}
			if !strings.Contains(strings.ToLower(got.Reason), strings.ToLower(tc.wantWhy)) {
				t.Errorf("reason %q does not mention %q", got.Reason, tc.wantWhy)
			}
		})
	}
}

// TestEvaluate_DenyAllPolicyDeniesEverything pins the fail-closed default: a
// binding that allows nothing must not degrade into allowing anything.
func TestEvaluate_DenyAllPolicyDeniesEverything(t *testing.T) {
	v := validatedWith(t)

	got := v.Evaluate(memberCtx(), []Frame{vaultCall(transferCalldata(t, signerAddr, big.NewInt(1)))})
	if got.Allowed {
		t.Fatal("a policy allowing no frames permitted one")
	}
}
