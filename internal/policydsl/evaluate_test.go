package policydsl

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

var (
	signerAddr   = common.HexToAddress("0xAAAA000000000000000000000000000000000001")
	linkedAddr   = common.HexToAddress("0xBBBB000000000000000000000000000000000002")
	strangerAddr = common.HexToAddress("0xCCCC000000000000000000000000000000000003")
)

// packCalldata builds real calldata so the evaluator is exercised against bytes
// an EVM would actually see.
func packCalldata(t *testing.T, abiText, method string, args ...any) []byte {
	t.Helper()
	parsed, err := abi.JSON(strings.NewReader(abiText))
	if err != nil {
		t.Fatalf("fixture ABI does not parse: %v", err)
	}
	data, err := parsed.Pack(method, args...)
	if err != nil {
		t.Fatalf("packing %s calldata: %v", method, err)
	}
	return data
}

func transferCalldata(t *testing.T, to common.Address, amount *big.Int) []byte {
	t.Helper()
	return packCalldata(t, vaultABI, "transfer", to, amount)
}

func balanceOfCalldata(t *testing.T, owner common.Address) []byte {
	t.Helper()
	return packCalldata(t, vaultABI, "balanceOf", owner)
}

// validatedWith builds a Validated from one binding's rules.
func validatedWith(t *testing.T, rules ...FrameRule) *Validated {
	t.Helper()
	return validatedFrom(t, []Binding{{Group: groupID, Allow: rules}})
}

func validatedFrom(t *testing.T, bindings []Binding) *Validated {
	t.Helper()
	p := &Policy{
		APIVersion:  APIVersion,
		Kind:        Kind,
		Org:         orgID,
		NestedCalls: NestedCallsRequireOwnRule,
		Bindings:    bindings,
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

func delegateRule(t *testing.T, callType CallType, args ...ArgConstraint) FrameRule {
	t.Helper()
	return FrameRule{
		StorageAddress: vaultAddr,
		CodeAddress:    libraryAddr.Hex(),
		Selector:       selTransfer,
		ABIDigest:      abiDigest(t, libraryABI),
		CallTypes:      []CallType{callType},
		Args:           args,
	}
}

func memberCtx() Context {
	return Context{
		Org:             orgID,
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

func delegateFrame(callType CallType, code common.Address, data []byte) Frame {
	return Frame{
		CallType:       callType,
		StorageAddress: common.HexToAddress(vaultAddr),
		CodeAddress:    code,
		Calldata:       data,
	}
}

func TestEvaluate(t *testing.T) {
	hundred := "100"

	tests := []struct {
		name     string
		rules    []FrameRule
		ctx      Context
		frames   []Frame
		want     bool
		wantCode DenialCode
		wantWhy  string // substring required in the operator reason
	}{
		{
			name:   "permitted selector on a permitted contract",
			rules:  []FrameRule{plainRule(t, selTransfer)},
			ctx:    memberCtx(),
			frames: []Frame{vaultCall(transferCalldata(t, strangerAddr, big.NewInt(1)))},
			want:   true,
		},
		{
			name:  "principal belongs to no bound group",
			rules: []FrameRule{plainRule(t, selTransfer)},
			ctx: Context{
				Org:    orgID,
				Groups: []string{"grp_other"},
				Signer: signerAddr,
			},
			frames:   []Frame{vaultCall(transferCalldata(t, strangerAddr, big.NewInt(1)))},
			want:     false,
			wantCode: DenialNoMatchingRule,
			wantWhy:  "no rule",
		},
		{
			name:     "principal is acting in another organisation",
			rules:    []FrameRule{plainRule(t, selTransfer)},
			ctx:      Context{Org: "org_other", Groups: []string{groupID}, Signer: signerAddr},
			frames:   []Frame{vaultCall(transferCalldata(t, strangerAddr, big.NewInt(1)))},
			want:     false,
			wantCode: DenialInvalidContext,
			wantWhy:  "organisation",
		},
		{
			name:     "context carries no organisation",
			rules:    []FrameRule{plainRule(t, selTransfer)},
			ctx:      Context{Groups: []string{groupID}, Signer: signerAddr},
			frames:   []Frame{vaultCall(transferCalldata(t, strangerAddr, big.NewInt(1)))},
			want:     false,
			wantCode: DenialInvalidContext,
			wantWhy:  "organisation",
		},
		{
			name:     "selector is not in the policy",
			rules:    []FrameRule{plainRule(t, selTransfer)},
			ctx:      memberCtx(),
			frames:   []Frame{vaultCall(balanceOfCalldata(t, signerAddr))},
			want:     false,
			wantCode: DenialNoMatchingRule,
			wantWhy:  "no rule",
		},
		{
			name:  "contract is not in the policy",
			rules: []FrameRule{plainRule(t, selTransfer)},
			ctx:   memberCtx(),
			frames: []Frame{{
				CallType:       CallTypeCall,
				StorageAddress: common.HexToAddress(relayAddr),
				CodeAddress:    common.HexToAddress(relayAddr),
				Calldata:       transferCalldata(t, strangerAddr, big.NewInt(1)),
			}},
			want:     false,
			wantCode: DenialNoMatchingRule,
			wantWhy:  "no rule",
		},
		{
			name:   "staticcall is permitted by default",
			rules:  []FrameRule{plainRule(t, selBalanceOf)},
			ctx:    memberCtx(),
			frames: []Frame{{CallType: CallTypeStaticCall, StorageAddress: common.HexToAddress(vaultAddr), CodeAddress: common.HexToAddress(vaultAddr), Calldata: balanceOfCalldata(t, signerAddr)}},
			want:   true,
		},
		{
			name:     "delegatecall is not permitted by default",
			rules:    []FrameRule{plainRule(t, selTransfer)},
			ctx:      memberCtx(),
			frames:   []Frame{delegateFrame(CallTypeDelegateCall, libraryAddr, transferCalldata(t, strangerAddr, big.NewInt(1)))},
			want:     false,
			wantCode: DenialNoMatchingRule,
			wantWhy:  "no rule",
		},
		{
			name:   "delegatecall is permitted when the rule names the code account",
			rules:  []FrameRule{delegateRule(t, CallTypeDelegateCall)},
			ctx:    memberCtx(),
			frames: []Frame{delegateFrame(CallTypeDelegateCall, libraryAddr, transferCalldata(t, strangerAddr, big.NewInt(1)))},
			want:   true,
		},
		{
			name:     "delegatecall through a different implementation is denied",
			rules:    []FrameRule{delegateRule(t, CallTypeDelegateCall)},
			ctx:      memberCtx(),
			frames:   []Frame{delegateFrame(CallTypeDelegateCall, strangerAddr, transferCalldata(t, strangerAddr, big.NewInt(1)))},
			want:     false,
			wantCode: DenialNoMatchingRule,
			wantWhy:  "no rule",
		},
		{
			name:     "callcode is not satisfied by a delegatecall rule",
			rules:    []FrameRule{delegateRule(t, CallTypeDelegateCall)},
			ctx:      memberCtx(),
			frames:   []Frame{delegateFrame(CallTypeCallCode, libraryAddr, transferCalldata(t, strangerAddr, big.NewInt(1)))},
			want:     false,
			wantCode: DenialNoMatchingRule,
			wantWhy:  "no rule",
		},
		{
			name:   "callcode is permitted when the rule names it",
			rules:  []FrameRule{delegateRule(t, CallTypeCallCode)},
			ctx:    memberCtx(),
			frames: []Frame{delegateFrame(CallTypeCallCode, libraryAddr, transferCalldata(t, strangerAddr, big.NewInt(1)))},
			want:   true,
		},
		{
			name:     "a delegatecall rule does not permit a plain call to the implementation",
			rules:    []FrameRule{delegateRule(t, CallTypeDelegateCall)},
			ctx:      memberCtx(),
			frames:   []Frame{{CallType: CallTypeCall, StorageAddress: libraryAddr, CodeAddress: libraryAddr, Calldata: transferCalldata(t, strangerAddr, big.NewInt(1))}},
			want:     false,
			wantCode: DenialNoMatchingRule,
			wantWhy:  "no rule",
		},
		{
			name:   "address argument equals the signer",
			rules:  []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourceSigner}})},
			ctx:    memberCtx(),
			frames: []Frame{vaultCall(transferCalldata(t, signerAddr, big.NewInt(1)))},
			want:   true,
		},
		{
			name:     "address argument does not equal the signer",
			rules:    []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourceSigner}})},
			ctx:      memberCtx(),
			frames:   []Frame{vaultCall(transferCalldata(t, strangerAddr, big.NewInt(1)))},
			want:     false,
			wantCode: DenialArgumentConstraint,
			wantWhy:  "argument 0",
		},
		{
			name:  "no signer was supplied, so a signer rule cannot be satisfied",
			rules: []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourceSigner}})},
			ctx:   Context{Org: orgID, Groups: []string{groupID}},
			// The zero address is what an unset signer looks like. Sending it as
			// the argument must not turn "must be you" into "must be nobody".
			frames:   []Frame{vaultCall(transferCalldata(t, common.Address{}, big.NewInt(1)))},
			want:     false,
			wantCode: DenialArgumentConstraint,
			wantWhy:  "no signer",
		},
		{
			name:   "address argument matches one of the principal's linked addresses",
			rules:  []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourcePrincipalLinked}})},
			ctx:    memberCtx(),
			frames: []Frame{vaultCall(transferCalldata(t, linkedAddr, big.NewInt(1)))},
			want:   true,
		},
		{
			name:     "address argument matches none of the linked addresses",
			rules:    []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourcePrincipalLinked}})},
			ctx:      memberCtx(),
			frames:   []Frame{vaultCall(transferCalldata(t, strangerAddr, big.NewInt(1)))},
			want:     false,
			wantCode: DenialArgumentConstraint,
			wantWhy:  "argument 0",
		},
		{
			name:     "principal has no linked addresses at all",
			rules:    []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourcePrincipalLinked}})},
			ctx:      Context{Org: orgID, Groups: []string{groupID}, Signer: signerAddr},
			frames:   []Frame{vaultCall(transferCalldata(t, linkedAddr, big.NewInt(1)))},
			want:     false,
			wantCode: DenialArgumentConstraint,
			wantWhy:  "argument 0",
		},
		{
			name:   "address argument equals a literal",
			rules:  []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourceLiteral, Value: strangerAddr.Hex()}})},
			ctx:    memberCtx(),
			frames: []Frame{vaultCall(transferCalldata(t, strangerAddr, big.NewInt(1)))},
			want:   true,
		},
		{
			name:     "address argument does not equal the literal",
			rules:    []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourceLiteral, Value: strangerAddr.Hex()}})},
			ctx:      memberCtx(),
			frames:   []Frame{vaultCall(transferCalldata(t, linkedAddr, big.NewInt(1)))},
			want:     false,
			wantCode: DenialArgumentConstraint,
			wantWhy:  "argument 0",
		},
		{
			name:   "uint argument is below the bound",
			rules:  []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 1, UintAtMost: &hundred})},
			ctx:    memberCtx(),
			frames: []Frame{vaultCall(transferCalldata(t, strangerAddr, big.NewInt(99)))},
			want:   true,
		},
		{
			name:   "uint argument is exactly at the bound",
			rules:  []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 1, UintAtMost: &hundred})},
			ctx:    memberCtx(),
			frames: []Frame{vaultCall(transferCalldata(t, strangerAddr, big.NewInt(100)))},
			want:   true,
		},
		{
			name:     "uint argument is above the bound",
			rules:    []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 1, UintAtMost: &hundred})},
			ctx:      memberCtx(),
			frames:   []Frame{vaultCall(transferCalldata(t, strangerAddr, big.NewInt(101)))},
			want:     false,
			wantCode: DenialArgumentConstraint,
			wantWhy:  "argument 1",
		},
		{
			name: "two constraints on one rule must both hold",
			rules: []FrameRule{plainRule(t, selTransfer,
				ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourceSigner}},
				ArgConstraint{Index: 1, UintAtMost: &hundred},
			)},
			ctx:      memberCtx(),
			frames:   []Frame{vaultCall(transferCalldata(t, signerAddr, big.NewInt(101)))},
			want:     false,
			wantCode: DenialArgumentConstraint,
			wantWhy:  "argument 1",
		},
		{
			name: "every nested frame needs its own rule",
			rules: []FrameRule{
				plainRule(t, selTransfer),
				plainRule(t, selBalanceOf),
			},
			ctx: memberCtx(),
			frames: []Frame{
				vaultCall(transferCalldata(t, strangerAddr, big.NewInt(1))),
				vaultCall(balanceOfCalldata(t, signerAddr)),
			},
			want: true,
		},
		{
			name:  "one unpermitted nested frame denies the whole execution",
			rules: []FrameRule{plainRule(t, selTransfer)},
			ctx:   memberCtx(),
			frames: []Frame{
				vaultCall(transferCalldata(t, strangerAddr, big.NewInt(1))),
				{
					CallType:       CallTypeCall,
					StorageAddress: common.HexToAddress(relayAddr),
					CodeAddress:    common.HexToAddress(relayAddr),
					Calldata:       transferCalldata(t, strangerAddr, big.NewInt(1)),
				},
			},
			want:     false,
			wantCode: DenialNoMatchingRule,
			wantWhy:  "frame 1",
		},
		{
			name:     "an execution with no observed frames is denied",
			rules:    []FrameRule{plainRule(t, selTransfer)},
			ctx:      memberCtx(),
			frames:   nil,
			want:     false,
			wantCode: DenialNoFrames,
			wantWhy:  "no frames",
		},
		{
			name:     "calldata too short to carry a selector",
			rules:    []FrameRule{plainRule(t, selTransfer)},
			ctx:      memberCtx(),
			frames:   []Frame{vaultCall([]byte{0x01, 0x02})},
			want:     false,
			wantCode: DenialMalformedCalldata,
			wantWhy:  "calldata",
		},
		{
			name:     "calldata arguments are truncated",
			rules:    []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourceSigner}})},
			ctx:      memberCtx(),
			frames:   []Frame{vaultCall(transferCalldata(t, signerAddr, big.NewInt(1))[:20])},
			want:     false,
			wantCode: DenialMalformedCalldata,
			wantWhy:  "decode",
		},
		{
			name:  "calldata carries bytes beyond its declared arguments",
			rules: []FrameRule{plainRule(t, selTransfer)},
			ctx:   memberCtx(),
			// A callee that reads raw input still sees the extra bytes, so a rule
			// that only checked the decodable prefix would not be checking what ran.
			frames:   []Frame{vaultCall(append(transferCalldata(t, strangerAddr, big.NewInt(1)), make([]byte, 32)...))},
			want:     false,
			wantCode: DenialMalformedCalldata,
			wantWhy:  "canonical",
		},
		{
			name:     "unknown call type on the frame",
			rules:    []FrameRule{plainRule(t, selTransfer)},
			ctx:      memberCtx(),
			frames:   []Frame{{CallType: "create", StorageAddress: common.HexToAddress(vaultAddr), CodeAddress: common.HexToAddress(vaultAddr), Calldata: transferCalldata(t, strangerAddr, big.NewInt(1))}},
			want:     false,
			wantCode: DenialNoMatchingRule,
			wantWhy:  "no rule",
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
				if got.Code != "" {
					t.Errorf("an allowed decision carried denial code %q", got.Code)
				}
				return
			}
			if got.Reason == "" {
				t.Fatal("a denial must carry a reason")
			}
			if got.Code != tc.wantCode {
				t.Errorf("Code = %q, want %q", got.Code, tc.wantCode)
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

// TestEvaluate_NilValidatedDenies covers the zero value reaching the evaluator.
func TestEvaluate_NilValidatedDenies(t *testing.T) {
	var v *Validated

	got := v.Evaluate(memberCtx(), []Frame{vaultCall(transferCalldata(t, signerAddr, big.NewInt(1)))})
	if got.Allowed {
		t.Fatal("a nil policy permitted a frame")
	}
	if got.Code != DenialInvalidContext {
		t.Errorf("Code = %q, want %q", got.Code, DenialInvalidContext)
	}
}

// TestEvaluate_PermissionIsTheUnionAcrossGroups checks that a principal in two
// groups gets what either binding allows, and that the order of their groups
// does not change the outcome.
func TestEvaluate_PermissionIsTheUnionAcrossGroups(t *testing.T) {
	hundred := "100"
	cat := testCatalog(t)
	cat.Groups["grp_auditors"] = struct{}{}

	p := &Policy{
		APIVersion:  APIVersion,
		Kind:        Kind,
		Org:         orgID,
		NestedCalls: NestedCallsRequireOwnRule,
		Bindings: []Binding{
			{Group: groupID, Allow: []FrameRule{plainRule(t, selTransfer, ArgConstraint{Index: 1, UintAtMost: &hundred})}},
			{Group: "grp_auditors", Allow: []FrameRule{plainRule(t, selTransfer)}},
		},
	}
	v, err := Validate(p, cat)
	if err != nil {
		t.Fatalf("fixture policy failed validation: %v", err)
	}

	// The bounded binding is scanned first and rejects this amount; the unbounded
	// one still has to be reached.
	frames := []Frame{vaultCall(transferCalldata(t, strangerAddr, big.NewInt(1000)))}

	for _, order := range [][]string{
		{groupID, "grp_auditors"},
		{"grp_auditors", groupID},
	} {
		t.Run(strings.Join(order, ","), func(t *testing.T) {
			got := v.Evaluate(Context{Org: orgID, Groups: order, Signer: signerAddr}, frames)
			if !got.Allowed {
				t.Fatalf("a binding that permits this frame was not reached: %s", got.Reason)
			}
		})
	}
}

// TestEvaluate_UintBoundHoldsForNarrowWidths covers the non-big.Int decode paths.
func TestEvaluate_UintBoundHoldsForNarrowWidths(t *testing.T) {
	ten := "10"
	v := validatedWith(t, FrameRule{
		StorageAddress: libraryAddr.Hex(),
		Selector:       selCap,
		ABIDigest:      abiDigest(t, libraryABI),
		Args:           []ArgConstraint{{Index: 0, UintAtMost: &ten}},
	})

	frame := func(limit uint64) Frame {
		return Frame{
			CallType:       CallTypeCall,
			StorageAddress: libraryAddr,
			CodeAddress:    libraryAddr,
			Calldata:       packCalldata(t, libraryABI, "cap", limit),
		}
	}

	if got := v.Evaluate(memberCtx(), []Frame{frame(10)}); !got.Allowed {
		t.Errorf("a uint64 at the bound was denied: %s", got.Reason)
	}
	if got := v.Evaluate(memberCtx(), []Frame{frame(11)}); got.Allowed {
		t.Error("a uint64 above the bound was permitted")
	}
}
