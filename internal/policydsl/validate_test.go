package policydsl

import (
	"strings"
	"testing"
)

// basePolicy returns a minimal valid policy that individual tests then break in
// exactly one way, so each failure is attributable to a single change.
func basePolicy(t *testing.T) *Policy {
	t.Helper()
	return &Policy{
		APIVersion:  APIVersion,
		Kind:        Kind,
		Org:         orgID,
		NestedCalls: NestedCallsRequireOwnRule,
		Bindings: []Binding{{
			Group: groupID,
			Allow: []FrameRule{{
				StorageAddress: vaultAddr,
				Selector:       selTransfer,
				ABIDigest:      abiDigest(t, vaultABI),
			}},
		}},
	}
}

func TestValidate_AcceptsMinimalPolicy(t *testing.T) {
	v, err := Validate(basePolicy(t), testCatalog(t))
	if err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	if v == nil {
		t.Fatal("Validate returned nil result without an error")
	}
	if v.Policy() == nil {
		t.Fatal("Validated.Policy() is nil")
	}
}

func TestValidate_AcceptsEmptyAllowListAsDenyAll(t *testing.T) {
	p := basePolicy(t)
	p.Bindings[0].Allow = nil

	// An empty allow list is a meaningful, fail-closed document: the group may
	// execute nothing. It must validate so that an operator can express it.
	if _, err := Validate(p, testCatalog(t)); err != nil {
		t.Fatalf("empty allow list should be valid (deny-all), got: %v", err)
	}
}

// TestValidate_AcceptsDelegateCallAgainstTheCodeAccountABI pins the rule that a
// delegatecall is described by the implementation's ABI, not the proxy's.
func TestValidate_AcceptsDelegateCallAgainstTheCodeAccountABI(t *testing.T) {
	p := basePolicy(t)
	p.Bindings[0].Allow[0] = FrameRule{
		StorageAddress: vaultAddr,
		CodeAddress:    libraryAddr.Hex(),
		Selector:       selTransfer,
		ABIDigest:      abiDigest(t, libraryABI),
		CallTypes:      []CallType{CallTypeDelegateCall},
	}

	if _, err := Validate(p, testCatalog(t)); err != nil {
		t.Fatalf("delegatecall rule pinned to the code account's ABI was rejected: %v", err)
	}
}

// TestValidate_AcceptsDifferentSelectorsOfAnOverloadedName shows that two rules
// on the same contract are distinct when their selectors differ, which is what
// makes selector addressing necessary.
func TestValidate_AcceptsDifferentSelectorsOfAnOverloadedName(t *testing.T) {
	p := basePolicy(t)
	p.Bindings[0].Allow = []FrameRule{
		{StorageAddress: vaultAddr, Selector: selTransfer, ABIDigest: abiDigest(t, vaultABI)},
		{StorageAddress: vaultAddr, Selector: selTransferMemo, ABIDigest: abiDigest(t, vaultABI)},
	}

	if _, err := Validate(p, testCatalog(t)); err != nil {
		t.Fatalf("two overloads of one name should be two distinct rules, got: %v", err)
	}
}

// TestValidate_AcceptsMixedCaseAddresses guards against a formatting difference
// being reported as an authorization failure.
func TestValidate_AcceptsMixedCaseAddresses(t *testing.T) {
	for _, form := range []string{
		strings.ToUpper("0x" + vaultAddr[2:]),
		strings.TrimPrefix(vaultAddr, "0x"),
	} {
		t.Run(form, func(t *testing.T) {
			p := basePolicy(t)
			p.Bindings[0].Allow[0].StorageAddress = form

			if _, err := Validate(p, testCatalog(t)); err != nil {
				t.Fatalf("address written as %q names a registered contract but was rejected: %v", form, err)
			}
		})
	}
}

func TestValidate_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(p *Policy)
		wantErr string
	}{
		{
			name:    "unsupported apiVersion",
			mutate:  func(p *Policy) { p.APIVersion = "privacy.gateway.fm/v2" },
			wantErr: "apiVersion",
		},
		{
			name:    "missing apiVersion",
			mutate:  func(p *Policy) { p.APIVersion = "" },
			wantErr: "apiVersion",
		},
		{
			name:    "wrong kind",
			mutate:  func(p *Policy) { p.Kind = "OrganizationPolicy" },
			wantErr: "kind",
		},
		{
			name:    "org does not match catalog",
			mutate:  func(p *Policy) { p.Org = "org_other" },
			wantErr: "org",
		},
		{
			name:    "unsupported nested-call semantic",
			mutate:  func(p *Policy) { p.NestedCalls = "inherit" },
			wantErr: "nestedCalls",
		},
		{
			name:    "missing nested-call semantic",
			mutate:  func(p *Policy) { p.NestedCalls = "" },
			wantErr: "nestedCalls",
		},
		{
			name:    "unknown group",
			mutate:  func(p *Policy) { p.Bindings[0].Group = "grp_nope" },
			wantErr: "group",
		},
		{
			name:    "empty group name",
			mutate:  func(p *Policy) { p.Bindings[0].Group = "" },
			wantErr: "group",
		},
		{
			name:    "contract not registered in org",
			mutate:  func(p *Policy) { p.Bindings[0].Allow[0].StorageAddress = relayAddr },
			wantErr: "storageAddress",
		},
		{
			name:    "storage address is malformed",
			mutate:  func(p *Policy) { p.Bindings[0].Allow[0].StorageAddress = "0x1234" },
			wantErr: "storageAddress",
		},
		{
			name:    "selector not hex",
			mutate:  func(p *Policy) { p.Bindings[0].Allow[0].Selector = "transfer" },
			wantErr: "selector",
		},
		{
			name:    "selector wrong length",
			mutate:  func(p *Policy) { p.Bindings[0].Allow[0].Selector = "0xa9059c" },
			wantErr: "selector",
		},
		{
			name:    "selector right length but not hex",
			mutate:  func(p *Policy) { p.Bindings[0].Allow[0].Selector = "0xzzzzzzzz" },
			wantErr: "selector",
		},
		{
			name:    "selector absent from ABI",
			mutate:  func(p *Policy) { p.Bindings[0].Allow[0].Selector = "0xdeadbeef" },
			wantErr: "selector",
		},
		{
			name:    "ABI digest does not match registered ABI",
			mutate:  func(p *Policy) { p.Bindings[0].Allow[0].ABIDigest = strings.Repeat("00", 32) },
			wantErr: "abiDigest",
		},
		{
			name:    "missing ABI digest",
			mutate:  func(p *Policy) { p.Bindings[0].Allow[0].ABIDigest = "" },
			wantErr: "abiDigest",
		},
		{
			name: "delegatecall without an explicit code address",
			mutate: func(p *Policy) {
				p.Bindings[0].Allow[0].CallTypes = []CallType{CallTypeDelegateCall}
			},
			wantErr: "codeAddress",
		},
		{
			name: "delegatecall into an unregistered code account",
			mutate: func(p *Policy) {
				// Without the implementation's ABI there is nothing that says what
				// the selector and arguments mean once its code is running.
				p.Bindings[0].Allow[0].CodeAddress = relayAddr
				p.Bindings[0].Allow[0].CallTypes = []CallType{CallTypeDelegateCall}
			},
			wantErr: "codeAddress",
		},
		{
			name: "delegatecall digest pinned to the storage account's ABI",
			mutate: func(p *Policy) {
				p.Bindings[0].Allow[0].CodeAddress = libraryAddr.Hex()
				p.Bindings[0].Allow[0].CallTypes = []CallType{CallTypeDelegateCall}
				// vaultABI is the proxy's, not the implementation's.
				p.Bindings[0].Allow[0].ABIDigest = abiDigest(t, vaultABI)
			},
			wantErr: "abiDigest",
		},
		{
			name: "delegatecall selector absent from the code account's ABI",
			mutate: func(p *Policy) {
				p.Bindings[0].Allow[0].CodeAddress = libraryAddr.Hex()
				p.Bindings[0].Allow[0].CallTypes = []CallType{CallTypeDelegateCall}
				p.Bindings[0].Allow[0].ABIDigest = abiDigest(t, libraryABI)
				p.Bindings[0].Allow[0].Selector = selNote // vault has it, the library does not
			},
			wantErr: "selector",
		},
		{
			name: "code address is malformed",
			mutate: func(p *Policy) {
				p.Bindings[0].Allow[0].CodeAddress = "0xnothex"
				p.Bindings[0].Allow[0].CallTypes = []CallType{CallTypeDelegateCall}
			},
			wantErr: "codeAddress",
		},
		{
			name: "unsupported call type",
			mutate: func(p *Policy) {
				p.Bindings[0].Allow[0].CallTypes = []CallType{"create2"}
			},
			wantErr: "callTypes",
		},
		{
			name: "call type listed twice",
			mutate: func(p *Policy) {
				p.Bindings[0].Allow[0].CallTypes = []CallType{CallTypeCall, CallTypeCall}
			},
			wantErr: "callTypes",
		},
		{
			name: "call mixed with delegatecall on a separate code account",
			mutate: func(p *Policy) {
				// The call entry could never match, because code and storage are
				// the same account for a plain call.
				p.Bindings[0].Allow[0].CodeAddress = libraryAddr.Hex()
				p.Bindings[0].Allow[0].ABIDigest = abiDigest(t, libraryABI)
				p.Bindings[0].Allow[0].CallTypes = []CallType{CallTypeCall, CallTypeDelegateCall}
			},
			wantErr: "callTypes",
		},
		{
			name: "argument index out of range",
			mutate: func(p *Policy) {
				p.Bindings[0].Allow[0].Args = []ArgConstraint{{
					Index:         7,
					AddressEquals: &AddressMatch{Source: AddressSourceSigner},
				}}
			},
			wantErr: "index",
		},
		{
			name: "argument index negative",
			mutate: func(p *Policy) {
				p.Bindings[0].Allow[0].Args = []ArgConstraint{{
					Index:         -1,
					AddressEquals: &AddressMatch{Source: AddressSourceSigner},
				}}
			},
			wantErr: "index",
		},
		{
			name: "constraint sets neither comparison",
			mutate: func(p *Policy) {
				p.Bindings[0].Allow[0].Args = []ArgConstraint{{Index: 0}}
			},
			wantErr: "exactly one",
		},
		{
			name: "constraint sets both comparisons",
			mutate: func(p *Policy) {
				max := "100"
				p.Bindings[0].Allow[0].Args = []ArgConstraint{{
					Index:         0,
					AddressEquals: &AddressMatch{Source: AddressSourceSigner},
					UintAtMost:    &max,
				}}
			},
			wantErr: "exactly one",
		},
		{
			name: "address constraint on a uint argument",
			mutate: func(p *Policy) {
				p.Bindings[0].Allow[0].Args = []ArgConstraint{{
					Index:         1, // amount, uint256
					AddressEquals: &AddressMatch{Source: AddressSourceSigner},
				}}
			},
			wantErr: "type",
		},
		{
			name: "uint constraint on an address argument",
			mutate: func(p *Policy) {
				max := "100"
				p.Bindings[0].Allow[0].Args = []ArgConstraint{{
					Index:      0, // to, address
					UintAtMost: &max,
				}}
			},
			wantErr: "type",
		},
		{
			name: "uint bound is not a decimal integer",
			mutate: func(p *Policy) {
				max := "0x64"
				p.Bindings[0].Allow[0].Args = []ArgConstraint{{Index: 1, UintAtMost: &max}}
			},
			wantErr: "uintAtMost",
		},
		{
			name: "uint bound carries a sign",
			mutate: func(p *Policy) {
				max := "+100"
				p.Bindings[0].Allow[0].Args = []ArgConstraint{{Index: 1, UintAtMost: &max}}
			},
			wantErr: "uintAtMost",
		},
		{
			name: "uint bound is negative",
			mutate: func(p *Policy) {
				max := "-1"
				p.Bindings[0].Allow[0].Args = []ArgConstraint{{Index: 1, UintAtMost: &max}}
			},
			wantErr: "uintAtMost",
		},
		{
			name: "uint bound cannot reject anything",
			mutate: func(p *Policy) {
				// 2^256-1 is the largest a uint256 can hold, so a bound there is a
				// no-op dressed as a limit.
				max := "115792089237316195423570985008687907853269984665640564039457584007913129639935"
				p.Bindings[0].Allow[0].Args = []ArgConstraint{{Index: 1, UintAtMost: &max}}
			},
			wantErr: "uintAtMost",
		},
		{
			name: "literal address source without a value",
			mutate: func(p *Policy) {
				p.Bindings[0].Allow[0].Args = []ArgConstraint{{
					Index:         0,
					AddressEquals: &AddressMatch{Source: AddressSourceLiteral},
				}}
			},
			wantErr: "value",
		},
		{
			name: "non-literal address source carrying a value",
			mutate: func(p *Policy) {
				p.Bindings[0].Allow[0].Args = []ArgConstraint{{
					Index:         0,
					AddressEquals: &AddressMatch{Source: AddressSourceSigner, Value: relayAddr},
				}}
			},
			wantErr: "value",
		},
		{
			name: "unknown address source",
			mutate: func(p *Policy) {
				p.Bindings[0].Allow[0].Args = []ArgConstraint{{
					Index:         0,
					AddressEquals: &AddressMatch{Source: "caller"},
				}}
			},
			wantErr: "source",
		},
		{
			name: "literal address is malformed",
			mutate: func(p *Policy) {
				p.Bindings[0].Allow[0].Args = []ArgConstraint{{
					Index:         0,
					AddressEquals: &AddressMatch{Source: AddressSourceLiteral, Value: "0x1234"},
				}}
			},
			wantErr: "value",
		},
		{
			name: "two constraints on the same argument",
			mutate: func(p *Policy) {
				p.Bindings[0].Allow[0].Args = []ArgConstraint{
					{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourceSigner}},
					{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourcePrincipalLinked}},
				}
			},
			wantErr: "index",
		},
		{
			name: "code address set for a plain call",
			mutate: func(p *Policy) {
				// Code and storage coincide for CALL, so naming a different code
				// address here has no single meaning and must be rejected.
				p.Bindings[0].Allow[0].CodeAddress = relayAddr
				p.Bindings[0].Allow[0].CallTypes = []CallType{CallTypeCall}
			},
			wantErr: "codeAddress",
		},
		{
			name: "code address set with no call types",
			mutate: func(p *Policy) {
				p.Bindings[0].Allow[0].CodeAddress = libraryAddr.Hex()
			},
			wantErr: "codeAddress",
		},
		{
			name:    "duplicate group binding",
			mutate:  func(p *Policy) { p.Bindings = append(p.Bindings, p.Bindings[0]) },
			wantErr: "group",
		},
		{
			name: "two rules covering the same contract, code account and selector",
			mutate: func(p *Policy) {
				max := "100"
				bounded := p.Bindings[0].Allow[0]
				bounded.Args = []ArgConstraint{{Index: 1, UintAtMost: &max}}
				// The unbounded rule would win under either-or, silently voiding
				// the bound the reviewer can see right above it.
				p.Bindings[0].Allow = []FrameRule{bounded, p.Bindings[0].Allow[0]}
			},
			wantErr: "already covered",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := basePolicy(t)
			tc.mutate(p)

			v, err := Validate(p, testCatalog(t))
			if err == nil {
				t.Fatalf("expected rejection, got a valid policy")
			}
			if v != nil {
				t.Errorf("Validate returned a non-nil result alongside an error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.wantErr)) {
				t.Errorf("error %q does not mention %q; operators need to know which field is wrong", err, tc.wantErr)
			}
		})
	}
}

func TestValidate_RejectsNilPolicy(t *testing.T) {
	v, err := Validate(nil, testCatalog(t))
	if err == nil {
		t.Fatal("a nil policy was accepted")
	}
	if v != nil {
		t.Error("Validate returned a result alongside an error")
	}
}

func TestValidate_RejectsUnparseableRegisteredABI(t *testing.T) {
	cat := testCatalog(t)
	cat.Contracts[vaultAddr] = ContractInfo{ABI: "{not an abi"}

	p := basePolicy(t)
	p.Bindings[0].Allow[0].ABIDigest = abiDigest(t, "{not an abi")

	if _, err := Validate(p, cat); err == nil {
		t.Fatal("a contract whose registered ABI does not parse was accepted")
	}
}

// TestValidate_OwnsItsOwnCopyOfTheDocument checks that editing the caller's
// policy after validation cannot change what is enforced or what is displayed.
func TestValidate_OwnsItsOwnCopyOfTheDocument(t *testing.T) {
	p := basePolicy(t)

	v, err := Validate(p, testCatalog(t))
	if err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}

	p.Bindings[0].Group = "grp_tampered"
	p.Bindings[0].Allow[0].Selector = "0xdeadbeef"

	got := v.Policy()
	if got.Bindings[0].Group != groupID {
		t.Errorf("group became %q after the caller edited its own document", got.Bindings[0].Group)
	}
	if got.Bindings[0].Allow[0].Selector != selTransfer {
		t.Errorf("selector became %q after the caller edited its own document", got.Bindings[0].Allow[0].Selector)
	}

	// The returned document must itself be a copy, not a handle on the internals.
	got.Bindings[0].Group = "grp_tampered_again"
	if again := v.Policy(); again.Bindings[0].Group != groupID {
		t.Errorf("group became %q after a caller edited a returned document", again.Bindings[0].Group)
	}
}
