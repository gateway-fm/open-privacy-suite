package policydsl

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// vaultABI is the fixture ABI used across the validation tests. It deliberately
// contains an overloaded name so that selector-only addressing is exercised.
const vaultABI = `[
  {"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable"},
  {"type":"function","name":"balanceOf","inputs":[{"name":"owner","type":"address"}],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
  {"type":"function","name":"note","inputs":[{"name":"memo","type":"string"}],"outputs":[],"stateMutability":"nonpayable"}
]`

const (
	selTransfer  = "0xa9059cbb" // transfer(address,uint256)
	selBalanceOf = "0x70a08231" // balanceOf(address)
	selNote      = "0x1b352c43" // note(string)

	vaultAddr = "0x1f98431c8ad98523631ae4a59f267346ea31f984"
	relayAddr = "0x2222222222222222222222222222222222222222"
	groupID   = "grp_traders"
	orgID     = "org_acme"
)

func abiDigest(t *testing.T, abiText string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(abiText))
	return hex.EncodeToString(sum[:])
}

func testCatalog(t *testing.T) Catalog {
	t.Helper()
	return Catalog{
		Org:    orgID,
		Groups: map[string]struct{}{groupID: {}},
		Contracts: map[string]ContractInfo{
			vaultAddr: {ABI: vaultABI},
		},
	}
}

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
			name:    "contract not registered in org",
			mutate:  func(p *Policy) { p.Bindings[0].Allow[0].StorageAddress = relayAddr },
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
			name: "unsupported call type",
			mutate: func(p *Policy) {
				p.Bindings[0].Allow[0].CallTypes = []CallType{"create2"}
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
			name: "uint bound is negative",
			mutate: func(p *Policy) {
				max := "-1"
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
			name:    "duplicate group binding",
			mutate:  func(p *Policy) { p.Bindings = append(p.Bindings, p.Bindings[0]) },
			wantErr: "group",
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
