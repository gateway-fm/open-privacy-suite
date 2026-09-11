package policydsl

import (
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// requireCompiler fails rather than skips when solc is missing.
//
// A silently skipped conformance test is worse than no conformance test: it
// reports success while proving nothing about the artifact that would actually
// be enforced. CI installs the pinned compiler for this reason.
func requireCompiler(t *testing.T) *Compiler {
	t.Helper()
	c := NewCompiler()
	if err := c.Available(context.Background()); err != nil {
		t.Fatalf("the pinned Solidity compiler is required for conformance: %v\n"+
			"Install solc %s, or point POLICY_SOLC at it.", err, SolidityVersion)
	}
	return c
}

const auditorsGroup = "grp_auditors"

// conformancePolicy exercises every constraint kind the grammar supports, so the
// two implementations are compared across all of it rather than on one rule.
func conformancePolicy(t *testing.T) (*Policy, Catalog) {
	t.Helper()

	hundred := "100"
	ten := "10"
	vaultDigest := abiDigest(t, vaultABI)
	libDigest := abiDigest(t, libraryABI)

	cat := testCatalog(t)
	cat.Groups[auditorsGroup] = struct{}{}

	p := &Policy{
		APIVersion:  APIVersion,
		Kind:        Kind,
		Org:         orgID,
		NestedCalls: NestedCallsRequireOwnRule,
		Bindings: []Binding{
			{
				Group: groupID,
				Allow: []FrameRule{
					{
						// Two constraints, and a fully static signature, so the
						// calldata length can be pinned exactly.
						StorageAddress: vaultAddr,
						Selector:       selTransfer,
						ABIDigest:      vaultDigest,
						Args: []ArgConstraint{
							{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourceSigner}},
							{Index: 1, UintAtMost: &hundred},
						},
					},
					{
						// A dynamic signature, so only a minimum length applies.
						StorageAddress: vaultAddr,
						Selector:       selTransferMemo,
						ABIDigest:      vaultDigest,
						Args: []ArgConstraint{
							{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourcePrincipalLinked}},
						},
					},
					{
						StorageAddress: vaultAddr,
						Selector:       selBalanceOf,
						ABIDigest:      vaultDigest,
						Args: []ArgConstraint{
							{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourceLiteral, Value: strangerAddr.Hex()}},
						},
					},
					{
						// No constraints at all, on a dynamic signature.
						StorageAddress: vaultAddr,
						Selector:       selNote,
						ABIDigest:      vaultDigest,
					},
					{
						// Delegatecall, described by the implementation's ABI.
						StorageAddress: vaultAddr,
						CodeAddress:    libraryAddr.Hex(),
						Selector:       selTransfer,
						ABIDigest:      libDigest,
						CallTypes:      []CallType{CallTypeDelegateCall, CallTypeCallCode},
					},
					{
						// A narrow unsigned width, which has its own overflow rule.
						StorageAddress: libraryAddr.Hex(),
						Selector:       selCap,
						ABIDigest:      libDigest,
						Args:           []ArgConstraint{{Index: 0, UintAtMost: &ten}},
					},
				},
			},
			{
				Group: auditorsGroup,
				Allow: []FrameRule{{
					StorageAddress: vaultAddr,
					Selector:       selBalanceOf,
					ABIDigest:      vaultDigest,
					CallTypes:      []CallType{CallTypeStaticCall},
				}},
			},
		},
	}

	return p, cat
}

func libCall(t *testing.T, limit uint64) Frame {
	t.Helper()
	return Frame{
		CallType:       CallTypeCall,
		StorageAddress: libraryAddr,
		CodeAddress:    libraryAddr,
		Calldata:       packCalldata(t, libraryABI, "cap", limit),
	}
}

// TestConformance_GoAndSolidityAgree is the load-bearing test of this package.
//
// The Go evaluator is the reference the schema is defined against; the compiled
// contract is what a node would actually run. If they can disagree, then either
// the reviewed policy or the enforced policy is a fiction, so every case here
// must produce the same decision and the same reason from both.
func TestConformance_GoAndSolidityAgree(t *testing.T) {
	compiler := requireCompiler(t)

	p, cat := conformancePolicy(t)
	reference, err := Validate(p, cat)
	if err != nil {
		t.Fatalf("the conformance policy failed validation: %v", err)
	}

	artifact, err := compiler.Build(context.Background(), reference)
	if err != nil {
		t.Fatalf("building the conformance policy: %v", err)
	}
	t.Logf("artifact: %d bytes of runtime bytecode, digest %s", len(artifact.RuntimeBytecode), artifact.RuntimeDigest[:16])

	compiled, err := NewEVMEvaluator(artifact)
	if err != nil {
		t.Fatalf("preparing the compiled policy for execution: %v", err)
	}

	member := Context{
		Org:             orgID,
		Groups:          []string{groupID},
		Signer:          signerAddr,
		LinkedAddresses: []common.Address{signerAddr, linkedAddr},
	}
	auditor := Context{Org: orgID, Groups: []string{auditorsGroup}, Signer: signerAddr}
	both := Context{
		Org:             orgID,
		Groups:          []string{auditorsGroup, groupID},
		Signer:          signerAddr,
		LinkedAddresses: []common.Address{signerAddr, linkedAddr},
	}

	memo := func(to common.Address) []byte {
		return packCalldata(t, vaultABI, "transfer0", to, big.NewInt(1), "memo")
	}

	cases := []struct {
		name   string
		ctx    Context
		frames []Frame
	}{
		{"permitted transfer within both bounds", member, []Frame{vaultCall(transferCalldata(t, signerAddr, big.NewInt(50)))}},
		{"transfer at the exact bound", member, []Frame{vaultCall(transferCalldata(t, signerAddr, big.NewInt(100)))}},
		{"transfer above the bound", member, []Frame{vaultCall(transferCalldata(t, signerAddr, big.NewInt(101)))}},
		{"transfer to someone other than the signer", member, []Frame{vaultCall(transferCalldata(t, strangerAddr, big.NewInt(1)))}},
		{"transfer with trailing calldata", member, []Frame{vaultCall(append(transferCalldata(t, signerAddr, big.NewInt(1)), make([]byte, 32)...))}},
		{"transfer with truncated calldata", member, []Frame{vaultCall(transferCalldata(t, signerAddr, big.NewInt(1))[:20])}},
		{"calldata shorter than a selector", member, []Frame{vaultCall([]byte{1, 2, 3})}},

		{"no signer supplied, signer rule cannot pass", Context{Org: orgID, Groups: []string{groupID}}, []Frame{vaultCall(transferCalldata(t, common.Address{}, big.NewInt(1)))}},

		{"linked address accepted on a dynamic signature", member, []Frame{vaultCall(memo(linkedAddr))}},
		{"unlinked address on a dynamic signature", member, []Frame{vaultCall(memo(strangerAddr))}},

		{"literal address matches", member, []Frame{vaultCall(balanceOfCalldata(t, strangerAddr))}},
		{"literal address does not match", member, []Frame{vaultCall(balanceOfCalldata(t, signerAddr))}},

		{"unconstrained rule on a dynamic signature", member, []Frame{vaultCall(packCalldata(t, vaultABI, "note", "hello"))}},

		{"delegatecall into the named implementation", member, []Frame{delegateFrame(CallTypeDelegateCall, libraryAddr, transferCalldata(t, strangerAddr, big.NewInt(1)))}},
		{"callcode into the named implementation", member, []Frame{delegateFrame(CallTypeCallCode, libraryAddr, transferCalldata(t, strangerAddr, big.NewInt(1)))}},
		{"delegatecall into a different implementation", member, []Frame{delegateFrame(CallTypeDelegateCall, strangerAddr, transferCalldata(t, strangerAddr, big.NewInt(1)))}},
		{"plain call where only delegatecall is permitted", member, []Frame{{CallType: CallTypeCall, StorageAddress: common.HexToAddress(vaultAddr), CodeAddress: libraryAddr, Calldata: transferCalldata(t, strangerAddr, big.NewInt(1))}}},

		{"narrow uint below its bound", member, []Frame{libCall(t, 5)}},
		{"narrow uint at its bound", member, []Frame{libCall(t, 10)}},
		{"narrow uint above its bound", member, []Frame{libCall(t, 11)}},

		{"auditor may staticcall balanceOf", auditor, []Frame{{CallType: CallTypeStaticCall, StorageAddress: common.HexToAddress(vaultAddr), CodeAddress: common.HexToAddress(vaultAddr), Calldata: balanceOfCalldata(t, signerAddr)}}},
		{"auditor may not plain-call balanceOf", auditor, []Frame{vaultCall(balanceOfCalldata(t, signerAddr))}},
		{"auditor may not transfer", auditor, []Frame{vaultCall(transferCalldata(t, signerAddr, big.NewInt(1)))}},

		{"membership in two groups takes the union", both, []Frame{{CallType: CallTypeStaticCall, StorageAddress: common.HexToAddress(vaultAddr), CodeAddress: common.HexToAddress(vaultAddr), Calldata: balanceOfCalldata(t, strangerAddr)}}},

		{"principal in no bound group", Context{Org: orgID, Groups: []string{"grp_none"}, Signer: signerAddr}, []Frame{vaultCall(transferCalldata(t, signerAddr, big.NewInt(1)))}},
		{"principal in no groups at all", Context{Org: orgID, Signer: signerAddr}, []Frame{vaultCall(transferCalldata(t, signerAddr, big.NewInt(1)))}},

		{"contract the policy never mentions", member, []Frame{{CallType: CallTypeCall, StorageAddress: common.HexToAddress(relayAddr), CodeAddress: common.HexToAddress(relayAddr), Calldata: transferCalldata(t, signerAddr, big.NewInt(1))}}},
		{"selector the policy never mentions", member, []Frame{vaultCall(append([]byte{0xde, 0xad, 0xbe, 0xef}, make([]byte, 64)...))}},
		{"frame kind outside the schema", member, []Frame{{CallType: "create", StorageAddress: common.HexToAddress(vaultAddr), CodeAddress: common.HexToAddress(vaultAddr), Calldata: transferCalldata(t, signerAddr, big.NewInt(1))}}},

		{"two permitted frames", member, []Frame{
			vaultCall(transferCalldata(t, signerAddr, big.NewInt(1))),
			vaultCall(balanceOfCalldata(t, strangerAddr)),
		}},
		{"a permitted frame followed by a denied one", member, []Frame{
			vaultCall(transferCalldata(t, signerAddr, big.NewInt(1))),
			vaultCall(balanceOfCalldata(t, signerAddr)),
		}},
		{"no frames at all", member, nil},
		{"a principal from another organisation", Context{Org: "org_other", Groups: []string{groupID}, Signer: signerAddr}, []Frame{vaultCall(transferCalldata(t, signerAddr, big.NewInt(1)))}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := reference.Evaluate(tc.ctx, tc.frames)
			got := compiled.Evaluate(orgID, tc.ctx, tc.frames)

			if want.Allowed != got.Allowed {
				t.Fatalf("the two implementations disagree: Go says allowed=%v (%s), the compiled policy says allowed=%v (%s)",
					want.Allowed, want.Reason, got.Allowed, got.Reason)
			}
			if want.Code != got.Code {
				t.Errorf("same decision, different reason: Go says %q (%s), the compiled policy says %q (%s)",
					want.Code, want.Reason, got.Code, got.Reason)
			}
		})
	}
}

// TestGenerateSolidity_IsDeterministic pins that one policy always renders one
// source, and therefore always compiles to one artifact a reviewer can approve.
func TestGenerateSolidity_IsDeterministic(t *testing.T) {
	p, cat := conformancePolicy(t)

	first, err := Validate(p, cat)
	if err != nil {
		t.Fatalf("validation: %v", err)
	}
	second, err := Validate(p, cat)
	if err != nil {
		t.Fatalf("validation: %v", err)
	}

	a, err := GenerateSolidity(first)
	if err != nil {
		t.Fatalf("generating: %v", err)
	}
	b, err := GenerateSolidity(second)
	if err != nil {
		t.Fatalf("generating: %v", err)
	}

	if a != b {
		t.Error("the same policy rendered two different sources; map iteration order is leaking into the artifact")
	}
	if !strings.Contains(a, "DO NOT EDIT") {
		t.Error("generated source must say it is generated")
	}
	if strings.Contains(a, "pragma solidity ^") {
		t.Error("the compiler version must be pinned exactly, not ranged")
	}
}

// TestBuild_RejectsAnUnpinnedCompiler proves the build refuses a compiler it was
// not reviewed against, rather than producing bytecode nobody approved.
func TestBuild_RejectsAnUnpinnedCompiler(t *testing.T) {
	c := &Compiler{Path: "/usr/bin/false"}

	if err := c.Available(context.Background()); err == nil {
		t.Fatal("a compiler that reports no version was accepted")
	}
}
