package policydsl

import (
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// checkFrameABI describes the entry point every generated policy exposes. It is
// written out rather than derived so that a change to the generated signature
// fails loudly here instead of silently packing the wrong shape.
const checkFrameABI = `[{
  "type": "function",
  "name": "checkFrame",
  "stateMutability": "pure",
  "inputs": [
    {"name": "callType",       "type": "uint8"},
    {"name": "storageAddress", "type": "address"},
    {"name": "codeAddress",    "type": "address"},
    {"name": "signer",         "type": "address"},
    {"name": "linked",         "type": "address[]"},
    {"name": "groups",         "type": "bytes32[]"},
    {"name": "payload",        "type": "bytes"}
  ],
  "outputs": [
    {"name": "allowed", "type": "bool"},
    {"name": "reason",  "type": "uint16"}
  ]
}]`

const checkABI = `[{"type":"function","name":"check","stateMutability":"pure","inputs":[
  {"name":"facts","type":"tuple","components":[
    {"name":"signer","type":"address"},{"name":"linkedAddresses","type":"address[]"},{"name":"groups","type":"bytes32[]"},
    {"name":"policyOrg","type":"bytes32"},{"name":"callerOrg","type":"bytes32"},{"name":"codeOrg","type":"bytes32"},{"name":"storageOrg","type":"bytes32"},
    {"name":"claims","type":"uint8"},{"name":"codeShared","type":"bool"},{"name":"storageShared","type":"bool"},{"name":"codeKind","type":"uint8"},{"name":"upgradeTargetOrg","type":"bytes32"},{"name":"groupClaims","type":"uint8[]"},{"name":"storageDeployer","type":"bool"},{"name":"storagePending","type":"bool"}]},
  {"name":"frame","type":"tuple","components":[
    {"name":"kind","type":"uint8"},{"name":"caller","type":"address"},{"name":"codeAddress","type":"address"},{"name":"storageAddress","type":"address"},
    {"name":"data","type":"bytes"},{"name":"value","type":"uint256"},{"name":"depth","type":"uint256"}]}],
  "outputs":[{"name":"reason","type":"uint256"}]}]`

type policyFacts struct {
	Signer           common.Address
	LinkedAddresses  []common.Address
	Groups           [][32]byte
	PolicyOrg        [32]byte
	CallerOrg        [32]byte
	CodeOrg          [32]byte
	StorageOrg       [32]byte
	Claims           uint8
	CodeShared       bool
	StorageShared    bool
	CodeKind         uint8
	UpgradeTargetOrg [32]byte
	GroupClaims      []uint8
	StorageDeployer  bool
	StoragePending   bool
}

type policyCall struct {
	Kind           uint8
	Caller         common.Address
	CodeAddress    common.Address
	StorageAddress common.Address
	Data           []byte
	Value          *big.Int
	Depth          *big.Int
}

var checkSpec = sync.OnceValues(func() (abi.ABI, error) {
	spec, err := abi.JSON(strings.NewReader(checkABI))
	if err == nil && spec.Methods["check"].Sig != CheckSignature {
		err = fmt.Errorf("policydsl: facts packing signature differs from generated entry point")
	}
	return spec, err
})

func packCheck(ctx Context, f Frame) ([]byte, error) {
	spec, err := checkSpec()
	if err != nil {
		return nil, err
	}
	kind, ok := CallTypeOrdinal(f.CallType)
	if !ok {
		return nil, fmt.Errorf("unsupported frame kind")
	}
	value := new(big.Int)
	if f.Value != nil {
		if f.Value.Sign() < 0 || f.Value.BitLen() > 256 {
			return nil, fmt.Errorf("native value must fit uint256")
		}
		value.Set(f.Value)
	}
	groups := make([][32]byte, len(ctx.Groups))
	groupClaims := make([]uint8, len(ctx.Groups))
	for i, g := range ctx.Groups {
		groups[i] = GroupID(g)
		groupClaims[i] = f.GroupClaims[g]
	}
	facts := policyFacts{Signer: ctx.Signer, LinkedAddresses: ctx.LinkedAddresses, Groups: groups,
		PolicyOrg: OrgID(ctx.Org), CallerOrg: OrgID(f.CallerOrg), CodeOrg: OrgID(f.CodeOrg), StorageOrg: OrgID(f.StorageOrg),
		Claims: ctx.Claims, CodeShared: f.CodeShared, StorageShared: f.StorageShared, CodeKind: f.CodeKind, UpgradeTargetOrg: OrgID(f.UpgradeTargetOrg), GroupClaims: groupClaims, StorageDeployer: f.StorageDeployer, StoragePending: f.StoragePending}
	frame := policyCall{Kind: kind, Caller: f.CallerAddress, CodeAddress: f.CodeAddress, StorageAddress: f.StorageAddress,
		Data: f.Calldata, Value: value, Depth: new(big.Int).SetUint64(f.Depth)}
	return spec.Pack("check", facts, frame)
}

var (
	checkFrameOnce sync.Once
	checkFrameSpec abi.ABI
	checkFrameErr  error
)

func checkFrameArguments() (abi.ABI, error) {
	checkFrameOnce.Do(func() {
		checkFrameSpec, checkFrameErr = abi.JSON(strings.NewReader(checkFrameABI))
		if checkFrameErr != nil {
			return
		}
		// The hand-written description and the signature the generator emits must
		// be the same function, or the evaluator would be calling something else.
		if got := checkFrameSpec.Methods["checkFrame"].Sig; got != CheckFrameSignature {
			checkFrameErr = fmt.Errorf("policydsl: the packing description is %q but generated policies expose %q", got, CheckFrameSignature)
		}
	})
	return checkFrameSpec, checkFrameErr
}

// methodSelector returns the four-byte selector of a signature.
func methodSelector(sig string) []byte {
	return crypto.Keccak256([]byte(sig))[:4]
}

// packCheckFrame builds the calldata for one policy evaluation.
func packCheckFrame(
	selector [4]byte,
	callType uint8,
	storageAddress, codeAddress, signer common.Address,
	linked []common.Address,
	groups []common.Hash,
	payload []byte,
) ([]byte, error) {
	spec, err := checkFrameArguments()
	if err != nil {
		return nil, err
	}

	// Nil slices encode differently from empty ones in some encoders; normalising
	// here keeps an absent linked-address set from looking like a malformed call.
	if linked == nil {
		linked = []common.Address{}
	}
	groupWords := make([][32]byte, len(groups))
	for i, g := range groups {
		groupWords[i] = g
	}
	if payload == nil {
		payload = []byte{}
	}

	args, err := spec.Methods["checkFrame"].Inputs.Pack(
		callType, storageAddress, codeAddress, signer, linked, groupWords, payload,
	)
	if err != nil {
		return nil, fmt.Errorf("policydsl: could not encode the policy call: %w", err)
	}

	return append(selector[:], args...), nil
}
