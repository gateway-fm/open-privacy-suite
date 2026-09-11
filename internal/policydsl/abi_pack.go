package policydsl

import (
	"fmt"
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
