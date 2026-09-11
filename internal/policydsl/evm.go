package policydsl

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/uint256"
)

// evaluationGasLimit bounds one policy call.
//
// A policy is a bounded comparison over the facts it is handed, so a run that
// approaches this has gone wrong. The limit exists so a generator bug becomes a
// denial rather than an unbounded loop in the middle of a request.
const evaluationGasLimit = 5_000_000

// policyAddress is where the artifact's code is placed in the throwaway state
// each evaluation runs against. It is arbitrary and never on a real chain.
var policyAddress = common.HexToAddress("0x00000000000000000000000000000000706f6c79")

// callerAddress is the account the evaluation is made from.
var callerAddress = common.HexToAddress("0x0000000000000000000000000000000000000001")

// EVMEvaluator executes a compiled policy artifact.
//
// It exists so a generated contract can be checked against the Go reference on
// the same inputs. The artifact it runs is the same one a node would later
// execute, which is what makes agreement here meaningful rather than incidental.
type EVMEvaluator struct {
	artifact  *Artifact
	stateDB   *state.StateDB
	chainCfg  *params.ChainConfig
	blockCtx  vm.BlockContext
	checkFrom [4]byte
}

// NewEVMEvaluator prepares an evaluator for one artifact.
func NewEVMEvaluator(a *Artifact) (*EVMEvaluator, error) {
	if a == nil || len(a.RuntimeBytecode) == 0 {
		return nil, fmt.Errorf("policydsl: no compiled policy to execute")
	}

	memdb := rawdb.NewMemoryDatabase()
	db := state.NewDatabase(triedb.NewDatabase(memdb, nil), state.NewCodeDB(memdb))
	stateDB, err := state.New(common.Hash{}, db)
	if err != nil {
		return nil, fmt.Errorf("policydsl: preparing the policy evaluation state: %w", err)
	}

	stateDB.CreateAccount(policyAddress)
	stateDB.SetCode(policyAddress, a.RuntimeBytecode, tracing.CodeChangeUnspecified)
	stateDB.CreateAccount(callerAddress)

	var selector [4]byte
	copy(selector[:], methodSelector(CheckFrameSignature))

	return &EVMEvaluator{
		artifact: a,
		stateDB:  stateDB,
		chainCfg: params.AllDevChainProtocolChanges,
		blockCtx: vm.BlockContext{
			CanTransfer: func(vm.StateDB, common.Address, *uint256.Int) bool { return true },
			Transfer:    func(vm.StateDB, common.Address, common.Address, *uint256.Int, *params.Rules) {},
			GetHash:     func(uint64) common.Hash { return common.Hash{} },
			BlockNumber: big.NewInt(1),
			Time:        1,
			Difficulty:  big.NewInt(0),
			GasLimit:    evaluationGasLimit,
			BaseFee:     big.NewInt(0),
			Random:      &common.Hash{},
		},
		checkFrom: selector,
	}, nil
}

// RuntimeDigest reports the digest of the code this evaluator runs, so a caller
// can show that the bytecode it executed is the bytecode that was approved.
func (e *EVMEvaluator) RuntimeDigest() string { return e.artifact.RuntimeDigest }

// Evaluate decides an execution by running the compiled policy on every frame.
//
// It applies the same whole-execution rules as the Go evaluator: an empty frame
// list and a context from another organisation both deny before any frame runs.
func (e *EVMEvaluator) Evaluate(policyOrg string, ctx Context, frames []Frame) Decision {
	if ctx.Org == "" || ctx.Org != policyOrg {
		return deny(DenialInvalidContext, fmt.Sprintf("the principal is acting in organisation %q, but this policy governs %q", ctx.Org, policyOrg))
	}
	if len(frames) == 0 {
		return deny(DenialNoFrames, "no frames were observed for this execution")
	}

	for i, f := range frames {
		allowed, reason, err := e.checkFrame(ctx, f)
		if err != nil {
			return deny(DenialMalformedCalldata, fmt.Sprintf("frame %d: %v", i, err))
		}
		if !allowed {
			return deny(reasonToDenialCode(reason), fmt.Sprintf("frame %d: the compiled policy returned reason %d", i, reason))
		}
	}

	return Decision{Allowed: true}
}

// checkFrame runs one frame through the artifact.
func (e *EVMEvaluator) checkFrame(ctx Context, f Frame) (bool, uint16, error) {
	ordinal, ok := callTypeOrdinal[f.CallType]
	if !ok {
		// A frame kind the artifact has no encoding for cannot be described to
		// it, so it cannot be permitted by it.
		return false, reasonNoMatchingRule, nil
	}

	groups := make([]common.Hash, 0, len(ctx.Groups))
	for _, g := range ctx.Groups {
		groups = append(groups, GroupID(g))
	}

	input, err := packCheckFrame(e.checkFrom, ordinal, f.StorageAddress, f.CodeAddress, ctx.Signer, ctx.LinkedAddresses, groups, f.Calldata)
	if err != nil {
		return false, 0, err
	}

	evm := vm.NewEVM(e.blockCtx, e.stateDB, e.chainCfg, vm.Config{NoBaseFee: true})
	evm.SetTxContext(vm.TxContext{Origin: callerAddress, GasPrice: uint256.NewInt(0)})

	ret, _, err := evm.StaticCall(callerAddress, policyAddress, input, vm.GasBudget{RegularGas: evaluationGasLimit})
	if err != nil {
		// A revert or an exhausted gas budget is a failure to decide, and a
		// policy that cannot decide denies.
		return false, 0, fmt.Errorf("the compiled policy did not return a decision: %w", err)
	}
	if len(ret) != 64 {
		return false, 0, fmt.Errorf("the compiled policy returned %d bytes, expected 64", len(ret))
	}

	allowed := new(big.Int).SetBytes(ret[:32]).Sign() != 0
	reason := uint16(new(big.Int).SetBytes(ret[32:]).Uint64())
	return allowed, reason, nil
}

// reasonToDenialCode maps the artifact's numeric reason onto the shared codes.
func reasonToDenialCode(reason uint16) DenialCode {
	switch reason {
	case reasonArgumentConstraint:
		return DenialArgumentConstraint
	case reasonMalformedCalldata:
		return DenialMalformedCalldata
	default:
		return DenialNoMatchingRule
	}
}
