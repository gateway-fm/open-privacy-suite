package policydsl

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

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

	// The digest is what an approval refers to, so it has to be checked against
	// the bytes rather than carried alongside them. An artifact loaded from
	// storage whose code no longer hashes to its recorded digest is not the
	// artifact that was approved, and running it would answer as though it were.
	if a.RuntimeDigest != "" {
		sum := sha256.Sum256(a.RuntimeBytecode)
		if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, a.RuntimeDigest) {
			return nil, fmt.Errorf("policydsl: the stored policy bytecode does not match its recorded digest; it is not the artifact that was approved")
		}
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
		if f.Value != nil && (f.Value.Sign() < 0 || f.Value.BitLen() > 256) {
			return deny(DenialInvalidContext, fmt.Sprintf("frame %d: native value must fit uint256", i))
		}
		reason, err := e.checkFacts(ctx, f)
		if err != nil {
			return deny(DenialMalformedCalldata, fmt.Sprintf("frame %d: %v", i, err))
		}
		if reason != reasonOK {
			return deny(reasonToDenialCode(reason), fmt.Sprintf("frame %d: the compiled policy returned reason %d", i, reason))
		}
	}

	return Decision{Allowed: true}
}

func (e *EVMEvaluator) checkFacts(ctx Context, f Frame) (uint16, error) {
	if _, ok := CallTypeOrdinal(f.CallType); !ok {
		return reasonNoMatchingRule, nil
	}
	input, err := packCheck(ctx, f)
	if err != nil {
		return 0, err
	}
	ret, err := e.execute(input)
	if err != nil {
		return 0, err
	}
	if len(ret) != 32 {
		return 0, fmt.Errorf("the facts policy returned %d bytes, expected 32", len(ret))
	}
	reason := new(big.Int).SetBytes(ret)
	if !reason.IsUint64() || reason.Uint64() > reasonInvalidFacts {
		return 0, fmt.Errorf("the facts policy returned an unknown reason")
	}
	return uint16(reason.Uint64()), nil
}

func (e *EVMEvaluator) execute(input []byte) ([]byte, error) {
	return e.staticRead(callerAddress, policyAddress, input, evaluationGasLimit)
}

// ReadContract supplies a state-backed getter reader to the offline Go oracle.
// Callers must arrange the same candidate state as their compiled evaluation;
// no admission-time network lookup is an execution authority. The nested caller
// matches the policy account and all journal effects are reverted afterwards.
func (e *EVMEvaluator) ReadContract(target common.Address, input []byte, gas uint64) ([]byte, error) {
	if gas == 0 || gas > RecordReadGas || len(input) > 4+64+MaxRecordIDBytes {
		return nil, fmt.Errorf("policydsl: record getter exceeds offline read bounds")
	}
	return e.staticRead(policyAddress, target, input, gas)
}

func (e *EVMEvaluator) staticRead(from, target common.Address, input []byte, gas uint64) ([]byte, error) {
	snapshot := e.stateDB.Snapshot()
	defer e.stateDB.RevertToSnapshot(snapshot)
	evm := vm.NewEVM(e.blockCtx, e.stateDB, e.chainCfg, vm.Config{NoBaseFee: true})
	evm.SetTxContext(vm.TxContext{Origin: callerAddress, GasPrice: uint256.NewInt(0)})
	ret, _, err := evm.StaticCall(from, target, input, vm.GasBudget{RegularGas: gas})
	if err != nil {
		return nil, fmt.Errorf("the compiled policy did not return a decision: %w", err)
	}
	return ret, nil
}

// checkFrame is the legacy offline compatibility oracle. New evaluation and the
// node use check(Facts,Call), which does not omit execution/ownership facts.
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

	ret, err := e.execute(input)
	if err != nil {
		// A revert or an exhausted gas budget is a failure to decide, and a
		// policy that cannot decide denies.
		return false, 0, err
	}
	if len(ret) != 64 {
		return false, 0, fmt.Errorf("the compiled policy returned %d bytes, expected 64", len(ret))
	}

	allowedWord := new(big.Int).SetBytes(ret[:32])
	reasonWord := new(big.Int).SetBytes(ret[32:])
	if allowedWord.BitLen() > 1 || reasonWord.BitLen() > 16 {
		return false, 0, fmt.Errorf("the compiled policy returned non-canonical bool or uint16 words")
	}
	allowed := allowedWord.Sign() != 0
	reason := uint16(reasonWord.Uint64())
	if (allowed && reason != reasonOK) || (!allowed && (reason < reasonNoMatchingRule || reason > reasonMalformedCalldata)) {
		return false, 0, fmt.Errorf("the compiled policy returned an inconsistent or unknown decision")
	}
	return allowed, reason, nil
}

// reasonToDenialCode maps the artifact's numeric reason onto the shared codes.
func reasonToDenialCode(reason uint16) DenialCode {
	switch reason {
	case reasonArgumentConstraint:
		return DenialArgumentConstraint
	case reasonMalformedCalldata:
		return DenialMalformedCalldata
	case reasonOwnership:
		return DenialOwnership
	case reasonValue:
		return DenialValue
	case reasonDepth:
		return DenialDepth
	case reasonUnsupportedCreate:
		return DenialUnsupportedCreate
	case reasonOperationalClaim:
		return DenialOperationalClaim
	case reasonInvalidFacts:
		return DenialInvalidFacts
	case reasonCaller:
		return DenialCaller
	default:
		return DenialNoMatchingRule
	}
}
