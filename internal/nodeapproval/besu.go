package nodeapproval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/tracer"
)

// nodeKind selects how the preflight execution facts are obtained.
type nodeKind uint8

const (
	nodeReth nodeKind = iota // OPS_APPROVAL_NODE=reth (default): debug_traceCall muxTracer, as on the Reth PoC
	nodeBesu                 // OPS_APPROVAL_NODE=besu: ops_prepareApproval served by the OPS Besu plugin
)

// configuredNodeKind also rejects a combination that could never produce an approval, so a
// misconfigured OPS fails at start-up rather than on every preflight: in Besu mode the execution
// picks the fingerprint (calls, or strict when it creates or destroys a contract), so pinning OPS
// to strict would reject every ordinary call.
func configuredNodeKind(hashMode uint8) (nodeKind, error) {
	switch os.Getenv("OPS_APPROVAL_NODE") {
	case "", "reth":
		return nodeReth, nil
	case "besu":
		if hashMode != HashCalls {
			return 0, errors.New("OPS_APPROVAL_NODE=besu derives the hash mode from the execution; leave OPS_APPROVAL_HASH_MODE unset")
		}
		return nodeBesu, nil
	default:
		return 0, errors.New("OPS_APPROVAL_NODE must be reth or besu")
	}
}

// besuPrepared is the ops_prepareApproval result. The plugin simulated the exact signed
// bytes with the producer's own tracer; OPS trusts the observed facts the same way it trusts
// debug_traceCall, but never the plugin's arithmetic: the fingerprint is recomputed here.
type besuPrepared struct {
	HashMode    uint8             `json:"hashMode"`
	ChainID     hexutil.Uint64    `json:"chainId"`
	TxHash      common.Hash       `json:"txHash"`
	Fingerprint common.Hash       `json:"fingerprint"`
	Calls       json.RawMessage   `json:"calls"`
	CodeHashes  map[string]string `json:"codeHashes"`
	Pre         json.RawMessage   `json:"pre"`
	Diff        json.RawMessage   `json:"diff"`
}

func (s *Service) prepareBesu(ctx context.Context, raw string, tx *types.Transaction, from common.Address, chain uint64) (*Prepared, error) {
	var res besuPrepared
	if err := s.rpc.CallContext(ctx, &res, "ops_prepareApproval", raw); err != nil {
		return nil, err
	}
	if !validHashMode(res.HashMode) || uint64(res.ChainID) != chain || res.TxHash != tx.Hash() {
		return nil, errors.New("plugin approval does not describe this transaction")
	}
	var calls, pre, diff object
	for _, part := range []struct {
		raw json.RawMessage
		out *object
	}{{res.Calls, &calls}, {res.Pre, &pre}, {res.Diff, &diff}} {
		if len(part.raw) == 0 {
			continue
		}
		d := json.NewDecoder(bytes.NewReader(part.raw))
		d.UseNumber() // nonce and balance can exceed float64 precision
		if err := d.Decode(part.out); err != nil {
			return nil, err
		}
	}
	codes := map[string]common.Hash{}
	codeHashes := map[string]string{}
	for address, hash := range res.CodeHashes {
		raw, err := hexutil.Decode(hash)
		if err != nil || len(raw) != common.HashLength || !common.IsHexAddress(address) {
			return nil, errors.New("plugin code hash map is malformed")
		}
		h := common.BytesToHash(raw)
		codes[strings.ToLower(address)] = h
		codeHashes[strings.ToLower(address)] = h.Hex()
	}
	// The root frame must be the signed envelope; a tree for some other call is not this
	// transaction's execution even when its fingerprint is self-consistent.
	rootKind, rootTo := "CALL", ""
	if tx.To() != nil {
		rootTo = strings.ToLower(tx.To().Hex())
	} else {
		// A deployment's root frame is the creation of the address the signed nonce determines.
		rootKind = "CREATE"
		rootTo = strings.ToLower(crypto.CreateAddress(from, tx.Nonce()).Hex())
	}
	rootValue, err := word(calls["value"])
	if err != nil {
		return nil, err
	}
	expectedValue, _ := word(hexutil.EncodeBig(tx.Value()))
	if str(calls["type"]) != rootKind || field(calls, "from", "") != strings.ToLower(from.Hex()) || field(calls, "to", "") != rootTo || field(calls, "input", "0x") != strings.ToLower(hexutil.Encode(tx.Data())) || rootValue != expectedValue {
		return nil, errors.New("plugin root frame does not match the signed transaction")
	}
	// OPS decides the mode from the execution itself, exactly as it does on the other node path:
	// a plugin cannot downgrade a deployment to the weaker calls fingerprint by labelling it so.
	hash, trace, mode, err := besuFingerprint(calls, codes, pre, diff)
	if err != nil {
		return nil, err
	}
	if mode != res.HashMode {
		return nil, errors.New("plugin approval mode does not match the execution")
	}
	if hash != res.Fingerprint {
		// The plugin's tracer and this encoder disagree: nothing is signed until someone looks.
		return nil, errors.New("plugin fingerprint disagrees with the OPS encoder")
	}
	empty := crypto.Keccak256Hash(nil).Hex()
	noCode := map[string]bool{}
	for address, code := range codeHashes {
		if code == empty {
			noCode[address] = true
		}
	}
	plain := tx.To() != nil && len(tx.Data()) == 0 && len(trace.CallTargets) == 1 && str(calls["type"]) == "CALL" && codeHashes[strings.ToLower(tx.To().Hex())] == empty
	fresh, surviving := map[string]bool{}, map[string]bool{}
	if mode == HashStrict {
		// Deployments are registered from the same snapshot the approval binds.
		fresh, surviving = creationSets(trace, pre, diff)
	}
	return &Prepared{Approval: Approval{HashMode: mode, ChainID: chain, TxHash: tx.Hash(), Fingerprint: hash}, Trace: trace, CodeHashes: codeHashes, FreshCreations: fresh, SurvivingCreations: surviving, PlainValueTransfer: plain, NoCodeRecipients: noCode}, nil
}

// besuFingerprint is fingerprintForMode over the plugin-served snapshots: the calls fingerprint
// unless the execution created or destroyed a contract, which only the strict one can express.
func besuFingerprint(calls object, codes map[string]common.Hash, pre, diff object) (common.Hash, *tracer.TraceResult, uint8, error) {
	hash, trace, err := callFingerprintWithCodes(calls, codes)
	if !errors.Is(err, errCallLifecycle) {
		return hash, trace, HashCalls, err
	}
	hash, trace, err = Fingerprint(calls, pre, diff)
	return hash, trace, HashStrict, err
}
