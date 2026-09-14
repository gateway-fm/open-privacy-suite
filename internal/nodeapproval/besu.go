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
)

// nodeKind selects how the preflight execution facts are obtained.
type nodeKind uint8

const (
	nodeReth nodeKind = iota // OPS_APPROVAL_NODE=reth (default): debug_traceCall muxTracer, as on the Reth PoC
	nodeBesu                 // OPS_APPROVAL_NODE=besu: ops_prepareApproval served by the OPS Besu plugin
)

// configuredNodeKind also rejects combinations that could never produce an approval, so a
// misconfigured OPS fails at start-up rather than on every preflight.
func configuredNodeKind(hashMode uint8) (nodeKind, error) {
	switch os.Getenv("OPS_APPROVAL_NODE") {
	case "", "reth":
		return nodeReth, nil
	case "besu":
		if hashMode != HashCalls {
			return 0, errors.New("OPS_APPROVAL_NODE=besu supports OPS_APPROVAL_HASH_MODE=calls only")
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
}

func (s *Service) prepareBesu(ctx context.Context, raw string, tx *types.Transaction, from common.Address, chain uint64) (*Prepared, error) {
	var res besuPrepared
	if err := s.rpc.CallContext(ctx, &res, "ops_prepareApproval", raw); err != nil {
		return nil, err
	}
	if res.HashMode != HashCalls || uint64(res.ChainID) != chain || res.TxHash != tx.Hash() {
		return nil, errors.New("plugin approval does not describe this transaction")
	}
	var calls object
	d := json.NewDecoder(bytes.NewReader(res.Calls))
	d.UseNumber()
	if err := d.Decode(&calls); err != nil {
		return nil, err
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
	rootTo := ""
	if tx.To() != nil {
		rootTo = strings.ToLower(tx.To().Hex())
	}
	rootValue, err := word(calls["value"])
	if err != nil {
		return nil, err
	}
	expectedValue, _ := word(hexutil.EncodeBig(tx.Value()))
	if str(calls["type"]) != "CALL" || field(calls, "from", "") != strings.ToLower(from.Hex()) || field(calls, "to", "") != rootTo || field(calls, "input", "0x") != strings.ToLower(hexutil.Encode(tx.Data())) || rootValue != expectedValue {
		return nil, errors.New("plugin root frame does not match the signed transaction")
	}
	hash, trace, err := callFingerprintWithCodes(calls, codes)
	if err != nil {
		return nil, err
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
	return &Prepared{Approval: Approval{HashMode: HashCalls, ChainID: chain, TxHash: tx.Hash(), Fingerprint: hash}, Trace: trace, CodeHashes: codeHashes, FreshCreations: map[string]bool{}, SurvivingCreations: map[string]bool{}, PlainValueTransfer: plain, NoCodeRecipients: noCode}, nil
}
