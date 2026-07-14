package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/rbac"
)

// Method access policy request-path wiring (RD-1206). The read gate runs inside
// applyResponseFilter (post-forward), so it decodes the caller's OWN already-
// fetched eth_call response — never a second upstream call, and allow/deny share
// the timing profile. The capture hook runs on the send methods, enqueuing the
// pre-decoded capture payload to the receipt-confirmed outbox.

// methodPolicyCaptureStore is the optional capability the processor needs for
// capture read/enqueue. Satisfied by *db.DB; absent in lightweight test
// harnesses (the gate then behaves as pre-feature for reads, and skips capture).
type methodPolicyCaptureStore interface {
	GetRecordCaptures(ctx context.Context, orgID, contractAddr, recordType, recordKey string) ([]rbac.CapturedField, error)
	EnqueuePendingRecordCaptures(ctx context.Context, txHash, orgID, contractAddr, senderDID string, writes []rbac.CapturedWrite) error
}

func (p *JSONRPCProcessor) methodPolicyStore() (methodPolicyCaptureStore, bool) {
	s, ok := p.rbacAccessCtrl.Store().(methodPolicyCaptureStore)
	return s, ok
}

// applyMethodPolicyGate gates an eth_call response by the target contract's
// per-record method policy. Not-gated calls pass through unchanged; a policy
// denial or any fail-closed condition returns an opaque error.
func (p *JSONRPCProcessor) applyMethodPolicyGate(ctx context.Context, req *ProcessRequest, responseBody []byte) []byte {
	_, to, data, _ := extractTxParams(req.Params)
	to = strings.ToLower(strings.TrimSpace(to))
	if to == "" || data == "" {
		return responseBody
	}
	store, ok := p.methodPolicyStore()
	if !ok {
		return responseBody // capability not wired — no policy enforcement possible
	}

	contract, err := p.rbacAccessCtrl.Store().GetContractByAddressGlobal(ctx, to)
	if err != nil {
		return denyMethodPolicy(responseBody) // DB error → fail closed
	}
	if contract == nil || len(contract.MethodPolicies) == 0 {
		return responseBody // no policy configured → passthrough (unchanged)
	}
	doc, perr := rbac.ParseMethodPolicyDocument(contract.MethodPolicies)
	if perr != nil {
		return denyMethodPolicy(responseBody) // corrupt policy → deny (M1)
	}

	calldata := common.FromHex(data)
	caller := rbac.NewCallerIdentity(req.UserID, p.linkedAddresses(ctx, req.UserID))
	ownerOrg := contract.OrgID
	loadCaptures := func(recordType, recordKey string) ([]rbac.CapturedField, error) {
		return store.GetRecordCaptures(ctx, ownerOrg, to, recordType, recordKey)
	}
	returnData := extractEthCallResultBytes(responseBody)
	paths := doc.ReturnAddressPaths(calldata, contract.ABI)
	resolveReturn := func() ([]common.Address, error) {
		if len(paths) == 0 || len(returnData) == 0 {
			return nil, nil
		}
		return rbac.DecodeReturnAddresses(returnData, calldata, paths, contract.ABI)
	}

	gated, dec, err := doc.EvaluateReader(calldata, caller, loadCaptures, resolveReturn, contract.ABI)
	if err != nil {
		return denyMethodPolicy(responseBody)
	}
	if !gated || dec.Allow {
		return responseBody
	}
	return denyMethodPolicy(responseBody)
}

// enqueueMethodPolicyCaptures decodes a send's calldata against the target
// contract's policy and enqueues the capture payload to the outbox. Best-effort
// (logs on failure) — mirrors the visibleTo outbox enqueue.
func (p *JSONRPCProcessor) enqueueMethodPolicyCaptures(ctx context.Context, req *ProcessRequest, toHex, dataHex string, visibleTo []string, txHash string) {
	toHex = strings.ToLower(strings.TrimSpace(toHex))
	if toHex == "" || dataHex == "" || txHash == "" {
		return
	}
	store, ok := p.methodPolicyStore()
	if !ok {
		return
	}
	contract, err := p.rbacAccessCtrl.Store().GetContractByAddressGlobal(ctx, toHex)
	if err != nil || contract == nil || len(contract.MethodPolicies) == 0 {
		return
	}
	doc, perr := rbac.ParseMethodPolicyDocument(contract.MethodPolicies)
	if perr != nil {
		return
	}
	writes, derr := doc.DecodeCaptures(common.FromHex(dataHex), req.UserID, visibleTo, contract.ABI)
	if derr != nil || len(writes) == 0 {
		return
	}
	if err := store.EnqueuePendingRecordCaptures(ctx, txHash, contract.OrgID, toHex, req.UserID, writes); err != nil {
		slog.Error("method-policy capture enqueue failed; tx is on-chain but the record's parties won't be captured",
			"tx", txHash, "contract", toHex, "sender", req.UserID, "org", contract.OrgID, "error", err)
	}
}

// linkedAddresses returns the caller's linked ETH addresses, or nil on error.
func (p *JSONRPCProcessor) linkedAddresses(ctx context.Context, did string) []string {
	addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, did)
	if err != nil {
		return nil
	}
	return addrs
}

// nodeForwarder is the subset of *proxy.Proxy the receipt checker needs.
type nodeForwarder interface {
	Forward(reqBody []byte) ([]byte, int, error)
}

// makeReceiptStatusFunc builds the reconciler's receipt checker backed by an
// upstream eth_getTransactionReceipt call (RD-1206 capture promotion).
func makeReceiptStatusFunc(fwd nodeForwarder) ReceiptStatusFunc {
	return func(ctx context.Context, txHash string) (mined bool, success bool, err error) {
		body, mErr := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1,
			"method": "eth_getTransactionReceipt",
			"params": []any{txHash}, // marshaled, never string-concatenated
		})
		if mErr != nil {
			return false, false, mErr
		}
		resp, _, fErr := fwd.Forward(body)
		if fErr != nil {
			return false, false, fErr
		}
		var r struct {
			Result *struct {
				Status string `json:"status"`
			} `json:"result"`
			Error *json.RawMessage `json:"error"`
		}
		if e := json.Unmarshal(resp, &r); e != nil {
			return false, false, e
		}
		if r.Error != nil {
			return false, false, nil // treat as transient — retry
		}
		if r.Result == nil {
			return false, false, nil // not yet mined
		}
		return true, strings.EqualFold(r.Result.Status, "0x1"), nil
	}
}

// denyMethodPolicy returns an opaque JSON-RPC error preserving the request id.
// The message carries no record detail (no existence oracle).
func denyMethodPolicy(responseBody []byte) []byte {
	id := rpcResponseID(responseBody)
	return []byte(`{"jsonrpc":"2.0","id":` + id + `,"error":{"code":-32000,"message":"not authorized to read this record"}}`)
}

// extractEthCallResultBytes returns the decoded bytes of an eth_call response's
// result hex, or nil when the response is an error / null / non-hex.
func extractEthCallResultBytes(responseBody []byte) []byte {
	var resp struct {
		Result *string          `json:"result"`
		Error  *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return nil
	}
	if resp.Error != nil || resp.Result == nil {
		return nil
	}
	s := strings.TrimSpace(*resp.Result)
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return nil
	}
	return common.FromHex(s)
}
