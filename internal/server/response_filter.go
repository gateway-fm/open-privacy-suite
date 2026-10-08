package server

// TODO: Multi-party event stakeholder whitelists
// Events using a business identifier (e.g., paymentIdentifier) instead of address parameters
// require a per-event-ID stakeholder whitelist (e.g., debtor bank, settlement bank, creditor
// bank for a PaymentInitiated event). This needs a new data model and admin API.
// Until then, events without indexed address parameters are filtered out for all users.
//
// TODO: eth_call response ABI decoding
// The response to eth_call is raw ABI-encoded bytes. For full field-level privacy
// (e.g., hiding the 'amount' field in getPaymentInfo unless user is a party),
// the proxy would need to decode the ABI response and selectively redact fields.
// This requires the contract ABI to be registered and per-function redaction rules.
//
// TODO: Traffic analysis via block metadata
// eth_getBlockTransactionCountByHash/Number reveal how many transactions are in a block,
// which enables coarse traffic analysis even without calldata access.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"privacy-proxy/internal/rbac"
)

// rpcResponseID extracts the raw "id" field from a JSON-RPC response body.
// Returns "null" if not found.
func rpcResponseID(body []byte) string {
	var envelope struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(body, &envelope) == nil && envelope.ID != nil {
		return string(envelope.ID)
	}
	return "null"
}

// nullResult is the fail-closed JSON-RPC response: a null result carrying the
// request id (or null when the body cannot be parsed). A filter that cannot
// evaluate an upstream shape returns this instead of the upstream body, which
// would otherwise reach the caller unfiltered (RD-1299).
func nullResult(responseBody []byte) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + rpcResponseID(responseBody) + `,"result":null}`)
}

// rpcResponseFromParsed serializes a JSON-RPC response from the members a
// filter parsed: jsonrpc, id, and the upstream error or the (possibly null)
// result. No other envelope member of the upstream body is copied — neither
// an extra member nor a case variant of "result" or "error" that the decoder
// folded onto the parsed field — so the envelope a filter returns carries
// only the result it evaluated or the upstream error (RD-1299). The result
// object itself is returned as the node sent it.
func rpcResponseFromParsed(id json.RawMessage, result, rpcErr *json.RawMessage) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	var (
		out []byte
		err error
	)
	if rpcErr != nil {
		out, err = json.Marshal(struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Error   json.RawMessage `json:"error"`
		}{JSONRPC: "2.0", ID: id, Error: *rpcErr})
	} else {
		res := json.RawMessage("null")
		if result != nil {
			res = *result
		}
		out, err = json.Marshal(struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Result  json.RawMessage `json:"result"`
		}{JSONRPC: "2.0", ID: id, Result: res})
	}
	if err != nil {
		return []byte(`{"jsonrpc":"2.0","id":null,"result":null}`)
	}
	return out
}

// addrSetFromLinked builds a lowercase address set for O(1) lookup.
func addrSetFromLinked(addrs []string) map[string]bool {
	set := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		set[strings.ToLower(a)] = true
	}
	return set
}

// FilterTransactionByHash filters a response carrying one transaction object
// (eth_getTransactionByHash and the by-block-index aliases). The admission
// verdict is rbac.DecideTxEnvelope for TxSurfaceTransaction: the viewer receives
// the full transaction if admitted, otherwise a null result (indistinguishable
// from an unknown hash).
//
// isAdminOnTo is computed at the call site (JSONRPCProcessor.viewerAdminContracts)
// with an org-scoped check: the tx's `to` is looked up to find its owning org,
// then the viewer's admin claim is verified in that org ONLY — defense in depth
// on top of the schema-level uniqueness constraint (migration 035: one address
// → one org). inVisibleTo is consulted lazily, only when the verdict still
// depends on it (standard profile, non-participant, non-admin).
//
// A null or error result passes through, and an admitted transaction is
// returned, rebuilt from the parsed members only; any shape that cannot be
// evaluated fails closed to null.
func FilterTransactionByHash(profile rbac.ReadProfile, responseBody []byte, userAddresses []string, isAdminOnTo bool, inVisibleTo func() bool) []byte {
	var resp struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Result  *json.RawMessage `json:"result"`
		Error   *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return nullResult(responseBody) // unparseable: fail closed
	}
	if resp.Error != nil && resp.Result != nil {
		return nullResult(responseBody)
	}
	// Pass through standalone errors and null results.
	if resp.Error != nil || resp.Result == nil {
		return rpcResponseFromParsed(resp.ID, nil, resp.Error)
	}
	raw := []byte(*resp.Result)
	if string(raw) == "null" {
		return rpcResponseFromParsed(resp.ID, nil, nil)
	}

	var tx struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := json.Unmarshal(raw, &tx); err != nil {
		return nullResult(responseBody) // result is not a tx object: fail closed
	}

	facts := rbac.TxEnvelopeFacts{
		Surface:       rbac.TxSurfaceTransaction,
		IsParticipant: isTxParticipant(userAddresses, tx.From, tx.To),
		IsAdminOnTo:   isAdminOnTo,
	}
	if !facts.IsParticipant && !facts.IsAdminOnTo && !profile.Strict() && inVisibleTo != nil {
		facts.InVisibleTo = inVisibleTo()
	}
	if rbac.DecideTxEnvelope(profile, facts) {
		return rpcResponseFromParsed(resp.ID, resp.Result, nil)
	}
	return nullResult(responseBody)
}

// isTxParticipant reports whether one of the viewer's linked addresses is the
// transaction's `from` or `to` — the only notion of participation the
// transaction-level decision accepts (RD-1299).
func isTxParticipant(userAddresses []string, from, to string) bool {
	addrSet := addrSetFromLinked(userAddresses)
	from = strings.ToLower(from)
	to = strings.ToLower(to)
	return (from != "" && addrSet[from]) || (to != "" && addrSet[to])
}

// zeroLogsBloomJSON is the canonical JSON value used to overwrite a block's
// logsBloom field — `"0x"` followed by 512 zero hex characters (the spec's
// 256-byte all-zero bloom). Computed once because every block-returning RPC
// response gets its bloom replaced with this value (RD-873).
var zeroLogsBloomJSON = json.RawMessage(`"0x` + strings.Repeat("0", 512) + `"`)

// zeroGasUsedJSON is the canonical hex-zero value used to overwrite a block's
// gas-aggregate fields (gasUsed, blobGasUsed). See FilterBlockTransactions
// docstring for the threat model (RD-929).
var zeroGasUsedJSON = json.RawMessage(`"0x0"`)

// zeroSizeJSON is the canonical hex-zero value used to overwrite a block's
// `size` field (RD-1052). Block size is the serialized byte length of the whole
// block — a per-block aggregate over every tx, including ones hidden from the
// viewer, so it leaks the presence/volume of other-org activity in the block.
// Mirrors the logsBloom / gasUsed treatment: zeroed unconditionally on the way
// out (0x0 is never a real block size, so it carries no information).
var zeroSizeJSON = json.RawMessage(`"0x0"`)

// FilterBlockTransactions filters an eth_getBlockByNumber or eth_getBlockByHash response.
// Removes non-participant transactions. If the user originally requested hashes, maps the
// filtered full tx objects back to the transaction hashes.
//
// As of RD-873 the block's logsBloom field is unconditionally zeroed for every
// viewer regardless of which transaction-filtering branch fires. The bloom
// filter contains hashed representations of addresses and event topics from
// every log in the block; a viewer who knows a target address can probe its
// activity in O(1). Our private-by-default model can't rely on "knowing the
// target address" staying false (out-of-band leakage, contract authors using
// addresses as identifiers), so the field is sanitised to all-zero on the way
// out. This closes decisions.md §2 G6.
//
// RD-929 extends the same treatment to gasUsed (and blobGasUsed for EIP-4844).
// These are block-aggregate fields: by spec they're the sum of every tx's gas
// in the block, including txs we hide from the viewer via the transactions[]
// filter above. Passing them through verbatim is a direct presence leak — a
// non-participant who sees transactions:[] paired with gasUsed:0x500000 learns
// "this block had hidden activity." Even for participants the field reveals
// the gas footprint of other users' txs in the same block. We mirror logsBloom
// and always return 0x0; users who need their own gas can get it from the
// per-tx receipts they already have access to.
func FilterBlockTransactions(profile rbac.ReadProfile, responseBody []byte, userAddresses []string, originalFull bool) []byte {
	var resp struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Result  *json.RawMessage `json:"result"`
		Error   *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return nullResult(responseBody) // unparseable: fail closed
	}
	if resp.Error != nil && resp.Result != nil {
		return nullResult(responseBody)
	}
	if resp.Error != nil || resp.Result == nil {
		return rpcResponseFromParsed(resp.ID, nil, resp.Error)
	}
	raw := []byte(*resp.Result)
	if string(raw) == "null" {
		return rpcResponseFromParsed(resp.ID, nil, nil)
	}

	// Parse the block as a map to preserve all fields
	var block map[string]json.RawMessage
	if err := json.Unmarshal(raw, &block); err != nil {
		return nullResult(responseBody) // result is not a block object: fail closed
	}

	// Always zero logsBloom and gas-aggregate fields before any further
	// filtering — fail-closed regardless of transaction-array shape (full
	// objects, hash list, empty, or absent). Done unconditionally rather
	// than per-branch so future branches added below can't accidentally
	// leave the fields untouched. See docstring for the threat model.
	if _, ok := block["logsBloom"]; ok {
		block["logsBloom"] = zeroLogsBloomJSON
	}
	if _, ok := block["gasUsed"]; ok {
		block["gasUsed"] = zeroGasUsedJSON
	}
	if _, ok := block["blobGasUsed"]; ok {
		block["blobGasUsed"] = zeroGasUsedJSON
	}
	if _, ok := block["size"]; ok {
		block["size"] = zeroSizeJSON // RD-1052
	}

	if txsRaw, ok := block["transactions"]; ok {
		// Check if transactions are objects or hashes (strings).
		var rawTxs []json.RawMessage
		if err := json.Unmarshal(txsRaw, &rawTxs); err != nil {
			// Not an array: nothing we can evaluate per-transaction, so
			// return none rather than the upstream value (fail closed).
			block["transactions"] = []byte("[]")
		} else if len(rawTxs) > 0 {
			// Peek at first element to determine if full objects or hashes.
			first := bytes.TrimSpace(rawTxs[0])
			if len(first) == 0 || first[0] == '"' {
				// We received hashes. If we already rewrote the request to full
				// objects, this shouldn't happen. For safety, clear the array.
				block["transactions"] = []byte("[]")
			} else {
				// Full transaction objects — keep only those the shared
				// decision admits as a block entry (participant only).
				filtered := make([]json.RawMessage, 0, len(rawTxs))
				for _, rawTx := range rawTxs {
					var tx struct {
						From string `json:"from"`
						To   string `json:"to"`
						Hash string `json:"hash"`
					}
					if err := json.Unmarshal(rawTx, &tx); err != nil {
						continue
					}
					if rbac.DecideTxEnvelope(profile, rbac.TxEnvelopeFacts{
						Surface:       rbac.TxSurfaceBlockEntry,
						IsParticipant: isTxParticipant(userAddresses, tx.From, tx.To),
					}) {
						if !originalFull {
							hashStr, _ := json.Marshal(tx.Hash)
							filtered = append(filtered, hashStr)
						} else {
							filtered = append(filtered, rawTx)
						}
					}
				}
				if filteredTxJSON, err := json.Marshal(filtered); err == nil {
					block["transactions"] = filteredTxJSON
				}
			}
		}
		// An empty array is left alone; the bloom rewrite above still applies.
	}

	blockJSON, err := json.Marshal(block)
	if err != nil {
		return nullResult(responseBody)
	}

	blockResult := json.RawMessage(blockJSON)
	blockOut, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{
		JSONRPC: "2.0",
		ID:      resp.ID,
		Result:  blockResult,
	})
	if err != nil {
		return nullResult(responseBody)
	}
	return blockOut
}

// FilterBlockReceipts filters an eth_getBlockReceipts response. Each receipt
// goes through the same per-receipt decision as eth_getTransactionReceipt
// (decideReceipt) as a block entry: the envelope is kept for a participant only
// (both profiles) and omitted otherwise, consistent with FilterBlockTransactions;
// a kept receipt's logs are filtered by the shared log engine (grant, ABI,
// dynamic-payload gate, event rules, RD-1162) and rendered by render, exactly as
// the single-receipt path renders them (RD-1299). logsBloom is zeroed. A null or
// error result passes through; any other non-array shape fails closed.
func FilterBlockReceipts(
	profile rbac.ReadProfile,
	responseBody []byte,
	userAddresses []string,
	perms *rbac.EffectivePermissions,
	abiProvider rbac.ABIProvider,
	visCtx *rbac.TxVisibilityContext,
	isAdminByContract map[string]bool,
	render admittedLogRenderer,
) []byte {
	var resp struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Result  *json.RawMessage `json:"result"`
		Error   *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return nullResult(responseBody) // unparseable: fail closed
	}
	if resp.Error != nil && resp.Result != nil {
		return nullResult(responseBody)
	}
	if resp.Error != nil || resp.Result == nil {
		return rpcResponseFromParsed(resp.ID, nil, resp.Error)
	}
	raw := []byte(*resp.Result)
	if string(raw) == "null" {
		return rpcResponseFromParsed(resp.ID, nil, nil)
	}

	var rawReceipts []json.RawMessage
	if err := json.Unmarshal(raw, &rawReceipts); err != nil {
		return nullResult(responseBody) // not an array: fail closed
	}

	receiptsFiltered := make([]json.RawMessage, 0, len(rawReceipts))
	for _, rawReceipt := range rawReceipts {
		// Non-participant receipts are omitted entirely; unparseable entries
		// are skipped (fail closed).
		if out, admit := decideReceipt(profile, rbac.TxSurfaceBlockEntry, rawReceipt, userAddresses, perms, abiProvider, visCtx, isAdminByContract, render); admit {
			receiptsFiltered = append(receiptsFiltered, out)
		}
	}

	receiptsJSON, err := json.Marshal(receiptsFiltered)
	if err != nil {
		return nullResult(responseBody)
	}

	receiptsResult := json.RawMessage(receiptsJSON)
	receiptsOut, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{
		JSONRPC: "2.0",
		ID:      resp.ID,
		Result:  receiptsResult,
	})
	if err != nil {
		return nullResult(responseBody)
	}
	return receiptsOut
}

// FilterBlockTransactionCount takes a response to eth_getBlockByNumber or Hash
// (which we rewrite into fetching the full block) and counts only the user's transactions.
func FilterBlockTransactionCount(responseBody []byte, userAddresses []string) []byte {
	var resp struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Result  *json.RawMessage `json:"result"`
		Error   *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return nullResult(responseBody) // unparseable: fail closed
	}
	if resp.Error != nil && resp.Result != nil {
		return nullResult(responseBody)
	}
	if resp.Error != nil || resp.Result == nil {
		return rpcResponseFromParsed(resp.ID, nil, resp.Error)
	}
	raw := []byte(*resp.Result)
	if string(raw) == "null" {
		return rpcResponseFromParsed(resp.ID, nil, nil)
	}

	// The request was rewritten to a full block fetch, so the result must be
	// a block object. Anything else (e.g. the node's raw count for a method
	// that was not rewritten — the total including other users' transactions)
	// fails closed.
	var block map[string]json.RawMessage
	if err := json.Unmarshal(raw, &block); err != nil {
		return nullResult(responseBody)
	}

	var rawTxs []json.RawMessage
	if txsRaw, ok := block["transactions"]; ok {
		if err := json.Unmarshal(txsRaw, &rawTxs); err != nil {
			return nullResult(responseBody)
		}
	}

	addrSet := addrSetFromLinked(userAddresses)
	count := 0
	for _, rawTx := range rawTxs {
		var tx struct {
			From string `json:"from"`
			To   string `json:"to"`
		}
		if err := json.Unmarshal(rawTx, &tx); err != nil {
			continue
		}
		from := strings.ToLower(tx.From)
		to := strings.ToLower(tx.To)
		if addrSet[from] || (to != "" && addrSet[to]) {
			count++
		}
	}

	hexCount := fmt.Sprintf("0x%x", count)
	hexResult, _ := json.Marshal(hexCount)

	out, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{
		JSONRPC: "2.0",
		ID:      resp.ID,
		Result:  hexResult,
	})
	if err != nil {
		return nullResult(responseBody)
	}
	return out
}
