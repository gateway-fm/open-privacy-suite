package server

import (
	"context"
	"encoding/json"
	"strings"

	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"
)

// addressVisibilityResolver resolves per-address visibility for the RPC log
// field-redaction step (RD-1214). It is satisfied by *db.DB via
// GetBatchVisibilityDetailed — the SAME method the explorer redactor calls — so
// the RPC and the explorer hide exactly the same embedded addresses for a given
// (viewer, log) pair. Symmetry is a property of sharing this resolver plus
// explorer.RedactLogAddressFields, not a convention. Wired at construction via
// JSONRPCProcessorConfig.AddressVisibilityResolver; when unset (unit tests that
// don't exercise field-redaction) the step is a no-op.
type addressVisibilityResolver interface {
	GetBatchVisibilityDetailed(ctx context.Context, viewerDID string, addresses []string) (map[string]explorer.AddressVisibility, error)
}

// redactEmbeddedLogAddresses zeroes, in every raw eth log, each embedded address
// (indexed topics + ABI-decoded non-indexed data) the viewer is NOT entitled to
// see. Admission has already happened upstream (rbac.FilterEventLogs); this is
// the field-level half of the RD-1214 unification, so eth_getLogs /
// eth_getTransactionReceipt return the same visible-address set the explorer
// would for the same viewer.
//
// It resolves visibility via p.addrVisResolver (the same GetBatchVisibilityDetailed
// the explorer uses) and applies explorer.RedactLogAddressFields (the same
// zeroing primitive). Fail-closed: a resolver error leaves visMap empty, so
// every embedded address resolves to a non-Full level and is zeroed. A nil
// resolver (not wired) is a no-op.
//
// Only "topics" and "data" are rewritten; all other log fields are preserved
// byte-for-byte. A malformed log entry is passed through unchanged — it carries
// no decodable address to leak, and admission already vetted it.
//
// abiProvider drives the non-indexed data scan (injected so the redaction is
// unit-testable without a DB-backed store); the callers pass
// p.contractABIProvider(ctx).
func (p *JSONRPCProcessor) redactEmbeddedLogAddresses(ctx context.Context, viewerDID string, rawLogs []json.RawMessage, abiProvider rbac.ABIProvider) []json.RawMessage {
	if p.addrVisResolver == nil || len(rawLogs) == 0 {
		return rawLogs
	}

	type parsedLog struct {
		fields map[string]json.RawMessage
		topics []*string
		data   string
		abi    json.RawMessage
		topic0 *string
		ok     bool
	}

	parsed := make([]parsedLog, len(rawLogs))
	addrSet := make(map[string]struct{})

	for i, rl := range rawLogs {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(rl, &m); err != nil {
			parsed[i] = parsedLog{ok: false}
			continue
		}
		var address string
		_ = json.Unmarshal(m["address"], &address)
		var topicStrs []string
		_ = json.Unmarshal(m["topics"], &topicStrs)
		var data string
		_ = json.Unmarshal(m["data"], &data)

		var abiRaw json.RawMessage
		if s := abiProvider.GetContractABI(address); s != "" {
			abiRaw = json.RawMessage(s)
		}

		topics := make([]*string, len(topicStrs))
		for j := range topicStrs {
			t := topicStrs[j]
			topics[j] = &t
		}
		var topic0 *string
		if len(topics) > 0 {
			topic0 = topics[0]
		}

		parsed[i] = parsedLog{fields: m, topics: topics, data: data, abi: abiRaw, topic0: topic0, ok: true}

		for _, a := range explorer.ExtractLogAddresses(topics, data, abiRaw, topic0) {
			addrSet[a] = struct{}{}
		}
	}

	// Fail-closed: an empty visMap zeroes every embedded address (all resolve to
	// a non-Full level). Only populated on a successful resolve.
	visMap := make(explorer.VisibilityMap)
	if len(addrSet) > 0 {
		addrs := make([]string, 0, len(addrSet))
		for a := range addrSet {
			addrs = append(addrs, a)
		}
		if detailed, err := p.addrVisResolver.GetBatchVisibilityDetailed(ctx, viewerDID, addrs); err == nil {
			for a, v := range detailed {
				visMap[strings.ToLower(a)] = v.Level
			}
		}
	}

	out := make([]json.RawMessage, len(rawLogs))
	for i, rl := range rawLogs {
		pl := parsed[i]
		if !pl.ok {
			out[i] = rl
			continue
		}
		redTopics, redData := explorer.RedactLogAddressFields(pl.topics, pl.data, pl.abi, pl.topic0, visMap)

		topicStrs := make([]string, len(redTopics))
		for j, t := range redTopics {
			if t != nil {
				topicStrs[j] = *t
			}
		}
		if tb, err := json.Marshal(topicStrs); err == nil {
			pl.fields["topics"] = tb
		}
		if db, err := json.Marshal(redData); err == nil {
			pl.fields["data"] = db
		}
		if rewritten, err := json.Marshal(pl.fields); err == nil {
			out[i] = rewritten
		} else {
			out[i] = rl
		}
	}
	return out
}

// redactLogsArrayResponseFields applies embedded-address field-redaction to an
// eth_getLogs response (result is a JSON array of logs). The response has
// already passed entry-level filtering (FilterLogsWithEventRules). On any parse
// failure the body is returned unchanged — the entry filter's own fail-closed
// paths (which return [] on malformed input) run first.
func (p *JSONRPCProcessor) redactLogsArrayResponseFields(ctx context.Context, viewerDID string, responseBody []byte) []byte {
	if p.addrVisResolver == nil {
		return responseBody
	}
	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil || resp.Error != nil || len(resp.Result) == 0 {
		return responseBody
	}
	var rawLogs []json.RawMessage
	if err := json.Unmarshal(resp.Result, &rawLogs); err != nil {
		return responseBody
	}
	redacted := p.redactEmbeddedLogAddresses(ctx, viewerDID, rawLogs, p.contractABIProvider(ctx))
	resultBytes, err := json.Marshal(redacted)
	if err != nil {
		return responseBody
	}
	out, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{JSONRPC: "2.0", ID: resp.ID, Result: resultBytes})
	if err != nil {
		return responseBody
	}
	return out
}

// redactReceiptResponseFields applies embedded-address field-redaction to the
// logs array nested in an eth_getTransactionReceipt response (result.logs).
// Other receipt fields are preserved. On a null/absent result or a parse
// failure the body is returned unchanged.
func (p *JSONRPCProcessor) redactReceiptResponseFields(ctx context.Context, viewerDID string, responseBody []byte) []byte {
	if p.addrVisResolver == nil {
		return responseBody
	}
	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil || resp.Error != nil || len(resp.Result) == 0 || string(resp.Result) == "null" {
		return responseBody
	}
	var receipt map[string]json.RawMessage
	if err := json.Unmarshal(resp.Result, &receipt); err != nil {
		return responseBody
	}
	logsRaw, ok := receipt["logs"]
	if !ok {
		return responseBody
	}
	var rawLogs []json.RawMessage
	if err := json.Unmarshal(logsRaw, &rawLogs); err != nil {
		return responseBody
	}
	redacted := p.redactEmbeddedLogAddresses(ctx, viewerDID, rawLogs, p.contractABIProvider(ctx))
	newLogs, err := json.Marshal(redacted)
	if err != nil {
		return responseBody
	}
	receipt["logs"] = newLogs
	resultBytes, err := json.Marshal(receipt)
	if err != nil {
		return responseBody
	}
	out, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{JSONRPC: "2.0", ID: resp.ID, Result: resultBytes})
	if err != nil {
		return responseBody
	}
	return out
}
