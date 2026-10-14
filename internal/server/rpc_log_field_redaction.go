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

// redactEmbeddedLogAddresses masks every log in rawLogs (all treated as
// rbac.LogPayloadMasked). Kept for callers that have no per-log admission
// decision to honour — the admin dry-run, which never evaluates visibleTo.
func (p *JSONRPCProcessor) redactEmbeddedLogAddresses(ctx context.Context, viewerDID string, rawLogs []json.RawMessage, abiProvider rbac.ABIProvider) []json.RawMessage {
	admitted := make([]rbac.AdmittedLog, len(rawLogs))
	for i, rl := range rawLogs {
		admitted[i] = rbac.AdmittedLog{Raw: rl, Payload: rbac.LogPayloadMasked}
	}
	return p.redactAdmittedLogs(ctx, viewerDID, admitted, abiProvider)
}

// logFieldRenderer returns the renderer the eth_getLogs / receipt filters use
// to turn admitted logs into the client response (see admittedLogRenderer).
func (p *JSONRPCProcessor) logFieldRenderer(ctx context.Context, viewerDID string, abiProvider rbac.ABIProvider) admittedLogRenderer {
	return func(admitted []rbac.AdmittedLog) []json.RawMessage {
		return p.redactAdmittedLogs(ctx, viewerDID, admitted, abiProvider)
	}
}

// redactAdmittedLogs renders admitted logs with the payload policy decided for
// each at admission (rbac.DecideLogEmitter):
//
//   - rbac.LogPayloadFull (the RD-874 visibleTo unlock for this exact viewer,
//     emitting contract and transaction): returned byte-for-byte, matching the
//     explorer's full reveal (REDACTION_SPEC §3.7.1).
//   - rbac.LogPayloadMasked (every other admission, and the zero value): each
//     embedded address (indexed topics + ABI-decoded non-indexed data) the
//     viewer is NOT entitled to see is zeroed — the field-level half of the
//     RD-1214 unification, so eth_getLogs / eth_getTransactionReceipt return
//     the same visible-address set the explorer would for the same viewer.
//
// Masking resolves visibility via p.addrVisResolver (the same
// GetBatchVisibilityDetailed the explorer uses) and applies
// explorer.RedactLogAddressFields (the same zeroing primitive). Fail-closed: a
// resolver error leaves visMap empty, so every embedded address resolves to a
// non-Full level and is zeroed; a masked log that cannot be parsed or
// re-encoded is dropped, never emitted raw. A nil resolver (not wired) is a
// no-op — unit tests that don't exercise field redaction.
//
// Only "topics" and "data" are rewritten; all other log fields are preserved.
// abiProvider drives the non-indexed data scan (callers pass
// p.contractABIProvider(ctx)).
func (p *JSONRPCProcessor) redactAdmittedLogs(ctx context.Context, viewerDID string, admitted []rbac.AdmittedLog, abiProvider rbac.ABIProvider) []json.RawMessage {
	if len(admitted) == 0 {
		return []json.RawMessage{}
	}
	if p.addrVisResolver == nil {
		return rawAdmittedLogs(admitted)
	}

	type parsedLog struct {
		fields map[string]json.RawMessage
		topics []*string
		data   string
		abi    json.RawMessage
		topic0 *string
		ok     bool
	}

	parsed := make([]parsedLog, len(admitted))
	addrSet := make(map[string]struct{})

	for i, a := range admitted {
		if a.Payload == rbac.LogPayloadFull {
			continue // rendered verbatim; its addresses need no resolution
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(a.Raw, &m); err != nil {
			continue // ok=false → dropped below (fail-closed)
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

		for _, addr := range explorer.ExtractLogAddresses(topics, data, abiRaw, topic0) {
			addrSet[addr] = struct{}{}
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

	out := make([]json.RawMessage, 0, len(admitted))
	for i, a := range admitted {
		if a.Payload == rbac.LogPayloadFull {
			out = append(out, a.Raw)
			continue
		}
		pl := parsed[i]
		if !pl.ok {
			continue
		}
		redTopics, redData := explorer.RedactLogAddressFields(pl.topics, pl.data, pl.abi, pl.topic0, visMap)

		topicStrs := make([]string, len(redTopics))
		for j, t := range redTopics {
			if t != nil {
				topicStrs[j] = *t
			}
		}
		tb, err := json.Marshal(topicStrs)
		if err != nil {
			continue
		}
		db, err := json.Marshal(redData)
		if err != nil {
			continue
		}
		pl.fields["topics"] = tb
		pl.fields["data"] = db
		rewritten, err := json.Marshal(pl.fields)
		if err != nil {
			continue
		}
		out = append(out, rewritten)
	}
	return out
}

// redactLogsArrayResponseFields applies embedded-address field-redaction to an
// eth_getLogs response (result is a JSON array of logs), masking every log.
// Used only by the admin dry-run, which evaluates no visibleTo and so has no
// unlocked log to preserve; the live path renders through logFieldRenderer. The response has
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
// logs array nested in an eth_getTransactionReceipt response (result.logs),
// masking every log (admin dry-run only; see redactLogsArrayResponseFields).
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
