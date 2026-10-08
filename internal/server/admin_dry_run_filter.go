package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/rbac"
)

// dryRunFilterUnavailable replaces an upstream read response when the
// production response filter is not wired. The upstream body is withheld
// rather than returned unfiltered (fail closed).
var dryRunFilterUnavailable = json.RawMessage(`{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"response filter unavailable"}}`)

// dryRunTraceReceiptHash returns a fresh random transaction hash for the
// receipt synthesized for a traced (never sent) write. It only lets the
// receipt pipeline treat the logs as one transaction; being random per request,
// it cannot name a real transaction, so no visibleTo share matches it.
func dryRunTraceReceiptHash() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(b[:]), nil
}

// filterDryRunReadResponse filters an upstream read response exactly as the
// impersonated user's own call would be filtered — the production
// applyResponseFilter, run as userDID with the CheckAccess result of the
// dry-run — with every authorization input pinned to the path org (RD-1308).
// Transaction admission, event rules, admin exemptions, visibleTo shares and
// embedded-address rendering all use the named organization's view.
func (s *Server) filterDryRunReadResponse(
	ctx context.Context,
	rpc apimodels.DryRunRPCBlock,
	userDID, orgID string,
	access *rbac.AccessCheckResult,
	body json.RawMessage,
) json.RawMessage {
	if s.jsonrpcProcessor == nil {
		slog.Error("dry-run: response filter not configured; withholding the upstream response", "method", rpc.Method)
		return dryRunFilterUnavailable
	}
	scoped := withViewerOrgScope(ctx, orgID)
	req := &ProcessRequest{UserID: userDID, OrgID: orgID, Method: rpc.Method, Params: rpc.Params}
	filtered := s.jsonrpcProcessor.applyResponseFilter(scoped, req, access, body)
	return json.RawMessage(s.jsonrpcProcessor.applyViewerOrgScopeEnvelope(scoped, rpc.Method, filtered))
}

// dryRunTraceLogsVisibleToUser returns the subset of a traced write's logs the
// impersonated user would see in that transaction's receipt. It builds the
// receipt the node would return (sender and target from the trace's top frame,
// the emitted logs) and runs it through the production receipt filter, pinned
// to the path org — the same admission (participation, event rules, admin
// exemption) and the same embedded-address field redaction as a real
// eth_getTransactionReceipt. A receipt the user may not read yields no logs.
func (s *Server) dryRunTraceLogsVisibleToUser(
	ctx context.Context,
	trace *dryRunTraceResult,
	userDID, orgID string,
	access *rbac.AccessCheckResult,
) []json.RawMessage {
	if trace == nil || len(trace.Logs) == 0 {
		return nil
	}
	if s.jsonrpcProcessor == nil {
		slog.Error("dry-run: response filter not configured; no trace logs reported as visible")
		return nil
	}

	var top struct {
		Type  string `json:"type"`
		From  string `json:"from"`
		To    string `json:"to"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(trace.Trace, &top)
	if top.Error != "" {
		// The tx would revert: its receipt carries no logs, whatever the
		// tracer reported for the failed frames.
		return nil
	}
	txHash, err := dryRunTraceReceiptHash()
	if err != nil {
		slog.Error("dry-run: could not build the trace receipt; no trace logs reported as visible", "err", err)
		return nil
	}
	quotedHash := json.RawMessage(`"` + txHash + `"`)

	logs := make([]map[string]json.RawMessage, 0, len(trace.Logs))
	for _, raw := range trace.Logs {
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entry); err != nil || entry == nil {
			continue // unparseable log: not visible (fail closed)
		}
		entry["transactionHash"] = quotedHash
		logs = append(logs, entry)
	}

	receipt := map[string]any{
		"transactionHash": txHash,
		"from":            top.From,
		"to":              top.To,
		"status":          "0x1",
		"logs":            logs,
	}
	if strings.HasPrefix(strings.ToUpper(top.Type), "CREATE") {
		// A deployment receipt has no recipient; the created address is
		// contractAddress (the RD-1183 admission treats the two differently).
		receipt["to"] = nil
		receipt["contractAddress"] = top.To
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": receipt})
	if err != nil {
		return nil
	}

	scoped := withViewerOrgScope(ctx, orgID)
	req := &ProcessRequest{UserID: userDID, OrgID: orgID, Method: rbac.MethodGetTransactionReceipt, Params: []any{txHash}}
	filtered := s.jsonrpcProcessor.applyResponseFilter(scoped, req, access, body)
	filtered = s.jsonrpcProcessor.applyViewerOrgScopeEnvelope(scoped, rbac.MethodGetTransactionReceipt, filtered)

	var env struct {
		Result *struct {
			Logs []map[string]json.RawMessage `json:"logs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(filtered, &env); err != nil || env.Result == nil {
		return nil
	}
	out := make([]json.RawMessage, 0, len(env.Result.Logs))
	for _, entry := range env.Result.Logs {
		delete(entry, "transactionHash") // the synthesized hash is not part of the trace
		b, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		out = append(out, b)
	}
	return out
}
