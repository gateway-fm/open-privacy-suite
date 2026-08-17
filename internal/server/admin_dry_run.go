package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RD-872 — admin dry-run / impersonation endpoint.
//
// Both write-method shapes (eth_sendTransaction with a tx object;
// eth_sendRawTransaction with a signed RLP blob) are translated to
// debug_traceCall. eth_sendRawTransaction reuses the production
// `decodeRawTransaction` helper so dry-run sees the same (from, to,
// data, value) the real-call path would.
//
//
// Lets a tier-2 org admin in :org_id ask "what would user X see if they
// made this RPC call?" without ever creating a user-shaped JWT,
// mutating chain state, or exposing data that the admin doesn't already
// have. Read methods pass through and get filtered as user X; write
// methods (eth_sendTransaction / eth_sendRawTransaction) are translated
// to debug_traceCall so the admin can see RBAC's verdict + the events
// the tx WOULD emit + the subset visible to user X.
//
// Why this is safe for tier-2: by the rbac resolver,
// computeOrgAdminPermissions synthesises full claims on every contract
// in the admin's org, so any data exposed via the impersonation
// pipeline is already in the admin's reach via direct calls. Net new
// data: zero. The endpoint is therefore an *ergonomics* tool wrapped
// in audit logging, not a privacy expansion.
//
// Super-admin (X-Admin-Token) is explicitly rejected — they have no
// data-layer reach into RPC/explorer responses today, and impersonation
// would be the path that gives it to them. They flip feature flags;
// they don't browse user data. Tier-3 admins (per-contract admin only,
// no `is_org_admin`) and the upcoming Read-Only Admin (RD-866) are
// likewise out of scope.
//
// Multi-org user data is structurally invisible: the synthetic
// principal is built via GetEffectivePermissionsByIDs(userID, :org_id),
// so a user who is also in Org B has Org B's grants resolved to nothing
// in this context. Cross-org existence is hidden behind a generic 404.

// dryRunRequest is the JSON body of POST /api/orgs/:org_id/dry-run.
type dryRunRequest struct {
	UserDID string         `json:"user_did" binding:"required"`
	RPC     dryRunRPCBlock `json:"rpc" binding:"required"`
}

// dryRunRPCBlock carries the JSON-RPC method + params that the admin
// is asking the proxy to evaluate as the impersonated user.
type dryRunRPCBlock struct {
	Method string `json:"method" binding:"required"`
	Params []any  `json:"params"`
}

// dryRunResponse is the handler's reply.
type dryRunResponse struct {
	Decision string `json:"decision"` // "allow" | "deny"
	Reason   string `json:"reason,omitempty"`
	// For read methods: the redacted-as-user response.
	Response json.RawMessage `json:"response,omitempty"`
	// For write methods: debug_traceCall output + per-user log filtering.
	Trace             json.RawMessage   `json:"trace,omitempty"`
	LogsEmitted       []json.RawMessage `json:"logs_emitted,omitempty"`
	LogsVisibleToUser []json.RawMessage `json:"logs_visible_to_user,omitempty"`
}

// dryRunResponseDoc is the OpenAPI mirror of dryRunResponse (RD-1166):
// swag cannot schema json.RawMessage, so the spec documents those
// pass-through fields as free-form JSON values. Wire shape is identical.
// Spec-only; never constructed at runtime.
type dryRunResponseDoc struct {
	Decision          string `json:"decision" example:"allow"`
	Reason            string `json:"reason,omitempty"`
	Response          any    `json:"response,omitempty"`
	Trace             any    `json:"trace,omitempty"`
	LogsEmitted       []any  `json:"logs_emitted,omitempty"`
	LogsVisibleToUser []any  `json:"logs_visible_to_user,omitempty"`
}

// supported method allowlist for Phase 1. Read methods pass through
// unchanged; write methods are translated to debug_traceCall. Anything
// outside this set returns 400 — clearer than silently no-op'ing,
// expandable as use cases come up.
var dryRunReadMethods = map[string]bool{
	"eth_call":                  true,
	"eth_getLogs":               true,
	"eth_getTransactionReceipt": true,
	"eth_getTransactionByHash":  true,
	"eth_getBalance":            true,
	"eth_getCode":               true,
	"eth_getStorageAt":          true,
	"eth_blockNumber":           true,
	"eth_chainId":               true,
}
var dryRunTraceMethods = map[string]bool{
	"eth_sendTransaction":    true,
	"eth_sendRawTransaction": true,
}

// handleDryRun handles POST /api/orgs/:org_id/dry-run.
//
// @Summary      Dry-run an RPC call as a user
// @Description  Evaluates "what would this user see if they made this RPC call?" in the path org, without mutating chain state. Read methods are forwarded and redacted as the impersonated user; write methods (eth_sendTransaction / eth_sendRawTransaction) are translated to debug_traceCall so the RBAC verdict and the events the tx would emit (and the subset visible to the user) can be inspected. Requires a tier-2 org-admin JWT of the path org: X-Admin-Token credentials (both the full super-admin token and the operator token) are explicitly rejected, since impersonation reads tenant data as the user. The impersonated user must exist and be a member of the path org, else an opaque 404 (no cross-org existence leak). Every evaluation is written to the impersonation audit log fail-closed. Supported methods: eth_call, eth_getLogs, eth_getTransactionReceipt, eth_getTransactionByHash, eth_getBalance, eth_getCode, eth_getStorageAt, eth_blockNumber, eth_chainId, eth_sendTransaction, eth_sendRawTransaction.
// @Tags         Admin: RBAC
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID (UUID)"
// @Param        request body dryRunRequest true "impersonation request (user_did and rpc.method/params)"
// @Success      200 {object} dryRunResponseDoc
// @Failure      400 {object} APIError "invalid body, unsupported method, self-dry-run, or missing user_did/rpc.method"
// @Failure      401 {object} APIError "missing admin authentication (no admin_subject)"
// @Failure      403 {object} APIError "source address not on the private network, or X-Admin-Token/operator credentials used (dry-run requires a tier-2 admin JWT)"
// @Failure      404 {object} APIError "impersonated user not found or not a member of the path org (opaque)"
// @Failure      500 {object} APIError "internal error (includes audit-log write failure — response withheld)"
// @Failure      502 {object} APIError "upstream node error or trace failure"
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/dry-run [post]
func (s *Server) handleDryRun(c *gin.Context) {
	ctx := c.Request.Context()
	orgID := c.Param("org_id")

	// Reject the token credentials explicitly. orgScopingMiddleware lets both
	// admin_token (full) and operator_token through any :org_id — we have to
	// gate here because dry-run is the one admin-API endpoint where that
	// "bypass org scoping" rule must NOT apply: impersonating a user is reading
	// tenant data as that user, which neither token may do.
	if am := c.GetString("auth_method"); am == "admin_token" || am == "operator_token" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "dry-run requires a tier-2 admin JWT; X-Admin-Token credentials are not authorised for impersonation",
		})
		return
	}

	// Admin must be JWT-authenticated tier-2 of :org_id. The middleware
	// chain (adminAuth + orgScoping) already enforces this; the
	// admin_subject context value is the admin's DID.
	adminDID := c.GetString("admin_subject")
	if adminDID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin authentication required"})
		return
	}

	// L8: cap body size so a misbehaving admin (or one whose JWT is
	// compromised) can't memory-pressure the proxy with a huge dry-run
	// payload. Mirror the JSON-RPC handler's 1MB cap.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxRequestBodySize)

	// Parse body.
	var req dryRunRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	req.UserDID = strings.TrimSpace(req.UserDID)
	if req.UserDID == "" || req.RPC.Method == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_did and rpc.method are required"})
		return
	}
	if req.UserDID == adminDID {
		// Self-dry-run is meaningless and would skew audit reasoning.
		// Reject explicitly.
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot dry-run as yourself"})
		return
	}

	// Verify method is in scope. Phase 1 supports a subset; outside
	// this set we return 400 so the admin gets a clear answer rather
	// than a silent denial.
	isRead := dryRunReadMethods[req.RPC.Method]
	isTrace := dryRunTraceMethods[req.RPC.Method]
	if !isRead && !isTrace {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "method not supported by dry-run; supported: eth_call, eth_getLogs, eth_getTransactionReceipt, eth_getTransactionByHash, eth_getBalance, eth_getCode, eth_getStorageAt, eth_blockNumber, eth_chainId, eth_sendTransaction, eth_sendRawTransaction",
		})
		return
	}

	// Resolve impersonated user — must exist AND have a membership in
	// admin's :org_id. Anything else returns a generic 404 so we never
	// leak cross-org existence to a tier-2 admin.
	user, err := s.db.GetUserByExternalID(ctx, req.UserDID)
	if err != nil || user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Membership gate: GetUserOrgIDs returns every org the user has at
	// least one group membership in. If admin's :org_id isn't there,
	// the user is invisible to this admin regardless of any other
	// org's data they might have. Same generic 404 either way.
	userOrgIDs, err := s.rbacAccessCtrl.GetUserOrgIDs(ctx, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	inAdminOrg := false
	for _, id := range userOrgIDs {
		if id == orgID {
			inAdminOrg = true
			break
		}
	}
	if !inAdminOrg {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	userPerms, err := s.rbacAccessCtrl.GetEffectivePermissionsByIDs(ctx, user.ID, orgID)
	if err != nil || userPerms == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Run RBAC CheckAccess as the impersonated user.
	//
	// C8: pass OrgID = admin's :org_id. Pre-fix the request had no
	// OrgID, so CheckAccess built OrgContext from the user's
	// memberships and picked whichever org owned the target contract.
	// For a multi-org user, that meant the FOREIGN org's grants
	// decided the answer — a tier-2 admin in Org A dry-running a Bob
	// who is also in Org B got Bob's Org B view on Org B-owned
	// contracts. With OrgID set, CheckAccess scopes resolution to
	// admin's org; cross-org contracts evaluate as if Bob were a
	// non-member there (the safe answer).
	accessReq, err := dryRunAccessRequest(req.UserDID, orgID, req.RPC)
	if err != nil {
		slog.Warn("dry-run: could not build access check", "method", req.RPC.Method, "err", err)
		if logErr := s.recordImpersonation(ctx, adminDID, req.UserDID, orgID, req.RPC, "error", "decode_error", c.GetString("correlation_id")); logErr != nil {
			slog.Error("dry-run: audit log write failed; refusing response", "err", logErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid raw transaction"})
		return
	}
	accessResult, err := s.rbacAccessCtrl.CheckAccess(ctx, accessReq)
	if err != nil {
		// H12: audit log fail-closed. If recordImpersonation errors,
		// refuse to return the response — a compromised admin who can
		// intermittently break the log write must not be able to
		// exfiltrate data with no audit trail.
		if logErr := s.recordImpersonation(ctx, adminDID, req.UserDID, orgID, req.RPC, "error", sanitizeDryRunReason(err), c.GetString("correlation_id")); logErr != nil {
			slog.Error("dry-run: audit log write failed; refusing response", "err", logErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	if !accessResult.Allowed {
		if logErr := s.recordImpersonation(ctx, adminDID, req.UserDID, orgID, req.RPC, "deny", sanitizeDryRunReason(accessResult.Reason), c.GetString("correlation_id")); logErr != nil {
			slog.Error("dry-run: audit log write failed; refusing response", "err", logErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		c.JSON(http.StatusOK, dryRunResponse{
			Decision: "deny",
			Reason:   accessResult.Reason,
		})
		return
	}

	// Allowed — execute or trace. Both branches log on success.
	if isTrace {
		traceResp, traceErr := s.forwardDryRunTrace(ctx, req.RPC)
		if traceErr != nil {
			if logErr := s.recordImpersonation(ctx, adminDID, req.UserDID, orgID, req.RPC, "error", sanitizeDryRunReason(traceErr), c.GetString("correlation_id")); logErr != nil {
				slog.Error("dry-run: audit log write failed; refusing response", "err", logErr)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
				return
			}
			c.JSON(http.StatusBadGateway, gin.H{"error": "upstream trace error"})
			return
		}
		if logErr := s.recordImpersonation(ctx, adminDID, req.UserDID, orgID, req.RPC, "allow", "", c.GetString("correlation_id")); logErr != nil {
			slog.Error("dry-run: audit log write failed; refusing response", "err", logErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		c.JSON(http.StatusOK, dryRunResponse{
			Decision:          "allow",
			Trace:             traceResp.Trace,
			LogsEmitted:       traceResp.Logs,
			LogsVisibleToUser: s.filterDryRunLogs(ctx, traceResp.Logs, userPerms, user, req.UserDID, orgID),
		})
		return
	}

	// Read method: forward through the proxy. H13: with the C8 scope
	// fix in place, the response is already restricted to admin's org
	// for CheckAccess purposes — but eth_getLogs and
	// eth_getTransactionReceipt would still pass through raw upstream
	// data without the production event-rule + param-rule + no-ABI
	// filters. Wire those filters here so the dry-run answer matches
	// what the impersonated user would actually see.
	rawResp, err := s.forwardDryRunRead(ctx, req.RPC, c.ClientIP())
	if err != nil {
		if logErr := s.recordImpersonation(ctx, adminDID, req.UserDID, orgID, req.RPC, "error", sanitizeDryRunReason(err), c.GetString("correlation_id")); logErr != nil {
			slog.Error("dry-run: audit log write failed; refusing response", "err", logErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		c.JSON(http.StatusBadGateway, gin.H{"error": "upstream error"})
		return
	}

	// Apply production redaction for the two read methods that carry
	// log data — pre-fix these were returned verbatim, so admins got a
	// strictly-broader view than the impersonated user would see in
	// production. Other read methods (eth_chainId, eth_blockNumber,
	// eth_getBalance, eth_call, eth_getCode, eth_getStorageAt) are
	// gated by CheckAccess and their response shape doesn't carry
	// per-log redaction concerns.
	if rawResp != nil {
		var addrs []string
		if user != nil && s.db != nil {
			if links, lerr := s.db.GetEthAddressesByDID(ctx, user.ExternalID); lerr == nil {
				addrs = make([]string, 0, len(links))
				for _, l := range links {
					addrs = append(addrs, strings.ToLower(l.EthAddress))
				}
			}
		}
		var abiProv rbac.ABIProvider
		if s.db != nil {
			abiProv = newStoreABIProvider(ctx, s.db)
		}
		// Field-redact embedded addresses too (RD-1214), using the impersonated
		// user's DID, so the dry-run reflects the user's REAL view — entry
		// filtering alone would still return embedded third-party addresses in
		// the clear, over-showing vs production. No-op if the processor/resolver
		// isn't wired or the user has no DID.
		viewerDID := ""
		if user != nil {
			viewerDID = user.ExternalID
		}
		switch req.RPC.Method {
		case "eth_getLogs":
			rawResp = FilterLogsWithEventRules([]byte(rawResp), addrs, userPerms, abiProv, nil, nil)
			if s.jsonrpcProcessor != nil && viewerDID != "" {
				rawResp = s.jsonrpcProcessor.redactLogsArrayResponseFields(ctx, viewerDID, []byte(rawResp))
			}
		case "eth_getTransactionReceipt":
			rawResp = FilterReceiptLogsWithEventRules([]byte(rawResp), addrs, userPerms, abiProv, nil, nil)
			if s.jsonrpcProcessor != nil && viewerDID != "" {
				rawResp = s.jsonrpcProcessor.redactReceiptResponseFields(ctx, viewerDID, []byte(rawResp))
			}
		}
	}

	if logErr := s.recordImpersonation(ctx, adminDID, req.UserDID, orgID, req.RPC, "allow", "", c.GetString("correlation_id")); logErr != nil {
		slog.Error("dry-run: audit log write failed; refusing response", "err", logErr)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, dryRunResponse{
		Decision: "allow",
		Response: rawResp,
	})
}

// sanitizeDryRunReason maps an error or reason string into a finite
// enum-shaped value safe to persist in impersonation_log.reason.
// Migration 047 explicitly forbids raw DB errors or embedded private
// addresses in this column (audit M4 / threat-model F1). The full
// error is preserved in slog.
func sanitizeDryRunReason(in any) string {
	const max = 200
	var s string
	switch v := in.(type) {
	case string:
		s = v
	case error:
		s = v.Error()
	default:
		s = fmt.Sprintf("%v", v)
	}
	lower := strings.ToLower(s)
	switch {
	case strings.Contains(lower, "method not allowed") ||
		strings.Contains(lower, "method not permitted"):
		return "method_not_allowed"
	case strings.Contains(lower, "no access") ||
		strings.Contains(lower, "no claim") ||
		strings.Contains(lower, "denied") ||
		strings.Contains(lower, "forbidden"):
		return "denied"
	case strings.Contains(lower, "rate limit"):
		return "rate_limited"
	case strings.Contains(lower, "compliance"):
		return "compliance"
	case strings.Contains(lower, "upstream") ||
		strings.Contains(lower, "debug_tracecall") ||
		strings.Contains(lower, "trace"):
		return "upstream_error"
	case strings.Contains(lower, "decode") || strings.Contains(lower, "malformed"):
		return "decode_error"
	case strings.Contains(lower, "user is banned"):
		return "user_banned"
	default:
		// Truncate as a final defense — never persist >200 chars of
		// free text.
		if len(s) > max {
			return s[:max]
		}
		return s
	}
}

// dryRunTraceResult is what forwardDryRunTrace returns to the handler.
type dryRunTraceResult struct {
	Trace json.RawMessage   // the raw debug_traceCall response (callTracer + withLog)
	Logs  []json.RawMessage // logs extracted from the trace frames
}

// forwardDryRunTrace translates a write-method call (eth_sendTransaction
// / eth_sendRawTransaction) into a debug_traceCall against the upstream
// node and returns the trace + extracted logs. No state mutation —
// debug_traceCall executes against current state and discards.
//
// eth_sendRawTransaction is RLP-decoded via the production helper
// (decodeRawTransaction in jsonrpc_processor.go) — same path the real
// raw-tx handler uses, so dry-run reaches the trace with the same
// (from, to, data, value) the production processor would. Sender
// recovery uses the chain-id-aware signer; signature must be valid
// (admins running dry-run on a malformed signed blob get a clear
// decode error, not a silent pass).
func (s *Server) forwardDryRunTrace(ctx context.Context, rpc dryRunRPCBlock) (*dryRunTraceResult, error) {
	if s.proxy == nil {
		return nil, fmt.Errorf("proxy not configured")
	}

	// Build the tx object passed to debug_traceCall. For
	// eth_sendTransaction the admin already supplied it; for
	// eth_sendRawTransaction we RLP-decode + recover sender, then
	// shape the same { from, to, data, value } object.
	var txObj map[string]any
	switch rpc.Method {
	case "eth_sendTransaction":
		if len(rpc.Params) == 0 {
			return nil, fmt.Errorf("eth_sendTransaction requires a tx object")
		}
		obj, ok := rpc.Params[0].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("eth_sendTransaction param[0] must be a tx object")
		}
		txObj = obj
	case "eth_sendRawTransaction":
		rawHex, err := extractRawTxHex(rpc.Params)
		if err != nil {
			return nil, fmt.Errorf("invalid raw transaction: %w", err)
		}
		from, to, data, value, _, err := decodeRawTransaction(rawHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode raw transaction: %w", err)
		}
		built := buildTxParams(from, to, data, value)
		if len(built) == 0 {
			return nil, fmt.Errorf("internal: buildTxParams returned empty")
		}
		obj, ok := built[0].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("internal: buildTxParams returned wrong type")
		}
		txObj = obj
	default:
		return nil, fmt.Errorf("unsupported trace method: %s", rpc.Method)
	}

	// Build the debug_traceCall request. callTracer + withLog gives us
	// nested call frames + the logs each frame would emit, which is
	// exactly what dry-run needs — RBAC gating + audit are already done
	// upstream of this call.
	traceReq := map[string]any{
		"jsonrpc": "2.0",
		"method":  "debug_traceCall",
		"params": []any{
			txObj,
			"latest",
			map[string]any{
				"tracer": "callTracer",
				"tracerConfig": map[string]any{
					"onlyTopCall": false,
					"withLog":     true,
				},
			},
		},
		"id": 1,
	}
	body, err := json.Marshal(traceReq)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	respBody, _, err := s.proxy.Forward(body)
	if err != nil {
		return nil, err
	}

	// Surface upstream errors clearly — most commonly "method
	// debug_traceCall is not available", which means the operator's
	// node doesn't expose the debug namespace.
	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("upstream returned malformed response")
	}
	if rpcResp.Error != nil {
		// Common case: debug_* not enabled on the node. Sanitise the
		// message so we don't echo arbitrary upstream output back to
		// the admin UI without inspection.
		if strings.Contains(strings.ToLower(rpcResp.Error.Message), "method") &&
			strings.Contains(strings.ToLower(rpcResp.Error.Message), "not") {
			return nil, fmt.Errorf("node does not support debug_traceCall — dry-run for write methods unavailable")
		}
		return nil, fmt.Errorf("trace failed: %s", rpcResp.Error.Message)
	}
	_ = ctx
	return &dryRunTraceResult{
		Trace: rpcResp.Result,
		Logs:  extractLogsFromCallTrace(rpcResp.Result),
	}, nil
}

// extractLogsFromCallTrace walks a callTracer-with-withLog response
// and pulls every `logs` array from every frame (top + nested). Each
// log entry comes back as raw JSON so downstream filters (the user-
// scoped FilterEventLogs) can consume it directly.
func extractLogsFromCallTrace(raw json.RawMessage) []json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var frame struct {
		Logs  []json.RawMessage `json:"logs"`
		Calls []json.RawMessage `json:"calls"`
	}
	if err := json.Unmarshal(raw, &frame); err != nil {
		return nil
	}
	out := make([]json.RawMessage, 0, len(frame.Logs))
	out = append(out, frame.Logs...)
	for _, sub := range frame.Calls {
		out = append(out, extractLogsFromCallTrace(sub)...)
	}
	return out
}

// filterDryRunLogs is the legacy package-level wrapper used by tests
// to assert the deny / allow shape of FilterEventLogs without needing
// a Server. New production code paths call the method on Server (see
// (*Server).filterDryRunLogs) which additionally wires an ABI
// provider. The wrapper passes nil for those, matching pre-M3 test
// expectations.
func filterDryRunLogs(logs []json.RawMessage, perms *rbac.EffectivePermissions, user *rbac.User, viewerDID string) []json.RawMessage {
	if len(logs) == 0 || perms == nil {
		return nil
	}
	_ = user
	_ = viewerDID
	return rbac.FilterEventLogs(logs, perms, []string{}, nil, nil, nil)
}

// filterDryRunLogs runs the impersonated user's RBAC view over the
// emitted logs, returning the subset they would actually see if they
// fetched the receipt. Reuses rbac.FilterEventLogs so the dry-run
// answer matches what a real eth_getTransactionReceipt would give the
// user.
//
// M3 / RD-930: pre-fix this called FilterEventLogs with `addrs` empty
// and the abiProvider / visCtx / adminContracts arguments as nil. That
// bypassed three production gates:
//   - param-rule `must_be=self` constraints always failed (no addrs)
//   - the RD-875/889 no-ABI deny gate didn't fire (abiProvider nil)
//   - per-contract admin bypass didn't apply (adminContracts nil)
//
// Now: resolve the impersonated user's linked ETH addresses and wire
// the production ABI provider. visibleTo unlock + admin bypass are
// still nil because they require per-tx visibility context which the
// dry-run synthetic principal doesn't have; we leave them at the
// safe (under-redact) defaults. This is an over-approximation in the
// other direction from what RD-930 pinned, but the audit answer is
// strictly more accurate.
func (s *Server) filterDryRunLogs(ctx context.Context, logs []json.RawMessage, perms *rbac.EffectivePermissions, user *rbac.User, viewerDID, orgID string) []json.RawMessage {
	if len(logs) == 0 || perms == nil {
		return nil
	}

	// Resolve the impersonated user's linked ETH addresses for
	// param-rule self-matching. Best-effort: if the lookup errors we
	// still pass an empty list and FilterEventLogs evaluates correctly,
	// just stricter (param-rule self always fails).
	var addrs []string
	if user != nil && s.db != nil {
		links, err := s.db.GetEthAddressesByDID(ctx, user.ExternalID)
		if err == nil {
			addrs = make([]string, 0, len(links))
			for _, l := range links {
				addrs = append(addrs, strings.ToLower(l.EthAddress))
			}
		} else {
			slog.Warn("dry-run: link resolution failed", "user_id", user.ID, "err", err)
		}
	}

	// abiProvider: wire the production store-backed provider so the
	// RD-875/889 no-ABI deny gate fires correctly. Without it,
	// FilterEventLogs treated every log as having no ABI to consult and
	// silently let through events from contracts that production would
	// have denied.
	var abiProv rbac.ABIProvider
	if s.db != nil {
		abiProv = newStoreABIProvider(ctx, s.db)
	}

	_ = viewerDID
	_ = orgID
	return rbac.FilterEventLogs(logs, perms, addrs, abiProv, nil, nil)
}

// forwardDryRunRead forwards a read-only RPC call to the upstream node
// and returns the raw response body for embedding in the dry-run
// reply. No redaction here — see the caller's comment for why.
func (s *Server) forwardDryRunRead(ctx context.Context, rpc dryRunRPCBlock, clientIP string) (json.RawMessage, error) {
	if s.proxy == nil {
		return nil, fmt.Errorf("proxy not configured")
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  rpc.Method,
		"params":  rpc.Params,
		"id":      1,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	respBody, _, err := s.proxy.Forward(body)
	if err != nil {
		return nil, err
	}
	_ = clientIP // forwarded for parity with regular path; unused in this minimal helper
	_ = ctx
	return json.RawMessage(respBody), nil
}

// recordImpersonation writes one row to the impersonation_log table.
// `reason` is operator-safe text — the caller is responsible for not
// passing raw DB errors or embedded private addresses.
func (s *Server) recordImpersonation(
	ctx context.Context,
	actorDID, impersonatedDID, orgID string,
	rpc dryRunRPCBlock,
	decision, reason, correlationID string,
) error {
	if s.db == nil {
		return nil
	}
	conn := s.db.Conn()
	if conn == nil {
		return nil
	}
	paramsHash := dryRunParamsHash(rpc.Method, rpc.Params)
	corr := uuid.NullUUID{}
	if id, err := uuid.Parse(correlationID); err == nil {
		corr.UUID = id
		corr.Valid = true
	}
	_, err := conn.ExecContext(ctx, `
		INSERT INTO impersonation_log (actor_did, impersonated_did, org_id, method, params_hash, decision, reason, correlation_id)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8)`,
		actorDID, impersonatedDID, orgID, rpc.Method, paramsHash, decision, reason, corr,
	)
	return err
}

// dryRunParamsHash returns a stable hex-encoded SHA-256 of (method,
// params). We never persist the raw params — they could carry private
// addresses or signed-tx blobs.
//
// L7: if json.Marshal errors (unreachable through current gin binding
// but a future refactor could trigger it), return an empty string so
// every error case doesn't collapse to the constant SHA-256 of "".
func dryRunParamsHash(method string, params []any) string {
	payload, err := json.Marshal(struct {
		Method string `json:"m"`
		Params []any  `json:"p"`
	}{Method: method, Params: params})
	if err != nil {
		slog.Warn("dryRunParamsHash: marshal failed", "method", method, "err", err)
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// dryRunAccessRequest builds the access check for an impersonated call with
// the same helpers JSONRPCProcessor.Process uses on a real request, so the
// dry-run verdict matches enforcement. Without FunctionSelector, CheckAccess
// denies every contract whose grant has function-level rules with "function
// selector required", so a call the user may make and one blocked by a param
// rule both came back as the same uninformative deny.
//
// eth_sendRawTransaction keeps its target and calldata inside the signed
// blob, so it is decoded and checked as eth_sendTransaction exactly as
// processRawTransaction does. Derived from the undecoded params it has no
// target at all, which skips the contract gates entirely and waves every
// raw tx through to the tracer whatever it points at.
func dryRunAccessRequest(userDID, orgID string, rpc dryRunRPCBlock) (*rbac.AccessCheckRequest, error) {
	method, params := rpc.Method, rpc.Params
	if rbac.ResolveMethodAlias(method) == "eth_sendRawTransaction" {
		rawHex, err := extractRawTxHex(params)
		if err != nil {
			return nil, err
		}
		from, to, data, value, _, err := decodeRawTransaction(rawHex)
		if err != nil {
			return nil, err
		}
		method, params = "eth_sendTransaction", buildTxParams(from, to, data, value)
	}

	accessMethod := rbac.ResolveMethodAlias(method)
	var requiredClaims []rbac.Claim
	if claim := rbac.ClassifyOperation(accessMethod, params); claim != "" {
		requiredClaims = []rbac.Claim{claim}
	}
	return &rbac.AccessCheckRequest{
		UserExternalID:   userDID,
		OrgID:            orgID,
		Method:           method,
		AccessMethod:     accessMethod,
		Params:           params,
		TargetAddress:    rbac.GetTargetAddress(accessMethod, params),
		FunctionSelector: rbac.GetFunctionSelector(accessMethod, params),
		RequiredClaims:   requiredClaims,
	}, nil
}
