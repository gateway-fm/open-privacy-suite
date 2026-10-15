package server

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/rbac"
)

// Keep the existing diagnostics UI on the same node evaluator as ordinary RPC.
// No legacy CheckAccess/trace-validator execution verdict is consulted here.
func (s *Server) handleNodeDryRun(c *gin.Context, req apimodels.DryRunRequest, user *rbac.User) {
	method, params := req.RPC.Method, req.RPC.Params
	trace := method == "eth_sendTransaction" || method == "eth_sendRawTransaction" || method == "debug_traceCall"
	if method == "eth_sendRawTransaction" {
		raw, err := extractRawTxHex(params)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid raw transaction"})
			return
		}
		from, to, data, value, _, err := decodeRawTransaction(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid raw transaction"})
			return
		}
		params = buildTxParams(from, to, data, value)
	}
	if method == "eth_sendTransaction" || method == "eth_sendRawTransaction" {
		if len(params) != 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid simulation call"})
			return
		}
		method = "debug_traceCall"
		params = append(params, "latest", map[string]any{"tracer": "callTracer", "tracerConfig": map[string]any{"withLog": true}})
	}
	result, ok := s.executeNodePreview(c, apimodels.NodeSimulationRequest{PrincipalID: user.ID, Method: method, Params: params, DryRun: true})
	if !ok {
		return
	}
	var out struct {
		Result json.RawMessage `json:"result"`
		Policy json.RawMessage `json:"policy"`
	}
	var verdict struct {
		WouldAllow *bool `json:"would_allow"`
	}
	if json.Unmarshal(result, &out) != nil || json.Unmarshal(out.Policy, &verdict) != nil || verdict.WouldAllow == nil || len(out.Result) == 0 {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid node diagnostics response"})
		return
	}
	response := dryRunResponse{Decision: "deny", Policy: out.Policy}
	if *verdict.WouldAllow {
		response.Decision = "allow"
	}
	if s.readProfile().Strict() {
		// Match the ordinary dry-run endpoint: only the verdict may leave
		// a privileged diagnostic under the strict read profile.
		response.Policy = nil
	} else if trace {
		response.Trace = out.Result
		response.LogsEmitted = extractLogsFromCallTrace(out.Result)
		var err error
		response.LogsVisibleToUser, err = s.dryRunTraceLogsVisibleToUser(c.Request.Context(), &dryRunTraceResult{Trace: out.Result, Logs: response.LogsEmitted}, user.ExternalID, c.Param("org_id"), &rbac.AccessCheckResult{Allowed: true, UserID: user.ID, OrgID: c.Param("org_id")})
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "visibility rules unavailable"})
			return
		}
	} else {
		response.Response, _ = json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": out.Result})
	}
	if err := s.recordImpersonation(c.Request.Context(), c.GetString("admin_subject"), user.ExternalID, c.Param("org_id"), req.RPC, response.Decision, "", c.GetString("correlation_id")); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "diagnostic audit unavailable"})
		return
	}
	c.JSON(http.StatusOK, response)
}
