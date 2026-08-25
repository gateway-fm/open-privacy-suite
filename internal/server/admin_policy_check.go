package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/tracer"

	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// policyCheckSubject identifies who the operation is checked for. Exactly one
// of DID or Address (e.g. recovered from a signature) must be set.
// The generated OpenAPI represents the alternatives as mutually exclusive
// oneOf schemas (see cmd/api-spec-postprocess), since swag cannot derive that
// from the optional fields.
type policyCheckSubject struct {
	DID     string `json:"did,omitempty"`
	Address string `json:"address,omitempty"`
}

// policyCheckSubjectDID and policyCheckSubjectAddress are the two mutually
// exclusive subject shapes for the generated OpenAPI oneOf (spec-only mirrors;
// the runtime model above is the single decoded form).
type policyCheckSubjectDID struct {
	DID string `json:"did"`
}
type policyCheckSubjectAddress struct {
	Address string `json:"address"`
}

// policyCheckRequest is the JSON body of POST /api/v1/admin/policy-check.
type policyCheckRequest struct {
	Subject   policyCheckSubject  `json:"subject" binding:"required"`
	Operation policyCheckRPCBlock `json:"operation" binding:"required"`
	// OrgID is optional; omitted, CheckAccess resolves it as a live request would.
	OrgID string `json:"org_id,omitempty"`
}

// policyCheckRPCBlock is the policy-check operation model. Unlike the shared
// dry-run model it carries no visibleTo/privateFor: policy-check rejects
// top-level visibility metadata, so the generated OpenAPI must not advertise
// it as accepted.
type policyCheckRPCBlock struct {
	Method string `json:"method" binding:"required"`
	Params []any  `json:"params"`
}

// rpcBlock converts the policy-check operation to the shared evaluation model.
func (op policyCheckRPCBlock) rpcBlock() dryRunRPCBlock {
	return dryRunRPCBlock{Method: op.Method, Params: op.Params}
}

// policyCheckResponse is the handler's reply: verdict only, no tenant data.
type policyCheckResponse struct {
	Allowed bool `json:"allowed"`
	// Reason is set only on deny, sanitized to a coarse category (RD-934).
	Reason string `json:"reason,omitempty"`
}

// policyCheckKnownReasonCategories is the wire-facing allowlist of deny
// categories; anything else maps to "denied" (RD-877).
var policyCheckKnownReasonCategories = map[string]bool{
	"method_not_allowed":  true,
	"denied":              true,
	"rate_limited":        true,
	"compliance":          true,
	"upstream_error":      true,
	"decode_error":        true,
	"user_banned":         true,
	"sender_not_linked":   true,
	"concurrency_limited": true,
}

const policyCheckLimiterKey = "admin_policy_check"

const policyCheckTraceTimeout = 5 * time.Second

const (
	policyCheckTraceRPSLimit   = 100
	policyCheckTraceDailyLimit = 10000
)

// sanitizePolicyCheckReason is the client-facing sanitizer: one of
// policyCheckKnownReasonCategories, else "denied".
func sanitizePolicyCheckReason(reason any) string {
	mapped := sanitizeDryRunReason(reason)
	if policyCheckKnownReasonCategories[mapped] {
		return mapped
	}
	return "denied"
}

// errPolicyCheckSubjectMalformed marks an invalid subject (neither or both of
// did/address); the handler answers 400.
var errPolicyCheckSubjectMalformed = errors.New("subject must have exactly one of did or address")

var errPolicyCheckSubjectAddressMalformed = errors.New("subject address must be a valid Ethereum address")

// resolvePolicyCheckSubject resolves the subject to the DID CheckAccess
// evaluates against, using eth_address_links so the caller cannot assert an
// identity. A multi-DID address refuses rather than picking a winner.
// Returns (did, "", nil) on success, ("", reason, nil) for a clean deny, or an
// error (400 for the sentinel, else 500).
func (s *Server) resolvePolicyCheckSubject(ctx context.Context, subj policyCheckSubject) (did string, denyReason string, err error) {
	hasDID := strings.TrimSpace(subj.DID) != ""
	hasAddr := strings.TrimSpace(subj.Address) != ""

	switch {
	case hasDID && hasAddr:
		return "", "", errPolicyCheckSubjectMalformed
	case !hasDID && !hasAddr:
		return "", "", errPolicyCheckSubjectMalformed
	case hasDID:
		return strings.TrimSpace(subj.DID), "", nil
	}

	// Normalize case so the collision count does not depend on the lookup's internals.
	addr := strings.ToLower(strings.TrimSpace(subj.Address))
	if !gethcommon.IsHexAddress(addr) {
		return "", "", errPolicyCheckSubjectAddressMalformed
	}
	dids, dbErr := s.db.GetDIDsByEthAddress(ctx, addr)
	if dbErr != nil {
		return "", "", dbErr
	}
	switch len(dids) {
	case 0:
		return "", "no identity is linked to this address", nil
	case 1:
		return dids[0], "", nil
	default:
		// Never echo which DIDs collided (RD-934). The audit row records
		// subject_address, which is enough to investigate via
		// GetAddressLinkCollisions.
		return "", "address is linked to multiple identities; refusing rather than choosing one", nil
	}
}

// handlePolicyCheck handles POST /api/v1/admin/policy-check.
//
// @Summary      Check whether a subject would be allowed to make an RPC call
// @Description  Privacy-policy verdict for a trusted infrastructure caller. Subject is a DID or Ethereum address. Operation is a JSON-RPC method and params. EVM execution methods use debug_traceCall with the same upstream credential as live calls. Write methods also run a side-effect-free compliance preview. The endpoint does not submit the call or consume a travel-rule record. A supplied sender must link to the subject. Trace checks are limited to 100 RPS and 10000 per day. debug_traceCall and debug_traceTransaction are not supported. Requires the full X-Admin-Token credential. The operator token and JWT admin credentials are not accepted. Every evaluation is audited and fails closed.
// @Tags         Admin: RBAC
// @Accept       json
// @Produce      json
// @Param        request body policyCheckRequest true "subject, operation, and optional org_id"
// @Success      200 {object} policyCheckResponse
// @Failure      400 {object} APIError "invalid body, missing operation.method, an invalid subject address, or subject has neither/both of did and address"
// @Failure      401 {object} APIError "missing or invalid X-Admin-Token"
// @Failure      403 {object} APIError "source address not on the private network, or the credential cannot read tenant policy"
// @Failure      500 {object} APIError "internal error (includes audit-log write failure, response withheld)"
// @Security     AdminToken
// @Router       /api/v1/admin/policy-check [post]
func (s *Server) handlePolicyCheck(c *gin.Context) {
	ctx := c.Request.Context()

	// Service credential only. Dev-mode and JWT admins are not authorized here.
	authMethod := c.GetString("auth_method")
	if authMethod != "admin_token" {
		if authMethod == "operator_token" {
			denyOperatorTenantRead(c)
			return
		}
		if authMethod == "jwt_admin" {
			respondForbidden(c, "policy-check requires the full X-Admin-Token service credential; JWT admin credentials are not authorised for this endpoint")
			return
		}
		respondUnauthorized(c, "admin authentication required")
		return
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxRequestBodySize)

	// DisallowUnknownFields rejects top-level visibility metadata
	// (visibleTo/privateFor) instead of silently dropping it: the operation
	// model does not carry those fields, and a misleading allow is worse than
	// a clean 400.
	var req policyCheckRequest
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		respondBadRequest(c, "invalid request body")
		return
	}
	// A single complete object is required: trailing JSON values would
	// otherwise be silently ignored and bypass the strict body validation.
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		respondBadRequest(c, "invalid request body")
		return
	}

	// Canonicalize like live /rpc ingress (RD-1180), else a mixed-case method
	// could get a different verdict here than in production.
	req.Operation.Method = rbac.CanonicalizeMethod(strings.TrimSpace(req.Operation.Method))
	if req.Operation.Method == "" {
		respondBadRequest(c, "operation.method is required")
		return
	}
	operation := req.Operation.rpcBlock()

	correlationID := getCorrelationID(c)
	did, denyReason, err := s.resolvePolicyCheckSubject(ctx, req.Subject)
	if err != nil {
		if errors.Is(err, errPolicyCheckSubjectMalformed) {
			respondBadRequest(c, "subject must have exactly one of did or address")
			return
		}
		if errors.Is(err, errPolicyCheckSubjectAddressMalformed) {
			respondBadRequest(c, "subject address must be a valid Ethereum address")
			return
		}
		// Infra failure: never return a verdict we cannot attribute to a policy decision.
		slog.Error("policy-check: subject resolution failed", "err", err)
		respondInternalError(c, "internal error")
		return
	}
	if denyReason != "" {
		if logErr := s.recordPolicyCheck(ctx, authMethod, "", req.Subject.Address, req.OrgID, operation, false, denyReason, correlationID); logErr != nil {
			slog.Error("policy-check: audit log write failed; refusing response", "err", logErr)
			respondInternalError(c, "internal error")
			return
		}
		c.JSON(http.StatusOK, policyCheckResponse{Allowed: false, Reason: sanitizePolicyCheckReason(denyReason)})
		return
	}
	if policyCheckUnsupportedTraceMethod(operation.Method) {
		if logErr := s.recordPolicyCheck(ctx, authMethod, did, req.Subject.Address, req.OrgID, operation, false, ReasonMethodNotAllowed, correlationID); logErr != nil {
			slog.Error("policy-check: audit log write failed; refusing response", "err", logErr)
			respondInternalError(c, "internal error")
			return
		}
		c.JSON(http.StatusOK, policyCheckResponse{Allowed: false, Reason: "method_not_allowed"})
		return
	}

	accessReq, err := dryRunAccessRequest(did, req.OrgID, operation)
	if err != nil {
		// A malformed raw transaction is a client error, not a denial; still audited.
		if logErr := s.recordPolicyCheck(ctx, authMethod, did, req.Subject.Address, req.OrgID, operation, false, "decode_error", correlationID); logErr != nil {
			slog.Error("policy-check: audit log write failed; refusing response", "err", logErr)
			respondInternalError(c, "internal error")
			return
		}
		respondBadRequest(c, "invalid operation")
		return
	}

	result, err := s.rbacAccessCtrl.CheckAccess(ctx, accessReq)
	if err != nil {
		// CheckAccess errors expose RBAC internals; they stay operator-only. The
		// audit write is best-effort here since this branch answers 500 either way.
		slog.Error("policy-check: CheckAccess errored", "subject_did", did, "method", operation.Method, "err", err)
		if logErr := s.recordPolicyCheck(ctx, authMethod, did, req.Subject.Address, req.OrgID, operation, false, "error", correlationID); logErr != nil {
			slog.Error("policy-check: audit log write also failed", "err", logErr)
		}
		respondInternalError(c, "internal error")
		return
	}

	allowed := result.Allowed
	auditReason, wireReason := "", ""
	if !allowed {
		auditReason = sanitizeDryRunReason(result.Reason)
		wireReason = sanitizePolicyCheckReason(result.Reason)
	} else {
		wireReason, auditReason, err = s.simulatePolicyCheck(ctx, did, operation, accessReq, result)
		if err != nil {
			// Caller-controlled operation shapes (malformed params) are a client
			// error; only infrastructure failures are 500.
			var clientErr *simulationClientError
			if errors.As(err, &clientErr) {
				respondBadRequest(c, "invalid operation")
				return
			}
			slog.Error("policy-check: simulation failed", "subject_did", did, "method", operation.Method, "err", err)
			if logErr := s.recordPolicyCheck(ctx, authMethod, did, req.Subject.Address, result.OrgID, operation, false, "error", correlationID); logErr != nil {
				slog.Error("policy-check: audit log write also failed", "err", logErr)
			}
			respondInternalError(c, "internal error")
			return
		}
		allowed = wireReason == ""
	}
	if logErr := s.recordPolicyCheck(ctx, authMethod, did, req.Subject.Address, result.OrgID, operation, allowed, auditReason, correlationID); logErr != nil {
		// H12: no verdict without an audit trail.
		slog.Error("policy-check: audit log write failed; refusing response", "err", logErr)
		respondInternalError(c, "internal error")
		return
	}
	c.JSON(http.StatusOK, policyCheckResponse{Allowed: allowed, Reason: wireReason})
}

// simulatePolicyCheck traces methods that can execute EVM code. It returns an
// empty reason when the trace passes.
func (s *Server) simulatePolicyCheck(
	ctx context.Context,
	subjectDID string,
	op dryRunRPCBlock,
	accessReq *rbac.AccessCheckRequest,
	accessResult *rbac.AccessCheckResult,
) (wireReason, auditReason string, err error) {
	effectiveMethod := rbac.ResolveMethodAlias(op.Method)
	switch effectiveMethod {
	case "eth_call", "eth_estimateGas", "eth_sendTransaction", "eth_sendRawTransaction":
	default:
		return "", "", nil
	}

	if s.db == nil || s.rbacAccessCtrl == nil || accessResult == nil || accessResult.OrgID == "" {
		return "", "", errors.New("resolved policy context is unavailable")
	}
	user, err := s.db.GetUserByExternalID(ctx, subjectDID)
	if err != nil || user == nil {
		return "", "", errors.New("resolved policy subject is unavailable")
	}
	if reason, senderErr := s.validatePolicyCheckSender(ctx, subjectDID, op); senderErr != nil {
		return "", "", senderErr
	} else if reason != "" {
		return sanitizePolicyCheckReason(reason), reason, nil
	}
	if reason, visibleToErr := validatePolicyCheckVisibleTo(op); visibleToErr != nil {
		return "", "", visibleToErr
	} else if reason != "" {
		return sanitizePolicyCheckReason(reason), reason, nil
	}
	perms, err := s.rbacAccessCtrl.GetEffectivePermissionsByIDs(ctx, user.ID, accessResult.OrgID)
	if err != nil || perms == nil {
		return "", "", errors.New("resolved policy permissions are unavailable")
	}
	var limiter *ConcurrencyLimiter
	if s.jsonrpcProcessor != nil {
		limiter = s.jsonrpcProcessor.concurrencyLimiter
	}
	if limiter != nil && !limiter.TryAcquire(policyCheckLimiterKey) {
		return ReasonConcurrencyLimited, ReasonConcurrencyLimited, nil
	}
	if limiter != nil {
		defer limiter.Release(policyCheckLimiterKey)
	}
	if s.jsonrpcProcessor != nil && s.jsonrpcProcessor.rateLimiter != nil {
		if allowed, _ := s.jsonrpcProcessor.rateLimiter.CheckAndIncrement(policyCheckLimiterKey, intPtr(policyCheckTraceRPSLimit), intPtr(policyCheckTraceDailyLimit)); !allowed {
			return ReasonRateLimited, ReasonRateLimited, nil
		}
	}
	traceCtx, cancel := context.WithTimeout(ctx, policyCheckTraceTimeout)
	defer cancel()

	apiKey := accessResult.RPCAPIKey
	apiKeyHeader := proxy.DefaultAPIKeyHeader
	if s.jsonrpcProcessor != nil {
		if apiKey == "" {
			apiKey = s.jsonrpcProcessor.defaultRPCAPIKey
		}
		apiKeyHeader = s.jsonrpcProcessor.resolveAPIKeyHeader()
	}
	if !s.policyCheckEOATransfer(traceCtx, op, apiKey, apiKeyHeader) {
		traceResult, traceErr := s.forwardSimulationTraceWithAPIKey(traceCtx, op, apiKey, apiKeyHeader)
		if traceErr != nil {
			// Malformed operation params are a client error, not an upstream failure.
			var clientErr *simulationClientError
			if errors.As(traceErr, &clientErr) {
				return "", "", traceErr
			}
			slog.Warn("policy-check: trace unavailable", "method", op.Method, "err", traceErr)
			return "upstream_error", "upstream_error", nil
		}
		if validationErr := s.validatePolicyCheckTrace(ctx, user, perms, accessResult.OrgID, accessReq.TargetAddress, traceResult.Parsed); validationErr != nil {
			if validationErr.StatusCode >= http.StatusInternalServerError {
				return "", "", errors.New("policy trace validation is unavailable")
			}
			wireReason = sanitizePolicyCheckReason(validationErr.Message)
			auditReason = sanitizeDryRunReason(validationErr.Message)
			return wireReason, auditReason, nil
		}
	}
	if effectiveMethod == "eth_sendTransaction" || effectiveMethod == "eth_sendRawTransaction" {
		from, to, data, value, extractErr := policyCheckTransactionFields(op)
		if extractErr != nil {
			return "", "", extractErr
		}
		if s.complianceChecker != nil {
			compResult, compErr := s.complianceChecker.CheckPreview(ctx, &compliance.CheckRequest{
				OrgID: accessResult.OrgID, UserID: user.ID, From: from, To: to, Data: data, Value: value,
			})
			if compErr != nil {
				return "", "", compErr
			}
			if !compResult.Allowed {
				return "compliance", ReasonComplianceBlocked, nil
			}
		}
	}
	return "", "", nil
}

// policyCheckEOATransfer mirrors the live simple-transfer fast path. A missing
// or failed code lookup never skips trace validation.
func (s *Server) policyCheckEOATransfer(ctx context.Context, op dryRunRPCBlock, apiKey, apiKeyHeader string) bool {
	method := rbac.ResolveMethodAlias(op.Method)
	if method != "eth_sendTransaction" && method != "eth_sendRawTransaction" {
		return false
	}
	_, to, data, _, err := policyCheckTransactionFields(op)
	if err != nil || to == "" || !isSimpleValueTransfer(data) || s.proxy == nil {
		return false
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "eth_getCode", "params": []any{to, "latest"}, "id": 1})
	if err != nil {
		return false
	}
	response, _, err := s.proxy.ForwardWithAPIKeyHeaderContext(ctx, body, apiKeyHeader, apiKey, "")
	if err != nil {
		return false
	}
	var result struct {
		Result string `json:"result"`
	}
	if json.Unmarshal(response, &result) != nil {
		return false
	}
	return result.Result == "0x" || result.Result == "0x0"
}

// validatePolicyCheckTrace mirrors live trace ownership. RBAC and compliance
// remain scoped to the resolved organization, but nested calls may enter any
// organization where the subject has an active membership.
func (s *Server) validatePolicyCheckTrace(
	ctx context.Context,
	user *rbac.User,
	perms *rbac.EffectivePermissions,
	orgID, targetAddr string,
	traceResult *tracer.TraceResult,
) *ProcessError {
	if user == nil || s.rbacAccessCtrl == nil {
		return &ProcessError{StatusCode: http.StatusInternalServerError, Message: sendTraceValidatorError, Reason: ReasonTracingUnavailable}
	}
	// Active memberships only (DB-side filter): an expired time-boxed grant
	// must not authorize nested calls into its former organization.
	memberships, err := s.rbacAccessCtrl.Store().ListActiveUserMembershipsWithDetails(ctx, user.ID)
	if err != nil {
		slog.Warn("policy-check: membership lookup failed", "subject_did", user.ExternalID, "err", err)
		return &ProcessError{StatusCode: http.StatusInternalServerError, Message: sendTraceValidatorError, Reason: ReasonTracingUnavailable}
	}
	userOrgIDs := make(map[string]bool)
	for _, membership := range memberships {
		if membership.Group != nil {
			userOrgIDs[membership.Group.OrgID] = true
		}
	}
	if len(userOrgIDs) == 0 {
		return &ProcessError{StatusCode: http.StatusInternalServerError, Message: sendTraceValidatorError, Reason: ReasonTracingUnavailable}
	}
	userHasDeploy := effectivePermissionsHasDeployClaim(perms)
	if s.jsonrpcProcessor != nil && s.jsonrpcProcessor.rbacAccessCtrl != nil {
		userHasDeploy = s.jsonrpcProcessor.userHasDeployClaim(ctx, memberships)
	}
	return s.validateTraceWithOrgIDs(ctx, user, perms, orgID, targetAddr, traceResult, userOrgIDs, userHasDeploy)
}

func intPtr(value int) *int { return &value }

func policyCheckUnsupportedTraceMethod(method string) bool {
	switch rbac.ResolveMethodAlias(method) {
	case "debug_traceCall", "debug_traceTransaction":
		return true
	default:
		return false
	}
}

// validatePolicyCheckVisibleTo applies the write-path visibleTo shape checks
// without resolving recipients or writing transaction visibility rows.
func validatePolicyCheckVisibleTo(op dryRunRPCBlock) (string, error) {
	method := rbac.ResolveMethodAlias(op.Method)
	if method != "eth_sendTransaction" && method != "eth_sendRawTransaction" {
		return "", nil
	}
	from, to, data, _, err := policyCheckTransactionFields(op)
	_ = from
	if err != nil {
		return "", err
	}
	entries := policyCheckVisibleToEntries(method, op.Params)
	if len(entries) == 0 {
		return "", nil
	}
	if len(entries) > visibleToMaxSize {
		return ReasonInvalidRequestShape, nil
	}
	if isSimpleValueTransfer(data) || to == "" || to == "0x" {
		return ReasonInvalidRequestShape, nil
	}
	return "", nil
}

func policyCheckVisibleToEntries(method string, params []any) []string {
	var raw any
	if method == "eth_sendTransaction" && len(params) > 0 {
		if tx, ok := params[0].(map[string]any); ok {
			raw = tx["visibleTo"]
		}
	}
	if method == "eth_sendRawTransaction" && len(params) > 1 {
		if opts, ok := params[1].(map[string]any); ok {
			raw = opts["visibleTo"]
		}
	}
	if method == "eth_sendRawTransaction" {
		return policyCheckRawVisibleToEntries(raw)
	}
	switch values := raw.(type) {
	case []any:
		entries := make([]string, 0, len(values))
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			if entry, ok := value.(string); ok && isValidDID(entry) {
				if _, duplicate := seen[entry]; duplicate {
					continue
				}
				seen[entry] = struct{}{}
				entries = append(entries, entry)
			}
		}
		return entries
	case []string:
		entries := make([]string, 0, len(values))
		seen := make(map[string]struct{}, len(values))
		for _, entry := range values {
			if isValidDID(entry) {
				if _, duplicate := seen[entry]; duplicate {
					continue
				}
				seen[entry] = struct{}{}
				entries = append(entries, entry)
			}
		}
		return entries
	default:
		return nil
	}
}

func policyCheckRawVisibleToEntries(raw any) []string {
	var entries []string
	switch values := raw.(type) {
	case []any:
		for _, value := range values {
			if entry, ok := value.(string); ok && entry != "" {
				entries = append(entries, entry)
			}
		}
	case []string:
		for _, entry := range values {
			if entry != "" {
				entries = append(entries, entry)
			}
		}
	}
	return entries
}

func (s *Server) validatePolicyCheckSender(ctx context.Context, subjectDID string, op dryRunRPCBlock) (string, error) {
	from, _, _, _, err := policyCheckTransactionFields(op)
	if err != nil {
		return "", err
	}
	if from == "" {
		return "", nil
	}
	if !gethcommon.IsHexAddress(from) {
		return ReasonInvalidRequestShape, nil
	}
	addresses, err := s.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, subjectDID)
	if err != nil {
		return "", err
	}
	for _, address := range addresses {
		if strings.EqualFold(address, from) {
			return "", nil
		}
	}
	return ReasonSenderNotLinked, nil
}

func policyCheckTransactionFields(op dryRunRPCBlock) (from, to, data, value string, err error) {
	if rbac.ResolveMethodAlias(op.Method) == "eth_sendRawTransaction" {
		rawHex, rawErr := extractRawTxHex(op.Params)
		if rawErr != nil {
			return "", "", "", "", rawErr
		}
		from, to, data, value, _, err = decodeRawTransaction(rawHex)
		return from, to, data, value, err
	}
	from, to, data, value = extractTxParams(op.Params)
	return from, to, data, value, nil
}

// recordPolicyCheck writes one row to policy_check_log. subjectDID may be empty
// when resolution denied before any DID was known; subjectAddress still records it.
func (s *Server) recordPolicyCheck(
	ctx context.Context,
	callerAuthMethod, subjectDID, subjectAddress, orgID string,
	op dryRunRPCBlock,
	allowed bool,
	reason, correlationID string,
) error {
	if s.db == nil {
		return nil
	}
	conn := s.db.Conn()
	if conn == nil {
		return nil
	}
	paramsHash := dryRunParamsHash(op.Method, op.Params)
	corr := uuid.NullUUID{}
	if id, err := uuid.Parse(correlationID); err == nil {
		corr.UUID = id
		corr.Valid = true
	}
	var didVal, addrVal, orgVal any
	if subjectDID != "" {
		didVal = subjectDID
	}
	if subjectAddress != "" {
		addrVal = strings.ToLower(strings.TrimSpace(subjectAddress))
	}
	if orgID != "" {
		orgVal = orgID
	}
	_, err := conn.ExecContext(ctx, `
		INSERT INTO policy_check_log (caller_auth_method, subject_did, subject_address, org_id, method, params_hash, allowed, reason, correlation_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9)`,
		callerAuthMethod, didVal, addrVal, orgVal, op.Method, paramsHash, allowed, reason, corr,
	)
	return err
}
