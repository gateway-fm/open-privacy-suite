package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"
	"privacy-proxy/internal/tracer"

	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
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

// policyCheckRequest is the JSON body of
// POST /api/v1/admin/cross-org-authorization-oracle.
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
func (op policyCheckRPCBlock) rpcBlock() apimodels.DryRunRPCBlock {
	return apimodels.DryRunRPCBlock{Method: op.Method, Params: op.Params}
}

// Oracle answers. deny only when policy was evaluated inside the oracle scope;
// indeterminate when part of the evaluation is outside it.
const (
	oracleDecisionAllow         = "allow"
	oracleDecisionDeny          = "deny"
	oracleDecisionIndeterminate = "indeterminate"

	oracleReasonDenied       = "denied"
	oracleReasonOutsideScope = "outside_oracle_scope"
	oracleReasonNotSimulated = "not_simulated"
)

// policyCheckWireResponse is projected according to the configured server
// mode. verdict_only omits Artifacts; full_simulation includes the trace.
type policyCheckWireResponse struct {
	Decision  string                    `json:"decision"`
	Reason    string                    `json:"reason,omitempty"`
	Artifacts *policyCheckWireArtifacts `json:"artifacts,omitempty"`
}

type policyCheckWireArtifacts struct {
	Trace json.RawMessage   `json:"trace"`
	Logs  []json.RawMessage `json:"logs,omitempty"`
}

// Spec-only mirrors keep RawMessage fields documented as JSON values rather
// than byte arrays while retaining the published component schema names.
type policyCheckResponse struct {
	Decision string `json:"decision" enums:"allow,deny,indeterminate"`
	// Reason is set on deny (denied) and indeterminate (outside_oracle_scope, not_simulated).
	Reason string `json:"reason,omitempty" enums:"denied,outside_oracle_scope,not_simulated"`
	// Artifacts appear only on allow in full_simulation mode: the raw, unredacted trace and logs.
	Artifacts *policyCheckArtifacts `json:"artifacts,omitempty"`
}

type policyCheckArtifacts struct {
	Trace any   `json:"trace"`
	Logs  []any `json:"logs,omitempty"`
}

// oracleOutcome is one evaluated answer. The internal reason and scope detail
// go to the audit record only; the wire carries the coarse reason.
type oracleOutcome struct {
	decision       string
	wireReason     string
	internalReason string
	scopeDetail    map[string]string
	artifacts      *policyCheckWireArtifacts
}

func oracleAllow() oracleOutcome { return oracleOutcome{decision: oracleDecisionAllow} }

func oracleDeny(internalReason string) oracleOutcome {
	return oracleOutcome{decision: oracleDecisionDeny, wireReason: oracleReasonDenied, internalReason: internalReason}
}

func oracleOutsideScope(internalReason string, detail map[string]string) oracleOutcome {
	return oracleOutcome{decision: oracleDecisionIndeterminate, wireReason: oracleReasonOutsideScope, internalReason: internalReason, scopeDetail: detail}
}

func oracleNotSimulated() oracleOutcome {
	return oracleOutcome{decision: oracleDecisionIndeterminate, wireReason: oracleReasonNotSimulated, internalReason: oracleReasonNotSimulated}
}

// oracleMaxMethodLength bounds operation.method before evaluation, so no audit
// field can overflow.
const oracleMaxMethodLength = 128

// crossOrgOracleLimitKey is the one concurrency key for every oracle request,
// so the limiter's per-key capacity (MAX_CONCURRENT_REQUESTS) caps the total
// traces in flight whatever the caller address.
const crossOrgOracleLimitKey = "cross_org_oracle"

// policyCheckTraceTimeout bounds one oracle or dry-run trace. A variable so
// tests can shorten it.
var policyCheckTraceTimeout = 5 * time.Second

// errSimUpstreamUnavailable wraps any upstream/trace failure (node error,
// timeout, empty or malformed trace): a transient condition, answered 503.
var errSimUpstreamUnavailable = errors.New("policy-check simulation upstream unavailable")

// upstreamRateLimitedError is an upstream HTTP 429 on a trace forward. The
// oracle answers 429 and passes Retry-After through.
type upstreamRateLimitedError struct{ retryAfter string }

func (e *upstreamRateLimitedError) Error() string { return "upstream rate limit reached" }

// errPolicyCheckSubjectMalformed marks an invalid subject (neither or both of
// did/address); the handler answers 400.
var errPolicyCheckSubjectMalformed = errors.New("subject must have exactly one of did or address")

var errPolicyCheckSubjectAddressMalformed = errors.New("subject address must be a valid Ethereum address")

// resolvePolicyCheckSubject resolves the subject to the DID CheckAccess
// evaluates against, using eth_address_links so the caller cannot assert an
// identity. A multi-DID address refuses rather than picking a winner.
// Returns (did, "", nil) on success, ("", reason, nil) when no single identity
// is linked, or an error (400 for the sentinel, else 500).
func (s *Server) resolvePolicyCheckSubject(ctx context.Context, subj policyCheckSubject) (did string, unresolvedReason string, err error) {
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
		return "", "address_not_linked", nil
	case 1:
		return dids[0], "", nil
	default:
		// Never echo which DIDs collided (RD-934). The audit row records
		// subject_address, which is enough to investigate via
		// GetAddressLinkCollisions.
		return "", "address_multiple_identities", nil
	}
}

// handlePolicyCheck handles POST /api/v1/admin/cross-org-authorization-oracle.
//
// @Summary      Check whether a subject would be allowed to make an RPC call
// @Description  Cross-organization privacy-policy oracle for an explicitly trusted infrastructure caller. Disabled by default (CROSS_ORG_AUTHORIZATION_ORACLE_MODE=disabled), in which case it answers 404. Subject is a DID or Ethereum address. Operation is a JSON-RPC method and params. The answer is decision=allow, deny or indeterminate. deny means policy was evaluated inside the oracle scope (the organizations in CROSS_ORG_AUTHORIZATION_ORACLE_ORG_IDS) and refuses the call. indeterminate means the oracle cannot judge: reason=outside_oracle_scope when the subject, the requested or resolved organization, the target or a nested call is outside that scope; reason=not_simulated when the method executes EVM code the oracle does not trace, including a targeted eth_createAccessList, which live RPC keeps on its entry-point check without a trace. The oracle never consults an organization outside the scope. Callers should proceed on allow, block on deny, and on indeterminate not block on the oracle but let the live call decide. Authority scope: the token holder may query any member of any allowlisted organization; the operator allowlist is the consent boundary. In verdict_only mode the response carries only the decision and its coarse reason. In full_simulation mode an allow also carries artifacts, the raw, unredacted trace and logs of the simulated call, by design; where the operator must not be able to access tenant data, use verdict_only. Per-organization consent is planned as follow-up work. EVM execution methods use debug_traceCall with the same upstream credential as live calls. Write methods also run a side-effect-free compliance preview. The endpoint does not submit the call or consume a travel-rule record. A supplied sender must link to the subject. Requests share one global concurrency cap (MAX_CONCURRENT_REQUESTS in flight); request-rate limits belong to the upstream RPC proxy. Traces use the subject organization's upstream API key, or the default key, so they count against that key's upstream quota; an upstream 429 is returned as 429 with its Retry-After. debug_traceCall and debug_traceTransaction are not supported (400). Admin, operator, and JWT credentials are not accepted. Every request that reaches evaluation writes one operator-only entry (no organization) to the hash-chained RBAC audit log, including a 429 or 503 after evaluation started; if that write fails the answer is withheld (500). Early 400s (malformed body, subject or method) and the concurrency-cap 429 are not audited. Operational failures (concurrency cap, upstream 429, trace errors or timeouts) return 429 or 503, never a policy verdict.
// @Tags         Admin: RBAC
// @Accept       json
// @Produce      json
// @Param        request body policyCheckRequest true "subject, operation, and optional org_id"
// @Success      200 {object} policyCheckResponse
// @Failure      400 {object} apimodels.APIError "invalid body, missing, over-long or unsupported operation.method, an invalid subject address, or subject has neither/both of did and address"
// @Failure      401 {object} apimodels.APIError "missing or invalid X-Cross-Org-Authorization-Oracle-Token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network"
// @Failure      404 {object} apimodels.APIError "the oracle is disabled (CROSS_ORG_AUTHORIZATION_ORACLE_MODE=disabled)"
// @Failure      429 {object} apimodels.APIError "global concurrency cap reached, or upstream 429 (Retry-After passed through); operational, not a policy verdict"
// @Failure      500 {object} apimodels.APIError "internal error (includes audit-log write failure, response withheld)"
// @Failure      503 {object} apimodels.APIError "policy simulation unavailable (upstream trace failure); operational, not a policy verdict"
// @Security     CrossOrgOracleToken
// @Router       /api/v1/admin/cross-org-authorization-oracle [post]
func (s *Server) handlePolicyCheck(c *gin.Context) {
	ctx := c.Request.Context()

	// Dedicated oracle credential only. General admin/operator/JWT credentials
	// are deliberately outside this cross-tenant trust boundary.
	authMethod := c.GetString("auth_method")
	if authMethod != "cross_org_authorization_oracle_token" {
		respondUnauthorized(c, "cross-org authorization oracle authentication required")
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
	if len(req.Operation.Method) > oracleMaxMethodLength {
		respondBadRequest(c, "operation.method is too long")
		return
	}
	if policyCheckUnsupportedTraceMethod(req.Operation.Method) {
		respondBadRequest(c, "operation not supported")
		return
	}
	req.OrgID = strings.TrimSpace(req.OrgID)
	operation := req.Operation.rpcBlock()
	rec := oracleAuditRecord{
		subjectDID:     strings.TrimSpace(req.Subject.DID),
		subjectAddress: req.Subject.Address,
		requestedOrgID: req.OrgID,
		operation:      operation,
		correlationID:  middleware.GetCorrelationID(c),
	}
	respond := func(out oracleOutcome) {
		rec.outcome = out
		if logErr := s.recordPolicyCheck(ctx, rec); logErr != nil {
			// No verdict without an audit trail.
			slog.Error("policy-check: audit log write failed; refusing response", "err", logErr)
			respondInternalError(c, "internal error")
			return
		}
		if out.decision == oracleDecisionIndeterminate {
			s.recordOracleIndeterminate(out.wireReason)
		}
		response := policyCheckWireResponse{Decision: out.decision, Reason: out.wireReason}
		if out.decision == oracleDecisionAllow && s.config != nil && strings.EqualFold(strings.TrimSpace(s.config.CrossOrgAuthorizationOracleMode), "full_simulation") {
			response.Artifacts = out.artifacts
		}
		c.JSON(http.StatusOK, response)
	}
	respondClientError := func() {
		rec.outcome = oracleOutcome{decision: "error", internalReason: "decode_error"}
		if logErr := s.recordPolicyCheck(ctx, rec); logErr != nil {
			slog.Error("policy-check: audit log write failed; refusing response", "err", logErr)
			respondInternalError(c, "internal error")
			return
		}
		respondBadRequest(c, "invalid operation")
	}

	if req.OrgID != "" && !s.crossOrgAuthorizationOracleOrgAllowed(req.OrgID) {
		respond(oracleOutsideScope("requested_org_outside_allowlist", map[string]string{"org_id": req.OrgID}))
		return
	}
	if _, err := dryRunAccessRequest("", "", operation); err != nil {
		respondClientError()
		return
	}

	did, unresolvedReason, err := s.resolvePolicyCheckSubject(ctx, req.Subject)
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
	if unresolvedReason != "" {
		// Never pick a winner among several identities, and never tell an
		// unlinked address apart from an out-of-scope one.
		respond(oracleOutsideScope(unresolvedReason, nil))
		return
	}
	rec.subjectDID = did

	out, evaluatedOrgID, err := s.evaluateOracle(ctx, did, req.OrgID, operation)
	rec.evaluatedOrgID = evaluatedOrgID
	if err != nil {
		var clientErr *simulationClientError
		var rateLimited *upstreamRateLimitedError
		recordUnavailable := func(reason string) bool {
			rec.outcome = oracleOutcome{decision: "unavailable", internalReason: reason}
			if logErr := s.recordPolicyCheck(ctx, rec); logErr != nil {
				slog.Error("policy-check: audit log write failed; refusing response", "err", logErr)
				respondInternalError(c, "internal error")
				return false
			}
			return true
		}
		switch {
		case errors.As(err, &clientErr):
			respondClientError()
		case errors.As(err, &rateLimited):
			// Operational unavailability is not a policy verdict: a caller must
			// not mistake a busy or degraded node for a deny.
			if !recordUnavailable("upstream_rate_limited") {
				return
			}
			if rateLimited.retryAfter != "" {
				c.Header("Retry-After", rateLimited.retryAfter)
			}
			respondTooManyRequests(c, "upstream rate limit reached; retry later")
		case errors.Is(err, errSimUpstreamUnavailable):
			slog.Warn("policy-check: simulation upstream unavailable", "subject_did", did, "method", operation.Method, "err", err)
			if !recordUnavailable(ReasonTracingUnavailable) {
				return
			}
			respondServiceUnavailable(c, "policy simulation unavailable; retry later")
		default:
			slog.Error("policy-check: evaluation failed", "subject_did", did, "method", operation.Method, "err", err)
			rec.outcome = oracleOutcome{decision: "error", internalReason: "error"}
			if logErr := s.recordPolicyCheck(ctx, rec); logErr != nil {
				slog.Error("policy-check: audit log write also failed", "err", logErr)
			}
			respondInternalError(c, "internal error")
		}
		return
	}
	respond(out)
}

// evaluateOracle answers for a resolved subject. It returns the organization
// it evaluated, for the audit record.
func (s *Server) evaluateOracle(ctx context.Context, did, requestedOrgID string, operation apimodels.DryRunRPCBlock) (oracleOutcome, string, error) {
	authorityAccessReq, err := dryRunAccessRequest(did, "", operation)
	if err != nil {
		return oracleOutcome{}, "", &simulationClientError{msg: "invalid operation"}
	}
	orgID, early, err := s.resolveOracleOrg(ctx, did, requestedOrgID, authorityAccessReq.TargetAddress)
	if err != nil || early != nil {
		if early != nil {
			return *early, orgID, nil
		}
		return oracleOutcome{}, orgID, err
	}

	// Pin CheckAccess to the evaluated organization, through both OrgID and
	// the view scope, so it never resolves memberships outside the allowlist.
	evaluation, err := s.evaluateOperation(withViewerOrgScope(ctx, orgID), did, operation, authorizationScopeAllActiveMemberships, orgID)
	if err != nil {
		var accessErr *operationAccessError
		if errors.As(err, &accessErr) {
			return oracleOutcome{}, orgID, err
		}
		// A malformed raw transaction is a client error, not a denial.
		return oracleOutcome{}, orgID, &simulationClientError{msg: "invalid operation"}
	}
	result := evaluation.AccessResult
	if result.OrgID != "" && !s.crossOrgAuthorizationOracleOrgAllowed(result.OrgID) {
		return oracleOutsideScope("resolved_org_outside_allowlist", map[string]string{"org_id": result.OrgID}), orgID, nil
	}
	if !result.Allowed {
		return oracleDeny(sanitizeDryRunReason(result.Reason)), orgID, nil
	}
	out, err := s.simulatePolicyCheck(ctx, did, operation, evaluation.AccessRequest, result)
	return out, orgID, err
}

// resolveOracleOrg picks the one organization CheckAccess evaluates. It runs
// before any policy loads and decides only from allowlisted organizations:
// a target owned outside the allowlist, or a subject with no allowlisted
// membership, is outside the oracle scope. A non-nil outcome is the answer.
func (s *Server) resolveOracleOrg(ctx context.Context, subjectDID, requestedOrgID, targetAddress string) (string, *oracleOutcome, error) {
	if s.db == nil || s.rbacAccessCtrl == nil {
		return "", nil, errors.New("policy authority store is unavailable")
	}
	ownerOrgID := ""
	if targetAddress != "" {
		contract, err := s.rbacAccessCtrl.Store().GetContractByAddressGlobal(ctx, targetAddress)
		if err != nil {
			return "", nil, err
		}
		if contract != nil {
			ownerOrgID = contract.OrgID
			if !s.crossOrgAuthorizationOracleOrgAllowed(ownerOrgID) {
				out := oracleOutsideScope("target_org_outside_allowlist", map[string]string{"org_id": ownerOrgID, "contract": strings.ToLower(targetAddress)})
				return "", &out, nil
			}
		}
	}
	allowed, err := s.oracleMemberships(ctx, subjectDID)
	if err != nil {
		return "", nil, err
	}
	if len(allowed) == 0 {
		out := oracleOutsideScope("no_allowlisted_membership", nil)
		return "", &out, nil
	}

	// As live RPC, a registered target is evaluated in its owner organization.
	orgID := ownerOrgID
	if orgID == "" {
		orgID = requestedOrgID
	}
	if orgID == "" {
		if len(allowed) > 1 {
			// An unregistered or absent target is ambiguous for a multi-org
			// subject, as on the live path.
			out := oracleDeny("ambiguous_organization")
			return "", &out, nil
		}
		for only := range allowed {
			orgID = only
		}
	}
	if !allowed[orgID] {
		out := oracleDeny("subject_not_member")
		return orgID, &out, nil
	}
	return orgID, nil, nil
}

// oracleMemberships returns the subject's active memberships in allowlisted
// organizations. Other memberships never reach a decision.
func (s *Server) oracleMemberships(ctx context.Context, subjectDID string) (map[string]bool, error) {
	user, err := s.db.GetUserByExternalID(ctx, subjectDID)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool)
	if user == nil {
		return allowed, nil
	}
	memberships, err := s.rbacAccessCtrl.Store().ListActiveUserMembershipsWithDetails(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	for _, membership := range memberships {
		if membership.Group != nil && s.crossOrgAuthorizationOracleOrgAllowed(membership.Group.OrgID) {
			allowed[membership.Group.OrgID] = true
		}
	}
	return allowed, nil
}

// oracleTracedMethods are the EVM execution methods the oracle simulates.
var oracleTracedMethods = map[string]bool{
	"eth_call": true, "eth_estimateGas": true, "eth_createAccessList": true,
	"eth_sendTransaction": true, "eth_sendRawTransaction": true,
}

// simulatePolicyCheck traces methods that can execute EVM code and answers
// for an operation CheckAccess allowed.
func (s *Server) simulatePolicyCheck(
	ctx context.Context,
	subjectDID string,
	op apimodels.DryRunRPCBlock,
	accessReq *rbac.AccessCheckRequest,
	accessResult *rbac.AccessCheckResult,
) (oracleOutcome, error) {
	effectiveMethod := rbac.ResolveMethodAlias(op.Method)
	if !oracleTracedMethods[effectiveMethod] {
		// A catalog read has no EVM execution, so the RBAC verdict is complete.
		// Anything else may execute code the oracle does not trace.
		if rbac.IsCatalogMethod(effectiveMethod) {
			return oracleAllow(), nil
		}
		return oracleNotSimulated(), nil
	}

	if effectiveMethod == "eth_createAccessList" && accessReq.TargetAddress != "" {
		// Live keeps a targeted access list on its entry-point gate, so the
		// nested scope is never evaluated: the oracle cannot judge it.
		return oracleNotSimulated(), nil
	}
	if s.db == nil || s.rbacAccessCtrl == nil || accessResult == nil || accessResult.OrgID == "" {
		return oracleOutcome{}, errors.New("resolved policy context is unavailable")
	}
	user, err := s.db.GetUserByExternalID(ctx, subjectDID)
	if err != nil || user == nil {
		return oracleOutcome{}, errors.New("resolved policy subject is unavailable")
	}
	if reason, senderErr := s.validatePolicyCheckSender(ctx, subjectDID, op); senderErr != nil {
		return oracleOutcome{}, senderErr
	} else if reason != "" {
		if reason == ReasonInvalidRequestShape {
			return oracleOutcome{}, &simulationClientError{msg: reason}
		}
		return oracleDeny(reason), nil
	}
	if reason, visibleToErr := validatePolicyCheckVisibleTo(op); visibleToErr != nil {
		return oracleOutcome{}, visibleToErr
	} else if reason != "" {
		if reason == ReasonInvalidRequestShape {
			return oracleOutcome{}, &simulationClientError{msg: reason}
		}
		return oracleDeny(reason), nil
	}
	perms, err := s.rbacAccessCtrl.GetEffectivePermissionsByIDs(ctx, user.ID, accessResult.OrgID)
	if err != nil || perms == nil {
		return oracleOutcome{}, errors.New("resolved policy permissions are unavailable")
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
	var artifacts policyCheckWireArtifacts
	if !s.policyCheckEOATransfer(traceCtx, op, apiKey, apiKeyHeader) {
		traceResult, traceErr := s.forwardDryRunTraceWithAPIKey(traceCtx, op, apiKey, apiKeyHeader)
		if traceErr != nil {
			// Malformed operation params are a client error, and an upstream 429
			// is passed through; neither is an upstream outage.
			var clientErr *simulationClientError
			var rateLimited *upstreamRateLimitedError
			if errors.As(traceErr, &clientErr) || errors.As(traceErr, &rateLimited) {
				return oracleOutcome{}, traceErr
			}
			// Any other trace failure (node error, timeout, empty/malformed
			// trace) is a transient upstream condition: surface 503, not a deny.
			return oracleOutcome{}, fmt.Errorf("%w: %v", errSimUpstreamUnavailable, traceErr)
		}
		if traceResult == nil || traceResult.Parsed == nil {
			return oracleOutcome{}, fmt.Errorf("%w: trace returned no result", errSimUpstreamUnavailable)
		}
		artifacts.Trace = traceResult.Trace
		artifacts.Logs = traceResult.Logs
		if validationErr := s.validatePolicyCheckTrace(ctx, user, perms, op.Method, accessResult.OrgID, accessReq.TargetAddress, traceResult.Parsed); validationErr != nil {
			if validationErr.StatusCode >= http.StatusInternalServerError {
				return oracleOutcome{}, fmt.Errorf("%w: trace validation unavailable", errSimUpstreamUnavailable)
			}
			v := traceVerdict(authorizationScopeAllowlisted, validationErr)
			return oracleOutcome{decision: v.decision, wireReason: v.wireReason, internalReason: v.internalReason, scopeDetail: v.detail}, nil
		}
	}
	if effectiveMethod == "eth_sendTransaction" || effectiveMethod == "eth_sendRawTransaction" {
		from, to, data, value, extractErr := policyCheckTransactionFields(op)
		if extractErr != nil {
			return oracleOutcome{}, extractErr
		}
		if s.complianceChecker != nil {
			compResult, compErr := complianceVerdict(ctx, s.complianceChecker, evaluationPreview, &compliance.CheckRequest{
				OrgID: accessResult.OrgID, UserID: user.ID, From: from, To: to, Data: data, Value: value,
			})
			if compErr != nil {
				return oracleOutcome{}, compErr
			}
			if !compResult.Allowed {
				return oracleDeny(ReasonComplianceBlocked), nil
			}
		}
	}
	out := oracleAllow()
	out.artifacts = &artifacts
	return out, nil
}

// policyCheckEOATransfer mirrors the live simple-transfer fast path. A missing
// or failed code lookup never skips trace validation.
func (s *Server) policyCheckEOATransfer(ctx context.Context, op apimodels.DryRunRPCBlock, apiKey, apiKeyHeader string) bool {
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

// validatePolicyCheckTrace mirrors live trace ownership within the oracle
// scope. Nested calls may enter any allowlisted organization where the subject
// has an active membership; a frame owned outside the allowlist yields
// DenialKindOutOfScope without consulting the subject's membership there.
func (s *Server) validatePolicyCheckTrace(
	ctx context.Context,
	user *rbac.User,
	perms *rbac.EffectivePermissions,
	method, orgID, targetAddr string,
	traceResult *tracer.TraceResult,
) *ProcessError {
	scope := evaluationScope{kind: authorizationScopeAllowlisted, orgID: orgID, inScope: s.crossOrgAuthorizationOracleOrgAllowed}
	userOrgIDs, userHasDeploy, err := traceOrgScope(ctx, s.rbacAccessCtrl, user, scope)
	if err != nil {
		slog.Warn("policy-check: trace scope lookup failed", "org_id", orgID, "err", err)
		return &ProcessError{StatusCode: http.StatusInternalServerError, Message: sendTraceValidatorError, Reason: ReasonTracingUnavailable}
	}
	opts := append(traceShapeOptions(method, targetAddr), rbac.WithEvaluationScope(s.crossOrgAuthorizationOracleOrgAllowed))
	return s.validateTraceWithOrgIDs(ctx, user, perms, orgID, targetAddr, traceResult, userOrgIDs, userHasDeploy, opts...)
}

func (s *Server) crossOrgAuthorizationOracleOrgAllowed(orgID string) bool {
	if s == nil || s.config == nil || strings.TrimSpace(orgID) == "" {
		return false
	}
	for _, allowedOrgID := range s.config.CrossOrgAuthorizationOracleOrgIDs {
		if strings.TrimSpace(allowedOrgID) == orgID {
			return true
		}
	}
	return false
}

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
func validatePolicyCheckVisibleTo(op apimodels.DryRunRPCBlock) (string, error) {
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

func (s *Server) validatePolicyCheckSender(ctx context.Context, subjectDID string, op apimodels.DryRunRPCBlock) (string, error) {
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
	linked, err := senderLinked(ctx, s.rbacAccessCtrl.Store(), subjectDID, from)
	if err != nil {
		return "", err
	}
	if !linked {
		return ReasonSenderNotLinked, nil
	}
	return "", nil
}

func policyCheckTransactionFields(op apimodels.DryRunRPCBlock) (from, to, data, value string, err error) {
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

// oracleAuditRecord is the audited view of one oracle request.
type oracleAuditRecord struct {
	subjectDID, subjectAddress     string
	requestedOrgID, evaluatedOrgID string
	operation                      apimodels.DryRunRPCBlock
	outcome                        oracleOutcome
	correlationID                  string
}

func (s *Server) recordOracleIndeterminate(reason string) {
	if s.metrics != nil && s.metrics.CrossOrgOracleIndeterminateTotal != nil {
		s.metrics.CrossOrgOracleIndeterminateTotal.WithLabelValues(reason).Inc()
	}
}

// recordPolicyCheck writes the one audit record of an evaluated request to the
// hash-chained RBAC audit log. org_id stays NULL, so the row is operator-only:
// a caller-chosen organization must never surface in that tenant's view.
func (s *Server) recordPolicyCheck(ctx context.Context, rec oracleAuditRecord) error {
	if s.db == nil {
		return errors.New("audit store is unavailable")
	}
	op := rec.operation
	payload := map[string]any{
		"subject_did":      rec.subjectDID,
		"subject_address":  strings.ToLower(strings.TrimSpace(rec.subjectAddress)),
		"requested_org_id": rec.requestedOrgID,
		"evaluated_org_id": rec.evaluatedOrgID,
		"method":           op.Method,
		"params_hash":      dryRunParamsHash(op.Method, op.Params),
		"decision":         rec.outcome.decision,
		"internal_reason":  rec.outcome.internalReason,
		"correlation_id":   rec.correlationID,
	}
	if len(rec.outcome.scopeDetail) > 0 {
		payload["scope_detail"] = rec.outcome.scopeDetail
	}
	return s.db.CreateAuditLog(ctx, &rbac.AuditLogEntry{
		ActorExternalID: "cross-org-authorization-oracle",
		Action:          "cross_org_oracle.query",
		ResourceType:    "configuration",
		ResourceName:    "cross_org_authorization_oracle",
		NewValue:        payload,
	})
}
