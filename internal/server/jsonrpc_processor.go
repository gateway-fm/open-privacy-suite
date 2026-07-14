package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/metrics"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/tracer"
)

// AuditBuffer is the durable staging buffer the hot path appends access-log
// entries to when async audit sealing is enabled (RD-1112). Satisfied by
// *internal/audit/buffer.Buffer.
type AuditBuffer interface {
	Append(data []byte) (uint64, error)
}

// JSONRPCProcessor handles the business logic for JSON-RPC requests.
// It separates concerns from HTTP handling, making the logic testable
// and reusable.
type JSONRPCProcessor struct {
	rbacAccessCtrl    *rbac.AccessController
	rateLimiter       RateLimiterInterface
	proxy             *proxy.Proxy
	accessLogger      AccessLogger
	runtimeTracer     *tracer.RuntimeTracer
	traceValidator    *rbac.TraceValidator
	complianceChecker *compliance.Checker

	// Enhanced audit fields
	enhancedLogger EnhancedAccessLogger
	hashChain      *audit.HashChain
	siemForwarder  *audit.SIEMForwarder
	logParams      bool
	// auditBuffer, when set (AUDIT_BUFFER_DIR configured), receives access-log
	// entries on the hot path instead of the synchronous chained write; a
	// background sealer drains it into the chain off the request path (RD-1112).
	auditBuffer AuditBuffer

	// Per-tx visibility store (visibleTo feature)
	txVisibilityStore rbac.TxVisibilityProvider

	// Circuit breaker + concurrency limiter (replaces rate limiter for authenticated users)
	circuitBreaker         *CircuitBreaker
	concurrencyLimiter     *ConcurrencyLimiter
	defaultRPCAPIKey       string
	defaultRPCAPIKeyHeader string // operator-wide header name from RPC_API_KEY_HEADER; empty => proxy.DefaultAPIKeyHeader

	// RD-915: eth_call cross-org tracing.
	// State snapshot held in an atomic.Pointer so the validator's hot
	// path reads it lock-free, and the super-admin toggle endpoint can
	// replace the whole snapshot atomically. The env-derived default is
	// installed once at startup via SetEthCallTracing; runtime overrides
	// from the admin endpoint are in-memory only — a restart re-arms
	// the env value, which is the durable change-management control
	// (RD-915 KD-5, ISO 27001 A.8.32).
	ethCallTracing      atomic.Pointer[runtimeToggleState]
	ethCallTraceTimeout time.Duration // ETH_CALL_TRACE_TIMEOUT — distinct from send-side TraceTimeout.

	// RD-1053: intra-org contract-grant scoping on internal trace frames.
	// Same atomic-snapshot pattern and super-admin runtime-override shape as
	// ethCallTracing above; defaults OFF. Governs read (eth_call /
	// debug_traceCall) and send (eth_sendTransaction / raw / deploy).
	intraOrgGrantTracing atomic.Pointer[runtimeToggleState]

	// Prometheus metrics
	metrics *metrics.Metrics
}

// runtimeToggleState captures the current value of a fleet-wide on/off
// security knob (eth_call tracing, intra-org grant scoping) plus the
// metadata needed to render a GET response from the admin endpoint.
// EnvDefault records the value the env var asked for at startup so operators
// can tell "currently overridden vs back to default" without inspecting the
// env. Source is "env" until the first runtime override.
type runtimeToggleState struct {
	Enabled    bool
	EnvDefault bool
	Source     string    // "env" | "runtime_override"
	ChangedAt  time.Time // zero until first override
	ChangedBy  string    // empty until first override
	Reason     string    // empty until first override
}

// TxVisibilitySaver saves per-tx visibleTo rules. Implemented by db.DB.
//
// M7 (security audit follow-up): the JSON-RPC hot path now uses
// EnqueuePendingTxVisibility (a write into the outbox table
// pending_tx_visibility). A background reconciler promotes outbox rows
// into tx_visible_to. SaveTxVisibility is kept on the interface for
// test fixtures and for callers that need the direct write path (e.g.
// migrations). Production code should NOT call SaveTxVisibility from
// the hot path — use the outbox to survive DB hiccups.
type TxVisibilitySaver interface {
	SaveTxVisibility(ctx context.Context, txHash string, visibleToDIDs []string, senderDID, orgID string) error
	EnqueuePendingTxVisibility(ctx context.Context, txHash string, visibleToDIDs []string, senderDID, orgID string) error
}

// AccessLogger logs access attempts for auditing.
type AccessLogger interface {
	LogAccess(ctx context.Context, userID, method string, statusCode int, clientIP string) error
}

// EnhancedAccessLogger logs access with correlation ID, params, and returns the entry ID for hash chain.
// responseStatus is nil when it matches statusCode (non-opaque request).
//
// LogAccessChained (RD-858) writes the row AND advances the hash chain
// atomically — preferred over the LogAccessEnhanced + UpdateAccessLogHash
// pair, which leaves entry_hash NULL on process crash between the two
// statements. The legacy pair is retained for tests that seed rows
// without chain participation.
type EnhancedAccessLogger interface {
	LogAccessChained(
		ctx context.Context,
		chain db.RBACAuditChain,
		externalID, method string,
		statusCode int,
		ipAddress, correlationID string,
		params []byte,
		responseStatus *int,
		orgID string,
		denialReason string,
	) (int64, time.Time, string, error)
	LogAccessEnhanced(ctx context.Context, externalID, method string, statusCode int, ipAddress, correlationID string, params []byte, responseStatus *int, orgID string, denialReason string) (int64, time.Time, error)
	UpdateAccessLogHash(ctx context.Context, id int64, hash string) error
}

// ProcessRequest represents a validated JSON-RPC request ready for processing.
type ProcessRequest struct {
	UserID        string
	OrgID         string // Optional: specify which org to use (for users with multiple memberships)
	Method        string
	Params        []any
	Body          []byte
	ClientIP      string
	CorrelationID string // Request correlation ID for audit trail
	// BypassPermsCache, when true, forces AccessController.CheckAccess to
	// skip its in-memory perms cache. Set by the RD-928 impersonation surface
	// so a "View as user X" call sees X's current permissions, not a snapshot
	// the cache picked up before X's last mutation. Threaded through to
	// rbac.AccessCheckRequest.BypassCache.
	BypassPermsCache bool

	// resolvedOrgID is the organization the access decision resolved against,
	// stamped onto access-log rows for RD-1135 org-scoped reads. It is set by
	// the processor AFTER CheckAccess (write-once) and read only by logAccess.
	// Distinct from OrgID, which is the request-supplied org SELECTOR fed INTO
	// CheckAccess — never mutate OrgID post-resolution (it changes the
	// CheckAccess resolution branch on any re-check). Empty => the row is
	// written with NULL org_id (anonymous / org-free metadata / pre-auth),
	// visible only to super-admin.
	resolvedOrgID string

	// denialReason is the curated reason code (RD-1137; see denial_reasons.go)
	// for a denied request, stamped onto the access-log row so the org-scoped
	// admin Access Logs view shows WHY, not just the status. Set at the denial
	// site right before logAccess; empty for success/unclassified => NULL.
	denialReason string
}

// ProcessResult represents the result of processing a JSON-RPC request.
type ProcessResult struct {
	StatusCode   int
	ResponseBody []byte
	Error        *ProcessError
}

// ProcessError represents an error during request processing.
type ProcessError struct {
	StatusCode int
	Message    string
	// Reason is the curated, stable denial-reason code (RD-1137; see
	// denial_reasons.go). Recorded on the access-log row for the org-scoped
	// admin view, and — for opt-in verbose callers (Part A) — surfaced on the
	// wire. Empty for non-denial or unclassified errors. Never raw error text.
	Reason string
}

func (e *ProcessError) Error() string {
	return e.Message
}

// NewJSONRPCProcessor creates a new processor with the given dependencies.
func NewJSONRPCProcessor(
	rbacCtrl *rbac.AccessController,
	rateLimiter RateLimiterInterface,
	proxyClient *proxy.Proxy,
	logger AccessLogger,
	cb *CircuitBreaker,
	cl *ConcurrencyLimiter,
	defaultAPIKey string,
) *JSONRPCProcessor {
	p := &JSONRPCProcessor{
		rbacAccessCtrl:      rbacCtrl,
		rateLimiter:         rateLimiter,
		proxy:               proxyClient,
		accessLogger:        logger,
		circuitBreaker:      cb,
		concurrencyLimiter:  cl,
		defaultRPCAPIKey:    defaultAPIKey,
		ethCallTraceTimeout: 5 * time.Second,
	}
	// Wire-level safe-by-default — the server constructor calls
	// SetEthCallTracing(...) right after to install the env-derived
	// value. Until then, tracing is on.
	p.ethCallTracing.Store(&runtimeToggleState{
		Enabled:    true,
		EnvDefault: true,
		Source:     "env",
	})
	// Intra-org grant scoping is OFF until env install (RD-1053). Org
	// ownership is the default isolation boundary; operators opt in.
	p.intraOrgGrantTracing.Store(&runtimeToggleState{
		Enabled:    false,
		EnvDefault: false,
		Source:     "env",
	})
	return p
}

// SetEthCallTracing installs the env-derived configuration for the RD-915
// eth_call cross-org tracing knobs. `enabled` defaults to true; the env
// var only flips it to false as a documented sev-1 rollback path.
// `timeout` caps how long the proxy waits for the upstream
// debug_traceCall on the eth_call validation path; distinct from the
// send-side TraceTimeout. This wipes any prior runtime override — boot
// always re-arms from env (RD-915 KD-5, ISO 27001 A.8.32).
func (p *JSONRPCProcessor) SetEthCallTracing(enabled bool, timeout time.Duration) {
	p.ethCallTracing.Store(&runtimeToggleState{
		Enabled:    enabled,
		EnvDefault: enabled,
		Source:     "env",
	})
	if timeout > 0 {
		p.ethCallTraceTimeout = timeout
	}
}

// SetEthCallTracingRuntimeOverride records an in-memory toggle from the
// super-admin endpoint. The change is NOT persisted: a restart re-arms
// the env value. `reason` and `who` are required for the audit trail.
// Returns the new snapshot so the handler can echo it in its response.
func (p *JSONRPCProcessor) SetEthCallTracingRuntimeOverride(enabled bool, who, reason string) *runtimeToggleState {
	prev := p.ethCallTracing.Load()
	envDefault := true
	if prev != nil {
		envDefault = prev.EnvDefault
	}
	next := &runtimeToggleState{
		Enabled:    enabled,
		EnvDefault: envDefault,
		Source:     "runtime_override",
		ChangedAt:  time.Now().UTC(),
		ChangedBy:  who,
		Reason:     reason,
	}
	p.ethCallTracing.Store(next)
	return next
}

// EthCallTracingSnapshot returns the current state for the admin GET
// handler. Never returns nil — the constructor seeds a default.
func (p *JSONRPCProcessor) EthCallTracingSnapshot() runtimeToggleState {
	s := p.ethCallTracing.Load()
	if s == nil {
		return runtimeToggleState{Enabled: true, EnvDefault: true, Source: "env"}
	}
	return *s
}

// SetIntraOrgGrantTracing installs the env-derived configuration for the
// RD-1053 intra-org contract-grant scoping knob. Defaults OFF; the env var
// flips it on for operators who want grants to gate contract-to-contract
// composition within an org. This wipes any prior runtime override — boot
// always re-arms from env (mirrors SetEthCallTracing; ISO 27001 A.8.32).
func (p *JSONRPCProcessor) SetIntraOrgGrantTracing(enabled bool) {
	p.intraOrgGrantTracing.Store(&runtimeToggleState{
		Enabled:    enabled,
		EnvDefault: enabled,
		Source:     "env",
	})
}

// SetIntraOrgGrantTracingRuntimeOverride records an in-memory toggle of the
// intra-org grant scoping knob from the super-admin endpoint. Not persisted:
// a restart re-arms the env value. Returns the new snapshot.
func (p *JSONRPCProcessor) SetIntraOrgGrantTracingRuntimeOverride(enabled bool, who, reason string) *runtimeToggleState {
	prev := p.intraOrgGrantTracing.Load()
	envDefault := false
	if prev != nil {
		envDefault = prev.EnvDefault
	}
	next := &runtimeToggleState{
		Enabled:    enabled,
		EnvDefault: envDefault,
		Source:     "runtime_override",
		ChangedAt:  time.Now().UTC(),
		ChangedBy:  who,
		Reason:     reason,
	}
	p.intraOrgGrantTracing.Store(next)
	return next
}

// IntraOrgGrantTracingSnapshot returns the current state for the admin GET
// handler. Never returns nil — the constructor seeds a default (OFF).
func (p *JSONRPCProcessor) IntraOrgGrantTracingSnapshot() runtimeToggleState {
	s := p.intraOrgGrantTracing.Load()
	if s == nil {
		return runtimeToggleState{Enabled: false, EnvDefault: false, Source: "env"}
	}
	return *s
}

// intraOrgGrantTracingEnabled is the lock-free hot-path read of the RD-1053
// knob. Returns false (org-ownership-only frames) until env install.
func (p *JSONRPCProcessor) intraOrgGrantTracingEnabled() bool {
	s := p.intraOrgGrantTracing.Load()
	return s != nil && s.Enabled
}

// intraOrgGrantTraceOptions returns the ValidateTrace options that enable
// RD-1053 intra-org grant scoping, or nil when the knob is off. When off we
// skip resolving the granted-contract set entirely, so the default path adds
// zero overhead. targetAddr (the already-authorized top-level `to`, empty for
// deploys) is always added to the granted set so the trace never re-denies a
// frame the grant-aware entry-point CheckAccess already allowed.
//
// Resolution errors are returned to the caller, which MUST fail closed
// (deny) — a knob that is on but whose grant set could not be resolved must
// never silently fall back to org-ownership-only.
func (p *JSONRPCProcessor) intraOrgGrantTraceOptions(ctx context.Context, userID, targetAddr string, userOrgIDs map[string]bool) ([]rbac.TraceOption, error) {
	if !p.intraOrgGrantTracingEnabled() {
		return nil, nil
	}
	granted, err := p.resolveGrantedContracts(ctx, userID, userOrgIDs)
	if err != nil {
		return nil, err
	}
	if targetAddr != "" {
		granted[strings.ToLower(targetAddr)] = true
	}
	return []rbac.TraceOption{rbac.WithIntraOrgGrantScoping(granted)}, nil
}

// resolveGrantedContracts returns the set of lowercased contract addresses
// the user has contract-level access to, unioned across all their orgs. This
// mirrors the entry-point CheckAccess contract-access decision: the resolved
// EffectivePermissions.ContractAccess map already folds in explicit
// contract_grants (by group), org-admin materialization, and deployer
// auto-grant rows (RD-735). Resolution is from the resolver cache — the
// target's own org is a guaranteed cache hit (CheckAccess just resolved it
// this request); additional orgs the user belongs to may be cold.
func (p *JSONRPCProcessor) resolveGrantedContracts(ctx context.Context, userID string, userOrgIDs map[string]bool) (map[string]bool, error) {
	granted := make(map[string]bool)
	for orgID := range userOrgIDs {
		perms, err := p.rbacAccessCtrl.GetEffectivePermissionsByIDs(ctx, userID, orgID)
		if err != nil {
			return nil, err
		}
		if perms == nil {
			continue
		}
		for addr := range perms.ContractAccess {
			granted[strings.ToLower(addr)] = true
		}
	}
	return granted, nil
}

// SetComplianceChecker sets the compliance checker for travel rule enforcement.
func (p *JSONRPCProcessor) SetComplianceChecker(checker *compliance.Checker) {
	p.complianceChecker = checker
}

// SetEnhancedAudit configures enhanced audit logging with hash chain and optional SIEM.
func (p *JSONRPCProcessor) SetEnhancedAudit(logger EnhancedAccessLogger, hashChain *audit.HashChain, siemForwarder *audit.SIEMForwarder, logParams bool) {
	p.enhancedLogger = logger
	p.hashChain = hashChain
	p.siemForwarder = siemForwarder
	p.logParams = logParams
}

// SetAuditBuffer enables async audit logging (RD-1112): logAccess appends to
// this durable buffer on the hot path and a background sealer drains it into
// the chain off the request path. When nil, logAccess uses the synchronous
// chained write (legacy behaviour).
func (p *JSONRPCProcessor) SetAuditBuffer(b AuditBuffer) {
	p.auditBuffer = b
}

// SetMetrics configures Prometheus metrics for the processor.
func (p *JSONRPCProcessor) SetMetrics(m *metrics.Metrics) {
	p.metrics = m
}

// SetDefaultRPCAPIKeyHeader sets the operator-wide header name used to forward
// the RPC API key (from the RPC_API_KEY_HEADER env var). Empty input means
// "use Authorization / Bearer" — the proxy default.
func (p *JSONRPCProcessor) SetDefaultRPCAPIKeyHeader(name string) {
	p.defaultRPCAPIKeyHeader = name
}

// resolveAPIKeyHeader returns the header name used to forward the upstream
// RPC API key. The header is operator-wide (set via the RPC_API_KEY_HEADER
// env var); there is no per-group override.
func (p *JSONRPCProcessor) resolveAPIKeyHeader() string {
	if p.defaultRPCAPIKeyHeader != "" {
		return p.defaultRPCAPIKeyHeader
	}
	return proxy.DefaultAPIKeyHeader
}

// SetTxVisibilityStore configures the per-tx visibility provider for
// visibleTo feature. When set, the processor resolves visibleTo rules
// from the DB during response filtering and stores them during send.
func (p *JSONRPCProcessor) SetTxVisibilityStore(store rbac.TxVisibilityProvider) {
	p.txVisibilityStore = store
}

// logAccess logs an access entry using enhanced logging (with hash chain + SIEM) if available,
// falling back to the basic logger.
func (p *JSONRPCProcessor) logAccess(ctx context.Context, req *ProcessRequest, statusCode int, responseStatus ...int) {
	respStatus := statusCode
	if len(responseStatus) > 0 {
		respStatus = responseStatus[0]
	}

	// RD-1112 async path: append to the durable buffer and return; the sealer
	// chains, persists, and forwards to SIEM off the hot path. Best-effort
	// (matches the synchronous path): on append failure, log loudly and fall
	// back to basic chain-less logging so coverage never drops below today.
	if p.auditBuffer != nil {
		var params []byte
		if p.logParams && req.Params != nil {
			params = audit.RedactParams(req.Method, req.Params)
		}
		var rsp *int
		if respStatus != statusCode {
			rsp = &respStatus
		}
		rec := db.AccessLogRecord{
			ExternalID:     req.UserID,
			Method:         req.Method,
			StatusCode:     statusCode,
			IPAddress:      req.ClientIP,
			CorrelationID:  req.CorrelationID,
			Params:         params,
			ResponseStatus: rsp,
			OrgID:          req.resolvedOrgID, // RD-1135
			DenialReason:   req.denialReason,  // RD-1137
		}
		if data, mErr := json.Marshal(rec); mErr != nil {
			slog.Error("audit record marshal failed; basic logging fallback", "error", mErr)
			p.accessLogger.LogAccess(ctx, req.UserID, req.Method, statusCode, req.ClientIP)
		} else if _, aErr := p.auditBuffer.Append(data); aErr != nil {
			slog.Error("audit buffer append failed; basic logging fallback (entry not chained)", "error", aErr)
			p.accessLogger.LogAccess(ctx, req.UserID, req.Method, statusCode, req.ClientIP)
		}
		return
	}

	if p.enhancedLogger != nil && p.hashChain != nil {
		var params []byte
		if p.logParams && req.Params != nil {
			params = audit.RedactParams(req.Method, req.Params)
		}

		var respStatusPtr *int
		if respStatus != statusCode {
			respStatusPtr = &respStatus
		}

		// RD-858: single-statement INSERT with entry_hash set atomically.
		// Closes the pre-fix race where a process crash between
		// LogAccessEnhanced and UpdateAccessLogHash left entry_hash
		// NULL — a state the verifier cannot distinguish from
		// tampering. The chain advances only when the INSERT commits.
		id, createdAt, hash, err := p.enhancedLogger.LogAccessChained(
			ctx,
			p.hashChain,
			req.UserID, req.Method, statusCode, req.ClientIP, req.CorrelationID,
			params, respStatusPtr, req.resolvedOrgID, req.denialReason,
		)
		if err != nil {
			// Fallback to basic logging
			p.accessLogger.LogAccess(ctx, req.UserID, req.Method, statusCode, req.ClientIP)
			return
		}
		_ = id

		// Forward to SIEM if configured
		if p.siemForwarder != nil {
			outcome := "success"
			if statusCode >= 400 {
				outcome = "denied"
			}
			if statusCode >= 500 {
				outcome = "error"
			}
			event := audit.SIEMEvent{
				Timestamp:     createdAt,
				EventType:     "access",
				CorrelationID: req.CorrelationID,
				ActorID:       req.UserID,
				Action:        req.Method,
				Outcome:       outcome,
				Details:       fmt.Sprintf("decision=%d response=%d", statusCode, respStatus),
				SourceIP:      req.ClientIP,
				EntryHash:     hash,
			}
			// Tag wildcard-resolved methods so SIEM consumers can filter on the
			// passthrough surface independently from explicitly-listed methods.
			if w := rbac.MatchWildcard(req.Method); w != nil {
				event.MatchedVia = "wildcard"
				event.MatchedPrefix = w.Prefix
			}
			p.siemForwarder.Send(event)
		}
		return
	}

	// Fallback to basic logging
	p.accessLogger.LogAccess(ctx, req.UserID, req.Method, statusCode, req.ClientIP)
}

// NewJSONRPCProcessorWithTracing creates a new processor with runtime tracing support.
func NewJSONRPCProcessorWithTracing(
	rbacCtrl *rbac.AccessController,
	rateLimiter RateLimiterInterface,
	proxyClient *proxy.Proxy,
	logger AccessLogger,
	runtimeTracer *tracer.RuntimeTracer,
	traceValidator *rbac.TraceValidator,
	cb *CircuitBreaker,
	cl *ConcurrencyLimiter,
	defaultAPIKey string,
) *JSONRPCProcessor {
	return &JSONRPCProcessor{
		rbacAccessCtrl:     rbacCtrl,
		rateLimiter:        rateLimiter,
		proxy:              proxyClient,
		accessLogger:       logger,
		runtimeTracer:      runtimeTracer,
		traceValidator:     traceValidator,
		circuitBreaker:     cb,
		concurrencyLimiter: cl,
		defaultRPCAPIKey:   defaultAPIKey,
	}
}

// ParseAndValidateBody parses and validates the JSON-RPC request body.
// Returns the method, params, and any validation error.
func ParseAndValidateBody(body []byte) (string, []any, *ProcessError) {
	if len(body) > MaxRequestBodySize {
		return "", nil, &ProcessError{
			StatusCode: http.StatusRequestEntityTooLarge,
			Message:    "request body too large",
		}
	}

	method, params, err := proxy.ParseRequest(body)
	if err != nil {
		if err == proxy.ErrBatchRequest {
			return "", nil, &ProcessError{
				StatusCode: http.StatusBadRequest,
				Message:    "batch JSON-RPC requests are not supported for security reasons",
			}
		}
		// Opaque client message; raw parse error (echoes offsets / body shape)
		// stays in slog. (RD-1178 / RD-934)
		slog.Warn("invalid JSON-RPC request", slog.Any("err", err))
		return "", nil, &ProcessError{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid JSON-RPC request",
		}
	}

	return method, params, nil
}

// Process handles the core business logic for a JSON-RPC request:
// 1. RBAC access check
// 2. Runtime tracing (if enabled, for eth_sendTransaction and eth_sendRawTransaction)
// 3. Rate limiting
// 4. Forwarding to the target node
func (p *JSONRPCProcessor) Process(ctx context.Context, req *ProcessRequest) *ProcessResult {
	start := time.Now()

	// Handle eth_sendRawTransaction specially - requires runtime tracing
	if req.Method == "eth_sendRawTransaction" {
		return p.processRawTransaction(ctx, req)
	}

	// Handle debug traces specially - requires strict deep tree validation
	if req.Method == "debug_traceTransaction" || req.Method == "debug_traceCall" {
		return p.processDebugTrace(ctx, req)
	}

	// Resolve method alias for access control (e.g. linea_estimateGas → eth_estimateGas).
	// The alias determines which access control rules apply (contract checks, storage tiering, etc.)
	// while the original method name is kept for the RBAC allowlist check and node forwarding.
	accessMethod := rbac.ResolveMethodAlias(req.Method)

	// Build RBAC access check request using the alias for target/selector extraction
	var requiredClaims []rbac.Claim
	if claim := rbac.ClassifyOperation(accessMethod, req.Params); claim != "" {
		requiredClaims = []rbac.Claim{claim}
	}

	targetAddr := rbac.GetTargetAddress(accessMethod, req.Params)

	accessReq := &rbac.AccessCheckRequest{
		UserExternalID:   req.UserID,
		OrgID:            req.OrgID,
		Method:           req.Method,
		AccessMethod:     accessMethod,
		Params:           req.Params,
		TargetAddress:    targetAddr,
		FunctionSelector: rbac.GetFunctionSelector(accessMethod, req.Params),
		RequiredClaims:   requiredClaims,
		BypassCache:      req.BypassPermsCache,
	}

	// Check RBAC access
	result, err := p.rbacAccessCtrl.CheckAccess(ctx, accessReq)
	if err != nil {
		slog.Error("RBAC access check failed", "method", req.Method, "error", err)
		p.recordRPCOutcome(req.Method, "error", start)
		p.logAccess(ctx, req, http.StatusInternalServerError, http.StatusNotFound)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusNotFound,
				Message:    "method not found",
			},
		}
	}

	// RD-1135: stamp the resolved org onto subsequent access-log rows (RBAC
	// denial, concurrency/rate-limit, trace denials, success). Write-once;
	// empty stays NULL (anonymous / org-free metadata) → super-admin-only.
	req.resolvedOrgID = result.OrgID

	if !result.Allowed {
		realStatus := http.StatusForbidden
		req.denialReason = ReasonMethodNotAllowed
		if result.AuthRequired {
			realStatus = http.StatusUnauthorized
			req.denialReason = ReasonAuthRequired
		}
		slog.Info("RBAC access denied", "method", req.Method, "user", req.UserID, "ip", req.ClientIP, "auth_required", result.AuthRequired)
		slog.Debug("RBAC denial details", "method", req.Method, "user", req.UserID, "reason", result.Reason)
		p.recordRPCOutcome(req.Method, "rbac_denied", start)
		p.recordRBACDecision("denied")
		p.logAccess(ctx, req, realStatus, http.StatusNotFound)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusNotFound,
				Message:    "method not found",
			},
		}
	}
	p.recordRBACDecision("allowed")

	// Concurrency gate moves ABOVE the trace path (RD-915 F5). Pre-RD-915
	// fix this sat below the trace, which meant a single JWT could pin N
	// upstream debug_traceCall connections concurrently (N == request rate
	// over the trace's wall-clock window) before any limiter fired. The
	// 5s per-trace timeout caps individual cost; only the limiter caps
	// aggregate. Acquire before trace so the cap covers the trace itself.
	if p.concurrencyLimiter != nil && !p.concurrencyLimiter.TryAcquire(req.UserID) {
		if p.metrics != nil {
			p.metrics.ConcurrencyRejectionsTotal.Inc()
		}
		p.recordRPCOutcome(req.Method, "concurrent_limit", start)
		req.denialReason = ReasonConcurrencyLimited // RD-1137
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusTooManyRequests,
				Message:    "too many concurrent requests",
			},
		}
	}
	if p.concurrencyLimiter != nil {
		defer p.concurrencyLimiter.Release(req.UserID)
	}

	// Runtime tracing: validate all call targets for eth_sendTransaction
	runtimeCreateTargets, traceErr := p.validateWithTracing(ctx, req, targetAddr)
	if traceErr != nil {
		p.recordRPCOutcome(req.Method, "send_trace_denied", start)
		// RD-1137: log the REAL status (not a hardcoded 403) + curated reason.
		req.denialReason = traceErr.Reason
		p.logAccess(ctx, req, traceErr.StatusCode)
		return &ProcessResult{
			Error: traceErr,
		}
	}

	// RD-915: runtime trace eth_call to enforce cross-org isolation on
	// internal calls. Without this the entry-point access check is the
	// only gate, and a same-org wrapper contract can STATICCALL into a
	// foreign-org private contract and bubble up the result. No caching
	// (proxy-pattern contracts can re-target via storage rewrites).
	if ethCallTraceErr := p.validateEthCallWithTracing(ctx, req, targetAddr); ethCallTraceErr != nil {
		p.recordRPCOutcome(req.Method, "eth_call_trace_denied", start)
		// RD-1137: log the REAL status (not a hardcoded 403) + curated reason —
		// this is what surfaces "sender_not_linked" etc. in the admin Access
		// Logs view instead of an opaque 403.
		req.denialReason = ethCallTraceErr.Reason
		p.logAccess(ctx, req, ethCallTraceErr.StatusCode)
		return &ProcessResult{
			Error: ethCallTraceErr,
		}
	}

	// Travel rule compliance check (after RBAC + tracing, before rate limiting)
	if req.Method == "eth_sendTransaction" {
		from, to, data, value := extractTxParams(req.Params)
		if compErr := p.checkCompliance(ctx, req, result.OrgID, result.UserID, from, to, data, value); compErr != nil {
			return compErr
		}
	}

	// Extract and strip visibleTo from eth_sendTransaction before forwarding.
	// Only accepted on contract calls (tx with data field) — plain ETH transfers
	// have no event logs, so visibleTo is rejected for them.
	var visibleTo []string
	if req.Method == "eth_sendTransaction" {
		// RD-1163: accept a top-level `visibleTo`/`privateFor` (DIDs and/or ETH
		// addresses, resolved fail-closed) alongside the params[0] form; union
		// them. Top-level is read first — the param extractor rebuilds the body
		// and would otherwise drop the top-level field before it is read.
		topRaw := extractAndStripTopLevelVisibleTo(req)
		paramDIDs := extractAndStripVisibleTo(req)
		var resolver ethAddressResolver
		if r, ok := p.rbacAccessCtrl.Store().(ethAddressResolver); ok {
			resolver = r
		}
		resolvedTop, capErr := resolveTopLevelVisibleTo(ctx, resolver, topRaw)
		if capErr != nil {
			return &ProcessResult{Error: capErr}
		}
		visibleTo = unionVisibleToDIDs(paramDIDs, resolvedTop)
		if len(visibleTo) > visibleToMaxSize {
			return &ProcessResult{
				Error: &ProcessError{
					StatusCode: http.StatusBadRequest,
					Message:    fmt.Sprintf("visibleTo list exceeds maximum size of %d entries", visibleToMaxSize),
				},
			}
		}
		if len(visibleTo) > 0 {
			_, to, data, _ := extractTxParams(req.Params)
			if isSimpleValueTransfer(data) || to == "" || to == "0x" {
				return &ProcessResult{
					Error: &ProcessError{
						StatusCode: http.StatusBadRequest,
						Message:    "visibleTo is only supported for contract calls that emit event logs",
					},
				}
			}
		}
	}

	// Concurrency limit acquired earlier (above the trace path) — see
	// the block following recordRBACDecision("allowed").

	// Resolve API key (group-specific or default)
	apiKey := result.RPCAPIKey
	if apiKey == "" {
		apiKey = p.defaultRPCAPIKey
	}
	apiKeyHeader := p.resolveAPIKeyHeader()

	// Check circuit breaker
	if p.circuitBreaker != nil && p.circuitBreaker.IsOpen(apiKey) {
		if p.metrics != nil {
			p.metrics.CircuitBreakerTripsTotal.WithLabelValues(maskAPIKey(apiKey)).Inc()
		}
		p.recordRPCOutcome(req.Method, "circuit_open", start)
		req.denialReason = ReasonRateLimited // RD-1137 (upstream rate limited)
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusTooManyRequests,
				Message:    "upstream rate limited, retry in 1s",
			},
		}
	}

	// Pre-register plain CREATE deployments to close the cross-org race window.
	// We do this as late as possible (after rate limiting) to avoid orphaned rows.
	var plainCreatePreRegAddr string
	if req.Method == "eth_sendTransaction" {
		from, to, _, _ := extractTxParams(req.Params)
		isPlainCreate := from != "" && (to == "" || to == "0x")
		if isPlainCreate {
			var preErr error
			plainCreatePreRegAddr, preErr = p.preRegisterPlainCreate(ctx, result.OrgID, result.UserID, req.Params)
			if preErr != nil {
				// Non-fatal: log and continue without pre-registration.
				// The cross-org window remains open for this tx, but the tx still proceeds.
				slog.Warn("plain CREATE pre-registration failed", "error", preErr)
				plainCreatePreRegAddr = ""
			}
		}
	}

	// Pre-register runtime CREATE/CREATE2 addresses discovered during trace validation.
	var runtimeCreateAddrs []string
	if len(runtimeCreateTargets) > 0 && req.Method == "eth_sendTransaction" {
		runtimeCreateAddrs = p.preRegisterRuntimeCreates(ctx, result.OrgID, runtimeCreateTargets)
	}

	// Prepare forward body by rewriting certain queries to ensure we get full tx objects
	forwardBody := req.Body
	if req.Method == "eth_getBlockByNumber" || req.Method == "eth_getBlockByHash" {
		isFull := false // JSON-RPC spec defaults missing to false (hashes only)
		if len(req.Params) >= 2 {
			if val, ok := req.Params[1].(bool); ok {
				isFull = val
			}
		}
		if !isFull {
			if rewriten := rewriteToFullTxObjects(req.Body, req.Params); rewriten != nil {
				forwardBody = rewriten
			}
		}
	} else if req.Method == "eth_getBlockTransactionCountByNumber" {
		if rewriten := rewriteToGetBlock(req.Body, "eth_getBlockByNumber", req.Params); rewriten != nil {
			forwardBody = rewriten
		}
	} else if req.Method == "eth_getBlockTransactionCountByHash" {
		if rewriten := rewriteToGetBlock(req.Body, "eth_getBlockByHash", req.Params); rewriten != nil {
			forwardBody = rewriten
		}
	}

	// Forward to node
	forwardStart := time.Now()
	responseBody, statusCode, err := p.proxy.ForwardWithAPIKeyHeader(forwardBody, apiKeyHeader, apiKey, req.ClientIP)
	if p.metrics != nil {
		p.metrics.RPCNodeForwardDuration.WithLabelValues(metrics.NormalizeRPCMethod(req.Method)).Observe(time.Since(forwardStart).Seconds())
	}

	// Circuit breaker: track upstream 429s
	if p.circuitBreaker != nil {
		if statusCode == http.StatusTooManyRequests {
			if p.metrics != nil {
				p.metrics.UpstreamRateLimitTotal.WithLabelValues(maskAPIKey(apiKey)).Inc()
			}
			p.circuitBreaker.Trip(apiKey)
		} else if statusCode == http.StatusOK {
			p.circuitBreaker.Reset(apiKey)
		}
	}
	if err != nil {
		p.recordRPCOutcome(req.Method, "forward_error", start)
		req.denialReason = ReasonUpstreamError // RD-1137
		p.logAccess(ctx, req, http.StatusBadGateway)
		// Opaque client message; the raw upstream error (node URL, dial/TLS
		// internals) stays in slog. (RD-1178 / RD-934)
		slog.Warn("failed to forward request", slog.String("method", req.Method), slog.String("user", req.UserID), slog.Any("err", err))
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusBadGateway,
				Message:    "failed to forward request",
			},
		}
	}

	// Handle plain CREATE pre-registration tracking/cleanup.
	if plainCreatePreRegAddr != "" {
		var rpcResp struct {
			Result string `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		nodeAccepted := statusCode == http.StatusOK &&
			err == nil &&
			json.Unmarshal(responseBody, &rpcResp) == nil &&
			rpcResp.Error == nil &&
			rpcResp.Result != ""

		if nodeAccepted {
			// Track and start background receipt polling.
			p.rbacAccessCtrl.TrackPlainCreateDeployment(rpcResp.Result, result.OrgID, result.UserID, plainCreatePreRegAddr)
			p.pollAndFinalizePlainCreate(rpcResp.Result, plainCreatePreRegAddr, result.OrgID, result.UserID)
		} else {
			// Node rejected the tx — delete the pre-registration immediately.
			if delErr := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
				context.Background(), plainCreatePreRegAddr); delErr != nil {
				slog.Warn("failed to clean up plain CREATE pre-registration", "address", plainCreatePreRegAddr, "error", delErr)
			}
		}
	}

	// Handle runtime CREATE/CREATE2 tracking/cleanup.
	if len(runtimeCreateAddrs) > 0 {
		var rpcResp2 struct {
			Result string `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		nodeAccepted := statusCode == http.StatusOK &&
			err == nil &&
			json.Unmarshal(responseBody, &rpcResp2) == nil &&
			rpcResp2.Error == nil &&
			rpcResp2.Result != ""

		if nodeAccepted {
			go p.pollAndFinalizeRuntimeCreates(rpcResp2.Result, runtimeCreateAddrs, result.OrgID, result.UserID)
		} else {
			// Node rejected — clean up pre-registrations
			for _, addr := range runtimeCreateAddrs {
				if delErr := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
					context.Background(), addr); delErr != nil {
					slog.Warn("failed to clean up runtime create pre-registration", "address", addr, "error", delErr)
				}
			}
		}
	}

	// NOTE: eth_sendTransaction is NOT system-linked here. Unlike eth_sendRawTransaction,
	// the `from` field comes from user-supplied params and is not cryptographically verified
	// by the proxy — only the Ethereum node verifies that the account is unlocked.
	// In a shared-node environment (e.g., Anvil with multiple unlocked accounts), a user
	// could forge any unlocked address as `from`. System-linking is only safe for
	// eth_sendRawTransaction where the sender is recovered from the signature.

	// M7 (security audit follow-up): write the visibleTo rule into the
	// outbox (pending_tx_visibility). A background reconciler (5s
	// ticker) promotes it to tx_visible_to. This survives DB hiccups —
	// the row stays in the outbox until the next reconciler tick. If
	// the outbox INSERT itself fails (which means the DB is completely
	// unreachable, a much rarer condition than the original
	// SaveTxVisibility race) we still log with the full recipient
	// count + sender + org for manual replay.
	//
	// The reconciler-driven model adds a small (≤ 5s) latency between
	// "tx on-chain" and "recipients can see it in explorer", which is
	// dominated by block-confirmation latency anyway.
	if len(visibleTo) > 0 && statusCode == http.StatusOK {
		if txHash := extractTxHashFromResult(responseBody); txHash != "" {
			if saver, ok := p.txVisibilityStore.(TxVisibilitySaver); ok {
				if err := saver.EnqueuePendingTxVisibility(ctx, txHash, visibleTo, req.UserID, result.OrgID); err != nil {
					slog.Error("visibleTo outbox enqueue failed; tx is on-chain but recipients won't see it",
						"tx", txHash, "recipients", len(visibleTo), "sender", req.UserID, "org", result.OrgID, "error", err)
				}
			}
		}
	}

	// RD-1206: enqueue method-policy record captures for this send (independent
	// of visibleTo — a create still captures payer/payee from sender/params).
	if statusCode == http.StatusOK {
		if txHash := extractTxHashFromResult(responseBody); txHash != "" {
			_, to, data, _ := extractTxParams(req.Params)
			p.enqueueMethodPolicyCaptures(ctx, req, to, data, visibleTo, txHash)
		}
	}

	// Apply response-level privacy filtering based on method.
	// This filters responses to prevent cross-participant data leakage
	// within the same organization.
	responseBody = p.applyResponseFilter(ctx, req, result, responseBody)

	// Log successful access
	p.recordRPCOutcome(req.Method, "success", start)
	p.logAccess(ctx, req, statusCode)

	return &ProcessResult{
		StatusCode:   statusCode,
		ResponseBody: responseBody,
	}
}

// viewerUUID extracts the internal user UUID from an AccessCheckResult,
// returning "" if the result is nil. The empty string is the safe input
// for viewerAdminContracts (which short-circuits to an empty admin map),
// matching the visibleTo-only fallback path where the viewer has no
// CheckAccess result but is still a legitimate visibleTo recipient.
func viewerUUID(result *rbac.AccessCheckResult) string {
	if result == nil {
		return ""
	}
	return result.UserID
}

// applyResponseFilter applies response-level privacy filters based on the JSON-RPC method.
// This prevents co-participants of the same contract from seeing each other's
// transaction data, event logs, and receipts.
//
// Filters applied:
//   - eth_getTransactionByHash: null for non-participants
//   - eth_getTransactionReceipt: null for non-participants
//   - eth_getLogs: remove log entries where user's address is not in indexed topics
//   - eth_getTransactionByBlockHashAndIndex / eth_getTransactionByBlockNumberAndIndex: null for non-participants
//   - eth_getBlockByHash / eth_getBlockByNumber: remove non-participant txs from block
//   - eth_getBlockReceipts: remove non-participant receipts from array
func (p *JSONRPCProcessor) applyResponseFilter(ctx context.Context, req *ProcessRequest, result *rbac.AccessCheckResult, responseBody []byte) []byte {
	// Resolve method alias so chain-specific methods (e.g. linea_getTransactionExclusionStatusV1)
	// inherit the same response filtering as their standard equivalents.
	m := rbac.ResolveMethodAlias(req.Method)
	switch {
	case strings.EqualFold(m, rbac.MethodGetTransactionByHash):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil {
			addrs = nil // DB error — proceed with nil addrs; visibleTo + admin bypass still apply
		}
		// Org-scoped admin bypass: compute whether the viewer has the
		// admin claim in the tx's `to` contract's OWNING org specifically
		// (not merged across all orgs the viewer belongs to). See
		// viewerAdminContracts doc for why.
		// IMPORTANT: viewerAdminContracts takes the internal user UUID
		// (result.UserID), NOT the JWT DID — internally it queries
		// user_memberships.user_id, which is the UUID FK. Passing the
		// DID silently returns no matches and the bypass never fires.
		// `result` may be nil on the visibleTo-only fallback path
		// (the visibleTo recipient may not have a CheckAccess result);
		// guard accordingly — empty userID makes viewerAdminContracts
		// short-circuit to an empty map, the right answer when the
		// viewer can't be admin-resolved.
		contractAddrs := extractContractAddressesFromResponse(responseBody)
		adminMap := p.viewerAdminContracts(ctx, viewerUUID(result), contractAddrs)
		isAdminOnTo := false
		for addr := range adminMap {
			if adminMap[addr] {
				isAdminOnTo = true
				break // tx-by-hash response has at most one `to`
			}
		}
		filtered := FilterTransactionByHash(responseBody, addrs, isAdminOnTo)
		// If participant + admin check returned null, check visibleTo as fallback
		if isNullResult(filtered) && p.isResponseTxVisibleTo(ctx, req.UserID, responseBody) {
			return responseBody
		}
		return filtered

	case strings.EqualFold(m, rbac.MethodGetTransactionReceipt):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil {
			addrs = nil // DB error — proceed with nil addrs, visCtx handles visibleTo
		}
		perms := p.resolvePermsForFilter(ctx, result)
		visCtx := p.buildTxVisibilityContext(ctx, req.UserID, responseBody)
		// Org-scoped admin map covers both the receipt-envelope bypass
		// (for receipt.to) and the per-log admin bypass (for each log's
		// emitting contract). Filter handles the lookup.
		// Pass the internal user UUID (result.UserID), not the JWT DID.
		// viewerUUID() guards against nil result (visibleTo-only path).
		adminMap := p.viewerAdminContracts(ctx, viewerUUID(result), extractContractAddressesFromResponse(responseBody))
		return FilterReceiptLogsWithEventRules(responseBody, addrs, perms, p.contractABIProvider(ctx), visCtx, adminMap)

	case strings.EqualFold(m, rbac.MethodGetLogs):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil {
			// DB error — fail closed
			id := rpcResponseID(responseBody)
			return []byte(`{"jsonrpc":"2.0","id":` + id + `,"result":[]}`)
		}
		// Note: empty addrs is OK — user may have no linked ETH addresses but
		// still has visibleTo entries. The filter handles this via visCtx.
		perms := p.resolvePermsForFilter(ctx, result)
		visCtx := p.buildTxVisibilityContext(ctx, req.UserID, responseBody)
		// RD-1162: admit logs of transactions the caller participated in
		// (their linked address is the tx from/to) even when the event carries
		// no address of theirs — bounded in FilterEventLogs by contract-grant
		// access. Senders aren't present in log entries, so resolve them via a
		// batched upstream eth_getTransactionByHash (a no-op when the caller has
		// no linked addresses or the unique-tx count exceeds the cap).
		if participants := p.buildParticipantTxHashes(addrs, responseBody); len(participants) > 0 {
			if visCtx == nil {
				visCtx = &rbac.TxVisibilityContext{ViewerDID: req.UserID}
			}
			visCtx.ParticipantTxHashes = participants
		}
		// Org-scoped admin-bypass map, indexed by each log's emitting
		// contract. Takes the internal user UUID (result.UserID), not
		// the JWT DID — viewerAdminContracts queries user_memberships
		// by UUID FK. viewerUUID() guards against nil result.
		adminMap := p.viewerAdminContracts(ctx, viewerUUID(result), extractContractAddressesFromResponse(responseBody))
		return FilterLogsWithEventRules(responseBody, addrs, perms, p.contractABIProvider(ctx), visCtx, adminMap)

	case strings.EqualFold(m, rbac.MethodGetTransactionByBlockHashAndIndex),
		strings.EqualFold(m, rbac.MethodGetTransactionByBlockNumberAndIndex):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil {
			addrs = nil // DB error — proceed with nil addrs; visibleTo + admin bypass still apply
		}
		// Pass the internal user UUID (result.UserID), not the JWT DID.
		// viewerUUID() guards against nil result.
		adminMap := p.viewerAdminContracts(ctx, viewerUUID(result), extractContractAddressesFromResponse(responseBody))
		isAdminOnTo := false
		for _, v := range adminMap {
			if v {
				isAdminOnTo = true
				break
			}
		}
		filtered := FilterTransactionByHash(responseBody, addrs, isAdminOnTo)
		// If participant + admin check returned null, check visibleTo as fallback
		if isNullResult(filtered) && p.isResponseTxVisibleTo(ctx, req.UserID, responseBody) {
			return responseBody
		}
		return filtered

	case strings.EqualFold(m, rbac.MethodGetBlockByHash),
		strings.EqualFold(m, rbac.MethodGetBlockByNumber):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil {
			// RD-1176: fail CLOSED. nil addrs match nothing, so the block's
			// transactions are filtered out rather than served unfiltered
			// (matches the sibling getBlockTransactionCount/getTransactionByHash
			// handlers). Previously this returned the raw block on a transient
			// linked-address DB error, leaking every participant's txs.
			addrs = nil
		}

		originalFull := false // JSON-RPC defaults false
		if len(req.Params) >= 2 {
			if isFull, ok := req.Params[1].(bool); ok {
				originalFull = isFull
			}
		}
		return FilterBlockTransactions(responseBody, addrs, originalFull)

	case strings.EqualFold(m, "eth_getBlockTransactionCountByHash"),
		strings.EqualFold(m, "eth_getBlockTransactionCountByNumber"):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil {
			return FilterBlockTransactionCount(responseBody, nil)
		}
		return FilterBlockTransactionCount(responseBody, addrs)

	case strings.EqualFold(m, rbac.MethodGetBlockReceipts):
		addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if err != nil {
			// RD-1176: fail CLOSED (nil addrs match nothing) rather than
			// serving the raw receipts of every participant in the block.
			addrs = nil
		}
		return FilterBlockReceipts(responseBody, addrs)

	case strings.EqualFold(m, rbac.MethodCall):
		// RD-1206: per-record method access policy. Gates the already-forwarded
		// eth_call response by the target contract's policy (no second upstream
		// call). Passthrough when the contract has no policy or the method is
		// not a gated reader.
		return p.applyMethodPolicyGate(ctx, req, responseBody)
	}
	return responseBody
}

func rewriteToFullTxObjects(originalBody []byte, params []any) []byte {
	var newParams []any
	if len(params) >= 2 {
		newParams = make([]any, len(params))
		copy(newParams, params)
		newParams[1] = true
	} else {
		newParams = make([]any, 2)
		if len(params) == 1 {
			newParams[0] = params[0]
		}
		newParams[1] = true
	}

	var env struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		Params  []any           `json:"params"`
		ID      json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(originalBody, &env); err != nil {
		return nil
	}
	env.Params = newParams
	b, err := json.Marshal(env)
	if err != nil {
		return nil
	}
	return b
}

func rewriteToGetBlock(originalBody []byte, newMethod string, params []any) []byte {
	var env struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		Params  []any           `json:"params"`
		ID      json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(originalBody, &env); err != nil {
		return nil
	}
	env.Method = newMethod

	newParams := make([]any, 0, 2)
	if len(params) > 0 {
		newParams = append(newParams, params[0])
	} else {
		newParams = append(newParams, "latest")
	}
	newParams = append(newParams, true)

	env.Params = newParams
	b, err := json.Marshal(env)
	if err != nil {
		return nil
	}
	return b
}

// checkCompliance runs travel rule compliance checks if the checker is configured.
// Called from both eth_sendTransaction and eth_sendRawTransaction paths.
// Returns nil if compliance passes or is disabled, or a ProcessResult with an error.
func (p *JSONRPCProcessor) checkCompliance(ctx context.Context, req *ProcessRequest, orgID, userID, from, to, data, value string) *ProcessResult {
	if p.complianceChecker == nil {
		return nil
	}

	compStart := time.Now()
	compResult, compErr := p.complianceChecker.Check(ctx, &compliance.CheckRequest{
		OrgID:         orgID,
		UserID:        userID,
		From:          from,
		To:            to,
		Data:          data,
		Value:         value,
		CorrelationID: req.CorrelationID,
	})
	if p.metrics != nil {
		p.metrics.ComplianceCheckDuration.WithLabelValues().Observe(time.Since(compStart).Seconds())
	}
	if compErr != nil {
		if p.metrics != nil {
			p.metrics.ComplianceDecisionsTotal.WithLabelValues("error").Inc()
		}
		p.logAccess(ctx, req, http.StatusInternalServerError)
		// M1: don't echo the raw compliance error to the client — it can
		// carry token addresses, threshold values, sanction text, and
		// upstream price-service detail. Keep the verbose message in
		// slog; surface a generic 5xx to the caller.
		slog.Error("compliance check failed", "method", req.Method, "err", compErr)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusInternalServerError,
				Message:    "compliance check failed",
			},
		}
	}
	if !compResult.Allowed {
		if p.metrics != nil {
			p.metrics.ComplianceDecisionsTotal.WithLabelValues("denied").Inc()
		}
		p.logAccess(ctx, req, http.StatusForbidden)
		// M1: map the deny reason to a finite enum-style category before
		// echoing. Pre-fix, "no price configured for token 0x..." in the
		// response confirmed existence of a private contract — same
		// disclosure shape RD-916/917 closed elsewhere. Keep the full
		// reason in compliance_log + slog only.
		slog.Info("compliance denied", "method", req.Method, "reason", compResult.Reason)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusForbidden,
				Message:    "compliance denied: " + sanitizeComplianceReason(compResult.Reason),
			},
		}
	}
	if compResult.Monitored {
		// RD-1044: monitor mode allowed a would-block violation through. It is
		// recorded in compliance_logs with would_block=true; surface it
		// distinctly in metrics + logs so enforcement posture is never
		// ambiguous. Sanctions are never monitored — they still hard-block above.
		if p.metrics != nil {
			p.metrics.ComplianceDecisionsTotal.WithLabelValues("monitored").Inc()
		}
		slog.Warn("compliance MONITOR mode: transaction allowed despite violation",
			"method", req.Method, "reason", compResult.Reason)
		return nil
	}
	if p.metrics != nil {
		p.metrics.ComplianceDecisionsTotal.WithLabelValues("allowed").Inc()
	}

	return nil
}

// sanitizeComplianceReason maps a compliance deny reason to a finite
// enum-style category safe to echo to the JSON-RPC client. The full
// reason (which may contain token addresses, sanction text, threshold
// values, or upstream price-service detail) is preserved in
// compliance_log + slog only.
//
// Categories chosen to be operationally useful without revealing any
// per-tenant data. See security audit M1.
func sanitizeComplianceReason(in string) string {
	lower := strings.ToLower(in)
	switch {
	case strings.Contains(lower, "sanction"):
		return "sanctioned address"
	case strings.Contains(lower, "no price") || strings.Contains(lower, "price not") || strings.Contains(lower, "unknown_price"):
		return "transaction value cannot be computed"
	case strings.Contains(lower, "threshold"):
		return "transaction exceeds threshold"
	case strings.Contains(lower, "record") && strings.Contains(lower, "required"):
		return "travel-rule record required"
	case strings.Contains(lower, "originator"):
		return "originator validation failed"
	case strings.Contains(lower, "currency"):
		return "currency configuration error"
	default:
		return "transaction blocked by compliance policy"
	}
}

// isSimpleValueTransfer returns true if the transaction has no calldata.
// Note: this alone is NOT sufficient to skip tracing - the caller must also
// verify the target is an EOA (not a contract) via eth_getCode, because
// contracts can execute receive()/fallback() which may make cross-org calls.
func isSimpleValueTransfer(data string) bool {
	// Normalize and check for empty calldata
	data = strings.TrimSpace(data)
	return data == "" || data == "0x" || data == "0X"
}

// processRawTransaction handles eth_sendRawTransaction with RLP decoding.
// This method is ONLY allowed when runtime tracing is enabled, because we need
// to trace all call targets to validate cross-org isolation.
func (p *JSONRPCProcessor) processRawTransaction(ctx context.Context, req *ProcessRequest) *ProcessResult {
	start := time.Now()

	// eth_sendRawTransaction requires runtime tracing for security
	if p.runtimeTracer == nil || !p.runtimeTracer.IsEnabled() {
		p.recordRPCOutcome(req.Method, "tracing_required", start)
		p.logAccess(ctx, req, http.StatusForbidden)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusForbidden,
				Message:    "eth_sendRawTransaction requires runtime tracing to be enabled for security validation",
			},
		}
	}

	// Extract and decode the raw transaction
	rawTxHex, err := extractRawTxHex(req.Params)
	if err != nil {
		// Opaque client message; raw extract/RLP error stays in slog. (RD-1178 / RD-934)
		slog.Warn("invalid raw transaction", slog.String("user", req.UserID), slog.Any("err", err))
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusBadRequest,
				Message:    "invalid raw transaction",
			},
		}
	}

	// Decode RLP to get transaction details
	from, to, data, value, txNonce, err := decodeRawTransaction(rawTxHex)
	if err != nil {
		slog.Warn("failed to decode raw transaction", slog.String("user", req.UserID), slog.Any("err", err))
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusBadRequest,
				Message:    "failed to decode raw transaction",
			},
		}
	}

	// Determine the operation type and required claims.
	// Only deployments need a claim gate; write access is controlled by the
	// method allowlist (eth_sendTransaction must be in allowed_methods).
	var requiredClaims []rbac.Claim
	isDeployment := to == ""
	if isDeployment {
		requiredClaims = []rbac.Claim{rbac.ClaimDeploy}
	}

	// Build RBAC access check request
	// For raw transactions, we use eth_sendTransaction for classification
	// since the operation is equivalent
	accessReq := &rbac.AccessCheckRequest{
		UserExternalID:   req.UserID,
		OrgID:            req.OrgID,
		Method:           "eth_sendTransaction", // Use sendTransaction for RBAC classification
		Params:           buildTxParams(from, to, data, value),
		TargetAddress:    to,
		FunctionSelector: extractSelector(data),
		RequiredClaims:   requiredClaims,
	}

	// Check RBAC access
	result, err := p.rbacAccessCtrl.CheckAccess(ctx, accessReq)
	if err != nil {
		slog.Error("RBAC access check failed", "method", req.Method, "error", err)
		p.recordRPCOutcome(req.Method, "error", start)
		p.logAccess(ctx, req, http.StatusInternalServerError, http.StatusNotFound)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusNotFound,
				Message:    "method not found",
			},
		}
	}

	// RD-1135: stamp the resolved org onto subsequent access-log rows (RBAC
	// denial, concurrency/rate-limit, trace denials, success). Write-once;
	// empty stays NULL (anonymous / org-free metadata) → super-admin-only.
	req.resolvedOrgID = result.OrgID

	if !result.Allowed {
		realStatus := http.StatusForbidden
		req.denialReason = ReasonMethodNotAllowed
		if result.AuthRequired {
			realStatus = http.StatusUnauthorized
			req.denialReason = ReasonAuthRequired
		}
		slog.Info("RBAC access denied", "method", req.Method, "user", req.UserID, "ip", req.ClientIP, "auth_required", result.AuthRequired)
		slog.Debug("RBAC denial details", "method", req.Method, "user", req.UserID, "reason", result.Reason)
		p.recordRPCOutcome(req.Method, "rbac_denied", start)
		p.recordRBACDecision("denied")
		p.logAccess(ctx, req, realStatus, http.StatusNotFound)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusNotFound,
				Message:    "method not found",
			},
		}
	}
	p.recordRBACDecision("allowed")

	// Concurrency gate moves ABOVE the trace path (RD-915 F5). Mirrors
	// the Process() path. Acquire before any trace so the cap covers
	// the trace itself, not just downstream forwarding.
	if p.concurrencyLimiter != nil && !p.concurrencyLimiter.TryAcquire(req.UserID) {
		if p.metrics != nil {
			p.metrics.ConcurrencyRejectionsTotal.Inc()
		}
		p.recordRPCOutcome(req.Method, "concurrent_limit", start)
		req.denialReason = ReasonConcurrencyLimited // RD-1137
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusTooManyRequests,
				Message:    "too many concurrent requests",
			},
		}
	}
	if p.concurrencyLimiter != nil {
		defer p.concurrencyLimiter.Release(req.UserID)
	}

	// Runtime tracing validation. For non-deploy raw transactions
	// (to != "") and for deploys (to == ""). Pre-M10 deploys skipped
	// tracing entirely, leaving constructor frames unvalidated; M10
	// closes that by routing deploys through validateDeployWithTracing.
	// The bytecode analyzer keeps running as a thinner fallback for
	// operators without debug_* on the upstream node, but the
	// authoritative gate is the trace.
	var runtimeCreateTargets []rbac.CreateTarget
	if to != "" {
		skipTrace := false
		if isSimpleValueTransfer(data) {
			// Only skip tracing for simple value transfers to EOAs.
			// Contracts can execute receive()/fallback() which may make cross-org calls.
			hasCode, err := p.runtimeTracer.HasCode(ctx, to)
			if err == nil && !hasCode {
				skipTrace = true // EOA - safe to skip tracing
			}
			// If err or hasCode: fall through to tracing
		}
		if !skipTrace {
			rawRuntimeCreateTargets, traceErr := p.validateRawTxWithTracing(ctx, req, from, to, data, value)
			if traceErr != nil {
				p.recordRPCOutcome(req.Method, "send_trace_denied", start)
				req.denialReason = traceErr.Reason // RD-1137
				p.logAccess(ctx, req, traceErr.StatusCode)
				return &ProcessResult{
					Error: traceErr,
				}
			}
			runtimeCreateTargets = rawRuntimeCreateTargets
		}
	} else if p.runtimeTracer != nil && p.runtimeTracer.IsEnabled() {
		// M10: raw-tx contract deployment. Trace + validate.
		user, err := p.rbacAccessCtrl.Store().GetUserByExternalID(ctx, req.UserID)
		if err != nil || user == nil {
			p.recordRPCOutcome(req.Method, "send_trace_denied", start)
			req.denialReason = ReasonTracingUnavailable // RD-1137
			p.logAccess(ctx, req, http.StatusForbidden)
			return &ProcessResult{
				Error: &ProcessError{StatusCode: http.StatusForbidden, Message: sendTraceDenyTracerError, Reason: ReasonTracingUnavailable},
			}
		}
		memberships, err := p.rbacAccessCtrl.Store().ListUserMembershipsWithDetails(ctx, user.ID)
		if err != nil {
			p.recordRPCOutcome(req.Method, "send_trace_denied", start)
			req.denialReason = ReasonTracingUnavailable // RD-1137
			p.logAccess(ctx, req, http.StatusForbidden)
			return &ProcessResult{
				Error: &ProcessError{StatusCode: http.StatusForbidden, Message: sendTraceDenyTracerError, Reason: ReasonTracingUnavailable},
			}
		}
		userOrgIDs := make(map[string]bool)
		for _, m := range memberships {
			if m.Group != nil {
				userOrgIDs[m.Group.OrgID] = true
			}
		}
		userHasDeploy := p.userHasDeployClaim(ctx, memberships)
		deployTargets, traceErr := p.validateDeployWithTracing(ctx, req, user.ID, from, data, value, userOrgIDs, userHasDeploy)
		if traceErr != nil {
			p.recordRPCOutcome(req.Method, "send_trace_denied", start)
			req.denialReason = traceErr.Reason // RD-1137
			p.logAccess(ctx, req, traceErr.StatusCode)
			return &ProcessResult{
				Error: traceErr,
			}
		}
		runtimeCreateTargets = deployTargets
	}

	// Travel rule compliance check (after RBAC + tracing, before rate limiting)
	if compErr := p.checkCompliance(ctx, req, result.OrgID, result.UserID, from, to, data, value); compErr != nil {
		return compErr
	}

	// Extract and strip visibleTo before forwarding. RD-1163: accept a top-level
	// `visibleTo`/`privateFor` (DIDs and/or ETH addresses, resolved fail-closed)
	// alongside the params[1] form; union them. Top-level is read first (the param
	// extractor rebuilds the body and would otherwise drop it). Only accepted on
	// contract calls — plain transfers have no event logs.
	topRaw := extractAndStripTopLevelVisibleTo(req)
	paramDIDs := extractAndStripRawTxVisibleTo(req)
	var vtResolver ethAddressResolver
	if r, ok := p.rbacAccessCtrl.Store().(ethAddressResolver); ok {
		vtResolver = r
	}
	resolvedTop, capErr := resolveTopLevelVisibleTo(ctx, vtResolver, topRaw)
	if capErr != nil {
		return &ProcessResult{Error: capErr}
	}
	rawTxVisibleTo := unionVisibleToDIDs(paramDIDs, resolvedTop)
	if len(rawTxVisibleTo) > visibleToMaxSize {
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusBadRequest,
				Message:    fmt.Sprintf("visibleTo list exceeds maximum size of %d entries", visibleToMaxSize),
			},
		}
	}
	if len(rawTxVisibleTo) > 0 {
		if isSimpleValueTransfer(data) || to == "" {
			return &ProcessResult{
				Error: &ProcessError{
					StatusCode: http.StatusBadRequest,
					Message:    "visibleTo is only supported for contract calls that emit event logs",
				},
			}
		}
	}

	// Concurrency limit acquired earlier (above the trace path) — see
	// the block following recordRBACDecision("allowed") in this function.

	// Resolve API key (group-specific or default)
	apiKey := result.RPCAPIKey
	if apiKey == "" {
		apiKey = p.defaultRPCAPIKey
	}
	apiKeyHeader := p.resolveAPIKeyHeader()

	// Check circuit breaker
	if p.circuitBreaker != nil && p.circuitBreaker.IsOpen(apiKey) {
		if p.metrics != nil {
			p.metrics.CircuitBreakerTripsTotal.WithLabelValues(maskAPIKey(apiKey)).Inc()
		}
		p.recordRPCOutcome(req.Method, "circuit_open", start)
		req.denialReason = ReasonRateLimited // RD-1137 (upstream rate limited)
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusTooManyRequests,
				Message:    "upstream rate limited, retry in 1s",
			},
		}
	}

	// Pre-register plain CREATE for raw transactions (nonce is embedded in the signed tx).
	var rawTxPlainCreateAddr string
	if isDeployment {
		fromAddr := gethcommon.HexToAddress(from)
		contractAddr := gethcrypto.CreateAddress(fromAddr, txNonce)
		addrStr := strings.ToLower(contractAddr.Hex())
		note := fmt.Sprintf("plain CREATE pending (raw tx): deployer=%s org=%s", result.UserID, result.OrgID)
		if preErr := p.rbacAccessCtrl.Store().PreRegisterPlainCreate(ctx, result.OrgID, addrStr, note); preErr != nil {
			slog.Warn("plain CREATE pre-registration failed for raw tx", "error", preErr)
		} else {
			rawTxPlainCreateAddr = addrStr
		}
	}

	// Pre-register runtime CREATE/CREATE2 addresses discovered during trace validation.
	var runtimeCreateAddrs []string
	if len(runtimeCreateTargets) > 0 {
		runtimeCreateAddrs = p.preRegisterRuntimeCreates(ctx, result.OrgID, runtimeCreateTargets)
	}

	// Forward the original raw transaction to node
	forwardStart := time.Now()
	responseBody, statusCode, err := p.proxy.ForwardWithAPIKeyHeader(req.Body, apiKeyHeader, apiKey, req.ClientIP)
	if p.metrics != nil {
		p.metrics.RPCNodeForwardDuration.WithLabelValues(metrics.NormalizeRPCMethod(req.Method)).Observe(time.Since(forwardStart).Seconds())
	}

	// Circuit breaker: track upstream 429s
	if p.circuitBreaker != nil {
		if statusCode == http.StatusTooManyRequests {
			if p.metrics != nil {
				p.metrics.UpstreamRateLimitTotal.WithLabelValues(maskAPIKey(apiKey)).Inc()
			}
			p.circuitBreaker.Trip(apiKey)
		} else if statusCode == http.StatusOK {
			p.circuitBreaker.Reset(apiKey)
		}
	}

	if err != nil {
		p.recordRPCOutcome(req.Method, "forward_error", start)
		// Clean up pre-registration on forward failure.
		if rawTxPlainCreateAddr != "" {
			if delErr := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
				context.Background(), rawTxPlainCreateAddr); delErr != nil {
				slog.Warn("failed to clean up plain CREATE pre-registration", "address", rawTxPlainCreateAddr, "error", delErr)
			}
		}
		for _, addr := range runtimeCreateAddrs {
			if delErr := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
				context.Background(), addr); delErr != nil {
				slog.Warn("failed to clean up runtime create pre-registration on forward error", "address", addr, "error", delErr)
			}
		}
		p.logAccess(ctx, req, http.StatusBadGateway)
		// Opaque client message; raw upstream error stays in slog. (RD-1178 / RD-934)
		slog.Warn("failed to forward raw transaction", slog.String("method", req.Method), slog.String("user", req.UserID), slog.Any("err", err))
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusBadGateway,
				Message:    "failed to forward request",
			},
		}
	}

	// Handle plain CREATE pre-registration tracking/cleanup.
	if rawTxPlainCreateAddr != "" {
		var rpcResp struct {
			Result string `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		nodeAccepted := statusCode == http.StatusOK &&
			err == nil &&
			json.Unmarshal(responseBody, &rpcResp) == nil &&
			rpcResp.Error == nil &&
			rpcResp.Result != ""

		if nodeAccepted {
			// Track and start background receipt polling.
			p.rbacAccessCtrl.TrackPlainCreateDeployment(rpcResp.Result, result.OrgID, result.UserID, rawTxPlainCreateAddr)
			p.pollAndFinalizePlainCreate(rpcResp.Result, rawTxPlainCreateAddr, result.OrgID, result.UserID)
		} else {
			// Node rejected the tx — delete the pre-registration immediately.
			if delErr := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
				context.Background(), rawTxPlainCreateAddr); delErr != nil {
				slog.Warn("failed to clean up plain CREATE pre-registration", "address", rawTxPlainCreateAddr, "error", delErr)
			}
		}
	}

	// Handle runtime CREATE/CREATE2 tracking/cleanup.
	if len(runtimeCreateAddrs) > 0 {
		var rpcResp2 struct {
			Result string `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		nodeAccepted := statusCode == http.StatusOK &&
			err == nil &&
			json.Unmarshal(responseBody, &rpcResp2) == nil &&
			rpcResp2.Error == nil &&
			rpcResp2.Result != ""

		if nodeAccepted {
			go p.pollAndFinalizeRuntimeCreates(rpcResp2.Result, runtimeCreateAddrs, result.OrgID, result.UserID)
		} else {
			// Node rejected — clean up pre-registrations
			for _, addr := range runtimeCreateAddrs {
				if delErr := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
					context.Background(), addr); delErr != nil {
					slog.Warn("failed to clean up runtime create pre-registration", "address", addr, "error", delErr)
				}
			}
		}
	}

	// System-link the sender's ETH address to their DID.
	if statusCode == http.StatusOK && from != "" && req.UserID != "" {
		if err := p.rbacAccessCtrl.Store().SystemLinkEthAddress(ctx, req.UserID, from); err != nil {
			slog.Warn("failed to system-link eth address", "user", req.UserID, "address", from, "error", err)
		}
	}

	// M7 (security audit follow-up): write the raw-tx visibleTo rule
	// into the outbox; reconciler promotes to tx_visible_to. Same
	// rationale as the eth_sendTransaction path above.
	if len(rawTxVisibleTo) > 0 && statusCode == http.StatusOK {
		if txHash := extractTxHashFromResult(responseBody); txHash != "" {
			if saver, ok := p.txVisibilityStore.(TxVisibilitySaver); ok {
				if err := saver.EnqueuePendingTxVisibility(ctx, txHash, rawTxVisibleTo, req.UserID, result.OrgID); err != nil {
					slog.Error("visibleTo outbox enqueue failed for raw tx; tx is on-chain but recipients won't see it",
						"tx", txHash, "recipients", len(rawTxVisibleTo), "sender", req.UserID, "org", result.OrgID, "error", err)
				}
			}
		}
	}

	// RD-1206: enqueue method-policy record captures for this raw send. `to` and
	// `data` were decoded from the signed tx above; captures ride the same
	// receipt-confirmed outbox as visibleTo.
	if statusCode == http.StatusOK {
		if txHash := extractTxHashFromResult(responseBody); txHash != "" {
			p.enqueueMethodPolicyCaptures(ctx, req, to, data, rawTxVisibleTo, txHash)
		}
	}

	// Log successful access
	p.recordRPCOutcome(req.Method, "success", start)
	p.logAccess(ctx, req, statusCode)

	return &ProcessResult{
		StatusCode:   statusCode,
		ResponseBody: responseBody,
	}
}

// extractRawTxHex extracts the raw transaction hex from eth_sendRawTransaction params.
func extractRawTxHex(params []any) (string, error) {
	if len(params) == 0 {
		return "", fmt.Errorf("missing transaction parameter")
	}

	rawTxHex, ok := params[0].(string)
	if !ok {
		return "", fmt.Errorf("transaction parameter must be a string")
	}

	return rawTxHex, nil
}

// decodeRawTransaction decodes an RLP-encoded transaction and extracts its fields.
// Returns from (recovered from signature), to, data, value as hex strings, and the nonce.
func decodeRawTransaction(rawTxHex string) (from, to, data, value string, nonce uint64, err error) {
	// Remove 0x prefix
	rawTxHex = strings.TrimPrefix(rawTxHex, "0x")
	rawTxHex = strings.TrimPrefix(rawTxHex, "0X")

	// Decode hex to bytes
	rawTxBytes, err := hex.DecodeString(rawTxHex)
	if err != nil {
		return "", "", "", "", 0, fmt.Errorf("invalid hex: %w", err)
	}

	// Decode RLP transaction
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(rawTxBytes); err != nil {
		return "", "", "", "", 0, fmt.Errorf("failed to decode transaction: %w", err)
	}

	nonce = tx.Nonce()

	// Extract 'to' address (nil for contract creation)
	if tx.To() != nil {
		to = tx.To().Hex()
	}

	// Extract data
	if len(tx.Data()) > 0 {
		data = "0x" + hex.EncodeToString(tx.Data())
	}

	// Extract value
	if tx.Value() != nil && tx.Value().Sign() > 0 {
		value = "0x" + tx.Value().Text(16)
	}

	// Recover 'from' address from signature
	signer := types.LatestSignerForChainID(tx.ChainId())
	fromAddr, err := types.Sender(signer, tx)
	if err != nil {
		return "", "", "", "", 0, fmt.Errorf("failed to recover sender: %w", err)
	}
	from = fromAddr.Hex()

	return from, to, data, value, nonce, nil
}

// buildTxParams builds transaction params for RBAC checking.
func buildTxParams(from, to, data, value string) []any {
	txObj := map[string]any{
		"from": from,
	}
	if to != "" {
		txObj["to"] = to
	}
	if data != "" {
		txObj["data"] = data
	}
	if value != "" {
		txObj["value"] = value
	}
	return []any{txObj}
}

// extractSelector extracts the function selector from calldata.
func extractSelector(data string) string {
	if len(data) < 10 {
		return ""
	}
	return strings.ToLower(data[:10])
}

// extractEthCallBlockParam returns the block parameter from an eth_call
// param list (the second positional arg), validated to a shape geth's
// debug_traceCall will accept. Returns nil when omitted — the tracer
// falls back to "latest" in that case. The supported shapes are:
//
//   - string: a block tag ("latest", "earliest", "pending", "safe",
//     "finalized") or a 0x-prefixed hex block number ("0x1234").
//   - EIP-1898 object: {"blockNumber": "0x.."} or
//     {"blockHash": "0x..", "requireCanonical": bool}.
//
// Returns an error for any other shape — passing unknown JSON through to
// the upstream would let an attacker craft a malformed-but-different
// param that geth interprets as "latest" while the trace path receives
// something else, undoing the symmetry F2 is meant to establish.
func extractEthCallBlockParam(params []any) (any, error) {
	if len(params) < 2 {
		return nil, nil
	}
	if params[1] == nil {
		return nil, nil
	}
	switch v := params[1].(type) {
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		if s == "" {
			return nil, nil
		}
		switch s {
		case "latest", "earliest", "pending", "safe", "finalized":
			return s, nil
		}
		// Hex block number — must be 0x-prefixed and parse as hex.
		if strings.HasPrefix(s, "0x") && len(s) > 2 {
			for _, c := range s[2:] {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					return nil, fmt.Errorf("eth_call block tag: not hex")
				}
			}
			return s, nil
		}
		return nil, fmt.Errorf("eth_call block tag: unknown")
	case map[string]any:
		// EIP-1898 — accept blockNumber XOR blockHash, both hex.
		bn, hasNumber := v["blockNumber"]
		bh, hasHash := v["blockHash"]
		if !hasNumber && !hasHash {
			return nil, fmt.Errorf("eth_call block object: missing blockNumber/blockHash")
		}
		if hasNumber && hasHash {
			return nil, fmt.Errorf("eth_call block object: cannot set both blockNumber and blockHash")
		}
		check := func(val any) error {
			s, ok := val.(string)
			if !ok {
				return fmt.Errorf("not a string")
			}
			s = strings.ToLower(strings.TrimSpace(s))
			if !strings.HasPrefix(s, "0x") || len(s) <= 2 {
				return fmt.Errorf("not 0x-hex")
			}
			for _, c := range s[2:] {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					return fmt.Errorf("non-hex")
				}
			}
			return nil
		}
		if hasNumber {
			if err := check(bn); err != nil {
				return nil, fmt.Errorf("eth_call blockNumber: %w", err)
			}
		}
		if hasHash {
			if err := check(bh); err != nil {
				return nil, fmt.Errorf("eth_call blockHash: %w", err)
			}
		}
		return v, nil
	default:
		return nil, fmt.Errorf("eth_call block param: unsupported type %T", params[1])
	}
}

// extractTxParams extracts transaction parameters from eth_sendTransaction params.
func extractTxParams(params []any) (from, to, data, value string) {
	if len(params) == 0 {
		return
	}

	txObj, ok := params[0].(map[string]any)
	if !ok {
		return
	}

	if f, ok := txObj["from"].(string); ok {
		from = f
	}
	if t, ok := txObj["to"].(string); ok {
		to = t
	}
	if d, ok := txObj["data"].(string); ok {
		data = d
	} else if d, ok := txObj["input"].(string); ok {
		data = d
	}
	if v, ok := txObj["value"].(string); ok {
		value = v
	}

	return
}

// extractNonceFromTxParams reads the "nonce" field from eth_sendTransaction params.
// Returns (nonce, true) if present and parseable, (0, false) otherwise.
func extractNonceFromTxParams(params []any) (uint64, bool) {
	if len(params) == 0 {
		return 0, false
	}
	txObj, ok := params[0].(map[string]any)
	if !ok {
		return 0, false
	}
	nonceVal, exists := txObj["nonce"]
	if !exists {
		return 0, false
	}
	nonceStr, ok := nonceVal.(string)
	if !ok {
		return 0, false
	}
	hexStr := strings.TrimPrefix(nonceStr, "0x")
	n, err := strconv.ParseUint(hexStr, 16, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// getNonceFromNode fetches the pending transaction count (nonce) for an address from the node.
func (p *JSONRPCProcessor) getNonceFromNode(from string) (uint64, error) {
	reqBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionCount",
		"params":  []any{from, "pending"},
		"id":      1,
	})
	if err != nil {
		return 0, err
	}
	respBody, _, err := p.proxy.Forward(reqBody)
	if err != nil {
		return 0, fmt.Errorf("get nonce: %w", err)
	}
	var resp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return 0, fmt.Errorf("parse nonce response: %w", err)
	}
	if resp.Error != nil {
		return 0, fmt.Errorf("nonce RPC error: %s", resp.Error.Message)
	}
	hexStr := strings.TrimPrefix(resp.Result, "0x")
	nonce, err := strconv.ParseUint(hexStr, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("parse nonce hex %q: %w", resp.Result, err)
	}
	return nonce, nil
}

// preRegisterPlainCreate computes the deterministic CREATE address from (from, nonce)
// and inserts it into preregistered_addresses for the deployer's org.
// This closes the cross-org race window before the tx is forwarded.
// Returns the pre-registered address (lowercase, 0x-prefixed).
func (p *JSONRPCProcessor) preRegisterPlainCreate(ctx context.Context, orgID, userID string, params []any) (string, error) {
	from, _, _, _ := extractTxParams(params)
	if from == "" {
		return "", fmt.Errorf("plain CREATE: missing 'from' in tx params")
	}

	// Get nonce: prefer explicit value from params, fall back to node query.
	nonce, hasNonce := extractNonceFromTxParams(params)
	if !hasNonce {
		var err error
		nonce, err = p.getNonceFromNode(from)
		if err != nil {
			return "", fmt.Errorf("plain CREATE nonce: %w", err)
		}
	}

	// Compute the deterministic CREATE address: keccak256(rlp([from, nonce]))[12:]
	contractAddr := gethcrypto.CreateAddress(gethcommon.HexToAddress(from), nonce)
	addrStr := strings.ToLower(contractAddr.Hex())

	note := fmt.Sprintf("plain CREATE pending: deployer=%s org=%s", userID, orgID)
	if err := p.rbacAccessCtrl.Store().PreRegisterPlainCreate(ctx, orgID, addrStr, note); err != nil {
		return "", fmt.Errorf("pre-register plain CREATE: %w", err)
	}

	return addrStr, nil
}

// pollAndFinalizePlainCreate polls for the receipt of a plain CREATE deployment
// and calls NotifyDeploymentMined to finalize or clean up the pre-registration.
// Runs in a goroutine; gives up after maxAttempts with exponential backoff.
func (p *JSONRPCProcessor) pollAndFinalizePlainCreate(txHash, preRegisteredAddr, orgID, deployerUserID string) {
	const maxAttempts = 12
	const baseDelay = 2 * time.Second

	go func() {
		ctx := context.Background()
		for attempt := 0; attempt < maxAttempts; attempt++ {
			if attempt > 0 {
				delay := baseDelay * time.Duration(1<<uint(attempt-1))
				if delay > 60*time.Second {
					delay = 60 * time.Second
				}
				time.Sleep(delay)
			}

			contractAddr, err := p.getTransactionReceipt(txHash)
			if err != nil {
				// Receipt not available yet — retry.
				continue
			}

			// Receipt obtained (contractAddr is "" on revert).
			if err := p.rbacAccessCtrl.NotifyDeploymentMined(ctx, txHash, contractAddr); err != nil {
				// Revert or finalization issue — logged inside NotifyDeploymentMined.
				slog.Warn("plain CREATE finalization failed", "tx_hash", txHash, "error", err)
			}
			return
		}

		// Exhausted retries — clean up the pre-registration to avoid orphaned rows.
		slog.Warn("plain CREATE: exhausted receipt retries, cleaning up pre-registration", "tx_hash", txHash, "address", preRegisteredAddr)
		if err := p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(
			context.Background(), preRegisteredAddr); err != nil {
			slog.Error("plain CREATE: failed to clean up pre-registration", "address", preRegisteredAddr, "error", err)
		}
	}()
}

// getTransactionReceipt fetches the receipt for a tx and returns the contract address.
// Returns ("", nil) if the receipt shows a revert.
// Returns ("", error) if the receipt is not yet available (tx not mined).
func (p *JSONRPCProcessor) getTransactionReceipt(txHash string) (string, error) {
	reqBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionReceipt",
		"params":  []any{txHash},
		"id":      1,
	})
	if err != nil {
		return "", err
	}
	respBody, _, err := p.proxy.Forward(reqBody)
	if err != nil {
		return "", fmt.Errorf("receipt RPC: %w", err)
	}
	var resp struct {
		Result *struct {
			Status          string `json:"status"`          // "0x1" = success, "0x0" = fail
			ContractAddress string `json:"contractAddress"` // set for deployments
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("parse receipt: %w", err)
	}
	if resp.Error != nil {
		return "", fmt.Errorf("receipt RPC error: %s", resp.Error.Message)
	}
	if resp.Result == nil {
		return "", fmt.Errorf("receipt not yet available")
	}
	// Status "0x0" = revert; return "" so caller knows to clean up.
	if resp.Result.Status == "0x0" {
		return "", nil
	}
	return strings.ToLower(resp.Result.ContractAddress), nil
}

// getTransactionReceiptStatus fetches the receipt for a tx and returns whether it succeeded.
// Returns (true, nil) if the receipt shows success (status "0x1").
// Returns (false, nil) if the receipt shows a revert (status "0x0").
// Returns (false, error) if the receipt is not yet available (tx not mined).
func (p *JSONRPCProcessor) getTransactionReceiptStatus(txHash string) (bool, error) {
	reqBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionReceipt",
		"params":  []any{txHash},
		"id":      1,
	})
	if err != nil {
		return false, err
	}
	respBody, _, err := p.proxy.Forward(reqBody)
	if err != nil {
		return false, fmt.Errorf("receipt RPC: %w", err)
	}
	var resp struct {
		Result *struct {
			Status string `json:"status"` // "0x1" = success, "0x0" = fail
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return false, fmt.Errorf("parse receipt: %w", err)
	}
	if resp.Error != nil {
		return false, fmt.Errorf("receipt RPC error: %s", resp.Error.Message)
	}
	if resp.Result == nil {
		return false, fmt.Errorf("receipt not yet available")
	}
	return resp.Result.Status == "0x1", nil
}

// preRegisterRuntimeCreates pre-registers addresses from runtime CREATE/CREATE2 operations
// discovered during trace validation. Returns the list of successfully pre-registered addresses.
func (p *JSONRPCProcessor) preRegisterRuntimeCreates(ctx context.Context, orgID string, targets []rbac.CreateTarget) []string {
	var addrs []string
	for _, t := range targets {
		addr := strings.ToLower(t.Address)
		note := fmt.Sprintf("runtime %s from %s", t.Type, t.From)
		if err := p.rbacAccessCtrl.Store().PreRegisterPlainCreate(ctx, orgID, addr, note); err != nil {
			slog.Warn("runtime create pre-registration failed", "address", addr, "type", t.Type, "error", err)
			continue
		}
		addrs = append(addrs, addr)
	}
	return addrs
}

// pollAndFinalizeRuntimeCreates polls for the receipt of a transaction that contains
// runtime CREATE/CREATE2 operations, then reconciles pre-registered addresses with
// the actual addresses from the mined trace.
func (p *JSONRPCProcessor) pollAndFinalizeRuntimeCreates(txHash string, preRegAddrs []string, orgID, userID string) {
	ctx := context.Background()
	const maxAttempts = 12
	const baseDelay = 2 * time.Second

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := baseDelay * time.Duration(1<<uint(attempt-1))
			if delay > 60*time.Second {
				delay = 60 * time.Second
			}
			time.Sleep(delay)
		}

		// Get receipt status (not contractAddress — runtime creates are internal)
		success, err := p.getTransactionReceiptStatus(txHash)
		if err != nil {
			continue // Not mined yet
		}

		if !success {
			// Transaction reverted — clean up all pre-registrations
			for _, addr := range preRegAddrs {
				_ = p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(ctx, addr)
			}
			slog.Info("runtime creates cleaned up (tx reverted)", "tx_hash", txHash)
			return
		}

		// Transaction succeeded — trace to get actual created addresses
		actualAddrs := make(map[string]bool)
		if p.runtimeTracer != nil {
			traceResult, traceErr := p.runtimeTracer.TraceMinedTransaction(ctx, txHash)
			if traceErr == nil && traceResult != nil {
				for _, target := range traceResult.CallTargets {
					if target.Type == "CREATE" || target.Type == "CREATE2" {
						actualAddrs[strings.ToLower(target.To)] = true
					}
				}
			} else {
				slog.Warn("failed to trace mined tx for runtime creates", "tx_hash", txHash, "error", traceErr)
				// Fall back: assume pre-registered addresses are correct
				for _, addr := range preRegAddrs {
					actualAddrs[addr] = true
				}
			}
		} else {
			// No tracer available — assume pre-registered addresses are correct
			for _, addr := range preRegAddrs {
				actualAddrs[addr] = true
			}
		}

		// Reconcile: finalize actual addresses, clean up stale pre-registrations
		preRegSet := make(map[string]bool)
		for _, addr := range preRegAddrs {
			preRegSet[addr] = true
		}

		// Finalize addresses that were actually created
		now := time.Now()
		for addr := range actualAddrs {
			// Use NotifyDeploymentMined for addresses we tracked via the pending tracker
			if preRegSet[addr] {
				// Track it so NotifyDeploymentMined can find it
				p.rbacAccessCtrl.TrackPlainCreateDeployment(txHash, orgID, userID, addr)
				if err := p.rbacAccessCtrl.NotifyDeploymentMined(ctx, txHash, addr); err != nil {
					slog.Warn("runtime create finalization via NotifyDeploymentMined failed",
						"address", addr, "tx_hash", txHash, "error", err)
				}
			} else {
				// Address wasn't pre-registered (diverged from simulation) — register directly
				slog.Info("runtime create: registering diverged address", "address", addr, "tx_hash", txHash, "org_id", orgID)
				contract := &rbac.Contract{
					ID:      uuid.New().String(),
					OrgID:   orgID,
					Address: addr,
					Name:    fmt.Sprintf("Contract %s", addr[:10]),
					Metadata: map[string]any{
						"auto_registered": true,
						"via":             "runtime_create",
						"tx_hash":         txHash,
					},
				}
				if userID != "" {
					contract.DeployedByUserID = &userID
				}
				contract.DeployedAt = &now
				if createErr := p.rbacAccessCtrl.Store().CreateContract(ctx, contract); createErr != nil {
					slog.Warn("failed to register diverged runtime create", "address", addr, "error", createErr)
				} else if userID != "" {
					if gErr := p.rbacAccessCtrl.Store().GrantContractToDeployerGroup(ctx, orgID, contract.ID, userID); gErr != nil {
						slog.Warn("failed to grant contract to deployer group for runtime create", "address", addr, "error", gErr)
					} else {
						// Drop the deployer's cached permissions so the next call to the
						// newly-registered contract re-resolves and sees the new grant.
						if invErr := p.rbacAccessCtrl.InvalidateUser(ctx, userID); invErr != nil {
							slog.Warn("failed to invalidate deployer cache after runtime create grant", "user_id", userID, "error", invErr)
						}
					}
				}
			}
		}

		// Clean up pre-registrations that weren't actually created (simulation diverged)
		for _, addr := range preRegAddrs {
			if !actualAddrs[addr] {
				slog.Info("runtime create: cleaning up diverged pre-registration", "address", addr, "tx_hash", txHash)
				_ = p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(ctx, addr)
			}
		}

		slog.Info("runtime creates finalized", "tx_hash", txHash, "pre_registered", len(preRegAddrs), "actual", len(actualAddrs))
		return
	}

	// Exhausted retries — clean up orphaned pre-registrations
	slog.Warn("runtime create finalization exhausted retries", "tx_hash", txHash)
	for _, addr := range preRegAddrs {
		_ = p.rbacAccessCtrl.Store().DeletePreregisteredAddressByAddress(ctx, addr)
	}
}

// recordRPCOutcome records RPC request count and duration metrics.
// The method is normalized to a known allowlist to prevent label cardinality bombs.
func (p *JSONRPCProcessor) recordRPCOutcome(method, outcome string, start time.Time) {
	if p.metrics == nil {
		return
	}
	safeMethod := metrics.NormalizeRPCMethod(method)
	p.metrics.RPCRequestsTotal.WithLabelValues(safeMethod, outcome).Inc()
	p.metrics.RPCRequestDuration.WithLabelValues(safeMethod).Observe(time.Since(start).Seconds())
}

// recordRBACDecision records an RBAC decision metric.
func (p *JSONRPCProcessor) recordRBACDecision(decision string) {
	if p.metrics == nil {
		return
	}
	p.metrics.RBACDecisionsTotal.WithLabelValues(decision).Inc()
}

// visibleToMaxSize bounds the per-tx visibleTo recipient list. Lists
// larger than this are rejected at sendTransaction with HTTP 400.
// Bound chosen for two reasons:
//
//  1. Storage: every entry persists in tx_visible_to indefinitely.
//     32 entries × ~50 bytes/DID × tx volume keeps growth predictable.
//  2. RD-874: under the unlock semantic each entry is an effective
//     ACL grant for that tx's events. Capping at 32 limits the blast
//     radius of an abusive tx sender listing every DID they can
//     enumerate.
//
// Operators with legitimate >32 recipient use cases should use a
// dedicated group + grant instead of stuffing visibleTo.
const visibleToMaxSize = 32

// extractAndStripVisibleTo extracts the visibleTo field from the tx object
// in eth_sendTransaction params[0], removes it so it's not forwarded to the node,
// and rebuilds req.Body. Returns the DID list (nil if not present).
func extractAndStripVisibleTo(req *ProcessRequest) []string {
	if len(req.Params) == 0 {
		return nil
	}
	txObj, ok := req.Params[0].(map[string]any)
	if !ok {
		return nil
	}
	raw, exists := txObj["visibleTo"]
	if !exists {
		return nil
	}
	// Remove from params so it's not forwarded.
	delete(txObj, "visibleTo")

	// Rebuild request body without the field.
	req.Body = rebuildRequestBody(req.Body, req.Params)

	// Parse the DID list, validate each, and dedupe (L2).
	switch v := raw.(type) {
	case []any:
		dids := make([]string, 0, len(v))
		seen := make(map[string]struct{}, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok || !isValidDID(s) {
				continue
			}
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			dids = append(dids, s)
		}
		if len(dids) > 0 {
			return dids
		}
	case []string:
		dids := make([]string, 0, len(v))
		seen := make(map[string]struct{}, len(v))
		for _, s := range v {
			if !isValidDID(s) {
				continue
			}
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			dids = append(dids, s)
		}
		if len(dids) > 0 {
			return dids
		}
	}
	return nil
}

// isValidDID validates the visibleTo DID format. L2 (security audit):
// pre-fix the raw string was stored verbatim, so garbage/spam entries
// bloated tx_visible_to and slowed every GetVisibleTxHashesForDID
// lookup. Now: must start with "did:", contain a method and method-
// specific identifier, total length ≤ 240, all chars in the iden3 /
// W3C-DID safe alphabet.
func isValidDID(s string) bool {
	if len(s) < len("did:x:y") || len(s) > 240 {
		return false
	}
	if !strings.HasPrefix(s, "did:") {
		return false
	}
	// Require at least one ':' after "did:" (method + ID).
	rest := s[4:]
	colon := strings.IndexByte(rest, ':')
	if colon <= 0 || colon == len(rest)-1 {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == ':' || ch == '-' || ch == '_' || ch == '.':
		default:
			return false
		}
	}
	return true
}

// extractAndStripRawTxVisibleTo extracts visibleTo from the second param
// of eth_sendRawTransaction: {"method": "eth_sendRawTransaction", "params": ["0xf86c...", {"visibleTo": ["did:..."]}]}
// Strips the second param from req.Params and req.Body.
func extractAndStripRawTxVisibleTo(req *ProcessRequest) []string {
	if len(req.Params) < 2 {
		return nil
	}
	opts, ok := req.Params[1].(map[string]any)
	if !ok {
		return nil
	}
	raw, exists := opts["visibleTo"]
	if !exists {
		return nil
	}

	// Strip the second param entirely (only the raw tx hex goes to the node).
	req.Params = req.Params[:1]
	req.Body = rebuildRequestBody(req.Body, req.Params)

	switch v := raw.(type) {
	case []any:
		dids := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				dids = append(dids, s)
			}
		}
		if len(dids) > 0 {
			return dids
		}
	case []string:
		if len(v) > 0 {
			return v
		}
	}
	return nil
}

// ethAddressResolver resolves an ETH address to its linked DID. Implemented by
// *db.DB (GetDIDByEthAddress); the processor's rbac store satisfies it via a type
// assertion (mirrors the optional-capability TxVisibilitySaver pattern). When the
// store does not implement it, address entries are dropped (fail-closed).
type ethAddressResolver interface {
	GetDIDByEthAddress(ctx context.Context, ethAddress string) (string, error)
}

// extractAndStripTopLevelVisibleTo reads a top-level `visibleTo` field — or its
// Quorum-compatible alias `privateFor` — from the JSON-RPC envelope (a sibling of
// `params`), removes it from req.Body so it is never forwarded to the node, and
// returns the raw recipient entries (DIDs and/or 0x ETH addresses, unresolved).
// This is the standard convention for per-tx privacy metadata (RD-1163). The
// param-embedded forms (params[0].visibleTo / params[1].visibleTo) remain
// supported for back-compat and are unioned with this at the call site.
//
// Must be called BEFORE the param extractors: those rebuild req.Body from
// {jsonrpc,method,params,id} and would drop the top-level field before it is read.
func extractAndStripTopLevelVisibleTo(req *ProcessRequest) []string {
	if len(req.Body) == 0 {
		return nil
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal(req.Body, &env); err != nil {
		return nil
	}
	vtRaw, hasVT := env["visibleTo"]
	pfRaw, hasPF := env["privateFor"]
	if !hasVT && !hasPF {
		return nil
	}
	entries := append(parseVisibleToRawList(vtRaw), parseVisibleToRawList(pfRaw)...)
	// Strip both keys so neither reaches the node, then rebuild the body.
	delete(env, "visibleTo")
	delete(env, "privateFor")
	if rebuilt, err := json.Marshal(env); err == nil {
		req.Body = rebuilt
	}
	return entries
}

// parseVisibleToRawList parses a JSON array of strings (["did:..","0x.."]) into a
// slice of non-empty raw entries. Non-array / non-string values are ignored.
func parseVisibleToRawList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		out := make([]string, 0, len(arr))
		for _, s := range arr {
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	var anyArr []any
	if err := json.Unmarshal(raw, &anyArr); err == nil {
		out := make([]string, 0, len(anyArr))
		for _, v := range anyArr {
			if s, ok := v.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// resolveVisibleToEntries turns raw visibleTo entries (DIDs and/or ETH addresses)
// into a deduped DID list. DIDs are validated (isValidDID); ETH addresses are
// resolved to their linked DID via resolver. FAIL-CLOSED: an address with no
// linked DID (or when no resolver is available, or on lookup error) is dropped —
// it never widens visibility. Non-DID / non-address entries are ignored.
func resolveVisibleToEntries(ctx context.Context, resolver ethAddressResolver, entries []string) []string {
	if len(entries) == 0 {
		return nil
	}
	out := make([]string, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		var did string
		switch {
		case isValidDID(e):
			did = e
		case isEthAddress(e) && resolver != nil:
			d, err := resolver.GetDIDByEthAddress(ctx, strings.ToLower(e))
			if err != nil || d == "" {
				continue // fail-closed: unknown/unresolvable address is dropped
			}
			did = d
		default:
			continue
		}
		if _, dup := seen[did]; dup {
			continue
		}
		seen[did] = struct{}{}
		out = append(out, did)
	}
	return out
}

// resolveTopLevelVisibleTo bounds the amplification risk flagged in RD-1163
// review: it rejects an over-cap raw list BEFORE resolving any entry, so a
// client cannot drive one GetDIDByEthAddress DB lookup per address for a list
// bounded only by the request body size (MaxRequestBodySize, ~1MB). Within the
// cap it resolves DIDs + ETH addresses fail-closed (see resolveVisibleToEntries),
// so the number of address lookups is bounded by visibleToMaxSize. Returns a 400
// ProcessError when the raw entry count exceeds visibleToMaxSize.
func resolveTopLevelVisibleTo(ctx context.Context, resolver ethAddressResolver, topRaw []string) ([]string, *ProcessError) {
	if len(topRaw) > visibleToMaxSize {
		return nil, &ProcessError{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("visibleTo list exceeds maximum size of %d entries", visibleToMaxSize),
		}
	}
	return resolveVisibleToEntries(ctx, resolver, topRaw), nil
}

// isEthAddress reports whether s is a 0x-prefixed 20-byte hex address.
func isEthAddress(s string) bool {
	if len(s) != 42 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X') {
		return false
	}
	for i := 2; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'f':
		case ch >= 'A' && ch <= 'F':
		default:
			return false
		}
	}
	return true
}

// unionVisibleToDIDs returns the deduped union of two DID lists, preserving order
// (all of a, then new entries from b).
func unionVisibleToDIDs(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	if len(a) == 0 {
		return b
	}
	out := make([]string, 0, len(a)+len(b))
	seen := make(map[string]struct{}, len(a)+len(b))
	for _, s := range a {
		if _, dup := seen[s]; !dup {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	for _, s := range b {
		if _, dup := seen[s]; !dup {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// rebuildRequestBody reconstructs the JSON-RPC request body from the modified params.
func rebuildRequestBody(originalBody []byte, params []any) []byte {
	var env struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		Params  []any           `json:"params"`
		ID      json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(originalBody, &env); err != nil {
		return originalBody // can't rebuild, pass through
	}
	env.Params = params
	rebuilt, err := json.Marshal(env)
	if err != nil {
		return originalBody
	}
	return rebuilt
}

// extractTxHashFromResult extracts the tx hash from a JSON-RPC response result field.
// Used after eth_sendTransaction / eth_sendRawTransaction to get the hash for
// visibleTo storage.
func extractTxHashFromResult(responseBody []byte) string {
	var resp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return ""
	}
	if resp.Error != nil || resp.Result == "" {
		return ""
	}
	return resp.Result
}

// maskAPIKey returns a masked version of an API key for safe use in logs and
// metrics labels. Shows only the last 4 characters prefixed with "****".
// Returns "" for empty keys, "****" for keys shorter than 4 characters.
func maskAPIKey(key string) string {
	if key == "" {
		return ""
	}
	if len(key) < 4 {
		return "****"
	}
	return "****" + key[len(key)-4:]
}
