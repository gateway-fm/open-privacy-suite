package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	gethcommon "github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/metrics"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/tracer"
)

// validateDeployWithTracing enforces cross-org isolation on every internal
// CALL/STATICCALL/DELEGATECALL/CREATE/CREATE2 frame executed by a contract
// constructor at deploy time (M10, security audit follow-up to RD-915).
//
// Pre-fix, both `eth_sendTransaction` and `eth_sendRawTransaction` with an
// empty `to` (contract creation) skipped runtime tracing entirely — the
// deploy_validator did static bytecode analysis that flagged constant
// CALL/DELEGATECALL targets but explicitly allowed dynamic targets,
// trusting a "runtime tracing validates them at execution time" claim that
// was never wired. A deployer with the deploy claim could ship a
// constructor that took `address foreignContract` as a constructor arg
// and `STATICCALL`ed into another org's private contract, persisting the
// foreign state in the new contract's storage.
//
// This function closes that gap by tracing the deploy via
// debug_traceCall (top-level frame with empty to) and feeding every
// internal frame through trace_validator.ValidateTrace. The same
// cross-org rules and CREATE/CREATE2 collision checks apply.
//
// Returns the discovered CREATE/CREATE2 targets so the caller can
// pre-register them. Returns a ProcessError when the trace itself
// errors or validation denies the deploy. Returns (nil, nil) when the
// feature is disabled or not applicable.
func (p *JSONRPCProcessor) validateDeployWithTracing(
	ctx context.Context, req *ProcessRequest,
	userID, from, data, value string,
	userOrgIDs map[string]bool, userHasDeploy bool,
) ([]rbac.CreateTarget, *ProcessError) {
	// Skip if tracing is not configured. Operators who run a node
	// without debug_* exposed (some managed RPC services) keep the
	// pre-M10 behavior; the bytecode analyzer remains as a thinner
	// fallback. The recommended deployment is geth/erigon with debug_*
	// available, in which case this runs and is the primary gate.
	if p.runtimeTracer == nil || p.traceValidator == nil || !p.runtimeTracer.IsEnabled() {
		return nil, nil
	}

	// Block param is "latest" — deploys execute against the current
	// chain state and there is no user-supplied block-tag knob.
	traceResult, err := p.runtimeTracer.TraceTransactionUncached(ctx, from, "", data, value, "latest")
	if err != nil {
		slog.Warn("deploy trace: upstream tracer error",
			slog.String("user", req.UserID), slog.Any("err", err))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyTracerError,
			Reason:     ReasonTracingUnavailable,
		}
	}
	if traceResult == nil {
		slog.Warn("deploy trace: nil result", slog.String("user", req.UserID))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyTracerError,
			Reason:     ReasonTracingUnavailable,
		}
	}

	// RD-1053: intra-org grant scoping for constructor frames. No top-level
	// `to` for a deploy, so targetAddr is "". When the knob is on, a
	// constructor that CALLs a same-org contract the deployer's groups have
	// no grant for is denied (the strict posture the operator opted into).
	traceOpts, optErr := p.intraOrgGrantTraceOptions(ctx, userID, "", userOrgIDs)
	if optErr != nil {
		slog.Warn("deploy trace: intra-org grant resolution failed",
			slog.String("user", req.UserID), slog.Any("err", optErr))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceValidatorError,
			Reason:     ReasonTracingUnavailable,
		}
	}

	// Validate the trace. The top-level frame is a CREATE (debug_traceCall
	// with empty `to` reports it as a deploy); ValidateTrace already
	// handles the deploy-claim gate + CREATE collision check + every
	// nested CALL/STATICCALL/DELEGATECALL frame against userOrgIDs.
	validationResult, err := p.traceValidator.ValidateTrace(ctx, userOrgIDs, traceResult, userHasDeploy, traceOpts...)
	if err != nil {
		slog.Warn("deploy trace: validator error",
			slog.String("user", req.UserID), slog.Any("err", err))
		return nil, &ProcessError{
			StatusCode: http.StatusInternalServerError,
			Message:    sendTraceValidatorError,
			Reason:     ReasonTracingUnavailable,
		}
	}
	if !validationResult.Allowed {
		slog.Info("deploy trace: denial", slog.String("user", req.UserID))
		slog.Debug("deploy trace: denial detail",
			slog.String("user", req.UserID),
			slog.String("reason", validationResult.Reason),
			slog.String("denied_target", validationResult.DeniedTarget))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyMessage(validationResult.Reason),
			Reason:     ReasonCrossOrg,
		}
	}
	return validationResult.CreateTargets, nil
}

// validateWithTracing performs runtime trace validation for eth_sendTransaction.
// Returns the list of CREATE/CREATE2 targets discovered during tracing (may be nil),
// and a ProcessError if validation fails.
func (p *JSONRPCProcessor) validateWithTracing(ctx context.Context, req *ProcessRequest, targetAddr string) ([]rbac.CreateTarget, *ProcessError) {
	// Skip if tracing is not configured
	if p.runtimeTracer == nil || p.traceValidator == nil || !p.runtimeTracer.IsEnabled() {
		return nil, nil
	}

	// Only trace eth_sendTransaction (state-changing calls)
	if req.Method != "eth_sendTransaction" {
		return nil, nil
	}

	// Skip contract deployments (no target address) - deployment validation is separate
	if targetAddr == "" {
		return nil, nil
	}

	// Get user info early for tiered validation
	user, err := p.rbacAccessCtrl.Store().GetUserByExternalID(ctx, req.UserID)
	if err != nil || user == nil {
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    "failed to get user for trace validation",
			Reason:     ReasonTracingUnavailable,
		}
	}

	// Get user's org memberships
	memberships, err := p.rbacAccessCtrl.Store().ListUserMembershipsWithDetails(ctx, user.ID)
	if err != nil {
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    "failed to get user memberships for trace validation",
			Reason:     ReasonTracingUnavailable,
		}
	}

	userOrgIDs := make(map[string]bool)
	for _, m := range memberships {
		if m.Group != nil {
			userOrgIDs[m.Group.OrgID] = true
		}
	}

	// Extract transaction parameters for tracing
	from, to, data, value := extractTxParams(req.Params)

	// M10 (security audit follow-up to RD-915): deploys are now traced
	// via validateDeployWithTracing. Pre-fix, the bytecode-level static
	// analyzer claimed to handle them, but it only validated CONSTANT
	// call targets — dynamic CALL/STATICCALL/DELEGATECALL with a
	// constructor-arg target slipped through, enabling cross-org state
	// exfiltration during constructor execution. Runtime tracing
	// validates every executed frame against userOrgIDs.
	if to == "" {
		userHasDeploy := p.userHasDeployClaim(ctx, memberships)
		return p.validateDeployWithTracing(ctx, req, user.ID, from, data, value, userOrgIDs, userHasDeploy)
	}

	// L6 (security audit follow-up to RD-915): rebind / verify
	// user-supplied `from`. Pre-fix, eth_sendTransaction trusted the
	// node to verify that the unlocked key matches the from address.
	// On a shared node (Anvil / multi-key staging), a JWT-bound user
	// could forge any unlocked address as `from` and reach
	// "if (msg.sender == orgB_router)" branches they would never
	// otherwise touch. The fix is the same shape as RD-915 KD-2 for
	// eth_call: empty `from` is allowed (node will treat it as the
	// default account), a user-supplied `from` must match one of the
	// JWT-linked EOAs.
	//
	// Defense-in-depth: production nodes also pin msg.sender via the
	// unlocked key, but we don't rely on that — the node may not be
	// under operator control (managed RPC) and key-unlock policy can
	// drift. Rejection rather than silent rebinding preserves the
	// audit trail of spoof attempts.
	if from != "" {
		userAddrs, addrErr := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if addrErr != nil {
			slog.Warn("eth_sendTransaction trace: linked-address lookup failed",
				slog.String("user", req.UserID), slog.Any("err", addrErr))
			return nil, &ProcessError{
				StatusCode: http.StatusForbidden,
				Message:    "failed to verify sender identity",
				Reason:     ReasonTracingUnavailable,
			}
		}
		fromLC := strings.ToLower(from)
		match := false
		for _, a := range userAddrs {
			if strings.ToLower(a) == fromLC {
				match = true
				break
			}
		}
		if !match {
			slog.Info("eth_sendTransaction trace: user-supplied from rejected (not in linked addresses)",
				slog.String("user", req.UserID), slog.String("from", from))
			return nil, &ProcessError{
				StatusCode: http.StatusBadRequest,
				Message:    "invalid sender: from address is not linked to your account",
				Reason:     ReasonSenderNotLinked,
			}
		}
	}

	// Only skip tracing for simple value transfers to EOAs.
	// Contracts can execute receive()/fallback() which may make cross-org calls.
	if isSimpleValueTransfer(data) {
		hasCode, err := p.runtimeTracer.HasCode(ctx, to)
		if err != nil {
			// Fail closed - if we can't check, trace anyway
			// (fall through to tracing below)
		} else if !hasCode {
			return nil, nil // EOA - safe to skip tracing
		}
		// Contract with empty calldata - must trace (receive/fallback could make calls)
	}

	// Perform the trace
	traceResult, err := p.runtimeTracer.TraceTransaction(ctx, from, to, data, value)
	if err != nil {
		slog.Warn("send trace: upstream tracer error",
			slog.String("user", req.UserID), slog.String("to", to), slog.Any("err", err))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyTracerError,
			Reason:     ReasonTracingUnavailable,
		}
	}

	if traceResult == nil {
		slog.Warn("send trace: nil result",
			slog.String("user", req.UserID), slog.String("to", to))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyTracerError,
			Reason:     ReasonTracingUnavailable,
		}
	}

	// Determine if user has deploy claim from any of their memberships
	userHasDeploy := p.userHasDeployClaim(ctx, memberships)

	// RD-1053: intra-org grant scoping (same knob as the read side). Fail
	// closed if the grant set can't be resolved.
	traceOpts, optErr := p.intraOrgGrantTraceOptions(ctx, user.ID, to, userOrgIDs)
	if optErr != nil {
		slog.Warn("send trace: intra-org grant resolution failed",
			slog.String("user", req.UserID), slog.Any("err", optErr))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceValidatorError,
			Reason:     ReasonTracingUnavailable,
		}
	}

	// Validate the trace against org isolation rules
	validationResult, err := p.traceValidator.ValidateTrace(ctx, userOrgIDs, traceResult, userHasDeploy, traceOpts...)
	if err != nil {
		slog.Warn("send trace: validator error",
			slog.String("user", req.UserID), slog.Any("err", err))
		return nil, &ProcessError{
			StatusCode: http.StatusInternalServerError,
			Message:    sendTraceValidatorError,
			Reason:     ReasonTracingUnavailable,
		}
	}

	if !validationResult.Allowed {
		slog.Info("send trace: denial",
			slog.String("user", req.UserID), slog.String("to", to))
		slog.Debug("send trace: denial detail",
			slog.String("user", req.UserID),
			slog.String("reason", validationResult.Reason),
			slog.String("denied_target", validationResult.DeniedTarget))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyMessage(validationResult.Reason),
			Reason:     ReasonCrossOrg,
		}
	}

	return validationResult.CreateTargets, nil
}

// User-facing deny messages for eth_call runtime tracing (RD-915 KD-3).
// Constants — never interpolate upstream node errors into the response,
// and never echo a non-precompile contract address (an attacker who didn't
// otherwise know that address exists in another org now does — same shape
// as RD-916). Diagnostic detail goes to slog.Debug + access_logs.
const (
	ethCallDenyCrossOrg       = "call denied: cross-org access not permitted"
	ethCallDenyDepthExceeded  = "call denied: trace depth exceeded; not provable as same-org"
	ethCallDenyTracerError    = "call denied: tracing temporarily unavailable"
	ethCallDenyInvalidRequest = "call denied: invalid request shape"
)

// User-facing deny messages for the send-side trace path (validateWithTracing
// and processRawTransaction). Same KD-3 rationale as the eth_call constants:
// the upstream error and the validator's DeniedTarget never reach the
// response body. Pre-RD-915 these sites %v'd the upstream error and Reason
// into the deny string; that's the same disclosure surface RD-916 + RD-915
// close on the read side.
const (
	sendTraceDenyCrossOrg    = "transaction denied: cross-org access not permitted"
	sendTraceDenyDeployClaim = "transaction denied: runtime contract creation requires the deploy claim"
	sendTraceDenyTracerError = "transaction denied: tracing temporarily unavailable"
	sendTraceValidatorError  = "transaction denied: trace validation unavailable"
)

// sendTraceDenyMessage maps a TraceValidationResult to the appropriate
// send-side constant message, keeping the response body opaque.
func sendTraceDenyMessage(reason string) string {
	if reason == "runtime contract creation requires deploy claim" {
		return sendTraceDenyDeployClaim
	}
	return sendTraceDenyCrossOrg
}

// validateEthCallWithTracing enforces cross-org isolation on every internal
// CALL/STATICCALL/DELEGATECALL frame produced by an eth_call (RD-915). Today
// the entry-point address is the only gate: an attacker can wrap a foreign-
// org private contract with a same-org facade and bubble up state through
// the return value. This closes the read-side of that gap. The send-side
// equivalent is validateWithTracing.
//
// Differences from the send path that matter:
//   - No caching. Proxy patterns (EIP-1967, Diamond, Beacon, transparent)
//     can re-target their internal calls by rewriting a storage slot, so
//     a (from,to,data,value) cache yields stale "allow" decisions after
//     a cross-org upgrade. We use TraceTransactionUncached. Regression net:
//     internal/server/eth_call_tracing_integration_test.go
//     (TestEthCallTracing_ProxyImplementationFlip exercises the same
//     (from,to,data,value) twice with different upstream traces and
//     confirms the second decision is fresh, plus
//     TestTraceTransactionUncached_BypassesCachedHit at the tracer layer).
//   - `from` is rebound to the JWT-bound EOA. Sends pin msg.sender via the
//     unlocked key; reads do not, and accepting user-supplied `from` lets
//     an attacker take an "if (msg.sender == orgB-router)" branch they
//     would never reach as themselves. Reject mismatched user-supplied
//     `from` with 400 invalid request rather than silently rebinding,
//     because silent rebinding would mask spoofing attempts in the logs.
//   - Distinct timeout (default 5s) caps individual trace duration. Note
//     this is NOT a quota cap — the concurrency limiter is acquired at
//     line ~460, AFTER this function runs, so a single JWT can issue many
//     concurrent eth_calls that each pin a tracer goroutine for up to the
//     timeout. Per-user gating before the tracer is tracked in RD-923.
//   - Distinct deny messages (the four constants above) — never %v the
//     upstream error and never echo the denied contract address.
//
// Returns nil to allow the eth_call to be forwarded; non-nil to deny.
func (p *JSONRPCProcessor) validateEthCallWithTracing(ctx context.Context, req *ProcessRequest, targetAddr string) *ProcessError {
	return p.validateEthCallWithTracingInOrg(ctx, req, targetAddr, "")
}

// validateEthCallWithTracingInOrg is the dry-run-safe variant of
// validateEthCallWithTracing. When orgID is non-empty, trace validation is
// pinned to that organization instead of using every organization the
// impersonated user belongs to. This prevents an Org A administrator from
// receiving an Org B trace merely because the target user is a member of both.
func (p *JSONRPCProcessor) validateEthCallWithTracingInOrg(ctx context.Context, req *ProcessRequest, targetAddr, orgID string) *ProcessError {
	// Lock-free atomic load of the (env + runtime-override) state. The
	// super-admin endpoint can replace this between any two invocations;
	// each call reads a self-consistent snapshot.
	if state := p.ethCallTracing.Load(); state == nil || !state.Enabled {
		return nil
	}
	if p.runtimeTracer == nil || p.traceValidator == nil || !p.runtimeTracer.IsEnabled() {
		return nil
	}
	// Resolve operator aliases before selecting the read-tracing policy.
	// eth_call and eth_estimateGas share this validation. Named passthrough
	// methods retain their configured behavior; send aliases are unsupported.
	resolved := rbac.ResolveMethodAlias(req.Method)
	if resolved != "eth_call" && resolved != "eth_estimateGas" {
		return nil
	}
	if targetAddr == "" {
		// No target — nothing to trace. The entry-point access check
		// would have already rejected this if RBAC required a target.
		return nil
	}

	from, to, data, value := extractTxParams(req.Params)

	// Extract the block param (params[1]) the same way the upstream
	// eth_call will receive it; if the trace runs at a different block
	// than the forwarded call, the trace at "latest" can allow a call
	// that returns historical cross-org state from a since-flipped proxy
	// — a time-shifted variant of the proxy-flip attack closed by the
	// uncached path. extractEthCallBlockParam validates the shape and
	// returns the value as the JSON-RPC layer should see it.
	blockParam, blockErr := extractEthCallBlockParam(req.Params)
	if blockErr != nil {
		return &ProcessError{StatusCode: http.StatusBadRequest, Message: ethCallDenyInvalidRequest, Reason: ReasonInvalidRequestShape}
	}

	// Input validation BEFORE tracing: malformed addresses cannot be
	// allowed to burn a concurrency slot or emit a metric labeled with
	// junk. gethcommon.IsHexAddress accepts mixed-case checksummed and
	// uppercase forms.
	if to == "" || !gethcommon.IsHexAddress(to) {
		return &ProcessError{StatusCode: http.StatusBadRequest, Message: ethCallDenyInvalidRequest, Reason: ReasonInvalidRequestShape}
	}
	if from != "" && !gethcommon.IsHexAddress(from) {
		return &ProcessError{StatusCode: http.StatusBadRequest, Message: ethCallDenyInvalidRequest, Reason: ReasonInvalidRequestShape}
	}

	// Resolve the JWT-bound user identity and rebind `from`. The JWT
	// already passed CheckAccess, so user lookup must succeed; if it
	// doesn't, fail closed.
	user, err := p.rbacAccessCtrl.Store().GetUserByExternalID(ctx, req.UserID)
	if err != nil || user == nil {
		slog.Warn("eth_call trace: user lookup failed",
			slog.String("user", req.UserID), slog.Any("err", err))
		return &ProcessError{StatusCode: http.StatusForbidden, Message: ethCallDenyTracerError, Reason: ReasonTracingUnavailable}
	}

	// Discover the user's linked EOAs. Any user-supplied `from` must
	// equal one of them. Empty `from` is allowed — the upstream node
	// will treat it as the zero address. Rejecting a mismatch (rather
	// than silently rebinding) preserves the audit trail of spoof
	// attempts: the access_log row records the attempted `from` and
	// the deny.
	userAddrs, addrErr := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
	if addrErr != nil {
		slog.Warn("eth_call trace: linked-address lookup failed",
			slog.String("user", req.UserID), slog.Any("err", addrErr))
		return &ProcessError{StatusCode: http.StatusForbidden, Message: ethCallDenyTracerError, Reason: ReasonTracingUnavailable}
	}
	if from != "" {
		fromLC := strings.ToLower(from)
		match := false
		for _, a := range userAddrs {
			if strings.ToLower(a) == fromLC {
				match = true
				break
			}
		}
		if !match {
			slog.Info("eth_call trace: user-supplied from rejected (not in linked addresses)",
				slog.String("user", req.UserID), slog.String("from", from))
			return &ProcessError{StatusCode: http.StatusBadRequest, Message: ethCallDenyInvalidRequest, Reason: ReasonSenderNotLinked}
		}
	}

	// Org memberships → for ValidateTrace's cross-org check. Admin dry-run
	// pins this to the path org; the normal RPC path retains the user's complete
	// membership set.
	userOrgIDs := make(map[string]bool)
	userHasDeploy := false
	if orgID != "" {
		perms, permErr := p.rbacAccessCtrl.GetEffectivePermissionsByIDs(ctx, user.ID, orgID)
		if permErr != nil || perms == nil {
			slog.Warn("eth_call trace: pinned-org permission lookup failed",
				slog.String("user_uuid", user.ID), slog.String("org_id", orgID), slog.Any("err", permErr))
			return &ProcessError{StatusCode: http.StatusForbidden, Message: ethCallDenyTracerError, Reason: ReasonTracingUnavailable}
		}
		userOrgIDs[orgID] = true
		userHasDeploy = effectivePermissionsHasDeployClaim(perms)
	} else {
		memberships, membershipErr := p.rbacAccessCtrl.Store().ListUserMembershipsWithDetails(ctx, user.ID)
		if membershipErr != nil {
			slog.Warn("eth_call trace: membership lookup failed",
				slog.String("user_uuid", user.ID), slog.Any("err", membershipErr))
			return &ProcessError{StatusCode: http.StatusForbidden, Message: ethCallDenyTracerError, Reason: ReasonTracingUnavailable}
		}
		for _, m := range memberships {
			if m.Group != nil {
				userOrgIDs[m.Group.OrgID] = true
			}
		}
		userHasDeploy = p.userHasDeployClaim(ctx, memberships)
	}

	// Per-call timeout. Distinct from the 30s send-side TraceTimeout.
	traceCtx, cancel := context.WithTimeout(ctx, p.ethCallTraceTimeout)
	defer cancel()

	// Uncached trace — see function-level docstring. blockParam mirrors
	// the param the forwarded eth_call will use so trace and actual call
	// run against the same chain state.
	traceResult, err := p.runtimeTracer.TraceTransactionUncached(traceCtx, from, to, data, value, blockParam)
	if err != nil {
		// Distinguish depth-exceeded from upstream-node errors. Both
		// are 403 from the user's POV (tracing-incomplete = deny), but
		// we surface a distinct message so triage can tell deep
		// recursion apart from a node hiccup. Never %v the err.
		if errors.Is(err, tracer.ErrTraceDepthExceeded) {
			slog.Info("eth_call trace: depth exceeded",
				slog.String("user", req.UserID), slog.String("to", to))
			return &ProcessError{StatusCode: http.StatusForbidden, Message: ethCallDenyDepthExceeded, Reason: ReasonTraceDepthExceeded}
		}
		slog.Warn("eth_call trace: upstream tracer error",
			slog.String("user", req.UserID), slog.String("to", to), slog.Any("err", err))
		return &ProcessError{StatusCode: http.StatusForbidden, Message: ethCallDenyTracerError, Reason: ReasonTracingUnavailable}
	}
	if traceResult == nil {
		// Tracer is enabled but returned nil — fail closed. This is
		// the same posture as the send path (line ~910).
		slog.Warn("eth_call trace: nil result", slog.String("user", req.UserID), slog.String("to", to))
		return &ProcessError{StatusCode: http.StatusForbidden, Message: ethCallDenyTracerError, Reason: ReasonTracingUnavailable}
	}

	// RD-1053: opt into intra-org grant scoping when the knob is on. Fail
	// closed if the grant set can't be resolved — a knob that is on must
	// never degrade to org-ownership-only.
	traceOpts, optErr := p.intraOrgGrantTraceOptions(ctx, user.ID, to, userOrgIDs)
	if optErr != nil {
		slog.Warn("eth_call trace: intra-org grant resolution failed",
			slog.String("user", req.UserID), slog.Any("err", optErr))
		return &ProcessError{StatusCode: http.StatusForbidden, Message: ethCallDenyTracerError, Reason: ReasonTracingUnavailable}
	}

	validationResult, err := p.traceValidator.ValidateTrace(ctx, userOrgIDs, traceResult, userHasDeploy, traceOpts...)
	if err != nil {
		slog.Warn("eth_call trace: validator error",
			slog.String("user", req.UserID), slog.Any("err", err))
		return &ProcessError{StatusCode: http.StatusInternalServerError, Message: ethCallDenyTracerError, Reason: ReasonTracingUnavailable}
	}
	if !validationResult.Allowed {
		// Diagnostic detail (which contract triggered the deny, and the
		// kind of denial) goes to slog only — never to the response body.
		// DenialKind lets audit / SIEM distinguish "touched another org"
		// from "touched an unregistered address" without parsing slog text.
		kind := string(validationResult.DenialKind)
		slog.Info("eth_call trace: denial",
			slog.String("user", req.UserID),
			slog.String("to", to),
			slog.String("kind", kind))
		slog.Debug("eth_call trace: denial detail",
			slog.String("user", req.UserID),
			slog.String("kind", kind),
			slog.String("reason", validationResult.Reason),
			slog.String("denied_target", validationResult.DeniedTarget))
		return &ProcessError{StatusCode: http.StatusForbidden, Message: ethCallDenyCrossOrg, Reason: ReasonCrossOrg}
	}

	return nil
}

// Opaque deny messages for the debug_trace* surface (RD-1304). Same KD-3
// posture as the eth_call constants above: never interpolate the upstream
// error, the validator Reason, or a contract address into the response body.
// A single traceDenyAccess covers a non-participant replay AND a non-existent
// tx so the wire cannot be used as a tx-existence oracle.
const (
	traceDenyAccess       = "trace access denied"
	traceDenyUnsafeTracer = "trace denied: unsupported tracer or trace option"
	traceDenyOverrides    = "trace denied: state or block overrides are not permitted"
	traceDenyInvalidShape = "trace denied: invalid request shape"
	traceDenyTracerError  = "trace denied: tracing temporarily unavailable"
	traceDenyCrossOrg     = "trace denied: access not permitted"
)

// proxyCallTracerConfig builds the client trace preset (RD-1304).
// Only call-tree frames are returned; logs and other tracer formats are
// unsupported. The response is parsed and validated before it is returned.
func proxyCallTracerConfig() map[string]any {
	return map[string]any{
		"tracer":       "callTracer",
		"tracerConfig": map[string]any{"onlyTopCall": false},
	}
}

// debugTracePlan is the validated, proxy-built upstream request plus the org
// scope and deploy status the trace must be validated against.
type debugTracePlan struct {
	upstreamReq   []byte             // proxy-built callTracer JSON-RPC request
	orgIDs        map[string]bool    // orgs to validate the trace tree against
	userHasDeploy bool               // real deploy-claim status (CREATE gate)
	traceOpts     []rbac.TraceOption // client trace grant scoping
}

// processDebugTrace applies the corresponding read method's access checks,
// constructs a supported callTracer request and validates the returned tree
// against the resolved organization and grants. The client receives the
// strictly parsed and validated tree. Internal proxy simulations use their
// dedicated tracer paths.
func (p *JSONRPCProcessor) processDebugTrace(ctx context.Context, req *ProcessRequest) *ProcessResult {
	start := time.Now()

	// Apply the exact method catalog before the trace-specific path.
	if !rbac.IsForwardableMethod(req.Method) {
		req.denialReason = ReasonMethodNotAllowed
		p.recordRPCOutcome(req.Method, "rbac_denied", start)
		p.recordRBACDecision("denied")
		p.logAccess(ctx, req, http.StatusForbidden, http.StatusNotFound)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusNotFound, Message: "method not found"}}
	}

	// RD-1305: refuse unsupported debug_traceCall options before tracing or
	// forwarding. The response is opaque; the reason remains in the access log.
	if denied, kind := rbac.DetectStateOverride(req.Method, req.Params); denied {
		req.denialReason = ReasonStateOverrideNotAllowed
		slog.Info("debug_trace state/block override denied", "method", req.Method, "user", req.UserID, "ip", req.ClientIP, "kind", kind)
		p.recordRPCOutcome(req.Method, "override_denied", start)
		p.recordRBACDecision("denied")
		p.logAccess(ctx, req, http.StatusForbidden, http.StatusNotFound)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusNotFound, Message: "method not found"}}
	}

	// Feature gate: tracing configured and the forwarding path wired.
	if p.runtimeTracer == nil || p.traceValidator == nil || !p.runtimeTracer.IsEnabled() || p.proxy == nil {
		p.logAccess(ctx, req, http.StatusForbidden)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusForbidden, Message: "runtime tracing is not supported or enabled on this proxy"}}
	}

	// Process canonicalizes built-in method spelling before trace dispatch.
	traceMethod := req.Method
	if a := rbac.ResolveMethodAlias(req.Method); a == "debug_traceCall" || a == "debug_traceTransaction" {
		traceMethod = a
	}

	// Load the caller. Fail closed.
	user, err := p.rbacAccessCtrl.Store().GetUserByExternalID(ctx, req.UserID)
	if err != nil || user == nil {
		p.logAccess(ctx, req, http.StatusUnauthorized)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusUnauthorized, Message: "failed to get user"}}
	}
	memberships, err := p.rbacAccessCtrl.Store().ListUserMembershipsWithDetails(ctx, user.ID)
	if err != nil {
		p.logAccess(ctx, req, http.StatusInternalServerError)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusInternalServerError, Message: "failed to get memberships"}}
	}

	userOrgIDs := make(map[string]bool)
	for _, m := range memberships {
		if m.Group != nil {
			userOrgIDs[m.Group.OrgID] = true
		}
	}
	// RD-1135: attribute access-log rows to the caller's org when unambiguous.
	if len(userOrgIDs) == 1 {
		for id := range userOrgIDs {
			req.resolvedOrgID = id
		}
	}

	// 1. Method allowlist (RD-1121). Uniform opaque 404 (real status logged).
	if !p.userCanTraceMethod(ctx, user.ID, memberships, req.Method) {
		req.denialReason = ReasonMethodNotAllowed
		slog.Info("RBAC trace denied: method not in allowlist", "method", req.Method, "user", req.UserID, "ip", req.ClientIP)
		p.logAccess(ctx, req, http.StatusForbidden, http.StatusNotFound)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusNotFound, Message: "method not found"}}
	}

	// 2. Vet the trace config/params. The caller's tracer is NEVER forwarded;
	//    anything other than an absent config or an explicit plain callTracer
	//    (no withLog), and any state/block override or malformed shape, is
	//    rejected fail-closed. (Override params are RD-1305's broader surface;
	//    on the trace path they are refused so this gate stays sound.)
	if perr := vetDebugTraceConfig(traceMethod, req.Params); perr != nil {
		req.denialReason = perr.Reason
		p.logAccess(ctx, req, perr.StatusCode)
		return &ProcessResult{Error: perr}
	}

	// 3. Concurrency + rate gates BEFORE any upstream trace (RD-915 F5): one
	//    allowlisted JWT must not pin unbounded concurrent traces.
	if p.concurrencyLimiter != nil && !p.concurrencyLimiter.TryAcquire(req.UserID) {
		if p.metrics != nil {
			p.metrics.ConcurrencyRejectionsTotal.Inc()
		}
		req.denialReason = ReasonConcurrencyLimited
		p.recordRPCOutcome(req.Method, "concurrent_limit", start)
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusTooManyRequests, Message: "too many concurrent requests"}}
	}
	if p.concurrencyLimiter != nil {
		defer p.concurrencyLimiter.Release(req.UserID)
	}
	rps, daily := 1, 100
	if allowed, rateLimitReason := p.rateLimiter.CheckAndIncrement(req.UserID, &rps, &daily); !allowed {
		req.denialReason = ReasonRateLimited
		p.recordRPCOutcome(req.Method, "rate_limited", start)
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusTooManyRequests, Message: rateLimitReason}}
	}

	// 4. Method-specific access gate + build the proxy callTracer request.
	var plan *debugTracePlan
	var gateErr *ProcessError
	switch traceMethod {
	case "debug_traceCall":
		plan, gateErr = p.gateDebugTraceCall(ctx, req, user)
	case "debug_traceTransaction":
		plan, gateErr = p.gateDebugTraceTransaction(ctx, req, user)
	default:
		gateErr = &ProcessError{StatusCode: http.StatusNotFound, Message: "method not found", Reason: ReasonMethodNotAllowed}
	}
	if gateErr != nil {
		req.denialReason = gateErr.Reason
		// A 404 is the masked wire status; log the real decision status.
		realStatus := gateErr.StatusCode
		if gateErr.StatusCode == http.StatusNotFound {
			realStatus = http.StatusForbidden
			if gateErr.Reason == ReasonAuthRequired {
				realStatus = http.StatusUnauthorized
			}
			p.logAccess(ctx, req, realStatus, http.StatusNotFound)
		} else {
			p.logAccess(ctx, req, gateErr.StatusCode)
		}
		p.recordRPCOutcome(req.Method, "trace_denied", start)
		return &ProcessResult{Error: gateErr}
	}

	// 5. Forward the proxy-built callTracer request, validate the EXACT payload
	//    it returns, and return it. Single upstream trace → no TOCTOU.
	rawResult, perr := p.forwardAndValidateTrace(ctx, req, plan)
	if perr != nil {
		req.denialReason = perr.Reason
		p.recordRPCOutcome(req.Method, "trace_denied", start)
		p.logAccess(ctx, req, perr.StatusCode)
		return &ProcessResult{Error: perr}
	}

	p.recordRPCOutcome(req.Method, "success", start)
	p.logAccess(ctx, req, http.StatusOK)

	id := extractRequestID(req.Body)
	env := make([]byte, 0, len(rawResult)+len(id)+32)
	env = append(env, []byte(`{"jsonrpc":"2.0","id":`)...)
	env = append(env, []byte(id)...)
	env = append(env, []byte(`,"result":`)...)
	env = append(env, rawResult...)
	env = append(env, '}')
	return &ProcessResult{StatusCode: http.StatusOK, ResponseBody: env}
}

// gateDebugTraceCall runs the eth_call-equivalent access checks for a client
// debug_traceCall and returns the proxy-built callTracer request pinned to the
// resolved org. The access decision, the Multicall guard and the forwarded
// request all use ONE canonical call object, so what the node executes is
// exactly what was checked. Fail-closed on every lookup error.
func (p *JSONRPCProcessor) gateDebugTraceCall(ctx context.Context, req *ProcessRequest, user *rbac.User) (*debugTracePlan, *ProcessError) {
	invalid := &ProcessError{StatusCode: http.StatusBadRequest, Message: traceDenyInvalidShape, Reason: ReasonInvalidRequestShape}

	call, cerr := canonicalTraceCall(req.Params[0]) // vetDebugTraceConfig already accepted it
	if cerr != nil {
		return nil, cerr
	}
	from, _ := call["from"].(string)
	to, _ := call["to"].(string)

	// Block param (params[1]); same validated shapes as eth_call's F2 path,
	// rebuilt from its known keys so nothing else reaches the node.
	blockParam, blockErr := extractEthCallBlockParam(req.Params)
	if blockErr != nil {
		return nil, invalid
	}
	blockParam, blockErr = rebuildTraceBlockParam(blockParam)
	if blockErr != nil {
		return nil, invalid
	}

	// Multicall batches reach many contracts from one entry point; eth_call
	// refuses them in CheckAccess, keyed on the method name, so the guard is
	// applied here explicitly for the trace twin.
	if isMC, _ := rbac.DetectMulticall("eth_call", []any{call}); isMC {
		return nil, &ProcessError{StatusCode: http.StatusNotFound, Message: "method not found", Reason: ReasonMethodNotAllowed}
	}

	// eth_call-equivalent CheckAccess. Method stays "debug_traceCall" so
	// HasMethod gates the trace allowlist and the ban/KYC blanket checks apply;
	// AccessMethod="eth_call" drives contract-grant / function-selector /
	// historical-state (index-1 block) checks against the top-level target.
	accessReq := &rbac.AccessCheckRequest{
		UserExternalID:   req.UserID,
		OrgID:            req.OrgID,
		Method:           "debug_traceCall",
		AccessMethod:     "eth_call",
		Params:           []any{call, blockParam},
		TargetAddress:    rbac.GetTargetAddress("eth_call", []any{call}),
		FunctionSelector: rbac.GetFunctionSelector("eth_call", []any{call}),
		BypassCache:      req.BypassPermsCache,
	}
	result, err := p.rbacAccessCtrl.CheckAccess(ctx, accessReq)
	if err != nil {
		slog.Error("debug_traceCall: CheckAccess errored", "user", req.UserID, "err", err)
		return nil, &ProcessError{StatusCode: http.StatusInternalServerError, Message: traceDenyTracerError, Reason: ReasonInternalError}
	}
	req.resolvedOrgID = result.OrgID
	if !result.Allowed {
		reason := ReasonMethodNotAllowed
		if result.AuthRequired {
			reason = ReasonAuthRequired
		}
		return nil, &ProcessError{StatusCode: http.StatusNotFound, Message: "method not found", Reason: reason}
	}
	if result.OrgID == "" {
		// An allowed decision always resolves an org; refuse rather than
		// fall back to the union of memberships.
		return nil, &ProcessError{StatusCode: http.StatusForbidden, Message: traceDenyTracerError, Reason: ReasonTracingUnavailable}
	}

	// A supplied sender must be linked to the caller (RD-915).
	if from != "" {
		addrs, addrErr := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
		if addrErr != nil {
			slog.Warn("debug_traceCall: linked-address lookup failed", "user", req.UserID, "err", addrErr)
			return nil, &ProcessError{StatusCode: http.StatusForbidden, Message: traceDenyTracerError, Reason: ReasonTracingUnavailable}
		}
		if !containsAddressFold(addrs, from) {
			slog.Info("debug_traceCall: user-supplied from rejected (not linked)", "user", req.UserID, "from", from)
			return nil, &ProcessError{StatusCode: http.StatusBadRequest, Message: traceDenyInvalidShape, Reason: ReasonSenderNotLinked}
		}
	}

	// Pin the trace to the resolved org: a multi-org caller on /rpc/:orgB
	// whose call reaches an org-A contract is denied, not allowed via the
	// union of memberships.
	orgIDs, userHasDeploy, perr := p.pinnedTraceScope(ctx, user.ID, result.OrgID)
	if perr != nil {
		return nil, perr
	}

	// Every same-org frame must be granted (the top-level target was just
	// authorized by CheckAccess).
	traceOpts, perr := p.clientTraceGrantScope(ctx, user.ID, orgIDs, to)
	if perr != nil {
		return nil, perr
	}

	body, mErr := buildTraceRequest("debug_traceCall", []any{call, blockParam, proxyCallTracerConfig()})
	if mErr != nil {
		return nil, &ProcessError{StatusCode: http.StatusInternalServerError, Message: traceDenyTracerError, Reason: ReasonInternalError}
	}
	return &debugTracePlan{upstreamReq: body, orgIDs: orgIDs, userHasDeploy: userHasDeploy, traceOpts: traceOpts}, nil
}

// gateDebugTraceTransaction enforces the eth_getTransactionByHash access and
// visibility rules on a mined-tx replay, pinned to one org:
//
//   - CheckAccess (Method=debug_traceTransaction, AccessMethod=
//     eth_getTransactionByHash) gives the ban/KYC gates, the path-org (or
//     single-org) resolution and the allowlist in that org — so the replay is
//     scoped to the org the request (or the view-as gate) names;
//   - the viewer must be a participant (linked address == from|to), an admin
//     of the tx's `to` contract in that org, or a visibleTo recipient;
//   - a `to` contract registered to another org is refused before the trace.
//
// A non-existent tx and a non-visible tx collapse to the same opaque 403 (no
// existence oracle). Fail-closed on every lookup error.
func (p *JSONRPCProcessor) gateDebugTraceTransaction(ctx context.Context, req *ProcessRequest, user *rbac.User) (*debugTracePlan, *ProcessError) {
	txHash, _ := req.Params[0].(string) // vetDebugTraceConfig validated 0x + 64 hex
	hidden := &ProcessError{StatusCode: http.StatusForbidden, Message: traceDenyAccess, Reason: ReasonTraceAccessDenied}

	accessReq := &rbac.AccessCheckRequest{
		UserExternalID: req.UserID,
		OrgID:          req.OrgID,
		Method:         "debug_traceTransaction",
		AccessMethod:   rbac.MethodGetTransactionByHash,
		Params:         []any{txHash},
		BypassCache:    req.BypassPermsCache,
	}
	result, err := p.rbacAccessCtrl.CheckAccess(ctx, accessReq)
	if err != nil {
		slog.Error("debug_traceTransaction: CheckAccess errored", "user", req.UserID, "err", err)
		return nil, &ProcessError{StatusCode: http.StatusInternalServerError, Message: traceDenyTracerError, Reason: ReasonInternalError}
	}
	req.resolvedOrgID = result.OrgID
	if !result.Allowed {
		reason := ReasonMethodNotAllowed
		if result.AuthRequired {
			reason = ReasonAuthRequired
		}
		return nil, &ProcessError{StatusCode: http.StatusNotFound, Message: "method not found", Reason: reason}
	}
	if result.OrgID == "" {
		return nil, &ProcessError{StatusCode: http.StatusForbidden, Message: traceDenyTracerError, Reason: ReasonTracingUnavailable}
	}
	orgID := result.OrgID

	// Cheap existence + parties lookup BEFORE the (more expensive) trace, so a
	// non-participant never triggers a trace.
	from, to, input, ok := p.fetchTxParties(ctx, req, txHash)
	if !ok {
		return nil, hidden
	}

	// A `to` contract owned by another org: the replay would be validated
	// against the pinned org and denied anyway; refuse before the trace.
	if to != "" {
		owner, oErr := p.rbacAccessCtrl.Store().GetContractOwnerOrgID(ctx, to)
		if oErr != nil {
			return nil, hidden
		}
		if owner != "" && owner != orgID {
			return nil, hidden
		}
	}

	orgIDs, userHasDeploy, perr := p.pinnedTraceScope(ctx, user.ID, orgID)
	if perr != nil {
		return nil, perr
	}
	if !p.viewerCanSeeMinedTx(ctx, req, user.ID, orgID, from, to, txHash) {
		return nil, hidden
	}

	// The top-level `to` must be a contract the viewer may access: the same
	// contract-access decision as eth_call in this org (grants, deployer
	// fallback, cross-org isolation). It is then an authorized frame, as the
	// CheckAccess-cleared target is for debug_traceCall. A creation tx (no
	// `to`) is covered by the deploy-claim rule in ValidateTrace.
	authorized := ""
	if to != "" {
		callParams := []any{map[string]any{"to": to, "data": input}, "latest"}
		toRes, toErr := p.rbacAccessCtrl.CheckAccess(ctx, &rbac.AccessCheckRequest{
			UserExternalID:   req.UserID,
			OrgID:            orgID,
			Method:           "debug_traceTransaction",
			AccessMethod:     "eth_call",
			Params:           callParams,
			TargetAddress:    to,
			FunctionSelector: rbac.GetFunctionSelector("eth_call", callParams),
			BypassCache:      req.BypassPermsCache,
		})
		if toErr != nil || toRes == nil || !toRes.Allowed {
			return nil, hidden
		}
		authorized = to
	}

	// Every other same-org frame must be a contract the viewer holds a grant
	// on: a replay shows every frame's input and output, which the
	// transaction lookup never does.
	traceOpts, perr := p.clientTraceGrantScope(ctx, user.ID, orgIDs, authorized)
	if perr != nil {
		return nil, perr
	}

	body, mErr := buildTraceRequest("debug_traceTransaction", []any{txHash, proxyCallTracerConfig()})
	if mErr != nil {
		return nil, &ProcessError{StatusCode: http.StatusInternalServerError, Message: traceDenyTracerError, Reason: ReasonInternalError}
	}
	return &debugTracePlan{upstreamReq: body, orgIDs: orgIDs, userHasDeploy: userHasDeploy, traceOpts: traceOpts}, nil
}

// pinnedTraceScope returns the single-org validation scope for a client trace
// and the caller's deploy-claim status in that org. Fail-closed.
func (p *JSONRPCProcessor) pinnedTraceScope(ctx context.Context, userUUID, orgID string) (map[string]bool, bool, *ProcessError) {
	perms, err := p.rbacAccessCtrl.GetEffectivePermissionsByIDs(ctx, userUUID, orgID)
	if err != nil || perms == nil {
		slog.Warn("debug_trace: pinned-org permission lookup failed", "user_uuid", userUUID, "org_id", orgID, "err", err)
		return nil, false, &ProcessError{StatusCode: http.StatusForbidden, Message: traceDenyTracerError, Reason: ReasonTracingUnavailable}
	}
	return map[string]bool{orgID: true}, effectivePermissionsHasDeployClaim(perms), nil
}

// clientTraceGrantScope returns intra-org grant scoping for the client trace
// path. Unlike the eth_call/send paths, where the RD-1053 knob decides, it is
// ALWAYS on here: a trace reveals every same-org frame's input and output,
// while eth_call returns only the final result and the explorer shows an
// ungranted same-org contract as private to the same viewer. authorized is a
// target already cleared by CheckAccess (empty for a replay). Fail-closed.
func (p *JSONRPCProcessor) clientTraceGrantScope(ctx context.Context, userUUID string, orgIDs map[string]bool, authorized string) ([]rbac.TraceOption, *ProcessError) {
	granted, err := p.resolveGrantedContracts(ctx, userUUID, orgIDs)
	if err != nil {
		slog.Warn("debug_trace: grant resolution failed", "user_uuid", userUUID, "err", err)
		return nil, &ProcessError{StatusCode: http.StatusForbidden, Message: traceDenyTracerError, Reason: ReasonTracingUnavailable}
	}
	if authorized != "" {
		granted[strings.ToLower(authorized)] = true
	}
	return []rbac.TraceOption{rbac.WithClientTraceGrantScoping(granted)}, nil
}

// forwardAndValidateTrace forwards the proxy-built callTracer request, parses
// the returned payload STRICTLY (a well-formed callTracer tree only; unknown
// frame types or non-callTracer bodies fail closed), validates every frame
// against the plan's org scope, and returns the re-marshaled sanitized frame —
// so the bytes returned are exactly the frames validated.
func (p *JSONRPCProcessor) forwardAndValidateTrace(ctx context.Context, req *ProcessRequest, plan *debugTracePlan) (json.RawMessage, *ProcessError) {
	traceAPIKey := p.defaultRPCAPIKey
	traceAPIKeyHeader := p.resolveAPIKeyHeader()
	if p.circuitBreaker != nil && p.circuitBreaker.IsOpen(traceAPIKey) {
		if p.metrics != nil {
			p.metrics.CircuitBreakerTripsTotal.WithLabelValues(maskAPIKey(traceAPIKey)).Inc()
		}
		return nil, &ProcessError{StatusCode: http.StatusTooManyRequests, Message: "upstream rate limited, retry in 1s", Reason: ReasonRateLimited}
	}
	forwardStart := time.Now()
	responseBody, statusCode, err := p.proxy.ForwardWithAPIKeyHeader(plan.upstreamReq, traceAPIKeyHeader, traceAPIKey, req.ClientIP)
	if p.metrics != nil {
		p.metrics.RPCNodeForwardDuration.WithLabelValues(metrics.NormalizeRPCMethod(req.Method)).Observe(time.Since(forwardStart).Seconds())
	}
	if p.circuitBreaker != nil {
		if statusCode == http.StatusTooManyRequests {
			if p.metrics != nil {
				p.metrics.UpstreamRateLimitTotal.WithLabelValues(maskAPIKey(traceAPIKey)).Inc()
			}
			p.circuitBreaker.Trip(traceAPIKey)
		} else if statusCode == http.StatusOK {
			p.circuitBreaker.Reset(traceAPIKey)
		}
	}
	if err != nil {
		slog.Warn("jsonrpc: trace forward failed", "method", req.Method, "err", err)
		return nil, &ProcessError{StatusCode: http.StatusBadGateway, Message: "failed to forward trace request", Reason: ReasonUpstreamError}
	}
	if statusCode == http.StatusTooManyRequests {
		return nil, &ProcessError{StatusCode: http.StatusTooManyRequests, Message: "upstream rate limited, retry in 1s", Reason: ReasonRateLimited}
	}
	if statusCode != http.StatusOK {
		slog.Warn("jsonrpc: trace upstream returned unsuccessful status", "method", req.Method, "status", statusCode)
		return nil, &ProcessError{StatusCode: http.StatusBadGateway, Message: traceDenyTracerError, Reason: ReasonUpstreamError}
	}

	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if jerr := json.Unmarshal(responseBody, &rpcResp); jerr != nil {
		slog.Warn("jsonrpc: trace upstream returned malformed response", "method", req.Method)
		return nil, &ProcessError{StatusCode: http.StatusBadGateway, Message: traceDenyTracerError, Reason: ReasonUpstreamError}
	}
	if rpcResp.Error != nil {
		// Never echo the node error (it can carry a method/JS-eval detail).
		slog.Warn("jsonrpc: trace upstream error", "method", req.Method, "code", rpcResp.Error.Code)
		return nil, &ProcessError{StatusCode: http.StatusForbidden, Message: traceDenyTracerError, Reason: ReasonTracingUnavailable}
	}

	sanitized, parsed, perr := tracer.ParseStrictCallTrace(rpcResp.Result)
	if perr != nil {
		if errors.Is(perr, tracer.ErrTraceDepthExceeded) {
			return nil, &ProcessError{StatusCode: http.StatusForbidden, Message: traceDenyCrossOrg, Reason: ReasonTraceDepthExceeded}
		}
		slog.Warn("jsonrpc: trace result is not a well-formed callTracer tree", "method", req.Method, "err", perr)
		return nil, &ProcessError{StatusCode: http.StatusForbidden, Message: traceDenyTracerError, Reason: ReasonTracingUnavailable}
	}

	validationResult, vErr := p.traceValidator.ValidateTrace(ctx, plan.orgIDs, parsed, plan.userHasDeploy, plan.traceOpts...)
	if vErr != nil {
		slog.Warn("jsonrpc: trace validation errored", "method", req.Method, "err", vErr)
		return nil, &ProcessError{StatusCode: http.StatusInternalServerError, Message: traceDenyTracerError, Reason: ReasonInternalError}
	}
	if !validationResult.Allowed {
		// Opaque constant; DenialKind/DeniedTarget to slog only (KD-3).
		slog.Info("jsonrpc: trace denied by validator", "method", req.Method, "kind", string(validationResult.DenialKind))
		return nil, &ProcessError{StatusCode: http.StatusForbidden, Message: traceDenyCrossOrg, Reason: ReasonCrossOrg}
	}
	if perr := p.validateClientTraceFrameAccess(ctx, req, plan.orgIDs, validationResult.ClientAccessTargets); perr != nil {
		return nil, perr
	}
	return sanitized, nil
}

// validateClientTraceFrameAccess applies the viewer's existing function and
// argument rules to organization-owned nested frames. The strict parser's
// storage context selects delegated permissions; the trace validator has
// already checked the implementation's ownership separately.
func (p *JSONRPCProcessor) validateClientTraceFrameAccess(ctx context.Context, req *ProcessRequest, orgIDs map[string]bool, targets []tracer.CallTarget) *ProcessError {
	if len(orgIDs) != 1 {
		return &ProcessError{StatusCode: http.StatusForbidden, Message: traceDenyTracerError, Reason: ReasonTracingUnavailable}
	}
	orgID := ""
	for id, allowed := range orgIDs {
		if allowed {
			orgID = id
		}
	}
	if orgID == "" {
		return &ProcessError{StatusCode: http.StatusForbidden, Message: traceDenyTracerError, Reason: ReasonTracingUnavailable}
	}
	for _, target := range targets {
		address := strings.ToLower(target.StorageAddress)
		if address == "" {
			return &ProcessError{StatusCode: http.StatusForbidden, Message: traceDenyTracerError, Reason: ReasonTracingUnavailable}
		}
		params := []any{map[string]any{"to": address, "data": target.Input}, "latest"}
		result, err := p.rbacAccessCtrl.CheckAccess(ctx, &rbac.AccessCheckRequest{
			UserExternalID:   req.UserID,
			OrgID:            orgID,
			Method:           req.Method,
			AccessMethod:     "eth_call",
			Params:           params,
			TargetAddress:    address,
			FunctionSelector: rbac.GetFunctionSelector("eth_call", params),
			BypassCache:      req.BypassPermsCache,
		})
		if err != nil || result == nil {
			slog.Warn("jsonrpc: trace frame permission check failed", "method", req.Method, "err", err)
			return &ProcessError{StatusCode: http.StatusInternalServerError, Message: traceDenyTracerError, Reason: ReasonInternalError}
		}
		if !result.Allowed || result.OrgID != orgID {
			return &ProcessError{StatusCode: http.StatusForbidden, Message: traceDenyAccess, Reason: ReasonTraceAccessDenied}
		}
	}
	return nil
}

// vetDebugTraceConfig validates the positional arity, the call object or tx
// hash, and the (optional) trace config of a client debug_trace* request. It
// rejects, fail-closed: any tracer other than plain callTracer, withLog,
// struct-logger flags, state/block overrides, extra positional args, a
// malformed tx hash or call object, and malformed config. Config keys are
// matched case-insensitively (as geth decodes them) and a case collision is
// ambiguous, so refused. The caller's config is never forwarded regardless;
// this returns a precise deny so a client learns why instead of getting a
// silently substituted format.
func vetDebugTraceConfig(method string, params []any) *ProcessError {
	invalid := &ProcessError{StatusCode: http.StatusBadRequest, Message: traceDenyInvalidShape, Reason: ReasonInvalidRequestShape}
	unsafe := &ProcessError{StatusCode: http.StatusBadRequest, Message: traceDenyUnsafeTracer, Reason: ReasonInvalidRequestShape}
	override := &ProcessError{StatusCode: http.StatusBadRequest, Message: traceDenyOverrides, Reason: ReasonInvalidRequestShape}

	var cfg any
	switch method {
	case "debug_traceCall":
		if len(params) < 1 || len(params) > 3 {
			return invalid
		}
		if _, cerr := canonicalTraceCall(params[0]); cerr != nil {
			return cerr
		}
		if len(params) == 3 {
			cfg = params[2]
		}
	case "debug_traceTransaction":
		// Keep the historical, caller-shape-only messages for these two cases:
		// they describe the caller's own request (no tenant state), and
		// operators/tooling already match on them.
		if len(params) < 1 {
			return &ProcessError{StatusCode: http.StatusBadRequest, Message: "missing transaction hash", Reason: ReasonInvalidRequestShape}
		}
		h, ok := params[0].(string)
		if !ok || !isTxHash(h) {
			return &ProcessError{StatusCode: http.StatusBadRequest, Message: "invalid transaction hash", Reason: ReasonInvalidRequestShape}
		}
		if len(params) > 2 {
			return invalid
		}
		if len(params) == 2 {
			cfg = params[1]
		}
	default:
		return invalid
	}

	if cfg == nil {
		return nil // no config → the proxy serves plain callTracer
	}
	cfgMap, ok := foldKeys(cfg)
	if !ok {
		return invalid // not an object, or keys that collide by case
	}
	// Override / positional-replay keys (singular and plural), matched
	// case-insensitively. The same set is refused by the override check at
	// the top of the trace path; a reject in either denies.
	for _, k := range []string{"stateoverrides", "stateoverride", "blockoverrides", "blockoverride", "txindex"} {
		if _, has := cfgMap[k]; has {
			return override
		}
	}
	if tr, has := cfgMap["tracer"]; has {
		s, _ := tr.(string)
		if s != "callTracer" {
			return unsafe
		}
	} else {
		// Struct-logger flags request an unsupported response format.
		for _, k := range []string{"enablememory", "disablestorage", "disablestack", "enablereturndata", "debug", "limit"} {
			if _, has := cfgMap[k]; has {
				return unsafe
			}
		}
	}
	if tc, has := cfgMap["tracerconfig"]; has {
		tcm, ok := foldKeys(tc)
		if !ok {
			return invalid
		}
		if wl, has := tcm["withlog"]; has {
			b, isBool := wl.(bool)
			if !isBool {
				return invalid
			}
			if b {
				return unsafe
			}
		}
	}
	return nil
}

// foldKeys returns v's keys lowercased, or ok=false when v is not a JSON
// object or two keys collide case-insensitively (ambiguous for a decoder that
// matches keys case-insensitively).
func foldKeys(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	out := make(map[string]any, len(m))
	for k, val := range m {
		lk := strings.ToLower(k)
		if _, dup := out[lk]; dup {
			return nil, false
		}
		out[lk] = val
	}
	return out, true
}

// canonicalTraceCall builds the ONE call object a client debug_traceCall is
// both access-checked against and executed with: from/to/data/value only,
// each a string when present. `data` and `input` are aliases — if both are
// set they must agree. A null, "" or "0x" `to` means contract creation (no
// `to`). Any other field (gas, fees, access lists, authorizations) is not
// forwarded. Malformed → opaque 400, before any upstream call.
func canonicalTraceCall(v any) (map[string]any, *ProcessError) {
	invalid := &ProcessError{StatusCode: http.StatusBadRequest, Message: traceDenyInvalidShape, Reason: ReasonInvalidRequestShape}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, invalid
	}
	str := func(key string) (string, bool, bool) { // value, present, wellTyped
		raw, present := obj[key]
		if !present {
			return "", false, true
		}
		s, isStr := raw.(string)
		return s, true, isStr
	}
	call := map[string]any{}

	if raw, present := obj["to"]; present && raw != nil {
		s, isStr := raw.(string)
		if !isStr {
			return nil, invalid
		}
		if s != "" && s != "0x" {
			if !gethcommon.IsHexAddress(s) {
				return nil, invalid
			}
			call["to"] = strings.ToLower(s)
		}
	}
	if s, present, typed := str("from"); present {
		if !typed || (s != "" && !gethcommon.IsHexAddress(s)) {
			return nil, invalid
		}
		if s != "" {
			call["from"] = strings.ToLower(s)
		}
	}
	data, hasData, dataTyped := str("data")
	input, hasInput, inputTyped := str("input")
	if !dataTyped || !inputTyped {
		return nil, invalid
	}
	if hasData && hasInput && !strings.EqualFold(data, input) {
		return nil, invalid
	}
	if !hasData {
		data = input
	}
	if data != "" {
		call["data"] = data
	}
	if s, present, typed := str("value"); present {
		if !typed {
			return nil, invalid
		}
		if s != "" {
			call["value"] = s
		}
	}
	return call, nil
}

// rebuildTraceBlockParam rebuilds a validated block param from its known
// shapes: a string tag/number passes through; an EIP-1898 object keeps only
// blockNumber, or blockHash plus a boolean requireCanonical.
func rebuildTraceBlockParam(v any) (any, error) {
	switch b := v.(type) {
	case nil:
		return "latest", nil
	case string:
		return b, nil
	case map[string]any:
		if n, ok := b["blockNumber"]; ok {
			return map[string]any{"blockNumber": n}, nil
		}
		out := map[string]any{"blockHash": b["blockHash"]}
		if rc, ok := b["requireCanonical"]; ok {
			rcb, isBool := rc.(bool)
			if !isBool {
				return nil, errors.New("requireCanonical must be a boolean")
			}
			out["requireCanonical"] = rcb
		}
		return out, nil
	default:
		return nil, errors.New("unsupported block param")
	}
}

// isTxHash reports whether s is a 0x-prefixed 32-byte hex hash.
func isTxHash(s string) bool {
	if len(s) != 66 || (!strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X")) {
		return false
	}
	for _, c := range s[2:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// buildTraceRequest marshals a JSON-RPC debug_trace* request the proxy sends
// upstream. id is fixed (the node's echoed id is discarded; the response to
// the client is re-wrapped with the client's own id).
func buildTraceRequest(method string, params []any) ([]byte, error) {
	return json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	})
}

// extractRequestID returns the caller's JSON-RPC id (string/number/null) from
// the raw body, as the exact bytes to echo. Defaults to null on any problem.
func extractRequestID(body []byte) string {
	var env struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(body, &env); err == nil && len(env.ID) > 0 {
		return string(env.ID)
	}
	return "null"
}

// fetchTxParties returns the transaction parties and calldata for access checks.
// A non-existent tx (null result), a transport error, or a malformed response
// all return ok=false (fail-closed / no existence oracle).
func (p *JSONRPCProcessor) fetchTxParties(ctx context.Context, req *ProcessRequest, txHash string) (from, to, input string, ok bool) {
	_ = ctx
	body, err := buildTraceRequest("eth_getTransactionByHash", []any{txHash})
	if err != nil {
		return "", "", "", false
	}
	responseBody, _, ferr := p.proxy.ForwardWithAPIKeyHeader(body, p.resolveAPIKeyHeader(), p.defaultRPCAPIKey, req.ClientIP)
	if ferr != nil {
		return "", "", "", false
	}
	var resp struct {
		Result *struct {
			From  string `json:"from"`
			To    string `json:"to"`
			Input string `json:"input"`
		} `json:"result"`
	}
	if json.Unmarshal(responseBody, &resp) != nil || resp.Result == nil {
		return "", "", "", false
	}
	return strings.ToLower(resp.Result.From), strings.ToLower(resp.Result.To), resp.Result.Input, true
}

// viewerCanSeeMinedTx mirrors the eth_getTransactionByHash visibility predicate
// (REDACTION_SPEC §3.8) within the pinned org: participant (linked address ==
// from|to), admin of the tx's `to` contract in orgID, or a visibleTo
// recipient. userUUID is the internal user id (NOT the DID). Fail-closed.
func (p *JSONRPCProcessor) viewerCanSeeMinedTx(ctx context.Context, req *ProcessRequest, userUUID, orgID, from, to, txHash string) bool {
	addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, req.UserID)
	if err != nil {
		return false // fail closed
	}
	set := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		if a != "" {
			set[strings.ToLower(a)] = struct{}{}
		}
	}
	if from != "" {
		if _, ok := set[from]; ok {
			return true
		}
	}
	if to != "" {
		if _, ok := set[to]; ok {
			return true
		}
		// Admin of the tx's `to` contract, in the pinned org only.
		owner, oErr := p.rbacAccessCtrl.Store().GetContractOwnerOrgID(ctx, to)
		if oErr == nil && owner == orgID {
			if perms, pErr := p.rbacAccessCtrl.GetEffectivePermissionsByIDs(ctx, userUUID, orgID); pErr == nil && perms != nil && perms.HasAdminOnContract(to) {
				return true
			}
		}
	}
	// visibleTo recipient of this specific tx.
	if p.txVisibilityStore != nil {
		if vis, verr := p.txVisibilityStore.GetBatchTxVisibility(ctx, []string{txHash}); verr == nil {
			for _, dids := range vis {
				for _, d := range dids {
					if strings.EqualFold(d, req.UserID) {
						return true
					}
				}
			}
		}
	}
	return false
}

// containsAddressFold reports whether addr (case-insensitive) is in addrs.
func containsAddressFold(addrs []string, addr string) bool {
	al := strings.ToLower(addr)
	for _, a := range addrs {
		if strings.ToLower(a) == al {
			return true
		}
	}
	return false
}

// validateRawTxWithTracing performs runtime trace validation for raw transactions.
// Returns the list of CREATE/CREATE2 targets discovered during tracing (may be nil),
// and a ProcessError if validation fails.
func (p *JSONRPCProcessor) validateRawTxWithTracing(ctx context.Context, req *ProcessRequest, from, to, data, value string) ([]rbac.CreateTarget, *ProcessError) {
	// Get user info for trace validation
	user, err := p.rbacAccessCtrl.Store().GetUserByExternalID(ctx, req.UserID)
	if err != nil || user == nil {
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    "failed to get user for trace validation",
			Reason:     ReasonTracingUnavailable,
		}
	}

	// Get user's org memberships
	memberships, err := p.rbacAccessCtrl.Store().ListUserMembershipsWithDetails(ctx, user.ID)
	if err != nil {
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    "failed to get user memberships for trace validation",
			Reason:     ReasonTracingUnavailable,
		}
	}

	userOrgIDs := make(map[string]bool)
	for _, m := range memberships {
		if m.Group != nil {
			userOrgIDs[m.Group.OrgID] = true
		}
	}

	// Perform the trace
	traceResult, err := p.runtimeTracer.TraceTransaction(ctx, from, to, data, value)
	if err != nil {
		slog.Warn("raw send trace: upstream tracer error",
			slog.String("user", req.UserID), slog.String("to", to), slog.Any("err", err))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyTracerError,
			Reason:     ReasonTracingUnavailable,
		}
	}

	if traceResult == nil {
		slog.Warn("raw send trace: nil result",
			slog.String("user", req.UserID), slog.String("to", to))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyTracerError,
			Reason:     ReasonTracingUnavailable,
		}
	}

	// Determine if user has deploy claim from any of their memberships
	userHasDeploy := p.userHasDeployClaim(ctx, memberships)

	// RD-1053: intra-org grant scoping (same knob as the other send paths).
	traceOpts, optErr := p.intraOrgGrantTraceOptions(ctx, user.ID, to, userOrgIDs)
	if optErr != nil {
		slog.Warn("raw send trace: intra-org grant resolution failed",
			slog.String("user", req.UserID), slog.Any("err", optErr))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceValidatorError,
			Reason:     ReasonTracingUnavailable,
		}
	}

	// Validate the trace against org isolation rules
	validationResult, err := p.traceValidator.ValidateTrace(ctx, userOrgIDs, traceResult, userHasDeploy, traceOpts...)
	if err != nil {
		slog.Warn("raw send trace: validator error",
			slog.String("user", req.UserID), slog.Any("err", err))
		return nil, &ProcessError{
			StatusCode: http.StatusInternalServerError,
			Message:    sendTraceValidatorError,
			Reason:     ReasonTracingUnavailable,
		}
	}

	if !validationResult.Allowed {
		slog.Info("raw send trace: denial",
			slog.String("user", req.UserID), slog.String("to", to))
		slog.Debug("raw send trace: denial detail",
			slog.String("user", req.UserID),
			slog.String("reason", validationResult.Reason),
			slog.String("denied_target", validationResult.DeniedTarget))
		return nil, &ProcessError{
			StatusCode: http.StatusForbidden,
			Message:    sendTraceDenyMessage(validationResult.Reason),
			Reason:     ReasonCrossOrg,
		}
	}

	return validationResult.CreateTargets, nil
}

// userHasDeployClaim checks whether any of the user's memberships grant the deploy claim.
func (p *JSONRPCProcessor) userHasDeployClaim(ctx context.Context, memberships []*rbac.MembershipWithDetails) bool {
	for _, m := range memberships {
		if m.Membership == nil {
			continue
		}
		access, err := p.rbacAccessCtrl.Store().GetGroupAccess(ctx, m.Membership.GroupID)
		if err != nil || access == nil {
			continue
		}
		for _, c := range access.Claims {
			if c == rbac.ClaimDeploy || c == rbac.ClaimAdmin {
				return true
			}
		}
	}
	return false
}

func effectivePermissionsHasDeployClaim(perms *rbac.EffectivePermissions) bool {
	if perms == nil {
		return false
	}
	for _, claim := range perms.Claims {
		if claim == rbac.ClaimDeploy || claim == rbac.ClaimAdmin {
			return true
		}
	}
	return false
}

// userCanTraceMethod reports whether the trace method is permitted by the
// method allowlist of at least one of the user's membership orgs (RD-1121).
//
// It mirrors userHasDeployClaim's "any org grants" multi-org semantics, but
// checks EffectivePermissions.HasMethod — the exact same allowlist matcher
// (default-deny catalog gate + exact-name / "*" expansion) every other RPC method is
// gated by in CheckAccess. The cross-org ValidateTrace content gate runs after
// this and is independent of it.
//
// Fail-closed by construction: a resolve error, a nil perms object, or an org
// whose allowlist omits the method all contribute "denied" for that org; the
// function returns true only on an explicit HasMethod == true. A user with no
// memberships (empty loop) is denied.
func (p *JSONRPCProcessor) userCanTraceMethod(ctx context.Context, userID string, memberships []*rbac.MembershipWithDetails, method string) bool {
	checked := make(map[string]struct{})
	for _, m := range memberships {
		if m.Group == nil {
			continue
		}
		orgID := m.Group.OrgID
		if _, seen := checked[orgID]; seen {
			continue
		}
		checked[orgID] = struct{}{}

		perms, err := p.rbacAccessCtrl.GetEffectivePermissionsByIDs(ctx, userID, orgID)
		if err != nil || perms == nil {
			// Fail-closed for this org; another org may still grant.
			continue
		}
		if perms.HasMethod(method) {
			return true
		}
	}
	return false
}
