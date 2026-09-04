package server

import (
	"context"
	"errors"
	"fmt"
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

	// Get user's org memberships (active only — an expired time-boxed grant
	// must not authorize nested calls into its former organization).
	memberships, err := p.rbacAccessCtrl.Store().ListActiveUserMembershipsWithDetails(ctx, user.ID)
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
	// Match via ResolveMethodAlias so chain-specific equivalents that the
	// operator has explicitly aliased to eth_call (e.g. linea_call) also go
	// through tracing. The send-side equivalent gate is method-literal because
	// eth_sendTransaction has no aliases today; the read side does (RD-915
	// design doc, "Open questions" — "Allowlist of methods that go through
	// eth_call tracing"). Wildcard-passthrough methods without an explicit
	// alias stay at the operator's discretion per RD-911 — opting into
	// wildcards opts out of RBAC, and re-tracing on top of that would defeat
	// the wildcard semantic.
	//
	// H10 (security audit follow-up to RD-915): eth_estimateGas runs the
	// EVM exactly like eth_call — revert reasons, SLOAD-derived branches,
	// and STATICCALL return values flow through the same way. The
	// cross-org composability leak the entry-point check used to allow is
	// identical. Both methods (and their operator-aliased equivalents)
	// share this gate.
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
		memberships, membershipErr := p.rbacAccessCtrl.Store().ListActiveUserMembershipsWithDetails(ctx, user.ID)
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

// processDebugTrace handles debug_traceTransaction and debug_traceCall safely.
// It uses TraceValidator to guarantee 100% org isolation before returning trace output.
func (p *JSONRPCProcessor) processDebugTrace(ctx context.Context, req *ProcessRequest) *ProcessResult {
	start := time.Now()

	if p.runtimeTracer == nil || p.traceValidator == nil || !p.runtimeTracer.IsEnabled() {
		p.logAccess(ctx, req, http.StatusForbidden)
		return &ProcessResult{
			Error: &ProcessError{
				StatusCode: http.StatusForbidden,
				Message:    "runtime tracing is not supported or enabled on this proxy",
			},
		}
	}

	// 1. The trace method must be in the caller's group method allowlist.
	user, err := p.rbacAccessCtrl.Store().GetUserByExternalID(ctx, req.UserID)
	if err != nil || user == nil {
		p.logAccess(ctx, req, http.StatusUnauthorized)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusUnauthorized, Message: "failed to get user"}}
	}

	memberships, err := p.rbacAccessCtrl.Store().ListActiveUserMembershipsWithDetails(ctx, user.ID)
	if err != nil {
		p.logAccess(ctx, req, http.StatusInternalServerError)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusInternalServerError, Message: "failed to get memberships"}}
	}

	// RD-1135: this path never calls CheckAccess (it has its own gate below), so
	// attribute access-log rows to the caller's org when it is unambiguous
	// (exactly one membership-org). A multi-org tracer's rows stay NULL
	// (super-admin-only): a replayed/mined trace can span orgs and has no single
	// owning org to attribute to. Set before the allowlist check so that denial
	// is attributed too.
	{
		orgSet := make(map[string]struct{})
		for _, m := range memberships {
			if m.Group != nil {
				orgSet[m.Group.OrgID] = struct{}{}
			}
		}
		if len(orgSet) == 1 {
			for id := range orgSet {
				req.resolvedOrgID = id
			}
		}
	}

	// RD-1121: gate debug_trace* by the group method allowlist, exactly like
	// every other named RPC method. Historically this path checked ONLY the
	// deploy/admin claim and skipped the allowlist, so an operator who curated
	// allowed_methods to exclude tracing was silently ignored for any group that
	// had the deploy claim. Tracing is not deploying; a distinctly-named method
	// belongs on the allowlist surface (Option B). The cross-org ValidateTrace
	// content gate below is retained regardless — it is independent of any claim.
	// Fail-closed: missing/empty perms or any resolution error => denied.
	if !p.userCanTraceMethod(ctx, user.ID, memberships, req.Method) {
		req.denialReason = ReasonMethodNotAllowed
		slog.Info("RBAC trace denied: method not in allowlist", "method", req.Method, "user", req.UserID, "ip", req.ClientIP)
		// Mirror the normal RBAC deny site (Process / processRawTransaction):
		// uniform opaque 404 on the wire, real status recorded in the access log.
		// Keeping a uniform 404 is what lets ReasonMethodNotAllowed stay on the
		// verbose-wire allowlist (see denial_reasons.go).
		p.logAccess(ctx, req, http.StatusForbidden, http.StatusNotFound)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusNotFound, Message: "method not found"}}
	}

	userOrgIDs := make(map[string]bool)
	for _, m := range memberships {
		if m.Group != nil {
			userOrgIDs[m.Group.OrgID] = true
		}
	}

	// 2. Perform the internal trace
	var traceResult *tracer.TraceResult
	var traceErr error
	// debugCallTarget is the top-level `to` for debug_traceCall (a
	// user-initiated simulation, the trace twin of eth_call). Empty for
	// debug_traceTransaction, which replays a historical mined tx the caller
	// did not necessarily originate — see the RD-1053 scoping note below.
	var debugCallTarget string

	if req.Method == "debug_traceTransaction" {
		if len(req.Params) == 0 {
			return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusBadRequest, Message: "missing transaction hash"}}
		}
		txHash, ok := req.Params[0].(string)
		if !ok {
			return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusBadRequest, Message: "invalid transaction hash"}}
		}
		traceResult, traceErr = p.runtimeTracer.TraceMinedTransaction(ctx, txHash)
	} else if req.Method == "debug_traceCall" {
		from, to, data, value := extractTxParams(req.Params)
		debugCallTarget = to
		traceResult, traceErr = p.runtimeTracer.TraceTransaction(ctx, from, to, data, value)
	}

	if traceErr != nil {
		p.logAccess(ctx, req, http.StatusForbidden)
		// RD-1178: opaque to the client — never echo the raw upstream node
		// error (matches the eth_call/send opaque-constant convention, KD-3).
		slog.Warn("jsonrpc: trace execution failed", "method", req.Method, "err", traceErr)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusForbidden, Message: "trace execution failed"}}
	}
	if traceResult == nil {
		p.logAccess(ctx, req, http.StatusForbidden)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusForbidden, Message: "trace returned no result"}}
	}

	// RD-1053: extend intra-org grant scoping to debug_traceCall — it runs
	// the EVM exactly like eth_call, so leaving it on org-ownership-only
	// would be a bypass for deploy/admin-claim users when the knob is on.
	// debug_traceTransaction is deliberately NOT scoped this way: it replays
	// a historical mined tx (not caller-initiated), and binding incident
	// debugging to the caller's own grants would defeat the purpose of the
	// claim-gated debug surface. Cross-org isolation still applies to both.
	var debugTraceOpts []rbac.TraceOption
	if req.Method == "debug_traceCall" {
		opts, optErr := p.intraOrgGrantTraceOptions(ctx, user.ID, debugCallTarget, userOrgIDs)
		if optErr != nil {
			slog.Warn("debug_traceCall: intra-org grant resolution failed",
				slog.String("user", req.UserID), slog.Any("err", optErr))
			p.logAccess(ctx, req, http.StatusForbidden)
			return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusForbidden, Message: "trace validation error"}}
		}
		debugTraceOpts = opts
	}

	// 3. Validate the trace tree strictly
	validationResult, err := p.traceValidator.ValidateTrace(ctx, userOrgIDs, traceResult, true, debugTraceOpts...)
	if err != nil {
		p.logAccess(ctx, req, http.StatusInternalServerError)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusInternalServerError, Message: "trace validation error"}}
	}

	// THE GATE: Ensure no cross-org leaks occur.
	if !validationResult.Allowed {
		p.logAccess(ctx, req, http.StatusForbidden)
		// We purposefully do NOT return the trace output here. We return the Access Denied reason.
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusForbidden, Message: fmt.Sprintf("cross-org trace denied: %s", validationResult.Reason)}}
	}

	// 4. Rate Limit (Tracing is expensive, hard limit to low RPS)
	rps, daily := 1, 100
	allowed, rateLimitReason := p.rateLimiter.CheckAndIncrement(req.UserID, &rps, &daily)
	if !allowed {
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusTooManyRequests, Message: rateLimitReason}}
	}

	// 5. Validated & Safe! Forward the exact request to the upstream node to fetch the raw requested trace format
	// (Since we used internal tracers like callTracer, but they might want struct logs or memory dumps)
	traceAPIKey := p.defaultRPCAPIKey
	traceAPIKeyHeader := p.resolveAPIKeyHeader()
	if p.circuitBreaker != nil && p.circuitBreaker.IsOpen(traceAPIKey) {
		if p.metrics != nil {
			p.metrics.CircuitBreakerTripsTotal.WithLabelValues(maskAPIKey(traceAPIKey)).Inc()
		}
		p.logAccess(ctx, req, http.StatusTooManyRequests)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusTooManyRequests, Message: "upstream rate limited, retry in 1s"}}
	}
	forwardStart := time.Now()
	responseBody, statusCode, err := p.proxy.ForwardWithAPIKeyHeader(req.Body, traceAPIKeyHeader, traceAPIKey, req.ClientIP)
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
		p.logAccess(ctx, req, http.StatusBadGateway)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusBadGateway, Message: "failed to forward trace request"}}
	}

	p.recordRPCOutcome(req.Method, "success", start)
	p.logAccess(ctx, req, statusCode)

	// Return the raw response exactly as it came from the node
	return &ProcessResult{
		StatusCode:   statusCode,
		ResponseBody: responseBody,
	}
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

	// Get user's org memberships (active only).
	memberships, err := p.rbacAccessCtrl.Store().ListActiveUserMembershipsWithDetails(ctx, user.ID)
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
// (glob expansion + global-wildcard deny floor) every other RPC method is
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
