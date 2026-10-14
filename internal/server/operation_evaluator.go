package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/rbac"
)

type authorizationScopeKind uint8

// Scopes: org-local (dry-run), allowlisted memberships (oracle), all active
// memberships (live RPC).
const (
	authorizationScopeOrgLocal authorizationScopeKind = iota
	authorizationScopeAllActiveMemberships
)

type operationEvaluation struct {
	AccessRequest *rbac.AccessCheckRequest
	AccessResult  *rbac.AccessCheckResult
}

type operationAccessError struct{ err error }

func (e *operationAccessError) Error() string { return e.err.Error() }
func (e *operationAccessError) Unwrap() error { return e.err }

// evaluateAccessRequest is the common RBAC decision primitive used by preview
// surfaces and live RPC. Callers share request-envelope construction where
// their wire formats permit it, then converge here for the actual policy
// evaluation and operational error classification.
func evaluateAccessRequest(ctx context.Context, accessController *rbac.AccessController, accessRequest *rbac.AccessCheckRequest) (*operationEvaluation, error) {
	if accessController == nil {
		return nil, errors.New("operation evaluator is unavailable")
	}
	accessResult, err := accessController.CheckAccess(ctx, accessRequest)
	if err != nil {
		return nil, &operationAccessError{err: err}
	}
	return &operationEvaluation{AccessRequest: accessRequest, AccessResult: accessResult}, nil
}

// evaluateOperation is the common RBAC entry point for preview surfaces. It
// centralizes operation-envelope derivation and access evaluation; simulation,
// compliance side effects, audit projection, and response shaping remain with
// the caller. Org-local callers pin OrgID. All-active-memberships callers may
// let CheckAccess resolve it from the operation.
func (s *Server) evaluateOperation(
	ctx context.Context,
	subjectDID string,
	operation apimodels.DryRunRPCBlock,
	scope authorizationScopeKind,
	orgID string,
) (*operationEvaluation, error) {
	if scope == authorizationScopeOrgLocal && orgID == "" {
		return nil, errors.New("org-local evaluation requires an organization")
	}
	accessRequest, err := dryRunAccessRequest(subjectDID, orgID, operation)
	if err != nil {
		return nil, err
	}
	return evaluateAccessRequest(ctx, s.rbacAccessCtrl, accessRequest)
}

// authorizationScopeAllowlisted is the oracle scope: active memberships in the
// operator allowlist only.
const authorizationScopeAllowlisted authorizationScopeKind = 2

// evaluationMode separates a preview (dry-run, oracle), which must have no
// side effect, from a commit (live RPC).
type evaluationMode uint8

const (
	evaluationPreview evaluationMode = iota
	evaluationCommit
)

// evaluationScope names the organizations a path may judge. orgID is the
// path org for org-local scope and the resolved org otherwise (its effective
// claims decide runtime contract creation). inScope is set for the allowlisted
// scope only.
type evaluationScope struct {
	kind    authorizationScopeKind
	orgID   string
	inScope func(orgID string) bool
}

// traceOrgScope is the scope-aware org selection shared by the live eth_call
// trace, dry-run and the oracle. It returns the organizations whose contracts
// count as the caller's own in a trace, and whether runtime contract creation
// is allowed. Expired memberships count for nothing.
func traceOrgScope(ctx context.Context, ac *rbac.AccessController, user *rbac.User, scope evaluationScope) (map[string]bool, bool, error) {
	if ac == nil || user == nil {
		return nil, false, errors.New("trace scope is unavailable")
	}
	orgIDs := make(map[string]bool)
	if scope.kind == authorizationScopeOrgLocal {
		perms, err := ac.GetEffectivePermissionsByIDs(ctx, user.ID, scope.orgID)
		if err != nil || perms == nil {
			return nil, false, fmt.Errorf("pinned-org permissions unavailable: %w", errOrNil(err))
		}
		orgIDs[scope.orgID] = true
		return orgIDs, effectivePermissionsHasDeployClaim(perms), nil
	}
	memberships, err := ac.Store().ListActiveUserMembershipsWithDetails(ctx, user.ID)
	if err != nil {
		return nil, false, err
	}
	memberships = liveMemberships(memberships)
	if scope.kind == authorizationScopeAllowlisted {
		inScope := make([]*rbac.MembershipWithDetails, 0, len(memberships))
		for _, m := range memberships {
			if m.Group != nil && scope.inScope != nil && scope.inScope(m.Group.OrgID) {
				inScope = append(inScope, m)
			}
		}
		memberships = inScope
	}
	for _, m := range memberships {
		if m.Group != nil {
			orgIDs[m.Group.OrgID] = true
		}
	}
	if scope.kind == authorizationScopeAllowlisted && !orgIDs[scope.orgID] {
		return nil, false, errors.New("evaluated organization is outside the scope")
	}
	if scope.orgID == "" {
		return orgIDs, membershipsHaveDeployClaim(ctx, ac.Store(), memberships), nil
	}
	perms, err := ac.GetEffectivePermissionsByIDs(ctx, user.ID, scope.orgID)
	if err != nil || perms == nil {
		return nil, false, fmt.Errorf("resolved-org permissions unavailable: %w", errOrNil(err))
	}
	// Live RPC decides creation by the resolved org's effective claims alone;
	// the oracle also accepts any allowlisted membership's claim.
	hasDeploy := effectivePermissionsHasDeployClaim(perms)
	if !hasDeploy && scope.kind == authorizationScopeAllowlisted {
		hasDeploy = membershipsHaveDeployClaim(ctx, ac.Store(), memberships)
	}
	return orgIDs, hasDeploy, nil
}

func errOrNil(err error) error {
	if err == nil {
		return errors.New("not found")
	}
	return err
}

// membershipsHaveDeployClaim reports whether any membership's group holds the
// deploy or admin claim.
func membershipsHaveDeployClaim(ctx context.Context, store rbac.Store, memberships []*rbac.MembershipWithDetails) bool {
	for _, m := range memberships {
		if m == nil || m.Membership == nil {
			continue
		}
		access, err := store.GetGroupAccess(ctx, m.Membership.GroupID)
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

// senderLinked is the sender-binding phase: a supplied from must be one of
// the subject's linked addresses. An empty from is accepted.
func senderLinked(ctx context.Context, store rbac.Store, subjectDID, from string) (bool, error) {
	if from == "" {
		return true, nil
	}
	addresses, err := store.GetLinkedEthAddresses(ctx, subjectDID)
	if err != nil {
		return false, err
	}
	for _, address := range addresses {
		if strings.EqualFold(address, from) {
			return true, nil
		}
	}
	return false, nil
}

// traceBlockParam validates the block parameter of an eth_call-shaped
// operation with the live helper, so every path traces the block the node
// would execute at and rejects the same malformed shapes.
func traceBlockParam(params []any) (any, error) {
	block, err := extractEthCallBlockParam(params)
	if err != nil {
		return nil, &simulationClientError{msg: "invalid block parameter"}
	}
	if block == nil {
		return "latest", nil
	}
	return block, nil
}

// complianceVerdict is the compliance phase. A preview has no side effect; a
// commit is the live check that may write compliance records.
func complianceVerdict(ctx context.Context, checker *compliance.Checker, mode evaluationMode, req *compliance.CheckRequest) (*compliance.CheckResult, error) {
	if mode == evaluationPreview {
		return checker.CheckPreview(ctx, req)
	}
	return checker.Check(ctx, req)
}

// operationVerdict is a projected trace outcome: decision plus an internal
// reason (audit only) and, for an out-of-scope frame, its detail.
type operationVerdict struct {
	decision       string
	wireReason     string
	internalReason string
	detail         map[string]string
}

// traceVerdict maps a trace denial to the answer of a scope. Org-local and
// allowlisted scopes answer indeterminate where the denial is only that the
// trace left their scope; the live path always denies.
func traceVerdict(scope authorizationScopeKind, denial *ProcessError) operationVerdict {
	deny := operationVerdict{decision: oracleDecisionDeny, wireReason: denial.Message, internalReason: sanitizeDryRunReason(denial.Reason)}
	switch scope {
	case authorizationScopeOrgLocal:
		if denial.TraceDenialKind == rbac.DenialKindForeignOrg || denial.TraceDenialKind == rbac.DenialKindCreateForeign {
			return operationVerdict{decision: oracleDecisionIndeterminate, wireReason: "external_scope_required", internalReason: "external_scope_required"}
		}
	case authorizationScopeAllowlisted:
		switch denial.TraceDenialKind {
		case rbac.DenialKindDeployClaim:
			// The claim may exist in an organization the oracle may not consult.
			return operationVerdict{decision: oracleDecisionIndeterminate, wireReason: oracleReasonOutsideScope, internalReason: "deploy_claim_not_in_scope"}
		case rbac.DenialKindOutOfScope:
			return operationVerdict{decision: oracleDecisionIndeterminate, wireReason: oracleReasonOutsideScope, internalReason: "nested_call_outside_allowlist",
				detail: map[string]string{"org_id": denial.TraceDeniedOrgID, "contract": denial.TraceDeniedTarget}}
		}
		deny.wireReason = oracleReasonDenied
	}
	return deny
}
