package server

import (
	"context"
	"errors"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/rbac"
)

type authorizationScopeKind uint8

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
