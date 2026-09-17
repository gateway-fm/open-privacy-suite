package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/policydsl"
	"privacy-proxy/internal/rbac"
)

func toRevisionResponse(rev *db.ExecutionPolicyRevision) apimodels.ExecutionPolicyRevision {
	out := apimodels.ExecutionPolicyRevision{
		ID:             rev.ID,
		Revision:       rev.Revision,
		BaseRevision:   rev.BaseRevision,
		CreatedBy:      rev.CreatedBy,
		ActivatedBy:    rev.ActivatedBy,
		Status:         rev.Status,
		PolicyDigest:   rev.PolicyDigest,
		SolidityDigest: rev.SolidityDigest,
		RuntimeDigest:  rev.RuntimeDigest,
		Compiler: apimodels.ExecutionPolicyCompiler{
			Version:       rev.Compiler.Version,
			OptimizerRuns: rev.Compiler.OptimizerRuns,
			EVMVersion:    rev.Compiler.EVMVersion,
		},
		CreatedAt: rev.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
	if rev.ActivatedAt != nil {
		out.ActivatedAt = rev.ActivatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	return out
}

// buildCatalog assembles the organisation snapshot a policy is checked against.
//
// It is read once and passed in whole, so validation is a function of the
// document and an explicit snapshot rather than of whatever the database
// happened to hold during each individual check.
func (s *Server) buildCatalog(ctx context.Context, orgID string) (policydsl.Catalog, error) {
	cat := policydsl.Catalog{
		Org:       orgID,
		Groups:    map[string]struct{}{},
		Contracts: map[string]policydsl.ContractInfo{},
	}

	groups, err := s.db.ListGroups(ctx, orgID)
	if err != nil {
		return cat, err
	}
	for _, g := range groups {
		// Administrator groups are a trust root, not ordinary policy: a document
		// that could name one could restrict, or appear to restrict, the very
		// authority that approves it. System groups are reserved to super-admin
		// for the same reason, so a tenant admin may not write rules about them
		// either. This is the same predicate the group-management handlers use.
		if g.IsOrgAdmin || g.IsOrgReadonlyAdmin || g.IsSystem {
			continue
		}
		cat.Groups[g.ID] = struct{}{}
	}

	contracts, err := s.db.ListContracts(ctx, orgID)
	if err != nil {
		return cat, err
	}
	for _, ct := range contracts {
		if strings.TrimSpace(ct.ABI) == "" {
			// Without an ABI there is nothing that says what a selector or an
			// argument position means, so the contract cannot carry a rule.
			continue
		}
		cat.Contracts[strings.ToLower(common.HexToAddress(ct.Address).Hex())] = policydsl.ContractInfo{ABI: ct.ABI}
	}

	return cat, nil
}

// getExecutionPolicyContext returns what an editor needs to write a candidate.
//
// @Summary      Read the execution-policy editing context
// @Description  Returns the revision a candidate must be written against, the groups and ABI-bearing contracts it may refer to, and the policy currently in force. Administrator groups and contracts without a registered ABI are omitted, because a rule cannot name either. Scoped to {org_id}; the restricted operator token is rejected.
// @Tags         Admin: Execution policy
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Success      200 {object} apimodels.ExecutionPolicyContext
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "operator token cannot manage per-org policy, or caller is out of org scope"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/execution-policy/context [get]
func (s *Server) getExecutionPolicyContext(c *gin.Context) {
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")
	ctx := c.Request.Context()

	cat, err := s.buildCatalog(ctx, orgID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read organization",
			"admin_execution_policy: buildCatalog failed", "org_id", orgID, "err", err)
		return
	}

	base, err := s.db.ActiveExecutionPolicyRevisionNumber(ctx, orgID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read policy revisions",
			"admin_execution_policy: ActiveExecutionPolicyRevisionNumber failed", "org_id", orgID, "err", err)
		return
	}

	out := apimodels.ExecutionPolicyContext{
		OrgID:        orgID,
		BaseRevision: base,
		APIVersion:   policydsl.APIVersion,
		Kind:         policydsl.Kind,
		NestedCalls:  policydsl.NestedCallsRequireOwnRule,
		Groups:       make([]string, 0, len(cat.Groups)),
		Contracts:    make([]apimodels.ExecutionPolicyContract, 0, len(cat.Contracts)),
	}
	for id := range cat.Groups {
		out.Groups = append(out.Groups, id)
	}

	contracts, err := s.db.ListContracts(ctx, orgID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read contracts",
			"admin_execution_policy: ListContracts failed", "org_id", orgID, "err", err)
		return
	}
	for _, ct := range contracts {
		summary := apimodels.ExecutionPolicyContract{
			Address: strings.ToLower(common.HexToAddress(ct.Address).Hex()),
			Name:    ct.Name,
		}
		if strings.TrimSpace(ct.ABI) != "" {
			summary.HasABI = true
			summary.ABIDigest = policydsl.ABIDigest(ct.ABI)
		}
		out.Contracts = append(out.Contracts, summary)
	}

	active, err := s.db.GetActiveExecutionPolicy(ctx, orgID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read the active policy",
			"admin_execution_policy: GetActiveExecutionPolicy failed", "org_id", orgID, "err", err)
		return
	}
	if active != nil {
		summary := toRevisionResponse(active)
		out.Active = &summary
	}

	c.JSON(http.StatusOK, out)
}

// submitExecutionPolicy validates and compiles a candidate and stores it as a
// draft awaiting approval.
//
// @Summary      Submit an execution-policy candidate
// @Description  Validates and compiles a candidate and stores it as an attributed draft. Full and read-only org admins may submit; token-only credentials cannot submit. base_revision names the currently active revision (zero before first activation), independently of draft numbering. Stale bases are refused. A different identified full org admin must activate the draft. Scoped to {org_id}; the restricted operator token is rejected.
// @Tags         Admin: Execution policy
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        request body apimodels.ExecutionPolicySubmitRequest true "Candidate policy and the revision it was written against"
// @Success      201 {object} apimodels.ExecutionPolicyRevisionDetail
// @Failure      400 {object} apimodels.APIError "the candidate is malformed or names something that does not exist"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "operator token cannot manage per-org policy, or caller is out of org scope"
// @Failure      409 {object} apimodels.APIError "the candidate was written against a superseded revision"
// @Failure      500 {object} apimodels.APIError
// @Failure      503 {object} apimodels.APIError "the policy compiler is unavailable"
// @Security     BearerAuth
// @Router       /api/v1/admin/orgs/{org_id}/execution-policy/revisions [post]
func (s *Server) submitExecutionPolicy(c *gin.Context) {
	if s.closeLegacyExecutionWriter(c) {
		return
	}
	if denyOperatorOrgScoped(c) {
		return
	}
	actor := auditActorUserID(c)
	if actor == nil {
		c.JSON(http.StatusForbidden, gin.H{"error": db.ErrPolicyActorRequired.Error()})
		return
	}
	orgID := c.Param("org_id")
	ctx := c.Request.Context()

	// Bound as raw JSON rather than through the spec model: the stored document
	// is the thing a reviewer approves, so it must be kept exactly as sent
	// rather than re-encoded from a decoded map.
	var input struct {
		Policy       json.RawMessage `json:"policy" binding:"required"`
		BaseRevision *int64          `json:"base_revision" binding:"required,gte=0"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_execution_policy: invalid submit body", "org_id", orgID, "err", err)
		return
	}

	// A policy is a hand-written document, not a data feed. Bounding it here
	// matters because everything downstream is expensive: the document is held
	// in memory, expanded into source, written to disk and handed to a compiler.
	// The legacy /api/admin mount carries no body limit of its own.
	if len(input.Policy) > maxExecutionPolicyBytes {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("policy document is %d bytes; the limit is %d", len(input.Policy), maxExecutionPolicyBytes),
		})
		return
	}

	policy, err := policydsl.Parse(input.Policy)
	if err != nil {
		// Validation messages name the field at fault and nothing else, so they
		// are safe to return: an administrator of this org supplied the text.
		respondClientError(c, http.StatusBadRequest, err, "invalid policy document", "admin_execution_policy: parse rejected without client text", "org_id", orgID)
		return
	}

	// Check the base revision before compiling. A submission written against a
	// superseded revision is going to be refused either way, and compiling first
	// would let a stale client burn a compile per retry.
	latest, err := s.db.ActiveExecutionPolicyRevisionNumber(ctx, orgID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read policy revisions",
			"admin_execution_policy: ActiveExecutionPolicyRevisionNumber failed (submit)", "org_id", orgID, "err", err)
		return
	}
	if *input.BaseRevision != latest {
		c.JSON(http.StatusConflict, gin.H{
			"error": fmt.Sprintf("policy base revision is stale: written against revision %d, current is %d", *input.BaseRevision, latest),
		})
		return
	}

	cat, err := s.buildCatalog(ctx, orgID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read organization",
			"admin_execution_policy: buildCatalog failed", "org_id", orgID, "err", err)
		return
	}

	validated, err := policydsl.Validate(policy, cat)
	if err != nil {
		respondClientError(c, http.StatusBadRequest, err, "invalid policy document", "admin_execution_policy: validate rejected without client text", "org_id", orgID)
		return
	}

	artifact, err := s.policyCompiler.Build(ctx, validated)
	if err != nil {
		// A missing or wrongly pinned compiler is an operator problem, not a
		// problem with the submitted document, and must not read as one.
		slog.Error("admin_execution_policy: building the policy artifact failed",
			"org_id", orgID, "err", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "the policy compiler is unavailable"})
		return
	}

	rev, err := s.db.CreateExecutionPolicyRevision(ctx, orgID, *input.BaseRevision, string(input.Policy), artifact, actor)
	if err != nil {
		if errors.Is(err, db.ErrPolicyStaleBase) {
			respondConflict(c, db.ErrPolicyStaleBase.Error())
			return
		}
		respondInternalErrorAndLog(c, "failed to store the policy revision",
			"admin_execution_policy: CreateExecutionPolicyRevision failed", "org_id", orgID, "err", err)
		return
	}

	s.recordAuditActionScoped(c, rbac.AuditActionCreate, rbac.ResourceTypeExecutionPolicy, rev.ID, "execution policy draft", orgID,
		nil,
		map[string]any{
			"revision":       rev.Revision,
			"status":         rev.Status,
			"policy_digest":  rev.PolicyDigest,
			"runtime_digest": rev.RuntimeDigest,
		})

	c.JSON(http.StatusCreated, apimodels.ExecutionPolicyRevisionDetail{
		ExecutionPolicyRevision: toRevisionResponse(rev),
		Source:                  rev.Source,
		SoliditySource:          rev.SoliditySource,
		RuntimeBytecode:         "0x" + hex.EncodeToString(rev.RuntimeBytecode),
	})
}

// listExecutionPolicyRevisions returns an organisation's policy history.
//
// @Summary      List execution-policy revisions
// @Description  Returns the organisation's policy revisions, newest first, with the digests of each. Scoped to {org_id}; the restricted operator token is rejected.
// @Tags         Admin: Execution policy
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Success      200 {array} apimodels.ExecutionPolicyRevision
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "operator token cannot manage per-org policy, or caller is out of org scope"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/execution-policy/revisions [get]
func (s *Server) listExecutionPolicyRevisions(c *gin.Context) {
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")

	revisions, err := s.db.ListExecutionPolicyRevisions(c.Request.Context(), orgID, 50)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to list policy revisions",
			"admin_execution_policy: ListExecutionPolicyRevisions failed", "org_id", orgID, "err", err)
		return
	}

	out := make([]apimodels.ExecutionPolicyRevision, 0, len(revisions))
	for _, rev := range revisions {
		out = append(out, toRevisionResponse(rev))
	}
	c.JSON(http.StatusOK, out)
}

// getExecutionPolicyRevision returns one revision in full.
//
// @Summary      Read one execution-policy revision
// @Description  Returns the submitted document, the Solidity generated from it, the compiled runtime bytecode and every digest, so a reviewer can check the artifact before approving it. Scoped to {org_id}; the restricted operator token is rejected.
// @Tags         Admin: Execution policy
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        revision_id path string true "Revision ID"
// @Success      200 {object} apimodels.ExecutionPolicyRevisionDetail
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "operator token cannot manage per-org policy, or caller is out of org scope"
// @Failure      404 {object} apimodels.APIError "no such revision in this organization"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/execution-policy/revisions/{revision_id} [get]
func (s *Server) getExecutionPolicyRevision(c *gin.Context) {
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")

	rev, err := s.db.GetExecutionPolicyRevision(c.Request.Context(), orgID, c.Param("revision_id"))
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read the policy revision",
			"admin_execution_policy: GetExecutionPolicyRevision failed", "org_id", orgID, "err", err)
		return
	}
	if rev == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy revision not found"})
		return
	}

	c.JSON(http.StatusOK, apimodels.ExecutionPolicyRevisionDetail{
		ExecutionPolicyRevision: toRevisionResponse(rev),
		Source:                  rev.Source,
		SoliditySource:          rev.SoliditySource,
		RuntimeBytecode:         "0x" + hex.EncodeToString(rev.RuntimeBytecode),
	})
}

// activateExecutionPolicyRevision puts a draft in force.
//
// @Summary      Activate an execution-policy revision
// @Description  Atomically activates a draft only if its recorded base is still active. Requires an identified full org admin different from the submitter; read-only and token-only credentials are refused. Legacy drafts without recorded provenance must be resubmitted. The approving administrator and artifact digests are audited. Scoped to {org_id}; the restricted operator token is rejected.
// @Tags         Admin: Execution policy
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        revision_id path string true "Revision ID"
// @Success      200 {object} apimodels.ExecutionPolicyRevision
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "operator token cannot manage per-org policy, or caller is out of org scope"
// @Failure      404 {object} apimodels.APIError "no such revision in this organization"
// @Failure      409 {object} apimodels.APIError "the revision is not a draft or its authoring base is stale"
// @Failure      500 {object} apimodels.APIError
// @Security     BearerAuth
// @Router       /api/v1/admin/orgs/{org_id}/execution-policy/revisions/{revision_id}/activate [post]
func (s *Server) activateExecutionPolicyRevision(c *gin.Context) {
	if s.closeLegacyExecutionWriter(c) {
		return
	}
	if denyOperatorOrgScoped(c) {
		return
	}
	if !requireHumanConfigurationActor(c) {
		return
	}
	actor := auditActorUserID(c)
	if actor == nil {
		c.JSON(http.StatusForbidden, gin.H{"error": db.ErrPolicyActorRequired.Error()})
		return
	}
	orgID := c.Param("org_id")
	revisionID := c.Param("revision_id")
	ctx := c.Request.Context()

	// Re-check the draft against the organisation as it is now, not as it was
	// when the draft was submitted. A contract's ABI can be replaced in between,
	// and activating a policy whose rules no longer describe the contracts they
	// name would put an artifact in force that nobody has reviewed against the
	// current state.
	candidate, err := s.db.GetExecutionPolicyRevision(ctx, orgID, revisionID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read the policy revision",
			"admin_execution_policy: GetExecutionPolicyRevision failed (activate)", "org_id", orgID, "err", err)
		return
	}
	if candidate == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy revision not found"})
		return
	}
	if err := s.revalidateStoredPolicy(ctx, orgID, candidate); err != nil {
		respondClientError(c, http.StatusConflict, err, "the stored policy no longer validates", "admin_execution_policy: revalidation failed without client text", "org_id", orgID)
		return
	}

	previous, err := s.db.GetActiveExecutionPolicy(ctx, orgID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read the active policy",
			"admin_execution_policy: GetActiveExecutionPolicy failed", "org_id", orgID, "err", err)
		return
	}

	rev, err := s.db.ActivateExecutionPolicyRevision(ctx, orgID, revisionID, actor)
	if err != nil {
		switch {
		case errors.Is(err, db.ErrPolicyActorRequired):
			respondForbidden(c, db.ErrPolicyActorRequired.Error())
			return
		case errors.Is(err, db.ErrPolicySelfApproval):
			respondForbidden(c, db.ErrPolicySelfApproval.Error())
			return
		case errors.Is(err, db.ErrPolicyNotDraft):
			respondConflict(c, db.ErrPolicyNotDraft.Error())
			return
		case errors.Is(err, db.ErrPolicyStaleBase):
			respondConflict(c, db.ErrPolicyStaleBase.Error())
			return
		}
		respondInternalErrorAndLog(c, "failed to activate the policy revision",
			"admin_execution_policy: ActivateExecutionPolicyRevision failed",
			"org_id", orgID, "revision_id", revisionID, "err", err)
		return
	}
	if rev == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy revision not found"})
		return
	}

	before := map[string]any{"active_revision": nil}
	if previous != nil {
		before = map[string]any{
			"active_revision": previous.Revision,
			"runtime_digest":  previous.RuntimeDigest,
		}
	}
	s.recordAuditActionScoped(c, rbac.AuditActionUpdate, rbac.ResourceTypeExecutionPolicy, rev.ID, "execution policy activated", orgID,
		before,
		map[string]any{
			"active_revision": rev.Revision,
			"runtime_digest":  rev.RuntimeDigest,
			"policy_digest":   rev.PolicyDigest,
		})

	c.JSON(http.StatusOK, toRevisionResponse(rev))
}

// isExecutionPolicyPreparation names the two draft-only POST capabilities a
// scoped read-only admin may use. Match registered routes exactly so an
// unrelated endpoint cannot obtain an exception by resembling a policy URL.
func isExecutionPolicyPreparation(c *gin.Context) bool {
	if c.Request.Method != http.MethodPost {
		return false
	}
	path := c.FullPath()
	for _, mount := range []string{"/api/v1/admin", "/api/admin"} {
		switch path {
		case mount + "/orgs/:org_id/execution-policy/revisions",
			mount + "/orgs/:org_id/execution-policy/revisions/:revision_id/simulate":
			return true
		}
	}
	return false
}

// withdrawExecutionPolicyRevision abandons a draft.
//
// @Summary      Withdraw an execution-policy draft
// @Description  Abandons a draft that was never activated. An active or superseded revision is part of the record of what was enforced and cannot be withdrawn. Scoped to {org_id}; the restricted operator token is rejected.
// @Tags         Admin: Execution policy
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        revision_id path string true "Revision ID"
// @Success      200 {object} apimodels.ExecutionPolicyRevision
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "operator token cannot manage per-org policy, or caller is out of org scope"
// @Failure      404 {object} apimodels.APIError "no such draft in this organization"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/execution-policy/revisions/{revision_id}/withdraw [post]
func (s *Server) withdrawExecutionPolicyRevision(c *gin.Context) {
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")
	revisionID := c.Param("revision_id")

	rev, err := s.db.WithdrawExecutionPolicyRevision(c.Request.Context(), orgID, revisionID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to withdraw the policy revision",
			"admin_execution_policy: WithdrawExecutionPolicyRevision failed",
			"org_id", orgID, "revision_id", revisionID, "err", err)
		return
	}
	if rev == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy draft not found"})
		return
	}

	s.recordAuditActionScoped(c, rbac.AuditActionDelete, rbac.ResourceTypeExecutionPolicy, rev.ID, "execution policy draft withdrawn", orgID,
		map[string]any{"revision": rev.Revision, "status": db.PolicyStatusDraft},
		map[string]any{"revision": rev.Revision, "status": rev.Status})

	c.JSON(http.StatusOK, toRevisionResponse(rev))
}

// auditActorUserID is the user row behind the current admin request, when there
// is one. A super-admin token has no user row; the audit helper still records
// the external identity and the authentication method in that case.
func auditActorUserID(c *gin.Context) *string {
	if uid := c.GetString("admin_user_id"); uid != "" {
		return &uid
	}
	return nil
}

// simulateExecutionPolicy evaluates a described execution against a revision.
//
// @Summary      Simulate an execution against a policy revision
// @Description  Legacy mode only; Reth mode returns 409 and uses configuration/execution-rules with execution/simulate. Evaluates a hypothetical execution against a stored revision and returns the decision. The candidate is evaluated twice, once by the reference evaluator and once by running the compiled contract, and the response reports whether the two agreed. Simulation mutates nothing and can be run against a draft, which is the point: it is how a reviewer checks what a policy would do before putting it in force. Scoped to {org_id}; the restricted operator token is rejected.
// @Tags         Admin: Execution policy
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        revision_id path string true "Revision ID"
// @Param        request body apimodels.ExecutionPolicySimulateRequest true "The execution to test"
// @Success      200 {object} apimodels.ExecutionPolicySimulateResponse
// @Failure      400 {object} apimodels.APIError "the described execution is malformed"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "operator token cannot manage per-org policy, or caller is out of org scope"
// @Failure      404 {object} apimodels.APIError "no such revision in this organization"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Failure      409 {object} apimodels.APIError "use configuration execution rules in Reth mode"
// @Router       /api/v1/admin/orgs/{org_id}/execution-policy/revisions/{revision_id}/simulate [post]
func (s *Server) simulateExecutionPolicy(c *gin.Context) {
	if s.closeLegacyExecutionWriter(c) {
		return
	}
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")
	ctx := c.Request.Context()

	var input apimodels.ExecutionPolicySimulateRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_execution_policy: invalid simulate body", "org_id", orgID, "err", err)
		return
	}

	rev, err := s.db.GetExecutionPolicyRevision(ctx, orgID, c.Param("revision_id"))
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read the policy revision",
			"admin_execution_policy: GetExecutionPolicyRevision failed (simulate)", "org_id", orgID, "err", err)
		return
	}
	if rev == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy revision not found"})
		return
	}

	policy, err := policydsl.Parse([]byte(rev.Source))
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read the stored policy",
			"admin_execution_policy: stored policy no longer parses", "org_id", orgID, "revision", rev.Revision, "err", err)
		return
	}
	cat, err := s.buildCatalog(ctx, orgID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read organization",
			"admin_execution_policy: buildCatalog failed (simulate)", "org_id", orgID, "err", err)
		return
	}
	validated, err := policydsl.Validate(policy, cat)
	if err != nil {
		// The stored policy no longer validates against the current catalog, for
		// example because a contract's ABI was replaced after it was approved.
		respondClientError(c, http.StatusConflict, clientErrorWithPrefix("the stored policy no longer validates against the organization's current contracts", err), "the stored policy no longer validates", "admin_execution_policy: revalidation failed without client text", "org_id", orgID)
		return
	}

	if err := checkSimulationSize(input); err != nil {
		respondClientError(c, http.StatusBadRequest, err, "invalid simulation request", "admin_execution_policy: simulation size rejected without client text")
		return
	}

	simCtx, frames, err := buildSimulationInputs(orgID, input)
	if err != nil {
		respondClientError(c, http.StatusBadRequest, err, "invalid simulation request", "admin_execution_policy: simulation input rejected without client text")
		return
	}
	// Ownership is a current server fact, never asserted by the hypothetical
	// frame request. Literal policy bindings now enforce it in both evaluators.
	for i := range frames {
		codeOwner, err := s.db.GetContractOwnerOrgID(ctx, frames[i].CodeAddress.Hex())
		if err != nil {
			respondInternalErrorAndLog(c, "failed to resolve simulation ownership", "admin_execution_policy: code owner failed", "err", err)
			return
		}
		storageOwner, err := s.db.GetContractOwnerOrgID(ctx, frames[i].StorageAddress.Hex())
		if err != nil {
			respondInternalErrorAndLog(c, "failed to resolve simulation ownership", "admin_execution_policy: storage owner failed", "err", err)
			return
		}
		frames[i].CodeOrg, frames[i].StorageOrg = codeOwner, storageOwner
	}

	reference := validated.Evaluate(simCtx, frames)

	compiled, err := policydsl.NewEVMEvaluator(&policydsl.Artifact{
		RuntimeBytecode: rev.RuntimeBytecode,
		RuntimeDigest:   rev.RuntimeDigest,
	})
	if err != nil {
		respondInternalErrorAndLog(c, "failed to load the compiled policy",
			"admin_execution_policy: NewEVMEvaluator failed", "org_id", orgID, "err", err)
		return
	}
	artifactDecision := compiled.Evaluate(orgID, simCtx, frames)

	agreed := reference.Allowed == artifactDecision.Allowed && reference.Code == artifactDecision.Code
	if !agreed {
		// This should be impossible: the conformance corpus exists to make it so.
		// If it ever happens the artifact is not the policy that was reviewed.
		slog.Error("admin_execution_policy: the reference evaluator and the compiled artifact disagreed",
			"org_id", orgID, "revision", rev.Revision, "runtime_digest", rev.RuntimeDigest,
			"reference_allowed", reference.Allowed, "artifact_allowed", artifactDecision.Allowed)
	}

	c.JSON(http.StatusOK, apimodels.ExecutionPolicySimulateResponse{
		Allowed:         reference.Allowed,
		Code:            string(reference.Code),
		Reason:          reference.Reason,
		CompiledAllowed: artifactDecision.Allowed,
		CompiledCode:    string(artifactDecision.Code),
		Agreed:          agreed,
		RuntimeDigest:   rev.RuntimeDigest,
	})
}

func (s *Server) closeLegacyExecutionWriter(c *gin.Context) bool {
	if s.config == nil || !s.config.NodePolicy.Enabled() {
		return false
	}
	c.JSON(http.StatusConflict, gin.H{"error": "Reth execution rules use configuration/execution-rules revisions and execution/simulate previews", "code": "use_configuration_execution_rules"})
	return true
}

// buildSimulationInputs converts a described execution into evaluator inputs.
func buildSimulationInputs(orgID string, input apimodels.ExecutionPolicySimulateRequest) (policydsl.Context, []policydsl.Frame, error) {
	ctx := policydsl.Context{Org: orgID, Groups: input.Groups}

	if input.Signer != "" {
		if !common.IsHexAddress(input.Signer) {
			return ctx, nil, clientErrorf("signer is not a valid address")
		}
		ctx.Signer = common.HexToAddress(input.Signer)
	}
	for _, a := range input.LinkedAddresses {
		if !common.IsHexAddress(a) {
			return ctx, nil, clientErrorf("linked_addresses contains a value that is not a valid address")
		}
		ctx.LinkedAddresses = append(ctx.LinkedAddresses, common.HexToAddress(a))
	}

	frames := make([]policydsl.Frame, 0, len(input.Frames))
	for i, f := range input.Frames {
		if !common.IsHexAddress(f.StorageAddress) {
			return ctx, nil, clientErrorf("frame %d: storage_address is not a valid address", i)
		}
		storage := common.HexToAddress(f.StorageAddress)

		code := storage
		if f.CodeAddress != "" {
			if !common.IsHexAddress(f.CodeAddress) {
				return ctx, nil, clientErrorf("frame %d: code_address is not a valid address", i)
			}
			code = common.HexToAddress(f.CodeAddress)
		}

		calldata, err := hex.DecodeString(strings.TrimPrefix(f.Calldata, "0x"))
		if err != nil {
			return ctx, nil, clientErrorf("frame %d: calldata is not valid hex", i)
		}

		frames = append(frames, policydsl.Frame{
			CallType:       policydsl.CallType(f.CallType),
			StorageAddress: storage,
			CodeAddress:    code,
			Calldata:       calldata,
		})
	}

	return ctx, frames, nil
}

// revalidateStoredPolicy re-checks a stored document against the organisation
// as it stands now.
//
// A revision is validated when it is submitted, but the organisation can change
// afterwards: a contract's ABI can be replaced, or a group deleted. Checking
// again before the document is relied on keeps a policy from being activated,
// or a simulation from being believed, when its rules no longer describe the
// contracts they name.
func (s *Server) revalidateStoredPolicy(ctx context.Context, orgID string, rev *db.ExecutionPolicyRevision) error {
	policy, err := policydsl.Parse([]byte(rev.Source))
	if err != nil {
		return clientErrorWithPrefix("the stored policy document is no longer readable", err)
	}

	cat, err := s.buildCatalog(ctx, orgID)
	if err != nil {
		slog.Error("admin_execution_policy: buildCatalog failed (revalidate)", "org_id", orgID, "err", err)
		return clientErrorf("could not read the organization's current contracts and groups")
	}

	if _, err := policydsl.Validate(policy, cat); err != nil {
		return clientErrorWithPrefix("the policy no longer validates against this organization's current contracts and groups", err)
	}
	return nil
}

// Limits on what one request may ask the policy machinery to do.
//
// These are not tuning knobs. Submitting compiles a contract, and simulating
// runs an EVM per frame with a gas budget that does not observe the request's
// context, so without a bound a single request can hold a core for as long as
// it takes to exhaust that gas. A policy is a hand-written document and a
// simulated execution is a hand-written scenario; both are small in every
// legitimate use.
const (
	maxExecutionPolicyBytes = 256 * 1024
	maxSimulationFrames     = 64
	maxSimulationAddresses  = 64
	maxSimulationGroups     = 64
	maxSimulationCalldata   = 64 * 1024
)

// checkSimulationSize bounds a described execution before any of it is run.
func checkSimulationSize(input apimodels.ExecutionPolicySimulateRequest) error {
	if len(input.Frames) > maxSimulationFrames {
		return clientErrorf("an execution may describe at most %d frames", maxSimulationFrames)
	}
	if len(input.LinkedAddresses) > maxSimulationAddresses {
		return clientErrorf("at most %d linked addresses may be supplied", maxSimulationAddresses)
	}
	if len(input.Groups) > maxSimulationGroups {
		return clientErrorf("at most %d groups may be supplied", maxSimulationGroups)
	}
	for i, f := range input.Frames {
		if len(f.Calldata) > maxSimulationCalldata {
			return clientErrorf("frame %d: calldata is longer than the %d-character limit", i, maxSimulationCalldata)
		}
	}
	return nil
}
