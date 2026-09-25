package server

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/policydsl"
	"privacy-proxy/internal/rbac"
)

// simulateNodeExecution evaluates a stored candidate against current chain state.
// @Summary Preview execution through the node policy evaluator
// @Description Named organization administrators can preview their own calls and stored execution revisions. Current active permissions remain mandatory for candidate previews. dryRun permits a full human organization administrator to diagnose another current member; independent organization isolation remains mandatory. This never submits a transaction or changes active policy. Candidate previews use current facts, including current memberships and registry state.
// @Tags Admin: Configuration
// @Accept json
// @Produce json
// @Param org_id path string true "Organization UUID"
// @Param request body apimodels.NodeSimulationRequest true "Simulation request"
// @Success 200 {object} object
// @Failure 400 {object} apimodels.APIError
// @Failure 403 {object} apimodels.APIError
// @Failure 404 {object} apimodels.APIError
// @Failure 429 {object} apimodels.APIError
// @Failure 503 {object} apimodels.APIError
// @Security BearerAuth
// @Router /api/v1/admin/orgs/{org_id}/execution/simulate [post]
func (s *Server) simulateNodeExecution(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var req apimodels.NodeSimulationRequest
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid simulation request"})
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid simulation request"})
		return
	}
	result, ok := s.executeNodePreview(c, req)
	if ok {
		c.Data(http.StatusOK, "application/json", result)
	}
}

func (s *Server) executeNodePreview(c *gin.Context, req apimodels.NodeSimulationRequest) (json.RawMessage, bool) {
	fail := func(code int, message string) (json.RawMessage, bool) {
		c.JSON(code, gin.H{"error": message})
		return nil, false
	}
	actor, ok := configurationRequestActor(c)
	if !ok {
		return nil, false
	}
	org := c.Param("org_id")
	if id, err := uuid.Parse(org); err != nil || id == uuid.Nil || id.String() != org {
		return fail(http.StatusBadRequest, "invalid organization")
	}
	if s.config == nil || !s.config.NodePolicy.Enabled() || s.nodeExecution == nil || s.rateLimiter == nil {
		return fail(http.StatusServiceUnavailable, "node simulation unavailable")
	}
	ctx := c.Request.Context()
	admin, err := s.db.GetUser(ctx, actor.UserID)
	if err != nil || admin == nil || admin.Banned {
		return fail(http.StatusForbidden, "current organization authority required")
	}
	if req.DryRun {
		if actor.PrincipalKind != string(auth.PrincipalHuman) {
			return fail(http.StatusForbidden, "diagnostics require a named human organization administrator")
		}
		_, orgs, err := s.db.IsOrgAdmin(ctx, actor.UserID)
		if err != nil || !slices.Contains(orgs, org) {
			return fail(http.StatusForbidden, "diagnostics require current full organization authority")
		}
	} else if req.PrincipalID != "" && req.PrincipalID != actor.UserID {
		return fail(http.StatusForbidden, "candidate preview uses your own authenticated principal")
	}
	if req.PrincipalID == "" {
		req.PrincipalID = actor.UserID
	}
	target, err := s.db.GetUser(ctx, req.PrincipalID)
	if err != nil || target == nil {
		return fail(http.StatusNotFound, "principal not found")
	}
	memberships, err := s.db.ListUserMembershipsInOrg(ctx, target.ID, org)
	if err != nil || len(memberships) == 0 {
		return fail(http.StatusNotFound, "principal not found")
	}
	rps, daily := 1, 100
	if allowed, _ := s.rateLimiter.CheckAndIncrement("node-preview:"+actor.ExternalID, &rps, &daily); !allowed {
		return fail(http.StatusTooManyRequests, "simulation request limit reached")
	}
	switch req.Method {
	case "eth_call", "eth_estimateGas", "debug_traceCall":
	default:
		return fail(http.StatusBadRequest, "unsupported simulation method")
	}
	if len(req.Params) < 1 || len(req.Params) > 3 {
		return fail(http.StatusBadRequest, "invalid simulation parameters")
	}
	call, ok := req.Params[0].(map[string]any)
	if !ok {
		return fail(http.StatusBadRequest, "invalid simulation call")
	}
	var signer string
	if req.DryRun {
		linked, err := s.db.GetLinkedEthAddresses(ctx, target.ExternalID)
		if err != nil {
			return fail(http.StatusServiceUnavailable, "simulation identity unavailable")
		}
		signer, _ = call["from"].(string)
		if signer == "" && len(linked) == 1 {
			signer = linked[0]
		}
		signer = strings.ToLower(signer)
		found := false
		for _, address := range linked {
			if strings.EqualFold(address, signer) {
				found = true
			}
		}
		if !found || len(signer) != 42 || !common.IsHexAddress(signer) {
			return fail(http.StatusBadRequest, "simulation requires a linked from address")
		}
	} else {
		if s.rbacAccessCtrl == nil {
			return fail(http.StatusServiceUnavailable, "simulation admission unavailable")
		}
		admission, err := s.rbacAccessCtrl.CheckExecutionAdmission(ctx, &rbac.AccessCheckRequest{UserExternalID: target.ExternalID, OrgID: org, Method: req.Method, AccessMethod: req.Method, Params: req.Params, BypassCache: true})
		if err != nil || admission == nil || !admission.Allowed {
			return fail(http.StatusForbidden, "simulation admission denied")
		}
		signer = admission.Signer
	}
	call["from"] = signer
	params, err := json.Marshal(req.Params)
	if err != nil {
		return fail(http.StatusBadRequest, "invalid simulation parameters")
	}
	request := nodepolicy.SimulationRequest{Method: req.Method, Params: params, DryRun: req.DryRun}
	if req.CandidateRevisionID != "" {
		candidate, err := s.db.GetConfigurationRevision(ctx, configuration.Scope{Kind: "organization", ID: org}, configuration.ExecutionRules, req.CandidateRevisionID)
		if err != nil || candidate == nil || (candidate.Status != "draft" && candidate.Status != "active") {
			return fail(http.StatusNotFound, "execution revision not found")
		}
		if !req.DryRun {
			doc, err := configuration.Parse([]byte(candidate.Source))
			if err != nil {
				return fail(http.StatusServiceUnavailable, "compiled revision unavailable")
			}
			spec, ok := doc.Spec.(configuration.ExecutionSpec)
			if !ok {
				return fail(http.StatusServiceUnavailable, "compiled revision unavailable")
			}
			policy, err := policydsl.Parse(spec.Policy)
			if err != nil {
				return fail(http.StatusServiceUnavailable, "compiled revision unavailable")
			}
			for _, binding := range policy.Bindings {
				for _, rule := range binding.Allow {
					for _, arg := range rule.Args {
						if arg.RecordParty != nil {
							c.JSON(http.StatusForbidden, gin.H{"error": "candidate record reads require an audited full human administrator diagnostic", "code": "candidate_state_reads_require_diagnostics"})
							return nil, false
						}
					}
				}
			}
		}
		set, err := policydsl.DecodeArtifactSet(candidate.Artifact)
		if err != nil {
			return fail(http.StatusServiceUnavailable, "compiled revision unavailable")
		}
		if artifact := set.Groups[""]; artifact != nil {
			request.CandidatePolicy = &nodepolicy.PolicyArtifact{OrgID: org, Revision: uint64(candidate.Revision), PolicyDigest: artifact.PolicyDigest, RuntimeDigest: artifact.RuntimeDigest, Bytecode: artifact.RuntimeBytecode}
		} else {
			groups := make([]string, 0, len(set.Groups))
			for group := range set.Groups {
				groups = append(groups, group)
			}
			sort.Strings(groups)
			candidates := make([]nodepolicy.PolicyArtifact, 0, len(groups))
			for _, group := range groups {
				artifact := set.Groups[group]
				candidates = append(candidates, nodepolicy.PolicyArtifact{OrgID: org, GroupID: group, Revision: uint64(candidate.Revision), PolicyDigest: artifact.PolicyDigest, RuntimeDigest: artifact.RuntimeDigest, Bytecode: artifact.RuntimeBytecode})
			}
			request.CandidatePolicies = &candidates
		}
	}
	wire, err := nodepolicy.EncodeSimulation(request)
	if err != nil {
		return fail(http.StatusBadRequest, "invalid simulation request or compiled artifact")
	}
	binding := nodepolicy.SimulationHash(wire)
	identity, err := s.nodeExecution.PrepareIdentity(ctx, NodeExecutionIdentityRequest{Scope: "simulation", PrincipalID: target.ID, OrgID: org, Signer: signer, BindingHash: binding})
	if err != nil {
		return fail(http.StatusServiceUnavailable, "node simulation is not ready")
	}
	// Commit an actor-attributed intent before executing privileged diagnostics.
	// Only the request digest is retained, never private calldata or node tickets.
	err = s.db.CreateAuditLog(ctx, &rbac.AuditLogEntry{ActorID: &actor.UserID, ActorExternalID: actor.ExternalID, OrgID: &org, Action: "execution.simulate", ResourceType: "execution_preview", NewValue: map[string]any{"principal_id": target.ID, "binding_hash": binding, "candidate_revision": req.CandidateRevisionID, "dry_run": req.DryRun}, IPAddress: c.ClientIP()})
	if err != nil {
		return fail(http.StatusServiceUnavailable, "simulation audit unavailable")
	}
	result, err := s.nodeExecution.Simulate(ctx, identity, wire)
	if err != nil || !json.Valid(result) {
		return fail(http.StatusForbidden, "simulation denied or unavailable")
	}
	return result, true
}
