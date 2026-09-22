package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/db"
)

func (s *Server) registerConfigurationRoutes(api *gin.RouterGroup) {
	api.POST("/orgs/:org_id/execution/simulate", s.simulateNodeExecution)
	base := "/orgs/:org_id/configuration/:kind"
	api.GET(base+"/context", s.getConfigurationContext)
	api.GET(base+"/managed", s.getConfigurationManaged)
	api.GET(base+"/revisions", s.listConfigurationRevisions)
	api.POST(base+"/revisions", s.submitConfigurationRevision)
	api.GET(base+"/revisions/:revision_id", s.getConfigurationRevision)
	api.POST(base+"/revisions/:revision_id/simulate", s.simulateConfigurationRevision)
	api.POST(base+"/revisions/:revision_id/activate", s.activateConfigurationRevision)
	api.POST(base+"/revisions/:revision_id/activate-ci", s.activateConfigurationCI)
	api.POST(base+"/revisions/:revision_id/withdraw", s.withdrawConfigurationRevision)
	// The managed read sits outside the platform group: the screens that edit
	// tenants and shared infrastructure run on the full admin token, which the
	// human-only platform gate refuses, so the read admits either principal.
	api.GET("/configuration/platform/managed", s.getPlatformConfigurationManaged)
	platform := api.Group("/configuration/platform", s.requireConfigurationPlatform)
	platform.GET("/context", s.getPlatformConfigurationContext)
	platform.GET("/revisions", s.listPlatformConfigurationRevisions)
	platform.POST("/revisions", s.submitPlatformConfigurationRevision)
	platform.GET("/revisions/:revision_id", s.getPlatformConfigurationRevision)
	platform.POST("/revisions/:revision_id/simulate", s.simulatePlatformConfigurationRevision)
	platform.POST("/revisions/:revision_id/activate", s.activatePlatformConfigurationRevision)
	platform.POST("/revisions/:revision_id/withdraw", s.withdrawPlatformConfigurationRevision)
}

// The platform stream shares the organization handlers (configurationRoute
// derives scope and kind from the absence of :org_id). These wrappers exist so
// the platform routes are documented with their own paths and without the
// organization path parameters; requireConfigurationPlatform gates them all.

// @Summary Read platform configuration editing context
// @Description Requires a named human principal on the deployment's platform allowlist.
// @Tags Admin: Configuration
// @Produce json
// @Success 200 {object} apimodels.ConfigurationContext
// @Failure 403 {object} apimodels.APIError
// @Security BearerAuth
// @Router /api/v1/admin/configuration/platform/context [get]
func (s *Server) getPlatformConfigurationContext(c *gin.Context) { s.getConfigurationContext(c) }

// @Summary Report whether the platform configuration stream is managed
// @Description Readable by a named human principal on the deployment's platform allowlist or by the full admin token, the two principals that manage tenants and shared infrastructure. True once a platform revision is active: the shared-infrastructure and tenant write endpoints then answer 409 and edits go through a platform revision.
// @Tags Admin: Configuration
// @Produce json
// @Success 200 {object} apimodels.ConfigurationManaged
// @Failure 401 {object} apimodels.APIError
// @Failure 403 {object} apimodels.APIError
// @Security BearerAuth
// @Security AdminToken
// @Router /api/v1/admin/configuration/platform/managed [get]
func (s *Server) getPlatformConfigurationManaged(c *gin.Context) {
	if !s.isConfigurationPlatformActor(c) && !isFullAdminToken(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "named platform configuration authority is required"})
		return
	}
	s.getConfigurationManaged(c)
}

// @Summary List platform configuration revisions
// @Tags Admin: Configuration
// @Produce json
// @Success 200 {object} apimodels.ConfigurationRevisionList
// @Failure 403 {object} apimodels.APIError
// @Security BearerAuth
// @Router /api/v1/admin/configuration/platform/revisions [get]
func (s *Server) listPlatformConfigurationRevisions(c *gin.Context) { s.listConfigurationRevisions(c) }

// @Summary Submit a complete platform configuration source document
// @Description Platform drafts require a human author; a different allowlisted human activates.
// @Tags Admin: Configuration
// @Accept json
// @Produce json
// @Param source body object true "Complete ops.configuration/v1 platform document"
// @Success 201 {object} apimodels.ConfigurationRevision
// @Failure 400 {object} apimodels.APIError
// @Failure 403 {object} apimodels.APIError
// @Failure 409 {object} apimodels.APIError
// @Security BearerAuth
// @Router /api/v1/admin/configuration/platform/revisions [post]
func (s *Server) submitPlatformConfigurationRevision(c *gin.Context) {
	s.submitConfigurationRevision(c)
}

// @Summary Read a platform configuration revision
// @Tags Admin: Configuration
// @Produce json
// @Param revision_id path string true "Revision UUID"
// @Success 200 {object} apimodels.ConfigurationRevision
// @Failure 403 {object} apimodels.APIError
// @Failure 404 {object} apimodels.APIError
// @Security BearerAuth
// @Router /api/v1/admin/configuration/platform/revisions/{revision_id} [get]
func (s *Server) getPlatformConfigurationRevision(c *gin.Context) { s.getConfigurationRevision(c) }

// @Summary Review a platform draft without mutation
// @Tags Admin: Configuration
// @Accept json
// @Produce json
// @Param revision_id path string true "Revision UUID"
// @Param request body apimodels.ConfigurationCoactivateRequest false "Sibling drafts"
// @Success 200 {object} apimodels.ConfigurationReview
// @Failure 400 {object} apimodels.APIError
// @Failure 403 {object} apimodels.APIError
// @Failure 404 {object} apimodels.APIError
// @Failure 409 {object} apimodels.APIError
// @Security BearerAuth
// @Router /api/v1/admin/configuration/platform/revisions/{revision_id}/simulate [post]
func (s *Server) simulatePlatformConfigurationRevision(c *gin.Context) {
	s.simulateConfigurationRevision(c)
}

// @Summary Activate a reviewed platform configuration revision
// @Description The activator must be a currently allowlisted human other than the author.
// @Tags Admin: Configuration
// @Accept json
// @Produce json
// @Param revision_id path string true "Revision UUID"
// @Param request body apimodels.ConfigurationCoactivateRequest false "Sibling drafts"
// @Success 200 {object} apimodels.ConfigurationRevisionList
// @Failure 400 {object} apimodels.APIError
// @Failure 403 {object} apimodels.APIError
// @Failure 404 {object} apimodels.APIError
// @Failure 409 {object} apimodels.APIError
// @Security BearerAuth
// @Router /api/v1/admin/configuration/platform/revisions/{revision_id}/activate [post]
func (s *Server) activatePlatformConfigurationRevision(c *gin.Context) {
	s.activateConfigurationRevision(c)
}

// @Summary Withdraw an unactivated platform configuration draft
// @Tags Admin: Configuration
// @Produce json
// @Param revision_id path string true "Revision UUID"
// @Success 200 {object} apimodels.ConfigurationRevision
// @Failure 403 {object} apimodels.APIError
// @Failure 404 {object} apimodels.APIError
// @Failure 409 {object} apimodels.APIError
// @Security BearerAuth
// @Router /api/v1/admin/configuration/platform/revisions/{revision_id}/withdraw [post]
func (s *Server) withdrawPlatformConfigurationRevision(c *gin.Context) {
	s.withdrawConfigurationRevision(c)
}

func (s *Server) requireConfigurationPlatform(c *gin.Context) {
	if !s.isConfigurationPlatformActor(c) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "named platform configuration authority is required"})
		return
	}
	c.Next()
}

// isConfigurationPlatformActor is the platform gate as a predicate: a named,
// verified human on the deployment's platform allowlist.
func (s *Server) isConfigurationPlatformActor(c *gin.Context) bool {
	kind, _ := c.Get("admin_principal_kind")
	return kind == auth.PrincipalHuman && s.configurationPlatformSubject(c.GetString("admin_subject")) && c.GetString("admin_user_id") != ""
}

func configurationRoute(c *gin.Context) (configuration.Scope, configuration.Kind, bool) {
	if c.Param("org_id") == "" {
		return configuration.Scope{Kind: "platform"}, configuration.Platform, true
	}
	scope := configuration.Scope{Kind: "organization", ID: c.Param("org_id")}
	kind := configuration.Kind(c.Param("kind"))
	id, err := uuid.Parse(scope.ID)
	if err != nil || id == uuid.Nil || id.String() != scope.ID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid configuration scope"})
		return scope, kind, false
	}
	if !slices.Contains(configuration.OrganizationKinds(), kind) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported configuration kind"})
		return scope, kind, false
	}
	return scope, kind, true
}
func configurationRequestActor(c *gin.Context) (db.ConfigurationActor, bool) {
	actor := db.ConfigurationActor{UserID: c.GetString("admin_user_id"), ExternalID: c.GetString("admin_subject"), IPAddress: c.ClientIP()}
	kind, _ := c.Get("admin_principal_kind")
	if principalKind, ok := kind.(auth.PrincipalKind); ok {
		actor.PrincipalKind = string(principalKind)
	}
	if actor.UserID == "" || actor.ExternalID == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "configuration requires a named authenticated principal"})
		return actor, false
	}
	return actor, true
}
func configurationRevisionResponse(r *db.ConfigurationRevision) apimodels.ConfigurationRevision {
	return apimodels.ConfigurationRevision{ID: r.ID, Scope: r.Scope, Kind: r.Kind, Revision: r.Revision, BaseRevision: r.BaseRevision, Source: r.Source, Digest: r.Digest, Dependencies: r.Dependencies, Status: r.Status, CreatedBy: r.CreatedBy, CreatedPrincipalKind: r.CreatedPrincipalKind, CreatedAt: r.CreatedAt, ActivatedBy: r.ActivatedBy, ActivatedAt: r.ActivatedAt, Artifact: r.Artifact}
}
func configurationRevisionList(rows []*db.ConfigurationRevision) apimodels.ConfigurationRevisionList {
	result := apimodels.ConfigurationRevisionList{Revisions: []apimodels.ConfigurationRevision{}}
	for _, row := range rows {
		result.Revisions = append(result.Revisions, configurationRevisionResponse(row))
	}
	return result
}
func configurationError(c *gin.Context, err error) {
	var databaseError interface{ SQLState() string }
	switch {
	case errors.Is(err, db.ErrConfigurationForbidden), errors.Is(err, db.ErrPolicyActorRequired), errors.Is(err, db.ErrPolicySelfApproval):
		c.JSON(http.StatusForbidden, gin.H{"error": "configuration action requires current authority and an independent approver"})
	case errors.Is(err, sql.ErrNoRows):
		c.JSON(http.StatusNotFound, gin.H{"error": "configuration revision not found"})
	case errors.As(err, &databaseError):
		if databaseError.SQLState() == "23505" || databaseError.SQLState() == "40001" || databaseError.SQLState() == "40P01" || databaseError.SQLState() == "55000" {
			c.JSON(http.StatusConflict, gin.H{"error": "configuration state changed; reload context and retry the revision"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "configuration operation failed"})
		}
	case errors.Is(err, db.ErrPolicyStaleBase):
		respondConflict(c, db.ErrPolicyStaleBase.Error())
	case errors.Is(err, db.ErrPolicyNotDraft):
		respondConflict(c, db.ErrPolicyNotDraft.Error())
	case errors.Is(err, db.ErrConfigurationConflict):
		respondClientError(c, http.StatusConflict, err, "configuration conflicts with the current revision state", "admin_configuration: conflict without client text")
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "configuration operation failed"})
	}
}

// getConfigurationManaged answers the one question an admin screen asks before
// it offers an edit control: does an active reviewed document own this stream?
// It is a read of one boolean and accepts the same credentials as the stream's
// legacy GET endpoints: named admins and the full admin token, while the
// restricted operator token is refused for tenant organisations exactly as
// every other per-tenant read refuses it. Nothing is authored, so no named
// principal is required. The same lookup gates the legacy writers
// (configurationWriterGuard), so the answer and the 409 can never disagree.
// @Summary Report whether a configuration stream is managed by an active revision
// @Description True once a revision of this stream is active: the stream's legacy write endpoints then answer 409 and the database refuses direct writes, so changes go through a configuration revision. False while the legacy setters are still the writer.
// @Tags Admin: Configuration
// @Produce json
// @Param org_id path string true "Organization UUID"
// @Param kind path string true "Configuration stream"
// @Success 200 {object} apimodels.ConfigurationManaged
// @Failure 400 {object} apimodels.APIError "malformed organisation id or unknown stream"
// @Failure 401 {object} apimodels.APIError
// @Failure 403 {object} apimodels.APIError "no admin authority for this organisation, or the restricted operator token on a tenant organisation"
// @Security BearerAuth
// @Security AdminToken
// @Router /api/v1/admin/orgs/{org_id}/configuration/{kind}/managed [get]
func (s *Server) getConfigurationManaged(c *gin.Context) {
	scope, kind, ok := configurationRoute(c)
	if !ok {
		return
	}
	if scope.Kind == "organization" && denyOperatorTenantRead(c) {
		return
	}
	managed, err := s.db.IsConfigurationManaged(c.Request.Context(), scope, kind)
	if err != nil {
		configurationError(c, err)
		return
	}
	c.JSON(http.StatusOK, apimodels.ConfigurationManaged{Kind: string(kind), Managed: managed})
}

// getConfigurationContext returns the complete editable source and live review metadata.
// @Summary Read configuration editing context
// @Tags Admin: Configuration
// @Produce json
// @Param org_id path string true "Organization UUID"
// @Param kind path string true "Configuration stream"
// @Success 200 {object} apimodels.ConfigurationContext
// @Failure 403 {object} apimodels.APIError
// @Security BearerAuth
// @Router /api/v1/admin/orgs/{org_id}/configuration/{kind}/context [get]
func (s *Server) getConfigurationContext(c *gin.Context) {
	if _, ok := configurationRequestActor(c); !ok {
		return
	}
	scope, kind, ok := configurationRoute(c)
	if !ok {
		return
	}
	view, err := s.db.GetConfigurationContext(c.Request.Context(), scope, kind)
	if err != nil {
		configurationError(c, err)
		return
	}
	source, err := json.Marshal(view.Source)
	if err != nil {
		configurationError(c, err)
		return
	}
	response := apimodels.ConfigurationContext{Source: source, LegacyExecution: []configuration.LegacyExecutionGrant{}}
	response.Capabilities = s.configurationCapabilities(c.Request.Context())
	response.Viewer, err = s.configurationViewer(c, scope)
	if err != nil {
		configurationError(c, err)
		return
	}
	if view.Active != nil {
		active := configurationRevisionResponse(view.Active)
		response.Active = &active
	}
	switch kind {
	case configuration.Groups:
		response.Groups = &view.Groups
	case configuration.ContractRegistry:
		response.Registry = &view.Registry
		response.LegacyExecution = view.LegacyExecution
	case configuration.Compliance:
		response.Compliance = &view.Compliance
	case configuration.Approvers:
		response.Approvers = view.Approvers
	case configuration.Platform:
		response.Platform = &view.Platform
	case configuration.ExecutionRules:
		response.Execution = view.Execution
		response.ExecutionMigration = view.ExecutionMigration
	}
	c.JSON(http.StatusOK, response)
}

// @Summary Submit a complete configuration source document
// @Tags Admin: Configuration
// @Accept json
// @Produce json
// @Param org_id path string true "Organization UUID"
// @Param kind path string true "Configuration stream"
// @Param source body object true "Complete ops.configuration/v1 document"
// @Success 201 {object} apimodels.ConfigurationRevision
// @Failure 400 {object} apimodels.APIError
// @Failure 403 {object} apimodels.APIError
// @Failure 409 {object} apimodels.APIError
// @Security BearerAuth
// @Router /api/v1/admin/orgs/{org_id}/configuration/{kind}/revisions [post]
func (s *Server) submitConfigurationRevision(c *gin.Context) {
	actor, ok := configurationRequestActor(c)
	if !ok {
		return
	}
	scope, kind, ok := configurationRoute(c)
	if !ok {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, configuration.MaxDocumentBytes+1))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot read source"})
		return
	}
	doc, err := configuration.Parse(raw)
	if err != nil {
		respondClientError(c, http.StatusBadRequest, err, "invalid configuration source", "admin_configuration: source rejected without client text")
		return
	}
	if doc.Scope != scope || doc.Kind != kind {
		c.JSON(http.StatusForbidden, gin.H{"error": "source scope and kind must match the route"})
		return
	}
	revision, err := s.db.SubmitConfigurationRevision(c.Request.Context(), raw, actor)
	if err != nil {
		configurationError(c, err)
		return
	}
	c.JSON(http.StatusCreated, configurationRevisionResponse(revision))
}

// @Summary List configuration revisions
// @Tags Admin: Configuration
// @Produce json
// @Param org_id path string true "Organization UUID"
// @Param kind path string true "Configuration stream"
// @Success 200 {object} apimodels.ConfigurationRevisionList
// @Security BearerAuth
// @Router /api/v1/admin/orgs/{org_id}/configuration/{kind}/revisions [get]
func (s *Server) listConfigurationRevisions(c *gin.Context) {
	if _, ok := configurationRequestActor(c); !ok {
		return
	}
	scope, kind, ok := configurationRoute(c)
	if !ok {
		return
	}
	limit, offset := parsePaginationParams(c, 50)
	rows, err := s.db.ListConfigurationRevisions(c.Request.Context(), scope, kind, limit, offset)
	if err != nil {
		configurationError(c, err)
		return
	}
	c.JSON(http.StatusOK, configurationRevisionList(rows))
}

// @Summary Read a configuration revision
// @Tags Admin: Configuration
// @Produce json
// @Param org_id path string true "Organization UUID"
// @Param kind path string true "Configuration stream"
// @Param revision_id path string true "Revision UUID"
// @Success 200 {object} apimodels.ConfigurationRevision
// @Security BearerAuth
// @Router /api/v1/admin/orgs/{org_id}/configuration/{kind}/revisions/{revision_id} [get]
func (s *Server) getConfigurationRevision(c *gin.Context) {
	if _, ok := configurationRequestActor(c); !ok {
		return
	}
	scope, kind, ok := configurationRoute(c)
	if !ok {
		return
	}
	revision, err := s.db.GetConfigurationRevision(c.Request.Context(), scope, kind, c.Param("revision_id"))
	if err != nil {
		configurationError(c, err)
		return
	}
	if revision == nil {
		configurationError(c, sql.ErrNoRows)
		return
	}
	c.JSON(http.StatusOK, configurationRevisionResponse(revision))
}
func (s *Server) configurationReviewInput(c *gin.Context) (configuration.Scope, []string, db.ConfigurationActor, bool) {
	actor, ok := configurationRequestActor(c)
	if !ok {
		return configuration.Scope{}, nil, actor, false
	}
	scope, kind, ok := configurationRoute(c)
	if !ok {
		return scope, nil, actor, false
	}
	revision, err := s.db.GetConfigurationRevision(c.Request.Context(), scope, kind, c.Param("revision_id"))
	if err != nil {
		configurationError(c, err)
		return scope, nil, actor, false
	}
	if revision == nil {
		configurationError(c, sql.ErrNoRows)
		return scope, nil, actor, false
	}
	input := apimodels.ConfigurationCoactivateRequest{Coactivate: []string{}}
	if c.Request.Body != nil {
		decoder := json.NewDecoder(io.LimitReader(c.Request.Body, 16385))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil && !errors.Is(err, io.EOF) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid coactivate request"})
			return scope, nil, actor, false
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "trailing coactivate request"})
			return scope, nil, actor, false
		}
	}
	ids := append([]string{revision.ID}, input.Coactivate...)
	return scope, ids, actor, true
}

// @Summary Review a draft and its sibling projections without mutation
// @Tags Admin: Configuration
// @Accept json
// @Produce json
// @Param org_id path string true "Organization UUID"
// @Param kind path string true "Configuration stream"
// @Param revision_id path string true "Revision UUID"
// @Param request body apimodels.ConfigurationCoactivateRequest false "Sibling drafts"
// @Success 200 {object} apimodels.ConfigurationReview
// @Security BearerAuth
// @Router /api/v1/admin/orgs/{org_id}/configuration/{kind}/revisions/{revision_id}/simulate [post]
func (s *Server) simulateConfigurationRevision(c *gin.Context) {
	scope, ids, actor, ok := s.configurationReviewInput(c)
	if !ok {
		return
	}
	view, err := s.db.ReviewConfigurationRevisions(c.Request.Context(), scope, ids, actor)
	if err != nil {
		configurationError(c, err)
		return
	}
	c.JSON(http.StatusOK, apimodels.ConfigurationReview{Revisions: configurationRevisionList(view.Candidates).Revisions, Groups: view.Groups, Registry: view.Registry, GroupDiff: view.GroupDiff, RegistryDiff: view.RegistryDiff, LegacyExecution: view.LegacyExecution, Compliance: view.Compliance, ComplianceDiff: view.ComplianceDiff, Approvers: view.Approvers, ApproversDiff: view.ApproversDiff, Platform: view.Platform, PlatformDiff: view.PlatformDiff, ExecutionDiff: view.ExecutionDiff})
}

// @Summary Activate reviewed configuration revisions atomically
// @Tags Admin: Configuration
// @Accept json
// @Produce json
// @Param org_id path string true "Organization UUID"
// @Param kind path string true "Configuration stream"
// @Param revision_id path string true "Revision UUID"
// @Param request body apimodels.ConfigurationCoactivateRequest false "Sibling drafts"
// @Success 200 {object} apimodels.ConfigurationRevisionList
// @Failure 403 {object} apimodels.APIError
// @Failure 409 {object} apimodels.APIError
// @Security BearerAuth
// @Router /api/v1/admin/orgs/{org_id}/configuration/{kind}/revisions/{revision_id}/activate [post]
func (s *Server) activateConfigurationRevision(c *gin.Context) {
	if !requireHumanConfigurationActor(c) {
		return
	}
	scope, ids, actor, ok := s.configurationReviewInput(c)
	if !ok {
		return
	}
	rows, err := s.db.ActivateConfigurationRevisions(c.Request.Context(), scope, ids, actor, s.authorizeConfigurationActivation)
	if err != nil {
		configurationError(c, err)
		return
	}
	if s.rbacAccessCtrl != nil {
		s.rbacAccessCtrl.InvalidateOrgLocalCache(scope.ID)
	}
	c.JSON(http.StatusOK, configurationRevisionList(rows))
}

// @Summary Withdraw an unactivated configuration draft
// @Tags Admin: Configuration
// @Produce json
// @Param org_id path string true "Organization UUID"
// @Param kind path string true "Configuration stream"
// @Param revision_id path string true "Revision UUID"
// @Success 200 {object} apimodels.ConfigurationRevision
// @Security BearerAuth
// @Router /api/v1/admin/orgs/{org_id}/configuration/{kind}/revisions/{revision_id}/withdraw [post]
func (s *Server) withdrawConfigurationRevision(c *gin.Context) {
	if !requireHumanConfigurationActor(c) {
		return
	}
	actor, ok := configurationRequestActor(c)
	if !ok {
		return
	}
	scope, kind, ok := configurationRoute(c)
	if !ok {
		return
	}
	row, err := s.db.WithdrawConfigurationRevision(c.Request.Context(), scope, kind, c.Param("revision_id"), actor, s.authorizeConfigurationActivation)
	if err != nil {
		configurationError(c, err)
		return
	}
	c.JSON(http.StatusOK, configurationRevisionResponse(row))
}

func (s *Server) authorizeConfigurationActivation(ctx context.Context, tx *db.Tx, view db.ConfigurationActivation) error {
	platform := s.configurationPlatformSubject(view.Actor.ExternalID)
	if view.Scope.Kind == "platform" {
		if !platform {
			return db.ErrConfigurationForbidden
		}
		for _, revision := range view.Candidates {
			subject, err := tx.ConfigurationActorSubject(ctx, revision.CreatedBy)
			if err != nil {
				return err
			}
			if !s.configurationPlatformSubject(subject) {
				return db.ErrConfigurationForbidden
			}
		}
		return nil
	}
	full, _, err := tx.ConfigurationActorRoles(ctx, view.Actor.UserID, view.Scope.ID)
	if err != nil {
		return err
	}
	if !full {
		return db.ErrConfigurationForbidden
	}
	if view.Actor.CIApproval == nil {
		eligible, err := tx.ConfigurationActorIsApprover(ctx, view.Actor.UserID, view)
		if err != nil {
			return err
		}
		if !eligible {
			return db.ErrConfigurationForbidden
		}
	}
	for _, revision := range view.Candidates {
		full, readonly, err := tx.ConfigurationActorRoles(ctx, revision.CreatedBy, view.Scope.ID)
		if err != nil {
			return err
		}
		if !full && !readonly {
			return db.ErrConfigurationForbidden
		}
	}
	if view.GroupDiff != nil {
		for _, change := range view.GroupDiff.Changes {
			if change.RequiresPlatform && !platform {
				return db.ErrConfigurationForbidden
			}
			if change.RequiresPlatform {
				for _, revision := range view.Candidates {
					if revision.Kind == configuration.Groups {
						subject, err := tx.ConfigurationActorSubject(ctx, revision.CreatedBy)
						if err != nil {
							return err
						}
						if !s.configurationPlatformSubject(subject) {
							return db.ErrConfigurationForbidden
						}
					}
				}
			}
		}
	}
	return nil
}

func (s *Server) configurationWriterGuard(kind configuration.Kind) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Authorization first, then the managed-stream lookup. The handlers
		// behind this guard carry the same operator/super-admin gates, but
		// running the lookup before them would (a) let a forbidden credential
		// reach a dependency and (b) answer "is this tenant's stream managed?"
		// to a caller the handler is about to reject.
		//
		// Groups are the exception: the operator token legitimately manages
		// org-admin and system groups (RD-1107 — minting org admins), and the
		// handler decides per group after loading it (denyOperatorRegularGroup).
		// A stream-level operator check here would be stricter than the
		// handler, so the groups stream keeps the handler's gate only.
		switch kind {
		case configuration.Platform:
			if !requireSuperAdmin(c) {
				c.Abort()
				return
			}
		case configuration.Groups:
		default:
			if denyOperatorOrgScoped(c) {
				c.Abort()
				return
			}
		}
		scope := configuration.Scope{Kind: "organization", ID: c.Param("org_id")}
		if kind == configuration.Platform {
			scope = configuration.Scope{Kind: "platform"}
		}
		managed, err := s.db.IsConfigurationManaged(c.Request.Context(), scope, kind)
		if err != nil {
			configurationError(c, err)
			c.Abort()
			return
		}
		if managed {
			c.JSON(http.StatusConflict, gin.H{"error": "use a configuration revision for this managed stream", "kind": kind})
			c.Abort()
			return
		}
		c.Next()
	}
}
