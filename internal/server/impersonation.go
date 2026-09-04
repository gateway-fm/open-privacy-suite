package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RD-928 — "View as user" impersonation surface.
// RD-994 — explicit, path-supplied org for multi-org admins.
//
// Tier-2 org admins can browse the explorer / call read-only RPC as if they
// were a target user in a specific org, without ever minting a user-shaped
// JWT. The org is named explicitly in the URL — the proxy no longer guesses
// it via a first-match against the admin's admin_org_ids. The mechanism is a
// parallel URL tree:
//
//   /api/v1/admin/impersonate/:target_did/in/:org_id/api/v1/explorer/<sub-path>
//   /api/v1/admin/impersonate/:target_did/in/:org_id/rpc[/:nested_org_id]
//
// These re-use the existing explorer / RPC handlers via a single per-request
// override carried in gin.Context. impersonationGateMiddleware does all the
// gating up front:
//
//   1. tier-2 admin only (super-admin token + tier-3 + read-only admin → 403)
//   2. :org_id MUST be one of the caller's admin_org_ids (else 403) — RD-994
//   3. target user exists AND has a membership in :org_id (else 404,
//      same shape as RD-872 dry-run / a cross-org target — never reveal
//      cross-org existence)
//   4. self-impersonation rejected
//   5. GET-only on this surface (write methods 405) — Phase 2 of RD-872 is
//      strictly read-only by design
//   6. defensive header strip: X-Admin-Token and any X-Impersonate-* headers
//      from the client are removed before the request hits the downstream
//      handler chain (the BFF should never have forwarded them, but DiD)
//   7. per-request impersonation_log row, fail-closed: if the audit write
//      errors we refuse the response rather than expose data unlogged
//
// RD-994 backwards-compat decision: the bare /impersonate/:target_did/...
// route (no /in/:org_id) is NOT supported. It returns 400. The project
// policy (MVP close to release, no backwards-compat shims) plus the security
// argument — silent first-match org selection is exactly the opacity RD-994
// removes — means we force explicit org selection rather than fall back to
// the old resolveImpersonationOrg behaviour. The BFF and dashboard always
// supply the org, so there is no legitimate caller of the bare route.
//
// On success the middleware sets:
//
//   c.Set(viewerDIDOverrideContextKey, target_did)
//   c.Set(impersonationActorDIDContextKey, admin_did)
//   c.Set(impersonationOrgIDContextKey, org_id)   // the explicit :org_id
//
// Downstream:
//
//   - getViewerDIDFromRequest (explorer_api.go) honors the override.
//   - handleJSONRPC reads it via getEffectiveViewerDID below.
//   - The CheckAccess call sets BypassCache so the impersonated viewer's
//     in-memory perms aren't served from a 5-min-stale entry. (The resolver's
//     DB cache may still serve stale up to its TTL — that's RD-956's surface,
//     not RD-928's.)
//
// Why this is safe for tier-2 admin same-org browse-as: by
// rbac.computeOrgAdminPermissions, the admin has full claims on every
// contract in their org, so any data exposed through the impersonated viewer
// is already in the admin's reach via direct calls. Net new data: zero. The
// surface is an *ergonomics* tool wrapped in audit logging, not a privilege
// expansion. Cross-org is structurally impossible because (a) :org_id must be
// one of the admin's own orgs and (b) the target-membership check in :org_id
// runs before the override is set.

// Context keys for the impersonation override. Strings, not custom types,
// so the explorer handlers (which already read string keys like "subject")
// stay readable. The keys are only written by impersonationGateMiddleware;
// see the SECURITY: comment in getViewerDIDFromRequest for the invariant.
const (
	viewerDIDOverrideContextKey   = "rd928_viewer_did_override"
	impersonationActorDIDContextKey = "rd928_impersonation_actor_did"
	impersonationOrgIDContextKey  = "rd928_impersonation_org_id"
)

// errImpersonationTargetNotFound is the sentinel returned by the same-org
// resolution path. It maps to a generic 404 so a tier-2 admin in Org A
// cannot probe whether `did:foo` exists in Org B.
var errImpersonationTargetNotFound = errors.New("user not found")

// registerImpersonationRoutes mounts the impersonation surface as a
// path-prepend namespace with an explicit org segment: every existing
// read-side URL on the proxy is reachable under
//
//	/api/v1/admin/impersonate/:target_did/in/:org_id<original-url>
//
// i.e. an explorer call to /api/v1/explorer/blocks/123 becomes
// /api/v1/admin/impersonate/<did>/in/<org>/api/v1/explorer/blocks/123, and an
// RPC call to /rpc becomes /api/v1/admin/impersonate/<did>/in/<org>/rpc. The
// BFF rewrites paths by simple concatenation — no segment surgery — which
// keeps the contract robust as new explorer endpoints are added.
//
// The route group inherits localhost-only + admin-auth from the parent admin
// group. impersonationGateMiddleware re-enforces tier-2 admin specifically
// (rejecting super-admin token + read-only admin), verifies :org_id is one of
// the caller's orgs, and verifies the target is a member of :org_id.
//
// Two sub-trees under /in/:org_id:
//   - /api/v1/explorer/* re-uses bindExplorerEndpoints (shared with the
//     production explorer routes) but with the impersonation gate +
//     viewer override.
//   - /rpc[/:nested_org_id] re-uses handleJSONRPC.
//
// RD-994: the bare /impersonate/:target_did/... routes (no /in/:org_id) are
// registered separately and unconditionally return 400 — we force the caller
// to name the org explicitly rather than silently first-matching it.
//
// auth.OptionalJWTAuthMiddleware is NOT applied here — the admin gate
// already validated the caller's JWT, and we don't want an anonymous viewer
// fallback under this tree.
func (s *Server) registerImpersonationRoutes(adminGroup *gin.RouterGroup) {
	// Explicit-org subtree: /impersonate/:target_did/in/:org_id/...
	impIn := adminGroup.Group("/impersonate/:target_did/in/:org_id")
	impIn.Use(s.impersonationGateMiddleware())

	// Explorer subtree is re-mounted at /api/v1/explorer (matching its
	// production prefix) so the BFF just prepends
	// /api/v1/admin/impersonate/<did>/in/<org> to whatever explorer URL it
	// was going to call. Reuse the same log-redaction middleware production
	// explorer routes use — impersonated paths can still embed Ethereum
	// addresses we don't want in access logs.
	explorerImp := impIn.Group("/api/v1/explorer")
	explorerImp.Use(explorerLogRedactionMiddleware())
	s.bindExplorerEndpoints(explorerImp)

	// RPC subtree: mirror the production /rpc and /rpc/:nested_org_id shapes.
	// /rpc has no /api/v1 prefix in production so it sits directly under
	// /api/v1/admin/impersonate/:target_did/in/:org_id/rpc here too.
	//
	// We register Any() (not GET) so non-GET methods reach the middleware's
	// 405 check instead of gin's no-route 404 — surfaces the right HTTP
	// semantics ("method not allowed" not "endpoint missing") to the BFF
	// and makes the "POST under impersonation is rejected" assertion
	// auditable. The middleware unconditionally rejects c.Request.Method
	// != GET.
	//
	// :nested_org_id is the production /rpc/:org_id shape; under
	// impersonation the gate's explicit :org_id is authoritative for org
	// anchoring (handleJSONRPC prefers the path :nested_org_id only when the
	// gate hasn't pinned one, which it always has here).
	impIn.Any("/rpc", s.handleJSONRPC)
	impIn.Any("/rpc/:nested_org_id", s.handleJSONRPC)

	// RD-994: bare routes without /in/:org_id. Mirror the same shapes so a
	// caller of the old URL tree gets a clear 400 ("org required") instead
	// of a 404 no-route. We deliberately do NOT run the gate here — there is
	// no org to anchor to, so there's nothing to authorise; the request is
	// malformed by construction.
	bare := adminGroup.Group("/impersonate/:target_did")
	bareReject := func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "org_id is required: use /api/v1/admin/impersonate/:target_did/in/:org_id/...",
		})
	}
	bareExplorer := bare.Group("/api/v1/explorer")
	s.bindImpersonationBareReject(bareExplorer, bareReject)
	bare.Any("/rpc", bareReject)
	bare.Any("/rpc/:nested_org_id", bareReject)
}

// bindImpersonationBareReject mirrors the explorer endpoint shapes registered
// by bindExplorerEndpoints, but wires every one to the supplied reject
// handler. It exists so the bare (org-less) impersonation tree returns a
// clean 400 on the exact same set of explorer paths the /in/:org_id tree
// serves, rather than a confusing no-route 404. A single wildcard would be
// simpler but gin forbids mixing a wildcard with the explicit child routes
// already registered on the sibling /in/:org_id group at the shared prefix,
// so we enumerate the prefix instead and let gin's tree match sub-paths via a
// catch-all under this group only.
func (s *Server) bindImpersonationBareReject(g *gin.RouterGroup, reject gin.HandlerFunc) {
	// A catch-all under the explorer prefix covers blocks, txs, addresses,
	// logs, transfers, tokens, chain-id, stats, etc. without coupling to the
	// concrete bindExplorerEndpoints route list. The /in/:org_id sibling owns
	// the real handlers; this group only ever returns 400.
	g.Any("/*any", reject)
}

// impersonationGateMiddleware enforces the RD-928/RD-994 gate rules and sets
// the viewer override + audit-log identity context values. See the
// package-level doc on this file for the full enforcement matrix.
func (s *Server) impersonationGateMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// X-Admin-Token credentials (admin_token full / operator_token) bypass
		// orgScopingMiddleware on regular admin routes; for impersonation they
		// must NOT — impersonation reads tenant data as a user, which neither
		// token may do. Reject explicitly with the same 403 surface as
		// handleDryRun.
		if am := c.GetString("auth_method"); am == "admin_token" || am == "operator_token" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "impersonation requires a tier-2 admin JWT; X-Admin-Token credentials are not authorised",
			})
			return
		}

		adminDID := c.GetString("admin_subject")
		if adminDID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "admin authentication required"})
			return
		}

		// Tier-2 admin only: read-only admin (RD-866) is excluded.
		// admin_org_ids is non-empty for tier-2 admins, empty for ROA.
		adminOrgIDs, ok := c.Get("admin_org_ids")
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "tier-2 admin required"})
			return
		}
		orgIDs, ok := adminOrgIDs.([]string)
		if !ok || len(orgIDs) == 0 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "tier-2 admin required"})
			return
		}

		// GET-only on this surface. Phase 2 of RD-872 is strictly
		// read-only by design — write methods go through /dry-run which
		// translates them to debug_traceCall against a discarded state.
		if c.Request.Method != http.MethodGet {
			c.AbortWithStatusJSON(http.StatusMethodNotAllowed, gin.H{
				"error": "impersonation surface is read-only; use POST /api/orgs/:org_id/dry-run for write-method traces",
			})
			return
		}

		targetDID := strings.TrimSpace(c.Param("target_did"))
		if targetDID == "" {
			// Gin shouldn't route us here without the param, but defend.
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "target_did required"})
			return
		}
		if targetDID == adminDID {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "cannot impersonate yourself"})
			return
		}

		// RD-994: org is explicit and path-supplied. The route guarantees
		// the param is present; defend against an empty value anyway.
		orgID := strings.TrimSpace(c.Param("org_id"))
		if orgID == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "org_id is required: use /api/v1/admin/impersonate/:target_did/in/:org_id/...",
			})
			return
		}

		// The caller must themselves be a tier-2 admin OF :org_id. Anything
		// outside their admin_org_ids is a 403 — this is the authorisation
		// boundary (vs the 404 target-membership check below, which is an
		// existence-hiding boundary). We answer 403 here and not 404 because
		// the org id is the admin's own claim surface: a tier-2 admin always
		// knows which orgs they administer, so there is nothing to hide.
		adminScoped := false
		for _, id := range orgIDs {
			if id == orgID {
				adminScoped = true
				break
			}
		}
		if !adminScoped {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "not a tier-2 admin of the requested org",
			})
			return
		}

		// Defensive header strip: a misbehaving BFF (or compromised one)
		// must not be able to smuggle alternate identity envelopes into
		// the downstream chain. RD-877's `subject` claim is JWT-derived
		// and immutable here; these headers are unused by Open Privacy Suite
		// and are stripped purely to keep the BFF contract clean.
		c.Request.Header.Del("X-Admin-Token")
		c.Request.Header.Del("X-Impersonate-User-DID")
		c.Request.Header.Del("X-Impersonate-Token")

		// Verify the target user exists AND is a member of the explicit
		// :org_id. A non-existent user, a user with no membership in
		// :org_id, and a user who only exists in some OTHER org all collapse
		// to the same generic 404 — so the response shape can't be used as a
		// cross-org user-existence oracle. (Authorisation of the admin over
		// :org_id was already settled above; this check is purely about the
		// target's presence in that org.)
		lookupErr := s.verifyImpersonationTargetInOrg(c.Request.Context(), targetDID, orgID)
		if errors.Is(lookupErr, errImpersonationTargetNotFound) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		if lookupErr != nil {
			slog.Error("impersonation: target membership check failed", "admin_did", adminDID, "err", lookupErr)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}

		// Set the override and identity tags BEFORE handler dispatch so
		// downstream code (getViewerDIDFromRequest, handleJSONRPC) sees
		// them. Audit log fires after dispatch so it captures the
		// downstream decision in `reason` (allow / deny / error).
		c.Set(viewerDIDOverrideContextKey, targetDID)
		c.Set(impersonationActorDIDContextKey, adminDID)
		c.Set(impersonationOrgIDContextKey, orgID)

		c.Next()

		// Post-handler: write one audit row per impersonated request. We
		// use the HTTP status as the decision proxy (2xx → "allow", 4xx
		// → "deny", 5xx → "error"). The request path is the "method"
		// column — params_hash is the sha256 of the raw query string
		// (impersonation token already stripped at the BFF, never
		// reaches us). Fail-closed: if the audit write errors AFTER a
		// 2xx response we can't unsend the body, but we log loudly and
		// flip the response code so the caller sees the inconsistency
		// on the next polled error.
		status := c.Writer.Status()
		decision := decisionFromStatus(status)
		reason := ""
		if decision != "allow" {
			reason = fmt.Sprintf("http_%d", status)
		}
		if logErr := s.recordImpersonationRequest(
			c.Request.Context(),
			adminDID,
			targetDID,
			orgID,
			c.Request.Method+" "+c.Request.URL.Path,
			c.Request.URL.RawQuery,
			decision,
			reason,
			middleware.GetCorrelationID(c),
		); logErr != nil {
			// Body already sent — we can't unsend. Log loudly. The next
			// caller attempting to use this admin's JWT will see the
			// audit-write health surface (when we add one) regardless.
			slog.Error("impersonation: audit log write failed AFTER response",
				"admin_did", adminDID, "target_did", targetDID, "path", c.Request.URL.Path, "err", logErr)
		}
	}
}

// verifyImpersonationTargetInOrg returns nil iff the target user exists AND
// has at least one group membership in orgID. It returns
// errImpersonationTargetNotFound for a non-existent user OR a user with no
// membership in orgID (including a user who only exists in some other org).
//
// RD-994: the org is now the explicit, caller-supplied :org_id — we no longer
// scan the intersection of admin/target orgs to pick one. The caller's
// authorisation over orgID is checked separately in the gate (a 403, not a
// 404). Here, never-seen DIDs and cross-org-only targets collapse to the same
// sentinel by design, so the response shape can't be used as a user-existence
// oracle across org boundaries.
func (s *Server) verifyImpersonationTargetInOrg(ctx context.Context, targetDID, orgID string) error {
	if s.db == nil {
		return fmt.Errorf("db not configured")
	}
	user, err := s.db.GetUserByExternalID(ctx, targetDID)
	if err != nil {
		return fmt.Errorf("user lookup: %w", err)
	}
	if user == nil {
		return errImpersonationTargetNotFound
	}
	userOrgIDs, err := s.rbacAccessCtrl.GetUserOrgIDs(ctx, user.ID)
	if err != nil {
		return fmt.Errorf("user org lookup: %w", err)
	}
	for _, uOrg := range userOrgIDs {
		if uOrg == orgID {
			return nil
		}
	}
	return errImpersonationTargetNotFound
}

// getEffectiveViewerDID returns the impersonation override if set, else the
// JWT-derived subject. Used by handleJSONRPC and any future handler that
// needs the "who is the request acting as" answer.
//
// Identical priority to getViewerDIDFromRequest in explorer_api.go — kept
// as a separate function because the explorer surface also has a wallet
// fallback comment chain that doesn't apply on the RPC side.
func getEffectiveViewerDID(c *gin.Context) string {
	if override, exists := c.Get(viewerDIDOverrideContextKey); exists {
		if did, ok := override.(string); ok && did != "" {
			return did
		}
	}
	if subject, exists := c.Get("subject"); exists {
		if did, ok := subject.(string); ok && did != "" {
			return did
		}
	}
	return ""
}

// isImpersonating reports whether the current request is running under the
// impersonation override. CheckAccess callers use this to set BypassCache.
func isImpersonating(c *gin.Context) bool {
	override, exists := c.Get(viewerDIDOverrideContextKey)
	if !exists {
		return false
	}
	did, ok := override.(string)
	return ok && did != ""
}

// decisionFromStatus maps HTTP status to the impersonation_log.decision
// enum. 2xx → allow, 4xx → deny, anything else → error.
func decisionFromStatus(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "allow"
	case status >= 400 && status < 500:
		return "deny"
	default:
		return "error"
	}
}

// recordImpersonationRequest writes one impersonation_log row for a non-RPC
// impersonated call (explorer GETs, RPC GETs). The dry-run RPC POST flow
// keeps its own recordImpersonation helper for back-compat with PR #199.
func (s *Server) recordImpersonationRequest(
	ctx context.Context,
	actorDID, impersonatedDID, orgID string,
	method string,
	rawQuery string,
	decision, reason, correlationID string,
) error {
	if s.db == nil {
		return nil
	}
	conn := s.db.Conn()
	if conn == nil {
		return nil
	}
	corr := uuid.NullUUID{}
	if id, err := uuid.Parse(correlationID); err == nil {
		corr.UUID = id
		corr.Valid = true
	}
	// Hash the query string (already token-stripped by the BFF before the
	// request reached us). We never persist the raw query — it can carry
	// private addresses or block-hash filters that should not appear in
	// the audit table per migration 047.
	paramsHash := ""
	if rawQuery != "" {
		sum := sha256.Sum256([]byte(rawQuery))
		paramsHash = hex.EncodeToString(sum[:])
	}
	_, err := conn.ExecContext(ctx, `
		INSERT INTO impersonation_log (actor_did, impersonated_did, org_id, method, params_hash, decision, reason, correlation_id)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8)`,
		actorDID, impersonatedDID, orgID, method, paramsHash, decision, reason, corr,
	)
	return err
}

// applyImpersonationToAccessRequest sets BypassCache on the given access
// request when the gin context carries the impersonation override. Reserved
// for explorer endpoints that build their own AccessCheckRequest (the RPC
// path goes through ProcessRequest.BypassPermsCache). Keep as a thin helper
// so future viewer-aware admin surfaces inherit cache-bypass for free.
func applyImpersonationToAccessRequest(c *gin.Context, req *rbac.AccessCheckRequest) {
	if !isImpersonating(c) {
		return
	}
	req.BypassCache = true
}
