package server

import (
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/rbac"
)

// errTargetForeignOrg is the opaque deny string used by every admin
// handler that loads a global-by-ID resource (user, group, contract,
// session, sanction, azure tenant, …) and rejects callers whose
// admin_org_ids does not include the resource's parent org.
//
// The string intentionally matches the "not found" case so a tier-2
// admin cannot distinguish "exists in another org" from "does not
// exist" — the same shape RD-916 / RD-917 / PR #207 established for
// the membership and group-list handlers.
const errTargetForeignOrg = "access denied to target resource"

// requireTargetInScope is the canonical cross-org gate for handlers
// whose route does NOT carry :org_id (the resource is identified by a
// global ID like :user_id, :membership_id, :session_id, …) OR whose
// :org_id path parameter is not sufficient to guarantee the loaded
// resource actually lives in that org (the handler must re-verify).
//
// Returns true if the caller may proceed. Returns false (and writes a
// 403) when the caller is a JWT admin whose admin_org_ids does not
// contain targetOrgID. Super-admin (X-Admin-Token) and dev-mode
// callers always proceed.
//
// Read-only admins ARE accepted here — this helper only enforces the
// org-scope dimension. Mutation-vs-read enforcement lives in
// orgScopingMiddleware (for routes with :org_id) or in the handler's
// own role check (use requireFullAdminInScope for that combination).
func requireTargetInScope(c *gin.Context, targetOrgID string) bool {
	authMethod := c.GetString("auth_method")
	if authMethod != "jwt_admin" {
		// admin_token (super-admin) or empty (dev mode) — bypass.
		return true
	}
	if targetOrgID == "" {
		// A truly global resource (system setting, anonymous group,
		// etc.) reaching this helper means the caller intended super-
		// admin only. JWT admins are denied.
		c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
		return false
	}
	// Allow if the org is in either full-admin or read-only-admin scope.
	if ids, ok := c.Get("admin_org_ids"); ok {
		if list, ok := ids.([]string); ok && slices.Contains(list, targetOrgID) {
			return true
		}
	}
	if ids, ok := c.Get("admin_readonly_org_ids"); ok {
		if list, ok := ids.([]string); ok && slices.Contains(list, targetOrgID) {
			return true
		}
	}
	c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
	return false
}

// requireFullAdminInScope is the mutating-handler companion to
// requireTargetInScope: same org-scope check, but also rejects
// read-only admins. Use this in any non-GET handler whose route does
// not carry :org_id (orgScopingMiddleware would normally apply the
// role check via the path param; without :org_id, the handler is
// responsible).
//
// Returns true if the caller is super-admin / dev or a full
// (is_org_admin) admin of targetOrgID. Returns false with 403 in
// every other case.
func requireFullAdminInScope(c *gin.Context, targetOrgID string) bool {
	authMethod := c.GetString("auth_method")
	if authMethod != "jwt_admin" {
		return true
	}
	if targetOrgID == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
		return false
	}
	if ids, ok := c.Get("admin_org_ids"); ok {
		if list, ok := ids.([]string); ok && slices.Contains(list, targetOrgID) {
			return true
		}
	}
	c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
	return false
}

// requireSuperAdmin rejects every caller except X-Admin-Token /
// dev mode. Use for genuinely global mutations (Azure tenant CRUD,
// system base-currency switch, global sanction add, …).
func requireSuperAdmin(c *gin.Context) bool {
	authMethod := c.GetString("auth_method")
	if authMethod == "admin_token" || authMethod == "" {
		return true
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "super-admin required"})
	return false
}

// RD-1107 / RD-1132 — the OPERATOR token (auth_method=="operator_token").
//
// The admin API is reachable with two X-Admin-Token values (see
// adminAuthMiddleware): the full ADMIN_API_TOKEN (auth_method=="admin_token",
// trusted ops / MCP — unrestricted) and the optional restricted
// OPERATOR_API_TOKEN (auth_method=="operator_token"). The operator is a
// platform/bootstrap principal — possibly a 3rd-party onboarder with no DB
// access — that may create/manage orgs and mint org admins, but must NOT touch
// or read per-org tenant data. The denyOperator* helpers enforce that; they
// fire ONLY for operator_token (admin_token and jwt_admin and dev pass through).

// errOperatorNoTenantMgmt is the opaque deny for an operator-token per-org
// MUTATION (RD-1107). The operator keeps org lifecycle, is_org_admin / system
// group ops (incl. minting org admins), but per-org RBAC + compliance are the
// org admin's job (Authorization: Bearer JWT).
const errOperatorNoTenantMgmt = "per-org management is the org admin's job; the operator token is for platform/bootstrap only"

// denyOperatorOrgScoped rejects the operator token on a mutation of org_id-scoped
// tenant data (contracts, grants, per-org compliance, …). jwt_admin (tier-2 —
// already org-scoped by orgScopingMiddleware), admin_token (full) and dev ("")
// pass through. Returns true and writes the 403 when the caller must be stopped.
//
// Call AFTER the org-scope / foreign-org checks so a cross-tenant probe still
// gets the opaque foreign-org error first.
func denyOperatorOrgScoped(c *gin.Context) bool {
	if c.GetString("auth_method") != "operator_token" {
		return false
	}
	// The default org is system infrastructure (the global landing org that
	// every self-onboarding user lands in), not a tenant — the operator may
	// still manage it, like is_system resources. All these routes carry :org_id.
	if c.Param("org_id") == rbac.DefaultOrgID {
		return false
	}
	c.JSON(http.StatusForbidden, gin.H{"error": errOperatorNoTenantMgmt})
	return true
}

// denyOperatorRegularGroup is the group-bound variant of denyOperatorOrgScoped:
// it rejects the operator token only when the target group is a REGULAR group
// (not is_org_admin / is_org_readonly_admin / is_system). The operator keeps full
// control of org-admin and system groups (minting org admins, anonymous-group
// config) — the exact inverse of denyJWTAdminTouchOrgAdminGroup, which reserves
// those same groups to the privileged path. A nil group is treated as regular
// (fail-closed). Returns true and writes the 403 when stopped; the handler must
// then return. Call AFTER the group load + nil/404 check and the foreign-org check.
func denyOperatorRegularGroup(c *gin.Context, group *rbac.Group) bool {
	if c.GetString("auth_method") != "operator_token" {
		return false
	}
	// Admin-tier and system groups stay operator-manageable: is_org_admin /
	// is_org_readonly_admin (minting/managing org admins), is_system (e.g. the
	// anonymous group), and the global default group — system infrastructure
	// that predates the is_system flag. Everything else is a tenant's regular
	// group and is the org admin's job. A nil group falls through to deny
	// (fail-closed).
	if group != nil && (group.IsOrgAdmin || group.IsOrgReadonlyAdmin || group.IsSystem || group.ID == rbac.DefaultGroupID) {
		return false
	}
	c.JSON(http.StatusForbidden, gin.H{"error": errOperatorNoTenantMgmt})
	return true
}

// errOperatorNoTenantRead is the opaque deny for RD-1132: the operator token may
// not READ tenant-confidential data (members, groups, contracts, grants, audit
// logs, per-org compliance, …). For an operator that reaches the system only
// through the admin API (e.g. a 3rd-party onboarder with no DB access) this is a
// real confidentiality boundary, not just accountability.
const errOperatorNoTenantRead = "tenant data is not readable with the operator token; use a tier-2 org-admin JWT"

// denyOperatorTenantRead rejects the operator token on a tenant-confidential READ
// (RD-1132 — the read-side counterpart to denyOperatorOrgScoped). The operator
// keeps the org list + org metadata + fleet/global reads; everything per-tenant
// is the org admin's (tier-2 JWT). admin_token (full), jwt_admin and dev ("")
// pass through. The default org/group stays readable (system infrastructure),
// matching the mutation gate: org-scoped routes carry :org_id, so the default-org
// check exempts them; global / by-:user_id / by-:address reads have no :org_id
// param (empty != DefaultOrgID) and are therefore blocked for the operator.
func denyOperatorTenantRead(c *gin.Context) bool {
	if c.GetString("auth_method") != "operator_token" {
		return false
	}
	if c.Param("org_id") == rbac.DefaultOrgID {
		return false
	}
	c.JSON(http.StatusForbidden, gin.H{"error": errOperatorNoTenantRead})
	return true
}

// ── Self-target guard (RD-1238) ──────────────────────────────────────────────
//
// A tier-2 org admin (jwt_admin) could set banned=true on their OWN user row.
// Banning revokes the target's refresh tokens and adminAuthMiddleware rejects a
// banned user on every subsequent request, so a self-ban is an instant, possibly
// accidental self-lockout. Recovery needs the full super-admin X-Admin-Token,
// because denyOperatorOrgScoped blocks the operator token from user mutations —
// for a single-admin org that means the org cannot recover on its own.

// errCannotSelfBan is returned when a caller tries to ban their own account.
// Not opaque on purpose: the caller already knows who they are and that the
// target is themselves, so there is nothing to leak, and a clear message is
// what stops the mistake from being repeated.
const errCannotSelfBan = "cannot ban your own account; ask another admin to do it"

// isSelfBanAttempt reports whether the caller is targeting their own user row.
// It only ever returns true for jwt_admin, the one principal that carries a user
// identity (adminAuthMiddleware sets admin_user_id alongside admin_org_ids).
// admin_token / operator_token / dev mode have no admin_user_id, so they always
// return false — a super-admin acting on any user, including one that happens to
// be an admin, is intended.
//
// The empty check is load-bearing: without it a caller with no admin_user_id
// would "match" an empty :user_id and get a confusing 400 instead of the normal
// scope/not-found path.
func isSelfBanAttempt(c *gin.Context, targetUserID string) bool {
	callerUserID := c.GetString("admin_user_id")
	if callerUserID == "" || targetUserID == "" {
		return false
	}
	return callerUserID == targetUserID
}
