package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1238: PUT /api/v1/admin/users/{user_id} let a tier-2 org-admin JWT set
// banned=true on their OWN user row. Banning revokes the caller's refresh
// tokens and adminAuthMiddleware rejects a banned user on every later request,
// so a self-ban is an instant self-lockout that only the full super-admin
// X-Admin-Token can undo (denyOperatorOrgScoped blocks the operator token from
// user mutations). The guard below rejects that one case; every other
// combination must keep working.

// jwtAdminRouterAsUser builds a router with a jwt_admin context that is a full
// admin of orgID AND is identified as callerUserID — the shape adminAuthMiddleware
// produces for a tier-2 org admin (server.go sets admin_user_id alongside
// admin_org_ids). Mirrors jwtAdminRouterForOrg, plus the caller identity the
// self-target guard needs.
func jwtAdminRouterAsUser(srv *Server, orgID, callerUserID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("auth_method", "jwt_admin")
		c.Set("admin_org_ids", []string{orgID})
		c.Set("admin_user_id", callerUserID)
		c.Next()
	})
	srv.registerRBACRoutes(r.Group("/api/v1/admin"))
	return r
}

// putUserJSON issues a bare PUT (no admin token header) against a router that
// injects its own auth context.
func putUserJSON(t *testing.T, router http.Handler, url string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// createOrgAdminUser creates an org with an org-admin group and a user who is a
// member of it, so requireUserInFullAdminScope resolves the user into orgID.
func createOrgAdminUser(t *testing.T, srv *Server) (orgID, userID string) {
	t.Helper()
	ctx := t.Context()

	orgID, groupID := createOrgWithOrgAdminGroup(t, srv)

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:" + uuid.New().String()[:8],
	}
	require.NoError(t, srv.db.CreateUser(ctx, user))
	require.NoError(t, srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: groupID,
		Source:  rbac.MembershipSourceAdmin,
	}))

	return orgID, user.ID
}

// The bug: a tier-2 org admin banning themselves. Must be rejected, and the
// user row must be left unbanned so the admin is not locked out.
func TestUpdateUser_SelfBan_Rejected_RD1238(t *testing.T) {
	srv, _ := setupTieredAdminTestServer(t, "secret")
	orgID, userID := createOrgAdminUser(t, srv)
	router := jwtAdminRouterAsUser(srv, orgID, userID)

	w := putUserJSON(t, router, "/api/v1/admin/users/"+userID, map[string]any{"banned": true})

	assert.Equal(t, http.StatusBadRequest, w.Code, "self-ban must be rejected: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), errCannotSelfBan)

	// Fail-closed on the data too: the ban must not have been persisted.
	user, err := srv.db.GetUser(t.Context(), userID)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.False(t, user.Banned, "self-ban was rejected but the row was still updated")
}

// Self-UNBAN stays allowed — a banned admin cannot reach this endpoint anyway
// (adminAuthMiddleware rejects them), so guarding it would only block recovery.
func TestUpdateUser_SelfUnban_Allowed_RD1238(t *testing.T) {
	srv, _ := setupTieredAdminTestServer(t, "secret")
	orgID, userID := createOrgAdminUser(t, srv)

	// Pre-ban the row directly so the request is a genuine unban.
	user, err := srv.db.GetUser(t.Context(), userID)
	require.NoError(t, err)
	user.Banned = true
	require.NoError(t, srv.db.UpdateUser(t.Context(), user))

	router := jwtAdminRouterAsUser(srv, orgID, userID)
	w := putUserJSON(t, router, "/api/v1/admin/users/"+userID, map[string]any{"banned": false})

	require.Equal(t, http.StatusOK, w.Code, "self-unban must be allowed: %s", w.Body.String())
	after, err := srv.db.GetUser(t.Context(), userID)
	require.NoError(t, err)
	assert.False(t, after.Banned, "self-unban did not clear the ban")
}

// A non-ban self-update (kyc/note) is untouched by the guard — only banned=true
// on self is rejected.
func TestUpdateUser_SelfNonBanUpdate_Allowed_RD1238(t *testing.T) {
	srv, _ := setupTieredAdminTestServer(t, "secret")
	orgID, userID := createOrgAdminUser(t, srv)
	router := jwtAdminRouterAsUser(srv, orgID, userID)

	w := putUserJSON(t, router, "/api/v1/admin/users/"+userID, map[string]any{"note": "own note"})

	require.Equal(t, http.StatusOK, w.Code, "self note update must be allowed: %s", w.Body.String())
	after, err := srv.db.GetUser(t.Context(), userID)
	require.NoError(t, err)
	assert.Equal(t, "own note", after.Note)
	assert.False(t, after.Banned)
}

// Banning SOMEONE ELSE in the caller's own org still works — the guard must not
// over-block the legitimate moderation path it sits on.
func TestUpdateUser_BanOtherUser_Allowed_RD1238(t *testing.T) {
	srv, _ := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()
	orgID, groupID := createOrgWithOrgAdminGroup(t, srv)

	mkUser := func() string {
		u := &rbac.User{ID: uuid.New().String(), ExternalID: "did:test:" + uuid.New().String()[:8]}
		require.NoError(t, srv.db.CreateUser(ctx, u))
		require.NoError(t, srv.db.CreateMembership(ctx, &rbac.UserMembership{
			ID: uuid.New().String(), UserID: u.ID, GroupID: groupID, Source: rbac.MembershipSourceAdmin,
		}))
		return u.ID
	}
	callerID := mkUser()
	targetID := mkUser()

	router := jwtAdminRouterAsUser(srv, orgID, callerID)
	w := putUserJSON(t, router, "/api/v1/admin/users/"+targetID, map[string]any{"banned": true})

	require.Equal(t, http.StatusOK, w.Code, "banning another user must still work: %s", w.Body.String())
	after, err := srv.db.GetUser(ctx, targetID)
	require.NoError(t, err)
	assert.True(t, after.Banned, "ban of another user did not persist")
}

// A super-admin (X-Admin-Token) has no admin_user_id in context. The guard must
// not fire for it — an empty caller id must never match the path param, and
// super-admin banning any user is intended behavior.
func TestUpdateUser_SuperAdminBan_NotBlockedByGuard_RD1238(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	_, userID := createOrgAdminUser(t, srv)

	w := putJSON(t, router, "/api/v1/admin/users/"+userID, map[string]any{"banned": true})

	require.Equal(t, http.StatusOK, w.Code, "super-admin ban must not be blocked: %s", w.Body.String())
	after, err := srv.db.GetUser(t.Context(), userID)
	require.NoError(t, err)
	assert.True(t, after.Banned)
}

// Regression guard for the empty-string match hazard: a jwt_admin whose
// admin_user_id was never set (defensive — adminAuthMiddleware always sets it)
// must not have the guard fire on an empty path param. Routing makes a truly
// empty :user_id unreachable, so this asserts the helper directly.
func TestIsSelfBanAttempt_EmptyIdentityNeverMatches_RD1238(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newCtx := func(authMethod, callerID string) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Set("auth_method", authMethod)
		if callerID != "" {
			c.Set("admin_user_id", callerID)
		}
		return c
	}

	// jwt_admin with no admin_user_id, empty target → must NOT be a self-ban.
	assert.False(t, isSelfBanAttempt(newCtx("jwt_admin", ""), ""),
		"empty caller identity must never match an empty target")

	// Super-admin / operator tokens carry no admin_user_id at all.
	assert.False(t, isSelfBanAttempt(newCtx("admin_token", ""), "some-user"))
	assert.False(t, isSelfBanAttempt(newCtx("operator_token", ""), "some-user"))

	// The real self-target case.
	assert.True(t, isSelfBanAttempt(newCtx("jwt_admin", "u1"), "u1"))
	assert.False(t, isSelfBanAttempt(newCtx("jwt_admin", "u1"), "u2"))
}

// The guard must key on the canonical UUID, not the raw path spelling.
// PostgreSQL's uuid type accepts non-canonical input (upper-case here), so
// GetUser and the scope check both resolve the caller's row while a raw
// string comparison would not match — which would walk the self-ban straight
// through the guard.
func TestUpdateUser_SelfBan_NonCanonicalUUID_StillRejected_RD1238(t *testing.T) {
	srv, _ := setupTieredAdminTestServer(t, "secret")
	orgID, userID := createOrgAdminUser(t, srv)
	router := jwtAdminRouterAsUser(srv, orgID, userID)

	// Same UUID, upper-cased: a different string, the same row.
	spoofed := strings.ToUpper(userID)
	require.NotEqual(t, userID, spoofed, "fixture UUID must contain hex letters to vary by case")

	w := putUserJSON(t, router, "/api/v1/admin/users/"+spoofed, map[string]any{"banned": true})

	assert.Equal(t, http.StatusBadRequest, w.Code,
		"non-canonical UUID must not bypass the self-ban guard: %s", w.Body.String())

	user, err := srv.db.GetUser(t.Context(), userID)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.False(t, user.Banned, "self-ban slipped through via a non-canonical UUID spelling")
}
