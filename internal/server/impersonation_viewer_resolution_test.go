package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1028 — impersonation viewer-resolution consistency for explorer single-item
// handlers.
//
// Under View-as, every explorer handler must resolve the IMPERSONATED viewer
// (the override DID set by impersonationGateMiddleware) — never the
// authenticated admin's "subject", and never the anonymous identity. Before the
// fix, the single-item handlers (token / address detail) used the override-blind
// getViewerIdentity (which reads only "subject"), so:
//   - an admin viewing-as a user with a contract grant got a wrong 404 (the live
//     GUSD/Bob bug), and
//   - the dangerous direction: an admin with BROADER access than the target
//     could have their access bleed into the impersonated view (fail-open).
//
// These tests construct the subject/override split the real middleware creates
// and assert the impersonated viewer governs in BOTH directions. They are the
// regression guard that the redaction matrix tests structurally could not catch
// (those set viewer == subject, so the override-blind path looked correct).

// setupImpersonationViewerRouter mirrors what impersonationGateMiddleware +
// adminAuth set on the real /api/v1/admin/impersonate/.../in/<org>/api/v1/explorer
// tree: an override DID (the impersonated target) and, separately, "subject"
// (the authenticated admin). Driven by request headers for deterministic tests.
func setupImpersonationViewerRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	grp := router.Group("/api/v1/explorer")
	grp.Use(func(c *gin.Context) {
		if sub := c.GetHeader("X-Test-Subject"); sub != "" {
			c.Set("subject", sub)
		}
		if ov := c.GetHeader("X-Test-Override"); ov != "" {
			setImpersonationContext(c, ov, c.GetString("subject"), "")
		}
		c.Next()
	})
	// One handler from each gate family:
	//   getExplorerToken           -> calculateAddressVisibilityWithDID gate
	//   getExplorerAddressTransactions -> addressVisibleOrFullGrant gate
	grp.GET("/tokens/:address", srv.getExplorerToken)
	grp.GET("/addresses/:address/transactions", srv.getExplorerAddressTransactions)
	return router
}

func impViewerGet(t *testing.T, router *gin.Engine, path, subject, override string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if subject != "" {
		req.Header.Set("X-Test-Subject", subject)
	}
	if override != "" {
		req.Header.Set("X-Test-Override", override)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// Repro of the live GUSD/Bob bug: admin views-as a target who has Full access to
// an org contract via a group contract_grant. The single-item handlers must
// serve the TARGET's Full view (200), even though the admin "subject" is a
// non-member of that org. Pre-RD-1028 these returned 404.
func TestImpersonationViewerResolution_ServesImpersonatedViewer_RD1028(t *testing.T) {
	srv, conn := setupTokenTestServer(t)
	router := setupImpersonationViewerRouter(srv)

	addr := "0xcccc00000000000000000000000000000000a028"
	groupID := registerOrgContract(t, srv.db, addr) // 'members' group + empty-claims grant => Full

	targetDID := "did:test:rd1028-target"
	targetUID := createTestUserForExplorer(t, srv.db, targetDID)
	addUserToGroup(t, srv.db, targetUID, groupID) // target is Full via the grant

	adminDID := "did:test:rd1028-admin"
	_ = createTestUserForExplorer(t, srv.db, adminDID) // admin is NOT a member of this org => Redacted

	seedToken(t, conn, addr, "GUSD", "Gateway Stablecoin", "ERC-20")

	// Sanity: target DIRECTLY (subject=target, no override) sees the token.
	w := impViewerGet(t, router, "/api/v1/explorer/tokens/"+addr, targetDID, "")
	require.Equal(t, http.StatusOK, w.Code, "target should see their own org token directly")

	// View-as: override=target (Full), subject=admin (non-member). Must serve the
	// target's Full view, not 404.
	w = impViewerGet(t, router, "/api/v1/explorer/tokens/"+addr, adminDID, targetDID)
	assert.Equal(t, http.StatusOK, w.Code,
		"impersonating a Full-access target must serve the token (impersonated viewer governs the calc gate)")

	w = impViewerGet(t, router, "/api/v1/explorer/addresses/"+addr+"/transactions", adminDID, targetDID)
	assert.Equal(t, http.StatusOK, w.Code,
		"impersonated viewer must govern the addressVisibleOrFullGrant gate too")
}

// Fail-open guard: admin has BROADER access than the target. View-as must show
// the TARGET's (narrower) view — the admin's access must not bleed through.
func TestImpersonationViewerResolution_DoesNotLeakAdminAccess_RD1028(t *testing.T) {
	srv, conn := setupTokenTestServer(t)
	router := setupImpersonationViewerRouter(srv)

	addr := "0xcccc00000000000000000000000000000000a029"
	groupID := registerOrgContract(t, srv.db, addr)

	adminDID := "did:test:rd1028-fullaccess-admin"
	adminUID := createTestUserForExplorer(t, srv.db, adminDID)
	addUserToGroup(t, srv.db, adminUID, groupID) // admin is Full via the grant

	targetDID := "did:test:rd1028-outsider"
	_ = createTestUserForExplorer(t, srv.db, targetDID) // target is NOT a member => Redacted

	seedToken(t, conn, addr, "GUSD", "Gateway Stablecoin", "ERC-20")

	// Sanity: admin DIRECTLY sees the token (Full).
	w := impViewerGet(t, router, "/api/v1/explorer/tokens/"+addr, adminDID, "")
	require.Equal(t, http.StatusOK, w.Code, "admin (Full) sees the token directly")

	// View-as: override=target (Redacted), subject=admin (Full). The single-item
	// endpoint 404s for a Redacted viewer; it must reflect the TARGET's view, not
	// the admin's Full. Pre-RD-1028 the override-blind handler read subject=admin
	// (Full) and returned 200 — leaking the admin's access into the View-as.
	w = impViewerGet(t, router, "/api/v1/explorer/tokens/"+addr, adminDID, targetDID)
	assert.Equal(t, http.StatusNotFound, w.Code,
		"View-as must show the target's (Redacted->404) view; admin's Full access must not bleed through")

	w = impViewerGet(t, router, "/api/v1/explorer/addresses/"+addr+"/transactions", adminDID, targetDID)
	assert.Equal(t, http.StatusNotFound, w.Code,
		"addressVisibleOrFullGrant must use the impersonated target, not the admin subject")
}
