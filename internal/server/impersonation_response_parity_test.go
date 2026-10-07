package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-928 — impersonation response parity.
//
// The whole point of the "View as user" surface is that the body a tier-2
// admin sees while impersonating target T is identical to the body T would
// see calling the same explorer endpoint directly. This invariant is the
// audit-grade promise: nothing in the impersonation chain is silently
// leaking extra data, nor silently filtering more aggressively than what
// the target user themselves can see — with one deliberate exception: the
// target's disclosure grants never apply under impersonation (RD-1318), so
// for a target holding grants the disclosed parts differ (pinned in
// impersonation_disclosure_grants_rd1318_test.go). This fixture holds none.
//
// We assert it against /api/v1/explorer/viewable-addresses because:
//
//   - Its response is a pure function of the viewer DID (it returns the
//     viewer's own linked addresses + disclosed-to-viewer grants). No
//     explorerStore is required, so the test runs against the same
//     testServerRBAC fixture used by the rest of the impersonation tests.
//   - It directly exercises s.getViewerDIDFromRequest, which is the
//     single chokepoint the impersonation override flows through. If the
//     override ever stops being honored (or starts being honored on the
//     wrong side), this test catches it.
//   - The body shape is stable: viewer_did, viewer_wallet, own_addresses,
//     disclosed_addresses. Mutations to any one of those due to the
//     wrong viewer surface as a diff in the test failure.
//
// Test 3 is the encoded parity invariant. Other endpoints that go through
// the visibility-filter / RedactTransactions layer can extend this file as
// they're stood up against the impersonation surface; the structure here
// is the template.

// impersonationParitySetup mounts both the production explorer routes
// (under /api/v1/explorer) AND the impersonation surface (under
// /api/v1/admin/impersonate) on the SAME server. A test pre-middleware
// reads X-Test-* headers and projects them into the gin context keys the
// production code reads: `subject` for the direct path, plus the admin
// gate context for the impersonation path.
//
// We deliberately do NOT use auth.OptionalJWTAuthMiddleware because that
// requires minting and parsing a real JWT. The middleware's only job is
// to set `subject` from a validated token — which we simulate here. The
// production code below the middleware reads `subject` via getViewerDIDFromRequest
// and has no other dependency on the JWT machinery.
type impersonationParityServer struct {
	*testServerRBAC
}

func setupImpersonationParity(t *testing.T) (*impersonationParityServer, *impersonationFixture) {
	t.Helper()
	f := setupImpersonationFixture(t)

	// Rebuild the router so we control the middleware chain end-to-end.
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(c *gin.Context) {
		// Direct-path simulation: set `subject` from header so
		// getViewerDIDFromRequest's JWT branch returns it.
		if sub := c.GetHeader("X-Test-Subject"); sub != "" {
			c.Set("subject", sub)
		}
		// Admin-path simulation: same shape as impersonation_test.go's
		// pre-middleware (admin_subject + admin_org_ids).
		if method := c.GetHeader("X-Test-Auth-Method"); method != "" {
			c.Set("auth_method", method)
			if method == "jwt_admin" {
				c.Set("admin_subject", c.GetHeader("X-Test-Admin-Subject"))
				c.Set("admin_org_ids", splitCSV(c.GetHeader("X-Test-Admin-Org-IDs")))
			}
		}
		c.Next()
	})

	// Production explorer mount (no localhost / no real JWT middleware —
	// the simulated `subject` is the test's hook into getViewerDIDFromRequest).
	explorer := api.Group("/explorer")
	f.srv.Server.bindExplorerEndpoints(explorer)

	// Impersonation mount (full gate + explorer remount).
	admin := api.Group("/admin")
	f.srv.Server.registerImpersonationRoutes(admin)

	f.srv.testServerRBAC.router = router
	return &impersonationParityServer{testServerRBAC: f.srv.testServerRBAC}, f
}

// TestImpersonation_ExplorerResponseParity_ViewableAddresses asserts that
// /api/v1/explorer/viewable-addresses returns byte-identical bodies via:
//
//	(a) direct call as the target user (X-Test-Subject = target DID)
//	(b) admin impersonation of the target user
//
// This is the load-bearing test for the entire "View as user" promise: the
// admin's view of the explorer must be exactly what the target user sees,
// no more (no data leak) and no less (impersonation doesn't filter
// differently from a real session).
//
// Setup gives the target user a linked ETH address (via SystemLinkEthAddress,
// which mirrors the production registration path). The admin has no linked
// addresses; if the override were ignored, the admin path would return an
// empty own_addresses list and the parity check would fail.
func TestImpersonation_ExplorerResponseParity_ViewableAddresses(t *testing.T) {
	srv, f := setupImpersonationParity(t)

	// Link an ETH address to the TARGET user. The admin has no linked
	// addresses — this is the parity differential that proves the
	// override is being honored.
	ctx := context.Background()
	const targetAddr = "0xabcd0000000000000000000000000000000000aa"
	require.NoError(t, srv.db.SystemLinkEthAddress(ctx, f.userDID, targetAddr))

	// Sanity check the fixture: the linked address actually landed.
	links, err := srv.db.GetEthAddressesByDID(ctx, f.userDID)
	require.NoError(t, err)
	require.Len(t, links, 1, "target user should have exactly one linked address from the fixture")

	// Direct path: target user calls /viewable-addresses with their own
	// `subject` set. Routes through getViewerDIDFromRequest → JWT branch.
	directReq := httptest.NewRequest(http.MethodGet, "/api/v1/explorer/viewable-addresses", nil)
	directReq.Header.Set("X-Test-Subject", f.userDID)
	directW := httptest.NewRecorder()
	srv.router.ServeHTTP(directW, directReq)
	require.Equal(t, http.StatusOK, directW.Code, "direct path: %s", directW.Body.String())

	// Impersonation path: admin calls the same endpoint under the
	// /admin/impersonate prefix. Routes through impersonationGateMiddleware
	// → sets viewerDIDOverrideContextKey → getViewerDIDFromRequest
	// reads the override.
	impReq := httptest.NewRequest(http.MethodGet,
		impersonatePath(f.userDID, f.orgID, "/api/v1/explorer/viewable-addresses"), nil)
	impReq.Header.Set("X-Test-Auth-Method", "jwt_admin")
	impReq.Header.Set("X-Test-Admin-Subject", f.adminDID)
	impReq.Header.Set("X-Test-Admin-Org-IDs", f.orgID)
	impW := httptest.NewRecorder()
	srv.router.ServeHTTP(impW, impReq)
	require.Equal(t, http.StatusOK, impW.Code, "impersonation path: %s", impW.Body.String())

	// Parity assertion: same bytes. If the override is ignored or the
	// admin's identity bleeds through, this diverges (admin has no linked
	// addresses, so own_addresses would be []).
	var directBody, impBody map[string]any
	require.NoError(t, json.Unmarshal(directW.Body.Bytes(), &directBody))
	require.NoError(t, json.Unmarshal(impW.Body.Bytes(), &impBody))
	assert.Equal(t, directBody, impBody,
		"impersonation response must match the target user's direct view; "+
			"direct=%s impersonation=%s", directW.Body.String(), impW.Body.String())

	// Spot-check the load-bearing field: viewer_did must be the TARGET's,
	// not the admin's. (Belt + braces against a future change that
	// happens to keep total-body equality while leaking the admin DID
	// somewhere — unlikely, but the explicit check is cheap.)
	assert.Equal(t, f.userDID, impBody["viewer_did"], "viewer_did must be the target's DID under impersonation")

	// And the own_addresses list reflects the TARGET's link, not the
	// admin's empty set.
	ownAddrs, _ := impBody["own_addresses"].([]any)
	require.Len(t, ownAddrs, 1, "expected exactly one linked address (the target's)")
	first, _ := ownAddrs[0].(map[string]any)
	assert.Equal(t, targetAddr, first["address"], "address in own_addresses must be the target's link")
}

// TestImpersonation_ExplorerResponseParity_AdminPathDoesNotLeakAdminIdentity
// is the failure-mode counterpart: if a tier-2 admin calls
// /viewable-addresses WITHOUT the impersonation prefix (i.e. as themselves),
// they should see THEIR OWN linked addresses (empty here), NOT the target's.
// Pairs with the parity test above to bound the override's scope: it must
// take effect on /admin/impersonate/* and only there.
func TestImpersonation_ExplorerResponseParity_AdminPathDoesNotLeakAdminIdentity(t *testing.T) {
	srv, f := setupImpersonationParity(t)
	ctx := context.Background()
	const targetAddr = "0xabcd0000000000000000000000000000000000aa"
	require.NoError(t, srv.db.SystemLinkEthAddress(ctx, f.userDID, targetAddr))

	// Admin calls /viewable-addresses directly as themselves. No override
	// set, no admin gate, just the production explorer route + simulated
	// `subject`.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/explorer/viewable-addresses", nil)
	req.Header.Set("X-Test-Subject", f.adminDID)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "direct admin path: %s", w.Body.String())

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, f.adminDID, body["viewer_did"], "non-impersonation direct call must return the caller's DID")
	ownAddrs, _ := body["own_addresses"].([]any)
	assert.Empty(t, ownAddrs, "admin has no linked addresses; non-impersonation own_addresses must be empty")
}
