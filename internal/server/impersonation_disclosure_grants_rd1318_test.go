package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1318 — a disclosure grant belongs to its grantee. A tier-2 admin viewing
// as the grantee (View-as) or dry-running as them must not read through it:
// the grant routes answer the uniform not-found, the viewer's disclosed-address
// list is empty, and visibility resolution ignores the grant. The grantee's own
// session is the positive control throughout.

const (
	rd1318AdminDID   = "did:test:rd1318_admin"
	rd1318GranteeDID = "did:test:rd1318_grantee"
	rd1318SubjectDID = "did:test:rd1318_subject"
	rd1318SubjectEOA = "0x1318000000000000000000000000000000000e01"
	rd1318GranteeEOA = "0x1318000000000000000000000000000000000e02"
	rd1318Peer       = "0x1318000000000000000000000000000000000e03" // the subject's counterparty, unregistered
)

type rd1318Fixture struct {
	srv       *Server
	router    *gin.Engine
	orgID     string
	grantID   string
	addressID string
	txHash    string
}

func setupRD1318Fixture(t *testing.T) *rd1318Fixture {
	t.Helper()
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		_, err := conn.ExecContext(ctx, q, args...)
		require.NoError(t, err)
	}

	orgID := uuid.New().String()
	exec("INSERT INTO organizations (id, slug, name, settings) VALUES ($1, 'rd1318', 'RD1318', '{}')", orgID)
	adminGroup := uuid.New().String()
	exec("INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'admins', 'Admins', 0, 'admins', true)", adminGroup, orgID)
	memberGroup := uuid.New().String()
	exec("INSERT INTO groups (id, org_id, slug, name, depth, path) VALUES ($1, $2, 'members', 'Members', 0, 'members')", memberGroup, orgID)

	addUserToGroup(t, database, createTestUserForExplorer(t, database, rd1318AdminDID), adminGroup)
	granteeUID := createTestUserForExplorer(t, database, rd1318GranteeDID)
	addUserToGroup(t, database, granteeUID, memberGroup)
	// RPC reads (dry-run, the mirror) pass CheckAccess, which requires KYC.
	exec("UPDATE users SET kyc = true WHERE id = $1", granteeUID)
	subjectUID := createTestUserForExplorer(t, database, rd1318SubjectDID)
	addUserToGroup(t, database, subjectUID, memberGroup)
	require.NoError(t, database.SystemLinkEthAddress(ctx, rd1318SubjectDID, rd1318SubjectEOA))
	require.NoError(t, database.SystemLinkEthAddress(ctx, rd1318GranteeDID, rd1318GranteeEOA))

	// The subject approved a Full disclosure (with activity logs) to the grantee.
	reqID := uuid.New().String()
	scope := `{"disclosure_level":"full","methods":["activity_logs"]}`
	exec(`INSERT INTO disclosure_requests (id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, 'rd1318', 'approved', NOW())`, reqID, rd1318GranteeDID, subjectUID, orgID, scope)
	grantID := uuid.New().String()
	exec(`INSERT INTO disclosure_grants (id, request_id, grant_token_hash, scope, granted_at, expires_at)
		VALUES ($1, $2, 'rd1318hash', $3::jsonb, NOW(), $4)`, grantID, reqID, scope, time.Now().Add(24*time.Hour))

	block := seedExplorerBlock(t, conn)
	txHash := "0x1318" + strings.Repeat("0", 60)
	seedExplorerTransaction(t, conn, block, txHash, rd1318SubjectEOA, rd1318Peer)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(c *gin.Context) {
		if sub := c.GetHeader("X-Test-Subject"); sub != "" {
			c.Set("subject", sub) // the grantee's own session
		}
		if c.GetHeader("X-Test-Admin") != "" {
			c.Set("auth_method", "jwt_admin")
			c.Set("admin_subject", rd1318AdminDID)
			c.Set("admin_org_ids", []string{orgID})
		}
		c.Next()
	})
	srv.bindExplorerEndpoints(api.Group("/explorer"))
	srv.registerImpersonationRoutes(api.Group("/admin"))

	return &rd1318Fixture{
		srv: srv, router: router, orgID: orgID, grantID: grantID, txHash: txHash,
		addressID: explorer.GenerateAddressID(rd1318SubjectEOA, grantID),
	}
}

// direct calls an explorer path as the grantee; viewAs calls it through the
// View-as mirror as the admin viewing as the grantee.
func (f *rd1318Fixture) direct(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/explorer"+path, nil)
	req.Header.Set("X-Test-Subject", rd1318GranteeDID)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func (f *rd1318Fixture) viewAs(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, impersonatePath(rd1318GranteeDID, f.orgID, "/api/v1/explorer"+path), nil)
	req.Header.Set("X-Test-Admin", "1")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func TestViewAs_GrantRoutes_DoNotActAsTheGrantee_RD1318(t *testing.T) {
	f := setupRD1318Fixture(t)
	routes := []string{
		"/grant/" + f.grantID + "/resolve/" + f.addressID,
		"/grant/" + f.grantID + "/" + f.addressID + "/transactions",
		"/grant/" + f.grantID + "/activity",
	}
	// Control: the View-as gate admits this admin for this target and org, so
	// the 404s below come from the grant routes, not from the gate.
	require.Equal(t, http.StatusOK, f.viewAs(t, "/viewable-addresses").Code)

	for _, path := range routes {
		t.Run(path, func(t *testing.T) {
			own := f.direct(t, path)
			require.Equal(t, http.StatusOK, own.Code, "control: the grantee uses their own grant: %s", own.Body.String())

			w := f.viewAs(t, path)
			assert.Equal(t, http.StatusNotFound, w.Code, "an admin viewing as the grantee must not use their grant: %s", w.Body.String())
			assert.Contains(t, w.Body.String(), "grant not found")
			assert.NotContains(t, strings.ToLower(w.Body.String()), strings.TrimPrefix(rd1318SubjectEOA, "0x"))
		})
	}

	// The 404 does not depend on the grant existing (no enumeration under View-as).
	existing := f.viewAs(t, "/grant/"+f.grantID+"/activity")
	missing := f.viewAs(t, "/grant/"+uuid.New().String()+"/activity")
	assert.Equal(t, existing.Code, missing.Code)
	assert.Equal(t, existing.Body.String(), missing.Body.String())
}

func TestViewAs_ViewableAddresses_ListNoDisclosedAddresses_RD1318(t *testing.T) {
	f := setupRD1318Fixture(t)
	decode := func(w *httptest.ResponseRecorder) apimodels.ViewableAddressesResponse {
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp apimodels.ViewableAddressesResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		return resp
	}

	own := decode(f.direct(t, "/viewable-addresses"))
	require.Len(t, own.DisclosedAddresses, 1, "control: the grantee sees their disclosed subject")
	require.Equal(t, rd1318SubjectEOA, strings.ToLower(own.DisclosedAddresses[0].Address))

	w := f.viewAs(t, "/viewable-addresses")
	asGrantee := decode(w)
	assert.Empty(t, asGrantee.DisclosedAddresses, "the grant is not the admin's to see")
	assert.NotContains(t, strings.ToLower(w.Body.String()), strings.TrimPrefix(rd1318SubjectEOA, "0x"))
	require.Len(t, asGrantee.OwnAddresses, 1, "the target's own addresses are still their view")
	assert.Equal(t, rd1318GranteeEOA, strings.ToLower(asGrantee.OwnAddresses[0].Address))
}

// The explorer pages under View-as resolve the grantee's visibility without
// the grant: the disclosed subject's transaction is not revealed, and no
// Full-grant reveal is audit-logged in the grantee's name.
func TestViewAs_ExplorerVisibilityIgnoresTheGrant_RD1318(t *testing.T) {
	f := setupRD1318Fixture(t)
	countGrantReveals := func() int {
		var n int
		require.NoError(t, f.srv.db.Conn().QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM rbac_audit_log WHERE resource_type = 'disclosure_grant' AND actor_external_id = $1`,
			rd1318GranteeDID).Scan(&n))
		return n
	}

	own := f.direct(t, "/transactions/"+f.txHash)
	require.Equal(t, http.StatusOK, own.Code, "control: the grantee sees the subject's tx through the grant: %s", own.Body.String())
	require.Contains(t, strings.ToLower(own.Body.String()), strings.TrimPrefix(rd1318SubjectEOA, "0x"))

	// The list endpoint records the Full-grant counterparty reveal (the
	// by-hash audit row does not insert today, a separate issue), so it is the
	// control for "a reveal is audit-logged against the grantee".
	before := countGrantReveals()
	ownList := f.direct(t, "/transactions?limit=25")
	require.Equal(t, http.StatusOK, ownList.Code)
	require.Contains(t, strings.ToLower(ownList.Body.String()), strings.TrimPrefix(rd1318Peer, "0x"), "control: the grant reveals the counterparty")
	revealsByGrantee := countGrantReveals()
	require.Positive(t, revealsByGrantee-before, "control: the grantee's own reveal is audit-logged")

	w := f.viewAs(t, "/transactions/"+f.txHash)
	assert.Equal(t, http.StatusNotFound, w.Code, "without the grant the subject's tx is hidden from the grantee's view: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "transaction not found")
	assert.NotContains(t, strings.ToLower(w.Body.String()), strings.TrimPrefix(rd1318SubjectEOA, "0x"))
	assert.NotContains(t, strings.ToLower(w.Body.String()), strings.TrimPrefix(rd1318Peer, "0x"))

	w = f.viewAs(t, "/transactions?limit=25")
	require.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, strings.ToLower(w.Body.String()), strings.TrimPrefix(rd1318Peer, "0x"))
	assert.Equal(t, revealsByGrantee, countGrantReveals(), "no grant reveal may be recorded in the grantee's name while an admin views as them")

	ownAddr := f.direct(t, "/addresses/"+rd1318SubjectEOA+"/transactions")
	require.Equal(t, http.StatusOK, ownAddr.Code, "control: the grantee opens the subject's page through the grant: %s", ownAddr.Body.String())
	w = f.viewAs(t, "/addresses/"+rd1318SubjectEOA+"/transactions")
	assert.Equal(t, http.StatusNotFound, w.Code, "address page: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "address not found")
	assert.NotContains(t, strings.ToLower(w.Body.String()), strings.TrimPrefix(rd1318Peer, "0x"), "address page: %s", w.Body.String())
}

// The visibility resolver ignores the viewer's grants under the mark the
// impersonation surfaces set — the layer that embedded-address redaction on the
// RPC mirror and the dry-run read through.
func TestDisclosureGrants_SuppressedUnderImpersonationMark_RD1318(t *testing.T) {
	f := setupRD1318Fixture(t)
	ctx := context.Background()
	marked := disclosure.WithoutViewerGrants(ctx)

	vis, err := f.srv.db.GetBatchVisibilityDetailed(ctx, rd1318GranteeDID, []string{rd1318SubjectEOA})
	require.NoError(t, err)
	require.Equal(t, explorer.VisibilityFull, vis[rd1318SubjectEOA].Level, "control: the grant makes the subject Full")

	vis, err = f.srv.db.GetBatchVisibilityDetailed(marked, rd1318GranteeDID, []string{rd1318SubjectEOA})
	require.NoError(t, err)
	assert.Equal(t, explorer.VisibilityHidden, vis[rd1318SubjectEOA].Level)
	plain, err := f.srv.db.GetBatchVisibility(marked, rd1318GranteeDID, []string{rd1318SubjectEOA})
	require.NoError(t, err)
	assert.Equal(t, explorer.VisibilityHidden, plain[rd1318SubjectEOA])

	has, err := f.srv.db.ViewerHasFullDisclosureGrant(ctx, rd1318GranteeDID, rd1318SubjectEOA)
	require.NoError(t, err)
	require.True(t, has, "control")
	has, err = f.srv.db.ViewerHasFullDisclosureGrant(marked, rd1318GranteeDID, rd1318SubjectEOA)
	require.NoError(t, err)
	assert.False(t, has)
}

// The dry-run and the View-as RPC mirror mark their context the same way:
// embedded addresses in a log are redacted as the user would see them WITHOUT
// their disclosure grants, while the user's own call shows the disclosed
// subject.
func TestDryRunAndViewAsRPC_DoNotUseTheUsersDisclosureGrants_RD1318(t *testing.T) {
	f := setupRD1318Fixture(t)
	ctx := context.Background()
	database := f.srv.db

	var memberGroup, granteeUID string
	require.NoError(t, database.Conn().QueryRowContext(ctx,
		`SELECT id FROM groups WHERE org_id = $1 AND slug = 'members'`, f.orgID).Scan(&memberGroup))
	require.NoError(t, database.Conn().QueryRowContext(ctx,
		`SELECT id FROM users WHERE external_id = $1`, rd1318GranteeDID).Scan(&granteeUID))
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: memberGroup, AllowedMethods: []string{rbac.MethodGetLogs},
	}))
	const token = "0x13180000000000000000000000000000000000c1"
	tokenID := wiringCreateContractWithABI(t, database, f.orgID, token, "RD1318 token", erc20ABI)
	const transferT0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	wiringCreateGrant(t, database, tokenID, memberGroup, &rbac.EventRulesField{Rules: []rbac.EventRule{{Topic0: transferT0, Name: "Transfer"}}})

	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": []any{map[string]any{
		"address": token, "topics": []string{transferT0, zeroPadAddrToTopic(rd1318GranteeEOA), zeroPadAddrToTopic(rd1318SubjectEOA)},
		"data": "0x00000000000000000000000000000000000000000000000000000000000003e8", "blockNumber": "0x1",
		"transactionHash": "0x1318" + strings.Repeat("1", 60), "logIndex": "0x0",
	}}})
	require.NoError(t, err)
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(stub.Close)
	f.srv.proxy = proxy.New(stub.URL)
	f.srv.jsonrpcProcessor = NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:            f.srv.rbacAccessCtrl,
		RateLimiter:               &noopRateLimiter{},
		Proxy:                     f.srv.proxy,
		AccessLogger:              database,
		CircuitBreaker:            middleware.NewCircuitBreaker(),
		ConcurrencyLimiter:        middleware.NewConcurrencyLimiter(50, 0),
		TxVisibilityStore:         database,
		AddressVisibilityResolver: database,
	})

	subject := strings.TrimPrefix(rd1318SubjectEOA, "0x")
	params := []any{map[string]any{"address": token, "fromBlock": "0x1", "toBlock": "0x1"}}
	own := f.srv.jsonrpcProcessor.applyResponseFilter(ctx,
		&ProcessRequest{Method: rbac.MethodGetLogs, Params: params, UserID: rd1318GranteeDID},
		&rbac.AccessCheckResult{Allowed: true, UserID: granteeUID, OrgID: f.orgID}, body)
	require.Contains(t, strings.ToLower(string(own)), subject, "control: the grantee's own call shows the disclosed subject")

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_method", "jwt_admin")
		c.Set("admin_subject", rd1318AdminDID)
		c.Next()
	})
	router.POST("/api/orgs/:org_id/dry-run", f.srv.handleDryRun)
	reqBody, err := json.Marshal(map[string]any{"user_did": rd1318GranteeDID, "rpc": map[string]any{"method": rbac.MethodGetLogs, "params": params}})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/orgs/"+f.orgID+"/dry-run", strings.NewReader(string(reqBody)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"allow"`, "the dry-run must be allowed, or the response assertion below proves nothing")
	assert.Contains(t, strings.ToLower(w.Body.String()), strings.TrimPrefix(rd1318GranteeEOA, "0x"), "the log stays admitted")
	assert.NotContains(t, strings.ToLower(w.Body.String()), subject, "the grantee's disclosure grant must not reveal the subject to the admin: %s", w.Body.String())

	// The View-as RPC mirror marks its context the same way.
	rpcBody, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": rbac.MethodGetLogs, "params": params})
	require.NoError(t, err)
	mreq := httptest.NewRequest(http.MethodGet, impersonatePath(rd1318GranteeDID, f.orgID, "/rpc"), strings.NewReader(string(rpcBody)))
	mreq.Header.Set("Content-Type", "application/json")
	mreq.Header.Set("X-Test-Admin", "1")
	mw := httptest.NewRecorder()
	f.router.ServeHTTP(mw, mreq)
	require.Equal(t, http.StatusOK, mw.Code, mw.Body.String())
	assert.Contains(t, strings.ToLower(mw.Body.String()), strings.TrimPrefix(rd1318GranteeEOA, "0x"), "the log stays admitted on the mirror")
	assert.NotContains(t, strings.ToLower(mw.Body.String()), subject, "the mirror must not apply the grantee's grant: %s", mw.Body.String())
}
