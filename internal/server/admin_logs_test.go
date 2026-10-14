package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupGetLogsTestServer wires up just enough of the Server to exercise the
// /api/v1/admin/logs handler against a real Postgres. The X-Admin-Token path
// bypasses JWT/org-scoping so the test focuses on the handler's parsing and
// pass-through behaviour.
func setupGetLogsTestServer(t *testing.T) (*Server, *gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = sharedTestDBURL(t)
	} else {
		if err := db.EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("PostgreSQL not available: %v", err)
		}
	}

	database, err := db.New(dbURL)
	require.NoError(t, err)
	require.NoError(t, db.ResetTestDatabase(database))

	jwtService, err := auth.NewJWTService(
		"test-secret",
		"test-refresh-secret",
		30*time.Minute,
		7*24*time.Hour,
	)
	require.NoError(t, err)

	const adminToken = "test-admin-token"
	cfg := &config.Config{ReadProfile: rbac.ReadProfileStandard, AdminAPIToken: adminToken}

	srv := &Server{
		db:             database,
		jwtService:     jwtService,
		rbacAccessCtrl: rbac.NewAccessController(database, 5*time.Minute),
		config:         cfg,
	}
	t.Cleanup(srv.rbacAccessCtrl.Stop)

	router := gin.New()
	admin := router.Group("/api/v1/admin")
	admin.Use(srv.adminAuthMiddleware())
	admin.GET("/logs", srv.getLogs)

	t.Cleanup(func() { srv.db.Close() })
	return srv, router, adminToken
}

// doGetLogs issues a GET /api/v1/admin/logs?<query> with the X-Admin-Token
// header set and returns the recorded response.
func doGetLogs(t *testing.T, router *gin.Engine, token string, query url.Values) *httptest.ResponseRecorder {
	t.Helper()
	target := "/api/v1/admin/logs"
	if encoded := query.Encode(); encoded != "" {
		target += "?" + encoded
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("X-Admin-Token", token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestGetLogsHandler exercises the admin /logs endpoint end-to-end against a
// real Postgres. Each sub-test owns its own seed data; the handler returns
// rows ordered by created_at DESC.
func TestGetLogsHandler(t *testing.T) {
	srv, router, token := setupGetLogsTestServer(t)
	ctx := context.Background()

	// Seed a small catalogue of rows that lets us exercise every filter
	// dimension. Inserts run in order so id and created_at both increase.
	type seedRow struct {
		externalID    string
		method        string
		statusCode    int
		correlationID string
	}
	seed := []seedRow{
		{"did:test:alice", "eth_call", 200, "corr-A"},
		{"did:test:alice", "eth_blockNumber", 200, "corr-B"},
		{"did:test:bob", "eth_call", 401, "corr-A"},
		{"did:test:bob", "eth_call", 200, "corr-C"},
		{"did:test:carol", "eth_getLogs", 500, ""},
		// dave covers extra 4xx codes that the outcome=denied filter must
		// catch alongside the 401. Without these the seed would only have
		// one 4xx row and the bug-fix coverage would be circumstantial.
		{"did:test:dave", "eth_call", 403, ""},
		{"did:test:dave", "eth_sendTransaction", 404, ""},
	}
	insertedIDs := make([]int64, 0, len(seed))
	for _, r := range seed {
		id, _, err := srv.db.LogAccessEnhanced(ctx, r.externalID, r.method, r.statusCode, "127.0.0.1", r.correlationID, nil, nil, "", "")
		require.NoError(t, err)
		insertedIDs = append(insertedIDs, id)
	}

	t.Run("no filters returns default page", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{})
		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Data   []map[string]any `json:"data"`
			Total  int64            `json:"total"`
			Limit  int              `json:"limit"`
			Offset int              `json:"offset"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

		assert.Equal(t, 100, body.Limit, "default limit")
		assert.Equal(t, 0, body.Offset, "default offset")
		assert.Equal(t, int64(len(seed)), body.Total)
		assert.Len(t, body.Data, len(seed))
	})

	t.Run("all filters together pass through to DB layer", func(t *testing.T) {
		// alice + eth_call + corr-A + status_code=200 → exactly one row.
		from := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
		to := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
		q := url.Values{
			"external_id":    []string{"did:test:alice"},
			"method":         []string{"eth_call"},
			"status_code":    []string{"200"},
			"correlation_id": []string{"corr-A"},
			"from":           []string{from},
			"to":             []string{to},
			"limit":          []string{"50"},
			"offset":         []string{"0"},
		}
		rec := doGetLogs(t, router, token, q)
		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Data   []map[string]any `json:"data"`
			Total  int64            `json:"total"`
			Limit  int              `json:"limit"`
			Offset int              `json:"offset"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		require.Len(t, body.Data, 1, "all filters together should narrow to one row")
		assert.Equal(t, "did:test:alice", body.Data[0]["external_id"])
		assert.Equal(t, "eth_call", body.Data[0]["method"])
		assert.EqualValues(t, 200, body.Data[0]["status_code"])
		assert.Equal(t, int64(1), body.Total)
		assert.Equal(t, 50, body.Limit)
		assert.Equal(t, 0, body.Offset)
	})

	t.Run("invalid status_code rejects with 400", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"status_code": []string{"abc"}})
		require.Equal(t, http.StatusBadRequest, rec.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "invalid status_code", body["error"])
	})

	t.Run("non-positive status_code rejects with 400", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"status_code": []string{"0"}})
		require.Equal(t, http.StatusBadRequest, rec.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "invalid status_code", body["error"])
	})

	t.Run("invalid from timestamp rejects with 400", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"from": []string{"not-a-date"}})
		require.Equal(t, http.StatusBadRequest, rec.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "invalid from timestamp; expected RFC3339", body["error"])
	})

	t.Run("invalid to timestamp rejects with 400", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"to": []string{"not-a-date"}})
		require.Equal(t, http.StatusBadRequest, rec.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "invalid to timestamp; expected RFC3339", body["error"])
	})

	t.Run("limit clamped at MaxAccessLogQueryLimit", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"limit": []string{"99999"}})
		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Limit int `json:"limit"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, db.MaxAccessLogQueryLimit, body.Limit, "limit must be clamped")
	})

	t.Run("negative limit falls through to default", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"limit": []string{"-5"}})
		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Limit int `json:"limit"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, 100, body.Limit, "negative limit ignored, default 100 applied")
	})

	t.Run("negative offset defaults to 0", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"offset": []string{"-3"}})
		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Offset int `json:"offset"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, 0, body.Offset, "negative offset ignored, default 0 applied")
	})

	t.Run("each individual filter narrows results correctly", func(t *testing.T) {
		// external_id alone
		rec := doGetLogs(t, router, token, url.Values{"external_id": []string{"did:test:bob"}})
		require.Equal(t, http.StatusOK, rec.Code)
		var body struct {
			Data  []map[string]any `json:"data"`
			Total int64            `json:"total"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, int64(2), body.Total)
		for _, row := range body.Data {
			assert.Equal(t, "did:test:bob", row["external_id"])
		}

		// method alone
		rec = doGetLogs(t, router, token, url.Values{"method": []string{"eth_getLogs"}})
		require.Equal(t, http.StatusOK, rec.Code)
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, int64(1), body.Total)

		// status_code alone
		rec = doGetLogs(t, router, token, url.Values{"status_code": []string{"500"}})
		require.Equal(t, http.StatusOK, rec.Code)
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, int64(1), body.Total)
	})

	// RD-914 — outcome buckets translate to status_code ranges. The bug this
	// guards against was the frontend mapping outcome=denied to a single 403
	// exact match, which missed 401/403/404 mixed rows.
	t.Run("outcome=denied returns every 4xx row regardless of code", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"outcome": []string{"denied"}})
		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Data  []map[string]any `json:"data"`
			Total int64            `json:"total"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		// Seed has 401 (bob), 403 (dave), 404 (dave) — three 4xx rows total.
		assert.Equal(t, int64(3), body.Total, "denied bucket must catch every 4xx, not only 403")
		seenCodes := map[int]bool{}
		for _, row := range body.Data {
			code := int(row["status_code"].(float64))
			seenCodes[code] = true
			assert.GreaterOrEqual(t, code, 400, "denied bucket leaked sub-400 row")
			assert.LessOrEqual(t, code, 499, "denied bucket leaked 5xx row")
		}
		assert.True(t, seenCodes[401] && seenCodes[403] && seenCodes[404], "expected 401, 403, 404 all present, got %v", seenCodes)
	})

	t.Run("outcome=success returns only 2xx rows", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"outcome": []string{"success"}})
		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Data  []map[string]any `json:"data"`
			Total int64            `json:"total"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		// Seed has alice×2 + bob×1 = three 2xx rows.
		assert.Equal(t, int64(3), body.Total)
		for _, row := range body.Data {
			code := int(row["status_code"].(float64))
			assert.GreaterOrEqual(t, code, 200)
			assert.LessOrEqual(t, code, 299)
		}
	})

	t.Run("outcome=error returns only 5xx rows", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"outcome": []string{"error"}})
		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Data  []map[string]any `json:"data"`
			Total int64            `json:"total"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		// Seed has carol/500 — exactly one 5xx row.
		assert.Equal(t, int64(1), body.Total)
		require.Len(t, body.Data, 1)
		assert.EqualValues(t, 500, body.Data[0]["status_code"])
	})

	t.Run("outcome=all behaves as no filter", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"outcome": []string{"all"}})
		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Total int64 `json:"total"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, int64(len(seed)), body.Total)
	})

	t.Run("outcome and status_code together rejected with 400", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{
			"outcome":     []string{"denied"},
			"status_code": []string{"401"},
		})
		require.Equal(t, http.StatusBadRequest, rec.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Contains(t, body["error"], "use status_code OR outcome")
	})

	t.Run("invalid outcome rejects with 400", func(t *testing.T) {
		rec := doGetLogs(t, router, token, url.Values{"outcome": []string{"bogus"}})
		require.Equal(t, http.StatusBadRequest, rec.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Contains(t, body["error"], "invalid outcome")
	})
}

// logsBody is the decoded /logs response shape used by the scoping tests.
type logsBody struct {
	Data  []map[string]any `json:"data"`
	Total int64            `json:"total"`
}

// TestGetLogsOrgScoping is the RD-1135 regression: a tier-2 (JWT) org admin
// must see ONLY their own org(s)' rows, super-admin sees everything (incl.
// unattributed NULL-org rows), and a JWT admin with no orgs sees nothing.
// The pre-fix bug returned the fleet-wide log to any admin.
//
// callerOrgScope reads auth_method + admin_org_ids/admin_readonly_org_ids from
// the gin context (set by adminAuthMiddleware in production). These tests inject
// that context directly so the focus stays on getLogs → callerOrgScope →
// buildAccessLogWhere scoping, not on JWT minting (covered elsewhere).
func TestGetLogsOrgScoping(t *testing.T) {
	srv, _, _ := setupGetLogsTestServer(t)
	ctx := context.Background()

	const orgA = "11111111-1111-1111-1111-111111111111"
	const orgB = "22222222-2222-2222-2222-222222222222"

	seed := []struct {
		ext    string
		method string
		status int
		org    string
	}{
		{"did:a:1", "eth_call", 200, orgA},
		{"did:a:2", "eth_sendTransaction", 200, orgA},
		{"did:b:1", "eth_call", 200, orgB},
		{"did:anon", "eth_blockNumber", 200, ""}, // unattributed → NULL org_id
	}
	for _, r := range seed {
		_, _, err := srv.db.LogAccessEnhanced(ctx, r.ext, r.method, r.status, "127.0.0.1", "", nil, nil, r.org, "")
		require.NoError(t, err)
	}

	// get issues GET /logs with an injected auth context. orgIDs==nil leaves
	// admin_org_ids unset (mirrors a JWT admin with no orgs when authMethod is
	// jwt_admin, or "no scoping" when authMethod is admin_token).
	get := func(authMethod string, setOrgIDs bool, orgIDs []string, query url.Values) logsBody {
		t.Helper()
		r := gin.New()
		r.GET("/api/v1/admin/logs", func(c *gin.Context) {
			c.Set("auth_method", authMethod)
			if setOrgIDs {
				c.Set("admin_org_ids", orgIDs)
			}
			srv.getLogs(c)
		})
		target := "/api/v1/admin/logs"
		if enc := query.Encode(); enc != "" {
			target += "?" + enc
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		require.Equal(t, http.StatusOK, rec.Code)
		var body logsBody
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		return body
	}

	t.Run("jwt admin of orgA sees only orgA rows", func(t *testing.T) {
		body := get("jwt_admin", true, []string{orgA}, url.Values{})
		assert.Equal(t, int64(2), body.Total, "count must be the scoped count, not fleet total")
		require.Len(t, body.Data, 2)
		for _, row := range body.Data {
			assert.Equal(t, orgA, row["org_id"], "leaked a non-orgA row")
		}
	})

	t.Run("jwt admin of orgB sees only orgB rows", func(t *testing.T) {
		body := get("jwt_admin", true, []string{orgB}, url.Values{})
		assert.Equal(t, int64(1), body.Total)
		require.Len(t, body.Data, 1)
		assert.Equal(t, "did:b:1", body.Data[0]["external_id"])
	})

	t.Run("jwt admin with zero orgs sees nothing (fail closed)", func(t *testing.T) {
		body := get("jwt_admin", true, []string{}, url.Values{})
		assert.Equal(t, int64(0), body.Total)
		assert.Empty(t, body.Data)
	})

	t.Run("jwt admin with no admin_org_ids set sees nothing", func(t *testing.T) {
		body := get("jwt_admin", false, nil, url.Values{})
		assert.Equal(t, int64(0), body.Total)
		assert.Empty(t, body.Data)
	})

	t.Run("super-admin sees all rows including NULL-org", func(t *testing.T) {
		body := get("admin_token", false, nil, url.Values{})
		assert.Equal(t, int64(len(seed)), body.Total)
		assert.Len(t, body.Data, len(seed))
	})

	t.Run("external_id filter cannot cross orgs (no enumeration oracle)", func(t *testing.T) {
		// orgA admin asks for orgB's user — org predicate is ANDed, so empty.
		body := get("jwt_admin", true, []string{orgA}, url.Values{"external_id": []string{"did:b:1"}})
		assert.Equal(t, int64(0), body.Total)
		assert.Empty(t, body.Data)
	})

	t.Run("NULL-org rows are invisible to tenant admins", func(t *testing.T) {
		// Neither orgA nor orgB admin should ever see the unattributed row.
		for _, org := range []string{orgA, orgB} {
			body := get("jwt_admin", true, []string{org}, url.Values{"external_id": []string{"did:anon"}})
			assert.Equal(t, int64(0), body.Total, "tenant admin saw an unattributed row")
		}
	})
}

// TestGetLogs_DenialReasonRoundTrip is the RD-1137 Part B regression: a denied
// request's curated reason persists and is returned in the /logs response, and
// a successful request omits it. This is what lets an admin see WHY in the
// Access Logs panel instead of only the status code.
func TestGetLogs_DenialReasonRoundTrip(t *testing.T) {
	srv, router, token := setupGetLogsTestServer(t)
	ctx := context.Background()

	_, _, err := srv.db.LogAccessEnhanced(ctx, "did:dr", "eth_estimateGas", 400, "127.0.0.1", "", nil, nil, "", ReasonSenderNotLinked)
	require.NoError(t, err)
	_, _, err = srv.db.LogAccessEnhanced(ctx, "did:dr", "eth_blockNumber", 200, "127.0.0.1", "", nil, nil, "", "")
	require.NoError(t, err)

	rec := doGetLogs(t, router, token, url.Values{})
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	var sawReason, sawSuccess bool
	for _, r := range body.Data {
		switch r["method"] {
		case "eth_estimateGas":
			assert.Equal(t, ReasonSenderNotLinked, r["denial_reason"], "denied row must carry the curated reason")
			sawReason = true
		case "eth_blockNumber":
			_, has := r["denial_reason"]
			assert.False(t, has, "successful row must omit denial_reason (NULL)")
			sawSuccess = true
		}
	}
	assert.True(t, sawReason, "expected the denied row in the response")
	assert.True(t, sawSuccess, "expected the success row in the response")
}
