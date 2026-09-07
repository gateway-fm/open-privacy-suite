package server

import (
	"context"
	"testing"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"
	"privacy-proxy/internal/tracer"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noopRateLimiter always allows requests.
type noopRateLimiter struct{}

func (n *noopRateLimiter) CheckAndIncrement(string, *int, *int) (bool, string) {
	return true, ""
}
func (n *noopRateLimiter) Stop() {}

// setupProcessorWithoutTracing creates a JSONRPCProcessor with no runtime tracer.
// This simulates a proxy deployment where tracing is disabled.
func setupProcessorWithoutTracing(t *testing.T) (*JSONRPCProcessor, *testServerRBAC) {
	t.Helper()
	ts := setupTestServerForRBAC(t)

	proc := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:     ts.rbacAccessCtrl,
		RateLimiter:        &noopRateLimiter{},
		Proxy:              nil, // no proxy needed for negative path tests
		AccessLogger:       ts.db,
		CircuitBreaker:     middleware.NewCircuitBreaker(),
		ConcurrencyLimiter: middleware.NewConcurrencyLimiter(50, 0),
	})
	return proc, ts
}

// setupProcessorWithTracing creates a JSONRPCProcessor with an enabled runtime tracer.
// The tracer points to an unreachable URL, which is fine because the tests exercise
// paths that fail before reaching the actual trace call.
func setupProcessorWithTracing(t *testing.T) (*JSONRPCProcessor, *testServerRBAC) {
	t.Helper()
	ts := setupTestServerForRBAC(t)

	rt := tracer.NewRuntimeTracer(tracer.RuntimeTracerConfig{
		NodeURL: "http://127.0.0.1:1", // unreachable; tests don't reach the tracer
		Enabled: true,
	})
	t.Cleanup(rt.Stop)

	tv := rbac.NewTraceValidator(ts.db)

	proc := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:     ts.rbacAccessCtrl,
		RateLimiter:        &noopRateLimiter{},
		Proxy:              nil, // no proxy needed
		AccessLogger:       ts.db,
		RuntimeTracer:      rt,
		TraceValidator:     tv,
		CircuitBreaker:     middleware.NewCircuitBreaker(),
		ConcurrencyLimiter: middleware.NewConcurrencyLimiter(50, 0),
	})
	return proc, ts
}

// insertGroupRawSQL inserts a group using raw SQL to avoid dependence on migration 028
// (auto_created column). This allows the tests to run on branches where that migration
// has not yet been applied.
func insertGroupRawSQL(t *testing.T, ctx context.Context, database *db.DB, id, orgID, slug, name, path string) {
	t.Helper()
	_, err := database.Conn().ExecContext(ctx,
		`INSERT INTO groups (id, org_id, slug, name, path, depth, is_org_admin)
		 VALUES ($1, $2, $3, $4, $5, 0, false)`,
		id, orgID, slug, name, path,
	)
	require.NoError(t, err)
}

// createOrgGroupUserMembership creates an org, group, group access, user, and membership
// in one call. Returns the user's external ID. The group gets the specified claims.
// Optional allowedMethods populate the group's method allowlist (default: empty).
func createOrgGroupUserMembership(t *testing.T, ctx context.Context, database *db.DB, claims []rbac.Claim, allowedMethods ...string) string {
	t.Helper()

	orgID := uuid.New().String()
	groupID := uuid.New().String()
	userID := uuid.New().String()
	externalID := "did:privado:test-" + uuid.New().String()

	err := database.CreateOrganization(ctx, &rbac.Organization{
		ID:   orgID,
		Slug: "test-org-" + orgID[:8],
		Name: "Test Org",
	})
	require.NoError(t, err)

	insertGroupRawSQL(t, ctx, database, groupID, orgID,
		"test-group-"+groupID[:8], "Test Group", "test-group-"+groupID[:8])

	methods := allowedMethods
	if methods == nil {
		methods = []string{}
	}
	err = database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        groupID,
		Claims:         claims,
		AllowedMethods: methods,
	})
	require.NoError(t, err)

	err = database.CreateUser(ctx, &rbac.User{
		ID:         userID,
		ExternalID: externalID,
	})
	require.NoError(t, err)

	err = database.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  userID,
		GroupID: groupID,
		Source:  rbac.MembershipSourceAdmin,
	})
	require.NoError(t, err)

	return externalID
}

func TestDebugTrace_DeniedWhenTracingDisabled(t *testing.T) {
	proc, _ := setupProcessorWithoutTracing(t)
	ctx := context.Background()

	req := &ProcessRequest{
		UserID: "did:privado:some-user",
		Method: "debug_traceTransaction",
		Params: []any{"0xabc123"},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error, "expected an error when tracing is disabled")
	assert.Equal(t, 403, result.Error.StatusCode)
	assert.Contains(t, result.Error.Message, "not supported or enabled")
}

func TestDebugTrace_DeniedWhenMethodNotInAllowlist(t *testing.T) {
	// RD-1121: a group that does NOT list debug_traceTransaction in its
	// allowed_methods is denied tracing — even with no claims (and, in the
	// regression test below, even WITH the deploy claim). The deny mirrors the
	// normal RBAC deny site: opaque 404 "method not found", no descriptive text.
	proc, ts := setupProcessorWithTracing(t)
	ctx := context.Background()

	// No claims and empty allowlist.
	externalID := createOrgGroupUserMembership(t, ctx, ts.db, []rbac.Claim{})

	req := &ProcessRequest{
		UserID: externalID,
		Method: "debug_traceTransaction",
		Params: []any{"0xabc123"},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error, "expected a denial when method not in allowlist")
	assert.Equal(t, 404, result.Error.StatusCode)
	assert.Equal(t, "method not found", result.Error.Message)
	// Opaque: must not leak the descriptive trace-gate reasons.
	assert.NotContains(t, result.Error.Message, "deploy")
	assert.NotContains(t, result.Error.Message, "allowlist")
}

// TestDebugTrace_DeniedWithDeployClaimButMethodNotAllowed is the core RD-1121
// regression: a group WITH the deploy claim but WITHOUT debug_traceTransaction
// in its allowed_methods must be denied. Pre-fix this path skipped the allowlist
// entirely and the deploy claim alone granted tracing.
func TestDebugTrace_DeniedWithDeployClaimButMethodNotAllowed(t *testing.T) {
	proc, ts := setupProcessorWithTracing(t)
	ctx := context.Background()

	// Deploy claim, but the allowlist omits the trace method.
	externalID := createOrgGroupUserMembership(t, ctx, ts.db,
		[]rbac.Claim{rbac.ClaimDeploy}, "eth_call", "eth_sendTransaction")

	req := &ProcessRequest{
		UserID: externalID,
		Method: "debug_traceTransaction",
		Params: []any{"0xabc123"},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error, "deploy claim must NOT grant tracing when the method is not allowlisted")
	assert.Equal(t, 404, result.Error.StatusCode)
	assert.Equal(t, "method not found", result.Error.Message)
}

// TestDebugTrace_AllowedByAllowlistWithoutDeployClaim proves the Option B
// decoupling: a group WITHOUT the deploy/admin claim but WITH debug_trace* in
// its allowed_methods passes the allowlist gate and reaches the tracer (the
// cross-org ValidateTrace content gate still applies downstream).
func TestDebugTrace_AllowedByAllowlistWithoutDeployClaim(t *testing.T) {
	proc, ts := setupProcessorWithTracing(t)
	ctx := context.Background()

	// No claims, but debug_traceTransaction IS in the allowlist.
	externalID := createOrgGroupUserMembership(t, ctx, ts.db,
		[]rbac.Claim{}, "debug_traceTransaction")

	req := &ProcessRequest{
		UserID: externalID,
		Method: "debug_traceTransaction",
		Params: []any{"0xdeadbeef"},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error, "expected an error (tracer unreachable)")
	// Passed the allowlist gate; failed only at the (unreachable) tracer. The
	// gate did NOT return the uniform 404 deny.
	assert.NotEqual(t, "method not found", result.Error.Message)
}

func TestDebugTrace_DeniedForUnknownUser(t *testing.T) {
	proc, _ := setupProcessorWithTracing(t)
	ctx := context.Background()

	req := &ProcessRequest{
		UserID: "did:privado:nonexistent-user",
		Method: "debug_traceTransaction",
		Params: []any{"0xabc123"},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error, "expected an error for unknown user")
	assert.Equal(t, 401, result.Error.StatusCode)
	assert.Contains(t, result.Error.Message, "failed to get user")
}

func TestDebugTrace_AllowlistedReachesTracer(t *testing.T) {
	// A group with debug_traceTransaction in its allowed_methods passes the
	// allowlist gate but fails at the tracer level because the tracer points to
	// an unreachable node. (Deploy claim also present — both gates would pass.)
	proc, ts := setupProcessorWithTracing(t)
	ctx := context.Background()

	externalID := createOrgGroupUserMembership(t, ctx, ts.db,
		[]rbac.Claim{rbac.ClaimDeploy}, "debug_traceTransaction")

	req := &ProcessRequest{
		UserID: externalID,
		Method: "debug_traceTransaction",
		Params: []any{"0xdeadbeef"},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error, "expected an error (tracer unreachable)")
	// The error should be from the trace execution, not from the allowlist gate.
	// This proves the gate passed and we reached the tracer.
	assert.NotEqual(t, "method not found", result.Error.Message)
	assert.NotContains(t, result.Error.Message, "not supported or enabled")
}

func TestDebugTrace_WildcardAllowlistReachesTracer(t *testing.T) {
	// A group whose allowlist is "*" (all methods) permits tracing too. Admin
	// claim present, but it's the "*" allowlist entry that grants the method.
	proc, ts := setupProcessorWithTracing(t)
	ctx := context.Background()

	externalID := createOrgGroupUserMembership(t, ctx, ts.db,
		[]rbac.Claim{rbac.ClaimAdmin}, "*")

	req := &ProcessRequest{
		UserID: externalID,
		Method: "debug_traceTransaction",
		Params: []any{"0xdeadbeef"},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error, "expected an error (tracer unreachable)")
	assert.NotEqual(t, "method not found", result.Error.Message)
}

func TestDebugTrace_DebugTraceCallAlsoHandled(t *testing.T) {
	// debug_traceCall goes through the same code path; gated by its own
	// allowlist entry.
	proc, ts := setupProcessorWithTracing(t)
	ctx := context.Background()

	externalID := createOrgGroupUserMembership(t, ctx, ts.db,
		[]rbac.Claim{rbac.ClaimDeploy}, "debug_traceCall")

	req := &ProcessRequest{
		UserID: externalID,
		Method: "debug_traceCall",
		Params: []any{map[string]any{
			"from":  "0x1111111111111111111111111111111111111111",
			"to":    "0x2222222222222222222222222222222222222222",
			"data":  "0x",
			"value": "0x0",
		}},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error, "expected an error (tracer unreachable)")
	// Should pass the allowlist gate for debug_traceCall as well.
	assert.NotEqual(t, "method not found", result.Error.Message)
}

func TestDebugTrace_DebugTraceCallDeniedWhenOnlyTransactionAllowlisted(t *testing.T) {
	// The two trace methods are gated independently. A group that allows only
	// debug_traceTransaction must still be denied debug_traceCall.
	proc, ts := setupProcessorWithTracing(t)
	ctx := context.Background()

	externalID := createOrgGroupUserMembership(t, ctx, ts.db,
		[]rbac.Claim{rbac.ClaimDeploy}, "debug_traceTransaction")

	req := &ProcessRequest{
		UserID: externalID,
		Method: "debug_traceCall",
		Params: []any{map[string]any{
			"to": "0x2222222222222222222222222222222222222222",
		}},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error)
	assert.Equal(t, 404, result.Error.StatusCode)
	assert.Equal(t, "method not found", result.Error.Message)
}

func TestDebugTrace_MissingTxHashReturnsBadRequest(t *testing.T) {
	proc, ts := setupProcessorWithTracing(t)
	ctx := context.Background()

	externalID := createOrgGroupUserMembership(t, ctx, ts.db,
		[]rbac.Claim{rbac.ClaimDeploy}, "debug_traceTransaction")

	req := &ProcessRequest{
		UserID: externalID,
		Method: "debug_traceTransaction",
		Params: []any{}, // empty params
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error)
	assert.Equal(t, 400, result.Error.StatusCode)
	assert.Contains(t, result.Error.Message, "missing transaction hash")
}

func TestDebugTrace_NoMembershipsDenied(t *testing.T) {
	proc, ts := setupProcessorWithTracing(t)
	ctx := context.Background()

	// Create a user with no memberships at all
	userID := uuid.New().String()
	externalID := "did:privado:nomember-" + uuid.New().String()

	require.NoError(t, ts.db.CreateUser(ctx, &rbac.User{
		ID: userID, ExternalID: externalID,
	}))

	req := &ProcessRequest{
		UserID: externalID,
		Method: "debug_traceTransaction",
		Params: []any{"0xabc"},
	}

	result := proc.processDebugTrace(ctx, req)
	require.NotNil(t, result.Error)
	// No memberships means no group allowlists the method — fail-closed deny.
	assert.Equal(t, 404, result.Error.StatusCode)
	assert.Equal(t, "method not found", result.Error.Message)
}
