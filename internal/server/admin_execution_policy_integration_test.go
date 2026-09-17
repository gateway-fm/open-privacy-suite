package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/policydsl"
	"privacy-proxy/internal/rbac"
)

// HTTP and database integration tests for the execution-policy admin API
// (RD-1287). Boots Postgres, runs migrations, mounts the real routes, and
// exercises the whole lifecycle: read the editing context, submit a candidate,
// review the artifact, simulate against it, activate, and supersede.
//
// These go through the router rather than calling handlers directly, because
// the parts most likely to be wrong are the ones only the real path exercises:
// route registration, binding, the operator-token gate and the status codes.

const (
	epTestVaultABI = `[{"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable"},` +
		`{"type":"function","name":"balanceOf","inputs":[{"name":"owner","type":"address"}],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"}]`

	epSelTransfer = "0xa9059cbb"
)

type testServerExecutionPolicy struct {
	*Server
	router *gin.Engine
	orgID  string
	group  string
	// vault is unique per test: contract addresses are globally unique, so a
	// shared fixture address would make these tests collide with each other.
	vault string
}

func setupTestServerForExecutionPolicy(t *testing.T) *testServerExecutionPolicy {
	t.Helper()

	// The compiler is required, not optional: an execution-policy test that
	// silently skipped compilation would exercise none of what makes this
	// feature work.
	compiler := policydsl.NewCompiler()
	if err := compiler.Available(context.Background()); err != nil {
		t.Fatalf("the pinned Solidity compiler is required: %v\nInstall solc %s, or point POLICY_SOLC at it.", err, policydsl.SolidityVersion)
	}

	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = sharedTestDBURL(t)
	} else if err := db.EnsureTestDatabase(dbURL); err != nil {
		t.Fatalf("PostgreSQL not available: %v", err)
	}

	database, err := db.New(dbURL)
	require.NoError(t, err)
	require.NoError(t, database.Migrate(context.Background()))
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()
	conn := database.Conn()
	_, _ = conn.ExecContext(ctx, "DELETE FROM execution_policy_revisions")

	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: fmt.Sprintf("ep-test-%d", time.Now().UnixNano()),
		Name: "Execution policy test org",
	}
	require.NoError(t, database.CreateOrganization(ctx, org))

	group := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: org.ID,
		Slug:  "traders",
		Name:  "traders",
		Path:  "traders",
	}
	require.NoError(t, database.CreateGroup(ctx, group))

	vault := common.BytesToAddress(uuid.New().NodeID()).Hex()
	contract := &rbac.Contract{
		ID:      uuid.New().String(),
		OrgID:   org.ID,
		Address: vault,
		Name:    "Vault",
		ABI:     epTestVaultABI,
	}
	require.NoError(t, database.CreateContract(ctx, contract))

	cfg := &config.Config{NodeURL: "http://localhost:8545", BaseURL: "http://localhost:8080"}
	jwtSvc, err := auth.NewJWTService("test-secret", "test-refresh", 30*time.Minute, 24*time.Hour)
	require.NoError(t, err)
	rbacCtrl := rbac.NewAccessController(database, 5*time.Minute)
	t.Cleanup(rbacCtrl.Stop)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Handler lifecycle fixtures carry real user attribution. Dedicated auth
	// tests below exercise production JWT/scoping middleware independently.
	author, reviewer := uuid.NewString(), uuid.NewString()
	for _, id := range []string{author, reviewer} {
		require.NoError(t, database.CreateUser(ctx, &rbac.User{ID: id, ExternalID: "did:test:" + id}))
	}
	router.Use(func(c *gin.Context) {
		actor := author
		if strings.HasSuffix(c.FullPath(), "/activate") {
			actor = reviewer
		}
		c.Set("admin_user_id", actor)
		c.Set("admin_principal_kind", auth.PrincipalHuman)
	})

	srv := &Server{
		db:             database,
		config:         cfg,
		jwtService:     jwtSvc,
		rbacAccessCtrl: rbacCtrl,
		policyCompiler: compiler,
	}
	srv.registerRBACRoutes(router.Group("/api/v1/admin"))

	return &testServerExecutionPolicy{Server: srv, router: router, orgID: org.ID, group: group.ID, vault: strings.ToLower(vault)}
}

func (s *testServerExecutionPolicy) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec
}

func (s *testServerExecutionPolicy) base() string {
	return "/api/v1/admin/orgs/" + s.orgID + "/execution-policy"
}

// epPolicy builds a candidate restricting transfers to the signer.
func (s *testServerExecutionPolicy) epPolicy(t *testing.T, maxAmount string) map[string]any {
	t.Helper()
	return map[string]any{
		"apiVersion":  policydsl.APIVersion,
		"kind":        policydsl.Kind,
		"org":         s.orgID,
		"nestedCalls": policydsl.NestedCallsRequireOwnRule,
		"bindings": []map[string]any{{
			"group": s.group,
			"allow": []map[string]any{{
				"storageAddress": s.vault,
				"selector":       epSelTransfer,
				"abiDigest":      policydsl.ABIDigest(epTestVaultABI),
				"args": []map[string]any{
					{"index": 0, "addressEquals": map[string]any{"source": "signer"}},
					{"index": 1, "uintAtMost": maxAmount},
				},
			}},
		}},
	}
}

func epTransferCalldata(t *testing.T, to common.Address, amount int64) string {
	t.Helper()
	parsed, err := abi.JSON(strings.NewReader(epTestVaultABI))
	require.NoError(t, err)
	data, err := parsed.Pack("transfer", to, big.NewInt(amount))
	require.NoError(t, err)
	return "0x" + common.Bytes2Hex(data)
}

// TestExecutionPolicy_Lifecycle walks the whole feature over HTTP.
func TestExecutionPolicy_Lifecycle(t *testing.T) {
	s := setupTestServerForExecutionPolicy(t)
	signer := common.HexToAddress("0xAAAA000000000000000000000000000000000001")
	stranger := common.HexToAddress("0xCCCC000000000000000000000000000000000003")

	// The editing context reports what a candidate may name.
	rec := s.do(t, http.MethodGet, s.base()+"/context", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var context struct {
		BaseRevision int64  `json:"base_revision"`
		APIVersion   string `json:"api_version"`
		Groups       []string
		Contracts    []struct {
			Address   string `json:"address"`
			HasABI    bool   `json:"has_abi"`
			ABIDigest string `json:"abi_digest"`
		}
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &context))
	require.Equal(t, int64(0), context.BaseRevision, "an organisation with no policy starts at revision zero")
	require.Equal(t, policydsl.APIVersion, context.APIVersion)
	require.Contains(t, context.Groups, s.group)
	require.Len(t, context.Contracts, 1)
	require.True(t, context.Contracts[0].HasABI)
	require.Equal(t, policydsl.ABIDigest(epTestVaultABI), context.Contracts[0].ABIDigest)

	// Submitting compiles the candidate and stores a draft.
	rec = s.do(t, http.MethodPost, s.base()+"/revisions", map[string]any{
		"policy":        s.epPolicy(t, "100"),
		"base_revision": 0,
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var draft struct {
		ID              string `json:"id"`
		Revision        int64  `json:"revision"`
		Status          string `json:"status"`
		RuntimeDigest   string `json:"runtime_digest"`
		SoliditySource  string `json:"solidity_source"`
		RuntimeBytecode string `json:"runtime_bytecode"`
		Compiler        struct {
			Version    string `json:"version"`
			EVMVersion string `json:"evm_version"`
		} `json:"compiler"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &draft))
	require.Equal(t, "draft", draft.Status)
	require.Equal(t, int64(1), draft.Revision)
	require.NotEmpty(t, draft.RuntimeDigest)
	require.Contains(t, draft.SoliditySource, "DO NOT EDIT")
	require.True(t, strings.HasPrefix(draft.RuntimeBytecode, "0x"))
	require.Greater(t, len(draft.RuntimeBytecode), 2, "the draft must carry real compiled bytecode")
	require.True(t, strings.HasPrefix(draft.Compiler.Version, policydsl.SolidityVersion+"+"),
		"the artifact must record the pinned compiler it was built with")

	// A draft enforces nothing yet, but it can be simulated. That is the point
	// of the two-step lifecycle: a reviewer sees what it would do first.
	simulate := func(revisionID string, to common.Address, amount int64) (allowed, agreed bool, code string) {
		t.Helper()
		rec := s.do(t, http.MethodPost, s.base()+"/revisions/"+revisionID+"/simulate", map[string]any{
			"groups": []string{s.group},
			"signer": signer.Hex(),
			"frames": []map[string]any{{
				"call_type":       "call",
				"storage_address": s.vault,
				"calldata":        epTransferCalldata(t, to, amount),
			}},
		})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		var out struct {
			Allowed         bool   `json:"allowed"`
			Code            string `json:"code"`
			CompiledAllowed bool   `json:"compiled_allowed"`
			Agreed          bool   `json:"agreed"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
		require.Equal(t, out.Allowed, out.CompiledAllowed,
			"the reference evaluator and the compiled artifact must reach the same decision")
		return out.Allowed, out.Agreed, out.Code
	}

	allowed, agreed, _ := simulate(draft.ID, signer, 50)
	require.True(t, allowed, "a transfer to the signer within the bound should be permitted")
	require.True(t, agreed)

	allowed, agreed, code := simulate(draft.ID, signer, 500)
	require.False(t, allowed, "a transfer above the bound must be denied")
	require.True(t, agreed)
	require.Equal(t, "argument_constraint", code)

	allowed, agreed, code = simulate(draft.ID, stranger, 1)
	require.False(t, allowed, "a transfer to someone other than the signer must be denied")
	require.True(t, agreed)
	require.Equal(t, "argument_constraint", code)

	// Activating puts it in force.
	rec = s.do(t, http.MethodPost, s.base()+"/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var active struct {
		Status      string `json:"status"`
		ActivatedAt string `json:"activated_at"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &active))
	require.Equal(t, "active", active.Status)
	require.NotEmpty(t, active.ActivatedAt)

	// Activating the same revision twice is a conflict, not a silent success.
	rec = s.do(t, http.MethodPost, s.base()+"/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())

	// The context now reports the active policy and a moved base revision.
	rec = s.do(t, http.MethodGet, s.base()+"/context", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var afterContext struct {
		BaseRevision int64 `json:"base_revision"`
		Active       *struct {
			Revision int64  `json:"revision"`
			Status   string `json:"status"`
		} `json:"active"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &afterContext))
	require.Equal(t, int64(1), afterContext.BaseRevision)
	require.NotNil(t, afterContext.Active)
	require.Equal(t, int64(1), afterContext.Active.Revision)

	// A second revision supersedes the first, and only one stays active.
	rec = s.do(t, http.MethodPost, s.base()+"/revisions", map[string]any{
		"policy":        s.epPolicy(t, "10"),
		"base_revision": 1,
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var second struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &second))
	require.Equal(t, int64(2), second.Revision)

	rec = s.do(t, http.MethodPost, s.base()+"/revisions/"+second.ID+"/activate", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = s.do(t, http.MethodGet, s.base()+"/revisions", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var listed []struct {
		Revision int64  `json:"revision"`
		Status   string `json:"status"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &listed))
	require.Len(t, listed, 2)

	activeCount := 0
	for _, r := range listed {
		if r.Status == "active" {
			activeCount++
		}
	}
	require.Equal(t, 1, activeCount, "exactly one revision may be in force")

	// The tighter bound is now the one enforced.
	allowed, _, _ = simulate(second.ID, signer, 50)
	require.False(t, allowed, "the newly activated revision lowered the bound to 10")
}

// TestExecutionPolicy_RejectsInvalidCandidates checks that a bad document is
// refused with an explanation, and never stored.
func TestExecutionPolicy_RejectsInvalidCandidates(t *testing.T) {
	s := setupTestServerForExecutionPolicy(t)

	cases := []struct {
		name    string
		mutate  func(p map[string]any)
		wantErr string
	}{
		{
			name:    "unknown group",
			mutate:  func(p map[string]any) { p["bindings"].([]map[string]any)[0]["group"] = "grp_nope" },
			wantErr: "group",
		},
		{
			name: "contract that is not registered",
			mutate: func(p map[string]any) {
				rule := p["bindings"].([]map[string]any)[0]["allow"].([]map[string]any)[0]
				rule["storageAddress"] = "0x2222222222222222222222222222222222222222"
			},
			wantErr: "storageAddress",
		},
		{
			name: "selector that is not in the ABI",
			mutate: func(p map[string]any) {
				rule := p["bindings"].([]map[string]any)[0]["allow"].([]map[string]any)[0]
				rule["selector"] = "0xdeadbeef"
			},
			wantErr: "selector",
		},
		{
			name: "stale ABI digest",
			mutate: func(p map[string]any) {
				rule := p["bindings"].([]map[string]any)[0]["allow"].([]map[string]any)[0]
				rule["abiDigest"] = strings.Repeat("00", 32)
			},
			wantErr: "abiDigest",
		},
		{
			name:    "another organisation's identifier",
			mutate:  func(p map[string]any) { p["org"] = "00000000-0000-0000-0000-0000000000ff" },
			wantErr: "org",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := s.epPolicy(t, "100")
			tc.mutate(policy)

			rec := s.do(t, http.MethodPost, s.base()+"/revisions", map[string]any{
				"policy": policy, "base_revision": 0,
			})
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			require.Contains(t, strings.ToLower(rec.Body.String()), strings.ToLower(tc.wantErr),
				"the error must name the field at fault")

			listed := s.do(t, http.MethodGet, s.base()+"/revisions", nil)
			require.Equal(t, http.StatusOK, listed.Code)
			require.Equal(t, "[]", strings.TrimSpace(listed.Body.String()),
				"a rejected candidate must not be stored")
		})
	}
}

// TestExecutionPolicy_StaleBaseIsRefused proves two administrators cannot
// silently overwrite each other.
func TestExecutionPolicy_StaleBaseIsRefused(t *testing.T) {
	s := setupTestServerForExecutionPolicy(t)

	rec := s.do(t, http.MethodPost, s.base()+"/revisions", map[string]any{
		"policy": s.epPolicy(t, "100"), "base_revision": 0,
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var draft struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &draft))
	rec = s.do(t, http.MethodPost, s.base()+"/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// A second author still believes active revision zero is current.
	rec = s.do(t, http.MethodPost, s.base()+"/revisions", map[string]any{
		"policy": s.epPolicy(t, "5"), "base_revision": 0,
	})
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	require.Contains(t, strings.ToLower(rec.Body.String()), "stale")
}

// TestExecutionPolicy_OperatorTokenRejected pins the denial path: the
// restricted operator token may not manage per-tenant policy.
func TestExecutionPolicy_OperatorTokenRejected(t *testing.T) {
	s := setupTestServerForExecutionPolicy(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_method", "operator_token")
		c.Next()
	})
	s.Server.registerRBACRoutes(router.Group("/api/v1/admin"))

	for _, path := range []string{
		s.base() + "/context",
		s.base() + "/revisions",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusForbidden, rec.Code, "operator token must be refused on %s", path)
	}

	req := httptest.NewRequest(http.MethodPost, s.base()+"/revisions", bytes.NewReader([]byte(`{"policy":{},"base_revision":0}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code, "operator token must not submit a policy")
}

// TestExecutionPolicy_WithdrawOnlyAffectsDrafts keeps the record of what was
// enforced intact.
func TestExecutionPolicy_WithdrawOnlyAffectsDrafts(t *testing.T) {
	s := setupTestServerForExecutionPolicy(t)

	rec := s.do(t, http.MethodPost, s.base()+"/revisions", map[string]any{
		"policy": s.epPolicy(t, "100"), "base_revision": 0,
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	var draft struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &draft))

	rec = s.do(t, http.MethodPost, s.base()+"/revisions/"+draft.ID+"/withdraw", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Withdrawing it twice finds no draft.
	rec = s.do(t, http.MethodPost, s.base()+"/revisions/"+draft.ID+"/withdraw", nil)
	require.Equal(t, http.StatusNotFound, rec.Code)

	// And an activated revision cannot be withdrawn at all.
	rec = s.do(t, http.MethodPost, s.base()+"/revisions", map[string]any{
		"policy": s.epPolicy(t, "42"), "base_revision": 0,
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var second struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &second))

	rec = s.do(t, http.MethodPost, s.base()+"/revisions/"+second.ID+"/activate", nil)
	require.Equal(t, http.StatusOK, rec.Code)

	rec = s.do(t, http.MethodPost, s.base()+"/revisions/"+second.ID+"/withdraw", nil)
	require.Equal(t, http.StatusNotFound, rec.Code, "an activated revision is part of the record and stays")
}

// TestExecutionPolicy_CrossOrgIsolation checks a revision cannot be reached
// through another organisation's path.
func TestExecutionPolicy_CrossOrgIsolation(t *testing.T) {
	s := setupTestServerForExecutionPolicy(t)
	ctx := context.Background()

	other := &rbac.Organization{ID: uuid.New().String(), Slug: fmt.Sprintf("ep-other-%d", time.Now().UnixNano()), Name: "Other"}
	require.NoError(t, s.db.CreateOrganization(ctx, other))

	rec := s.do(t, http.MethodPost, s.base()+"/revisions", map[string]any{
		"policy": s.epPolicy(t, "100"), "base_revision": 0,
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var draft struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &draft))

	otherBase := "/api/v1/admin/orgs/" + other.ID + "/execution-policy"

	for _, path := range []string{
		otherBase + "/revisions/" + draft.ID,
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusNotFound, rec.Code,
			"a revision must not be reachable through another organisation's path")
	}

	for _, path := range []string{
		otherBase + "/revisions/" + draft.ID + "/activate",
		otherBase + "/revisions/" + draft.ID + "/withdraw",
	} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusNotFound, rec.Code,
			"a revision must not be mutable through another organisation's path")
	}
}

// TestExecutionPolicy_ActivationRechecksTheCurrentCatalog proves a draft cannot
// be put in force after the contracts it describes have changed underneath it.
func TestExecutionPolicy_ActivationRechecksTheCurrentCatalog(t *testing.T) {
	s := setupTestServerForExecutionPolicy(t)
	ctx := context.Background()

	rec := s.do(t, http.MethodPost, s.base()+"/revisions", map[string]any{
		"policy": s.epPolicy(t, "100"), "base_revision": 0,
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var draft struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &draft))

	// Replace the ABI the draft's rules were written against. The stored rule
	// still pins the old digest, so it no longer describes this contract.
	contract, err := s.db.GetContractByAddress(ctx, s.orgID, s.vault)
	require.NoError(t, err)
	require.NotNil(t, contract)
	newABI := `[{"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"}],"outputs":[],"stateMutability":"nonpayable"}]`
	require.NoError(t, s.db.UpdateContractABI(ctx, contract.ID, newABI))

	rec = s.do(t, http.MethodPost, s.base()+"/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	require.Contains(t, strings.ToLower(rec.Body.String()), "no longer validates")

	// And simulating it says the same thing rather than answering from a policy
	// that no longer matches the contracts.
	rec = s.do(t, http.MethodPost, s.base()+"/revisions/"+draft.ID+"/simulate", map[string]any{
		"groups": []string{s.group},
		"frames": []map[string]any{{
			"call_type":       "call",
			"storage_address": s.vault,
			"calldata":        epSelTransfer + strings.Repeat("0", 128),
		}},
	})
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
}

func TestExecutionPolicy_AuthenticatedReviewBoundary(t *testing.T) {
	s := setupTestServerForExecutionPolicy(t)
	s.config.AdminAPIToken = "bootstrap-test-token"
	router := gin.New()
	s.registerRBACRoutes(router.Group("/api/v1/admin", s.adminAuthMiddleware(), s.orgScopingMiddleware()))
	ctx := t.Context()
	principal := func(readonly bool, kind auth.PrincipalKind) string {
		id := uuid.NewString()
		group := &rbac.Group{ID: uuid.NewString(), OrgID: s.orgID, Slug: "review-" + id, Name: "Reviewer " + id, Path: "review-" + id,
			IsOrgAdmin: !readonly, IsOrgReadonlyAdmin: readonly}
		require.NoError(t, s.db.CreateGroup(ctx, group))
		user := &rbac.User{ID: id, ExternalID: "did:test:" + id}
		require.NoError(t, s.db.CreateUser(ctx, user))
		require.NoError(t, s.db.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.NewString(), UserID: id, GroupID: group.ID, Source: rbac.MembershipSourceAdmin}))
		token, err := s.jwtService.IssueAccessTokenForPrincipal(user.ExternalID, true, kind, nil)
		require.NoError(t, err)
		return token
	}
	readonly, admin, otherAdmin := principal(true, auth.PrincipalHuman), principal(false, auth.PrincipalHuman), principal(false, auth.PrincipalHuman)
	service, legacy := principal(false, auth.PrincipalService), principal(false, "")
	request := func(token, path string, body any) *httptest.ResponseRecorder {
		return orgAdminGateReq(t, router, http.MethodPost, path, token, "", mustJSON(t, body))
	}
	payload := map[string]any{"policy": s.epPolicy(t, "100"), "base_revision": 0}
	missingBase := request(admin, s.base()+"/revisions", map[string]any{"policy": s.epPolicy(t, "100")})
	require.Equal(t, http.StatusBadRequest, missingBase.Code, "the base must be explicitly supplied even for first activation")
	bootstrap := orgAdminGateReq(t, router, http.MethodPost, s.base()+"/revisions", "", s.config.AdminAPIToken, mustJSON(t, payload))
	require.Equal(t, http.StatusForbidden, bootstrap.Code, "shared bootstrap token is not an accountable document author")
	for _, author := range []string{readonly, admin} {
		rec := request(author, s.base()+"/revisions", payload)
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		var draft struct {
			ID        string `json:"id"`
			CreatedBy string `json:"created_by"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &draft))
		require.NotEmpty(t, draft.CreatedBy)
		rec = request(author, s.base()+"/revisions/"+draft.ID+"/activate", nil)
		require.Equal(t, http.StatusForbidden, rec.Code, "read-only and same-author activation are both denied")
		if author == readonly {
			signer := common.HexToAddress("0x1111111111111111111111111111111111111111")
			rec = request(readonly, s.base()+"/revisions/"+draft.ID+"/simulate", map[string]any{
				"groups": []string{s.group}, "signer": signer.Hex(), "frames": []map[string]any{{
					"call_type": "call", "storage_address": s.vault, "calldata": epTransferCalldata(t, signer, 1),
				}},
			})
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		} else {
			for _, token := range []string{service, legacy} {
				rec = request(token, s.base()+"/revisions/"+draft.ID+"/activate", nil)
				require.Equal(t, http.StatusForbidden, rec.Code, "service and legacy tokens cannot approve as a human")
			}
			rec = request(otherAdmin, s.base()+"/revisions/"+draft.ID+"/activate", nil)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		}
	}
	rec := request(readonly, "/api/v1/admin/orgs/"+s.orgID+"/memberships/by-did", map[string]any{})
	require.Equal(t, http.StatusForbidden, rec.Code)
}
