package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// policyCheckTestServer mirrors dryRunTestServer (admin_dry_run_test.go):
// a tiny test-mode middleware injects the auth context fields the production
// adminAuthMiddleware would set, so tests drive handlePolicyCheck's OWN gates
// without re-testing gin auth itself (covered in admin_auth_test.go).
//
// Header set by tests:
//   - X-Test-Auth-Method: "jwt_admin" | "admin_token" | "operator_token" | ""
type policyCheckTestServer struct {
	*testServerRBAC
}

type policyCheckDenyingRateLimiter struct{}

func (policyCheckDenyingRateLimiter) CheckAndIncrement(string, *int, *int) (bool, string) {
	return false, "rate limit exceeded"
}

func (policyCheckDenyingRateLimiter) Stop() {}

func setupPolicyCheckTestServer(t *testing.T) *policyCheckTestServer {
	t.Helper()
	ts := setupTestServerForRBAC(t)

	router := gin.New()
	api := router.Group("/api")
	api.Use(func(c *gin.Context) {
		method := c.GetHeader("X-Test-Auth-Method")
		if method != "" {
			c.Set("auth_method", method)
		}
		c.Next()
	})
	api.POST("/policy-check", ts.handlePolicyCheck)

	ts.router = router
	node := newPolicyTraceNode(t, "")
	ts.proxy = proxy.New(node.URL)
	return &policyCheckTestServer{testServerRBAC: ts}
}

func newPolicyTraceNode(t *testing.T, nestedTarget string) *httptest.Server {
	t.Helper()
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Params) == 0 {
			http.Error(w, "invalid trace request", http.StatusBadRequest)
			return
		}
		var tx map[string]any
		if err := json.Unmarshal(req.Params[0], &tx); err != nil {
			http.Error(w, "invalid transaction object", http.StatusBadRequest)
			return
		}
		from, _ := tx["from"].(string)
		to, _ := tx["to"].(string)
		if from == "" {
			from = "0x0000000000000000000000000000000000000000"
		}
		frame := map[string]any{"type": "CALL", "from": from, "to": to}
		if to == "" {
			frame["type"] = "CREATE"
			delete(frame, "to")
		}
		if nestedTarget != "" {
			frame["calls"] = []map[string]any{{"type": "STATICCALL", "from": to, "to": nestedTarget}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  frame,
		})
	}))
	t.Cleanup(node.Close)
	return node
}

func policyCheckPost(t *testing.T, srv *policyCheckTestServer, authMethod string, body any) *httptest.ResponseRecorder {
	t.Helper()
	jb, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/policy-check", bytes.NewReader(jb))
	req.Header.Set("Content-Type", "application/json")
	if authMethod != "" {
		req.Header.Set("X-Test-Auth-Method", authMethod)
	}
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	return w
}

// pcFixture is a two-org fixture:
//
//	orgA: participant group (grant on acContractAddr: balanceOf(self) via a
//	      function-level param rule, the exact shape RD-435 regressed on),
//	      one user in it with a linked address, one address linked to TWO
//	      DIDs (collision), one address linked to none (via a revoked-only
//	      link, indistinguishable from never having been linked).
//	orgB: a second org the participant user is ALSO a member of, and a
//	      second, unrelated org+contract for cross-org isolation checks.
//	orgC: a third org with one user and no grant.
type pcFixture struct {
	srv              *policyCheckTestServer
	db               *db.DB
	orgA             string
	orgB             string
	orgC             string
	group            string // orgA participant group, granted on contractAddr
	userDID          string
	userAddr         string // linked to userDID
	collisionAddr    string // linked to userDID AND otherDID
	otherDID         string
	unlinkedAddr     string // never linked
	revokedOnlyAddr  string // linked once, then revoked
	contractAddr     string
	orgBContractAddr string
	bankCUserDID     string
}

const (
	pcBalanceOfABI      = `[{"name":"balanceOf","type":"function","inputs":[{"name":"owner","type":"address"}],"outputs":[{"name":"","type":"uint256"}]}]`
	pcBalanceOfSelector = "0x70a08231"
)

func setupPCFixture(t *testing.T) *pcFixture {
	t.Helper()
	srv := setupPolicyCheckTestServer(t)
	ctx := context.Background()
	database := srv.db

	orgA := uuid.New().String()
	orgB := uuid.New().String()
	orgC := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgA, Slug: "pc-a", Name: "PC A", Settings: map[string]any{}}))
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgB, Slug: "pc-b", Name: "PC B", Settings: map[string]any{}}))
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgC, Slug: "pc-c", Name: "PC C", Settings: map[string]any{}}))

	group := drCreateGroup(t, database, orgA, "pc-participant", nil, false)
	userDID := "did:pc:user"
	userID := drCreateUserInGroup(t, database, userDID, group)

	contractAddr := "0xAC000000000000000000000000000000000000a1"
	contractID := drCreateContract(t, database, orgA, contractAddr, "ACContract")
	require.NoError(t, database.UpdateContractABI(ctx, contractID, pcBalanceOfABI))
	require.NoError(t, database.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID: uuid.New().String(), ContractID: contractID, GroupID: group,
		Functions: []rbac.FunctionRule{{
			Selector:   pcBalanceOfSelector,
			ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}},
		}},
	}))

	userAddr := "0x000000000000000000000000000000000000ac01"
	require.NoError(t, database.SystemLinkEthAddress(ctx, userDID, userAddr))

	otherDID := "did:pc:other"
	otherGroup := drCreateGroup(t, database, orgB, "pc-other", nil, false)
	drCreateUserInGroup(t, database, otherDID, otherGroup)

	collisionAddr := "0x000000000000000000000000000000000000ac02"
	require.NoError(t, database.SystemLinkEthAddress(ctx, userDID, collisionAddr))
	require.NoError(t, database.SystemLinkEthAddress(ctx, otherDID, collisionAddr))

	revokedOnlyAddr := "0x000000000000000000000000000000000000ac03"
	require.NoError(t, database.SystemLinkEthAddress(ctx, userDID, revokedOnlyAddr))
	require.NoError(t, database.RevokeEthAddressLink(ctx, userDID, revokedOnlyAddr))

	// orgB contract, so orgA's user (once added to orgB below where needed)
	// can hit a genuinely different org's contract for cross-org checks.
	orgBContractAddr := "0xAC000000000000000000000000000000000000b1"
	drCreateContract(t, database, orgB, orgBContractAddr, "ACOrgBContract")

	bankCGroup := drCreateGroup(t, database, orgC, "pc-bankc", nil, false)
	bankCUserDID := "did:pc:bankc"
	drCreateUserInGroup(t, database, bankCUserDID, bankCGroup)

	_ = userID

	return &pcFixture{
		srv:              srv,
		db:               srv.db,
		orgA:             orgA,
		orgB:             orgB,
		orgC:             orgC,
		group:            group,
		userDID:          userDID,
		userAddr:         userAddr,
		collisionAddr:    collisionAddr,
		otherDID:         otherDID,
		unlinkedAddr:     "0x000000000000000000000000000000000000ac99",
		revokedOnlyAddr:  revokedOnlyAddr,
		contractAddr:     contractAddr,
		orgBContractAddr: orgBContractAddr,
		bankCUserDID:     bankCUserDID,
	}
}

func pcBalanceOfCallOp(contract, argAddr string) map[string]any {
	return map[string]any{
		"method": "eth_call",
		"params": []any{
			map[string]any{
				"to":   contract,
				"data": pcBalanceOfSelector + "000000000000000000000000" + strings.TrimPrefix(argAddr, "0x"),
			},
			"latest",
		},
	}
}

func decodePolicyCheckResponse(t *testing.T, w *httptest.ResponseRecorder) policyCheckResponse {
	t.Helper()
	var resp policyCheckResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp), "body: %s", w.Body.String())
	return resp
}

// ---------------------------------------------------------------- auth -----

func TestPolicyCheck_RejectsUnauthenticated(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	w := policyCheckPost(t, f.srv, "" /* no credential */, body)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPolicyCheck_RejectsJWTAdmin(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	w := policyCheckPost(t, f.srv, "jwt_admin", body)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "service credential")
}

func TestPolicyCheck_AcceptsAdminToken(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	w := policyCheckPost(t, f.srv, "admin_token", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.True(t, decodePolicyCheckResponse(t, w).Allowed)
}

func TestPolicyCheck_RejectsUnlinkedSender(t *testing.T) {
	f := setupPCFixture(t)
	op := pcBalanceOfCallOp(f.contractAddr, f.userAddr)
	op["params"].([]any)[0].(map[string]any)["from"] = f.unlinkedAddr
	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject": map[string]any{"did": f.userDID}, "operation": op,
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.False(t, resp.Allowed)
	assert.Equal(t, ReasonSenderNotLinked, resp.Reason)
}

func TestPolicyCheck_UsesConcurrencyLimit(t *testing.T) {
	f := setupPCFixture(t)
	limiter := NewConcurrencyLimiter(1, 1)
	require.True(t, limiter.TryAcquire(policyCheckLimiterKey))
	defer limiter.Release(policyCheckLimiterKey)
	f.srv.jsonrpcProcessor = &JSONRPCProcessor{concurrencyLimiter: limiter}

	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.False(t, resp.Allowed)
	assert.Equal(t, ReasonConcurrencyLimited, resp.Reason)
}

func TestPolicyCheck_UsesTraceRateLimit(t *testing.T) {
	f := setupPCFixture(t)
	f.srv.jsonrpcProcessor = &JSONRPCProcessor{rateLimiter: policyCheckDenyingRateLimiter{}}
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}

	w := policyCheckPost(t, f.srv, "admin_token", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.False(t, resp.Allowed)
	assert.Equal(t, ReasonRateLimited, resp.Reason)
}

// policyCheckPostRaw posts a raw body, for cases a marshalled struct cannot
// express (e.g. trailing content after the JSON object).
func policyCheckPostRaw(t *testing.T, srv *policyCheckTestServer, authMethod, raw string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/policy-check", bytes.NewReader([]byte(raw)))
	req.Header.Set("Content-Type", "application/json")
	if authMethod != "" {
		req.Header.Set("X-Test-Auth-Method", authMethod)
	}
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	return w
}

func TestPolicyCheck_RejectsTrailingJSON(t *testing.T) {
	f := setupPCFixture(t)
	valid := `{"subject":{"did":"` + f.userDID + `"},"operation":{"method":"eth_call","params":[{"to":"` + f.contractAddr + `","data":"0x70a08231"},"latest"]}}`
	w := policyCheckPostRaw(t, f.srv, "admin_token", valid+`{"unexpected":true}`)
	assert.Equal(t, http.StatusBadRequest, w.Code, "trailing JSON must be rejected; body: %s", w.Body.String())
}

func TestPolicyCheck_MalformedCallParamsReturn400(t *testing.T) {
	f := setupPCFixture(t)
	// eth_call with a non-object first param is a caller error, not a 500.
	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": map[string]any{"method": "eth_call", "params": []any{"not-an-object"}},
	})
	assert.Equal(t, http.StatusBadRequest, w.Code, "malformed params must return 400; body: %s", w.Body.String())
}

func TestPolicyCheck_RejectsOperatorToken(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	w := policyCheckPost(t, f.srv, "operator_token", body)
	require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "tenant data")
}

func TestPolicyCheck_RejectsDebugTraceMethods(t *testing.T) {
	f := setupPCFixture(t)
	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject": map[string]any{"did": f.userDID},
		"operation": map[string]any{
			"method": "debug_traceCall",
			"params": []any{map[string]any{"to": f.contractAddr}},
		},
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.False(t, resp.Allowed)
	assert.Equal(t, "method_not_allowed", resp.Reason)

	var subjectDID string
	require.NoError(t, f.db.Conn().QueryRowContext(context.Background(), `
		SELECT subject_did FROM policy_check_log
		 WHERE method = 'debug_traceCall' ORDER BY created_at DESC LIMIT 1`).Scan(&subjectDID))
	assert.Equal(t, f.userDID, subjectDID)
}

// ------------------------------------------------------------- body ----

func TestPolicyCheck_RejectsInvalidJSON(t *testing.T) {
	f := setupPCFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/api/policy-check", bytes.NewReader([]byte("{not json")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Auth-Method", "admin_token")
	w := httptest.NewRecorder()
	f.srv.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPolicyCheck_RejectsMissingOperationMethod(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": map[string]any{"params": []any{}},
	}
	w := policyCheckPost(t, f.srv, "admin_token", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPolicyCheck_RejectsSubjectWithBothFields(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID, "address": f.userAddr},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	w := policyCheckPost(t, f.srv, "admin_token", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "exactly one of did or address")
}

func TestPolicyCheck_RejectsSubjectWithNeitherField(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	w := policyCheckPost(t, f.srv, "admin_token", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "exactly one of did or address")
}

func TestPolicyCheck_RejectsMalformedAddressSubject(t *testing.T) {
	f := setupPCFixture(t)
	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject":   map[string]any{"address": "not-an-ethereum-address"},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "valid Ethereum address")

	var count int
	require.NoError(t, f.db.Conn().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM policy_check_log`).Scan(&count))
	assert.Zero(t, count)
}

// -------------------------------------------------------------- subject ---

func TestPolicyCheck_UnknownDIDDenied(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": "did:pc:nobody"},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	w := policyCheckPost(t, f.srv, "admin_token", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.False(t, resp.Allowed)
	assert.NotEmpty(t, resp.Reason)
}

// TestPolicyCheck_AddressSubjectResolvesAndMatchesDID verifies that an address
// subject gets the same decision as its linked DID. The self-referencing rule
// also verifies that the database supplies the identity link.
func TestPolicyCheck_AddressSubjectResolvesAndMatchesDID(t *testing.T) {
	f := setupPCFixture(t)

	byDID := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	byAddr := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject":   map[string]any{"address": f.userAddr},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	require.Equal(t, http.StatusOK, byDID.Code)
	require.Equal(t, http.StatusOK, byAddr.Code, "body: %s", byAddr.Body.String())
	assert.Equal(t, decodePolicyCheckResponse(t, byDID), decodePolicyCheckResponse(t, byAddr))
	assert.True(t, decodePolicyCheckResponse(t, byAddr).Allowed)
}

func TestPolicyCheck_AddressSubjectCaseInsensitive(t *testing.T) {
	f := setupPCFixture(t)
	mixedCase := "0x" + strings.ToUpper(strings.TrimPrefix(f.userAddr, "0x"))
	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject":   map[string]any{"address": mixedCase},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.True(t, decodePolicyCheckResponse(t, w).Allowed)
}

func TestPolicyCheck_UnlinkedAddressDenied(t *testing.T) {
	f := setupPCFixture(t)
	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject":   map[string]any{"address": f.unlinkedAddr},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.unlinkedAddr),
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.False(t, resp.Allowed)
	assert.Equal(t, "denied", resp.Reason)
}

// TestPolicyCheck_RevokedLinkOnlyDenied: a link that was revoked must behave
// identically to never having been linked. GetDIDsByEthAddress already
// filters revoked=false, so this pins that the ENDPOINT doesn't accidentally
// bypass that filter (e.g. via a different, unfiltered lookup path).
func TestPolicyCheck_RevokedLinkOnlyDenied(t *testing.T) {
	f := setupPCFixture(t)
	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject":   map[string]any{"address": f.revokedOnlyAddr},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.revokedOnlyAddr),
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.False(t, resp.Allowed)
	assert.Equal(t, "denied", resp.Reason)
}

// TestPolicyCheck_CollisionAddressRefusesToChoose is the central subject-
// resolution guard: an address claimed by two DIDs must be refused, never
// resolved to either one by tie-break order. GetDIDByEthAddress (singular,
// used elsewhere for UI convenience lookups) explicitly picks a winner via
// ORDER BY ... LIMIT 1; this endpoint uses the plural GetDIDsByEthAddress and
// must never collapse to that behaviour.
func TestPolicyCheck_CollisionAddressRefusesToChoose(t *testing.T) {
	f := setupPCFixture(t)
	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject":   map[string]any{"address": f.collisionAddr},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.collisionAddr),
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.False(t, resp.Allowed)
	assert.Equal(t, "denied", resp.Reason)

	// Neither colliding DID appears in the audit row: resolution never got far
	// enough to pick one.
	var subjectDID *string
	require.NoError(t, f.srv.db.Conn().QueryRowContext(context.Background(), `
		SELECT subject_did FROM policy_check_log
		 WHERE subject_address = $1 ORDER BY created_at DESC LIMIT 1`,
		f.collisionAddr,
	).Scan(&subjectDID))
	assert.Nil(t, subjectDID)
}

// ------------------------------------------------------------------ org ---

func TestPolicyCheck_OrgOmittedDerivedFromRegisteredTarget(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
		// org_id omitted entirely.
	}
	w := policyCheckPost(t, f.srv, "admin_token", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.True(t, decodePolicyCheckResponse(t, w).Allowed)
}

// TestPolicyCheck_OrgOmittedMultiOrgSubjectDenied: the subject belongs to two
// orgs and the operation targets an unregistered address, so nothing
// disambiguates which org's rules to evaluate. CheckAccess denies with the
// RD-877 org-cardinality message; this pins that the wire response collapses
// it to "denied" rather than leaking that a subject has multiple memberships.
func TestPolicyCheck_OrgOmittedMultiOrgSubjectDenied(t *testing.T) {
	f := setupPCFixture(t)
	ctx := context.Background()

	// Make the fixture's user ALSO a member of orgB, via a second group.
	secondGroup := drCreateGroup(t, f.srv.db, f.orgB, "pc-second", nil, false)
	require.NoError(t, f.srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: mustUserIDByDID(t, f.srv.db, f.userDID), GroupID: secondGroup,
		Source: rbac.MembershipSourceAdmin,
	}))

	body := map[string]any{
		"subject": map[string]any{"did": f.userDID},
		"operation": map[string]any{
			"method": "eth_call",
			"params": []any{map[string]any{"to": "0x0000000000000000000000000000000000feed01", "data": "0x"}, "latest"},
		},
	}
	w := policyCheckPost(t, f.srv, "admin_token", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.False(t, resp.Allowed)
	assert.Equal(t, "denied", resp.Reason, "org cardinality must not leak verbatim onto the wire")

	// The audit row keeps the informative reason: it is operator-only.
	var auditReason string
	require.NoError(t, f.srv.db.Conn().QueryRowContext(ctx, `
		SELECT reason FROM policy_check_log
		 WHERE subject_did = $1 AND allowed = false ORDER BY created_at DESC LIMIT 1`,
		f.userDID,
	).Scan(&auditReason))
	assert.Contains(t, auditReason, "multiple organizations")
}

func TestPolicyCheck_ExplicitOrgIDCrossOrgTargetDenied(t *testing.T) {
	f := setupPCFixture(t)
	ctx := context.Background()
	// Make the user a member of orgB too, so the ONLY reason for denial is
	// that orgBContractAddr belongs to orgB while org_id names orgA.
	secondGroup := drCreateGroup(t, f.srv.db, f.orgB, "pc-second-b", nil, false)
	require.NoError(t, f.srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: mustUserIDByDID(t, f.srv.db, f.userDID), GroupID: secondGroup,
		Source: rbac.MembershipSourceAdmin,
	}))

	body := map[string]any{
		"subject": map[string]any{"did": f.userDID},
		"operation": map[string]any{
			"method": "eth_call",
			"params": []any{map[string]any{"to": f.orgBContractAddr, "data": "0x"}, "latest"},
		},
		"org_id": f.orgA,
	}
	w := policyCheckPost(t, f.srv, "admin_token", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.False(t, decodePolicyCheckResponse(t, w).Allowed)
}

func TestPolicyCheck_ExplicitOrgIDSubjectNotMemberDenied(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject": map[string]any{"did": f.userDID}, // only a member of orgA
		"operation": map[string]any{
			"method": "eth_call",
			"params": []any{map[string]any{"to": f.orgBContractAddr, "data": "0x"}, "latest"},
		},
		"org_id": f.orgB,
	}
	w := policyCheckPost(t, f.srv, "admin_token", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.False(t, decodePolicyCheckResponse(t, w).Allowed)
}

func TestPolicyCheck_ExplicitOrgIDUnknownDenied(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
		"org_id":    uuid.New().String(), // does not exist
	}
	w := policyCheckPost(t, f.srv, "admin_token", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.False(t, decodePolicyCheckResponse(t, w).Allowed)
}

func TestPolicyCheck_ThirdPartyNoGrantAnywhereDenied(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.bankCUserDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	w := policyCheckPost(t, f.srv, "admin_token", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.False(t, decodePolicyCheckResponse(t, w).Allowed)
}

// ------------------------------------------------------------ operation ---

// TestPolicyCheck_FunctionLevelRulesMatchEnforcement is the RD-435 regression,
// ported to this endpoint. It exists here (not just in admin_dry_run_test.go)
// because handlePolicyCheck has its own handler-level path: if a future change
// stopped it calling dryRunAccessRequest, this catches the same class of bug.
func TestPolicyCheck_FunctionLevelRulesMatchEnforcement(t *testing.T) {
	f := setupPCFixture(t)
	otherAddr := "0x000000000000000000000000000000000000ac77"

	tests := []struct {
		name      string
		argAddr   string
		wantAllow bool
	}{
		{"own balance", f.userAddr, true},
		{"another address", otherAddr, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
				"subject":   map[string]any{"did": f.userDID},
				"operation": pcBalanceOfCallOp(f.contractAddr, tc.argAddr),
			})
			require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
			resp := decodePolicyCheckResponse(t, w)
			assert.Equal(t, tc.wantAllow, resp.Allowed)
			if !tc.wantAllow {
				assert.NotEmpty(t, resp.Reason)
				assert.NotContains(t, resp.Reason, "function selector required",
					"pre-#435 symptom: a param-rule deny must not be reported as a missing selector")
			}
		})
	}
}

func TestPolicyCheck_ChecksummedTargetNormalized(t *testing.T) {
	f := setupPCFixture(t)
	checksummed := "0x" + strings.ToUpper(strings.TrimPrefix(f.contractAddr, "0x")[:1]) + strings.TrimPrefix(f.contractAddr, "0x")[1:]
	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(checksummed, f.userAddr),
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.True(t, decodePolicyCheckResponse(t, w).Allowed)
}

func TestPolicyCheck_ReadTraceDeniesNestedForeignCall(t *testing.T) {
	f := setupPCFixture(t)
	node := newPolicyTraceNode(t, f.orgBContractAddr)
	f.srv.proxy = proxy.New(node.URL)

	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"org_id":    f.orgA,
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.False(t, resp.Allowed)
	assert.Equal(t, "denied", resp.Reason)
}

func TestPolicyCheck_WriteTraceDeniesNestedForeignCall(t *testing.T) {
	f := setupPCFixture(t)
	ctx := context.Background()

	groupID := uuid.New().String()
	require.NoError(t, f.db.CreateGroup(ctx, &rbac.Group{
		ID: groupID, OrgID: f.orgA, Slug: "pc-writer", Name: "pc-writer", Depth: 0, Path: "pc-writer",
	}))
	require.NoError(t, f.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, AllowedMethods: []string{"eth_sendTransaction"},
	}))
	writerDID := "did:pc:writer"
	drCreateUserInGroup(t, f.db, writerDID, groupID)
	writerAddr := "0x000000000000000000000000000000000000ac52"
	require.NoError(t, f.db.SystemLinkEthAddress(ctx, writerDID, writerAddr))
	target := "0x000000000000000000000000000000000000ac51"
	drCreateGrant(t, f.db, drCreateContract(t, f.db, f.orgA, target, "PCWriterTarget"), groupID)

	node := newPolicyTraceNode(t, f.orgBContractAddr)
	f.srv.proxy = proxy.New(node.URL)
	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject": map[string]any{"did": writerDID},
		"org_id":  f.orgA,
		"operation": map[string]any{
			"method": "eth_sendTransaction",
			"params": []any{map[string]any{
				"from": writerAddr,
				"to":   target, "data": "0x12345678", "value": "0x0",
			}},
		},
	})

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.False(t, resp.Allowed)
	assert.Equal(t, "denied", resp.Reason)
}

func TestPolicyCheck_WriteRunsCompliancePreview(t *testing.T) {
	f := setupPCFixture(t)
	ctx := context.Background()
	groupID := uuid.New().String()
	require.NoError(t, f.db.CreateGroup(ctx, &rbac.Group{
		ID: groupID, OrgID: f.orgA, Slug: "pc-compliance", Name: "pc-compliance", Depth: 0, Path: "pc-compliance",
	}))
	require.NoError(t, f.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, AllowedMethods: []string{"eth_sendTransaction"},
	}))
	did := "did:pc:compliance"
	drCreateUserInGroup(t, f.db, did, groupID)
	from := "0x000000000000000000000000000000000000ac61"
	to := "0x000000000000000000000000000000000000ac62"
	require.NoError(t, f.db.SystemLinkEthAddress(ctx, did, from))
	drCreateGrant(t, f.db, drCreateContract(t, f.db, f.orgA, to, "PCComplianceTarget"), groupID)
	require.NoError(t, f.db.UpsertComplianceConfig(ctx, &compliance.ComplianceConfig{
		ID: uuid.New().String(), OrgID: f.orgA, Enabled: true, ThresholdFiat: 1000,
	}))
	require.NoError(t, f.db.UpsertTokenPrice(ctx, &compliance.TokenPrice{
		ID: uuid.New().String(), OrgID: f.orgA, TokenAddress: "native", Symbol: "ETH",
		Decimals: 18, PriceFiat: 1000, PricesByCurrency: map[string]float64{"usd": 1000},
	}, "usd"))
	f.srv.complianceChecker = compliance.NewChecker(f.db, 24*time.Hour, 15*time.Minute)

	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject": map[string]any{"did": did},
		"org_id":  f.orgA,
		"operation": map[string]any{
			"method": "eth_sendTransaction",
			"params": []any{map[string]any{"from": from, "to": to, "value": "0x1bc16d674ec80000"}},
		},
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.False(t, resp.Allowed)
	assert.Equal(t, "compliance", resp.Reason)

	var logs int
	require.NoError(t, f.db.Conn().QueryRowContext(ctx, `SELECT COUNT(*) FROM compliance_logs WHERE org_id = $1`, f.orgA).Scan(&logs))
	assert.Zero(t, logs)
}

func TestPolicyCheck_TraceUnavailableFailsClosed(t *testing.T) {
	f := setupPCFixture(t)
	ctx := context.Background()
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"error":   map[string]any{"code": -32601, "message": "method not found"},
		})
	}))
	t.Cleanup(node.Close)
	f.srv.proxy = proxy.New(node.URL)

	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"org_id":    f.orgA,
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.False(t, resp.Allowed)
	assert.Equal(t, "upstream_error", resp.Reason)

	var reason string
	require.NoError(t, f.db.Conn().QueryRowContext(ctx, `
		SELECT reason FROM policy_check_log
		 WHERE subject_did = $1 ORDER BY created_at DESC LIMIT 1`, f.userDID).Scan(&reason))
	assert.Equal(t, "upstream_error", reason)
}

func TestPolicyCheck_TraceUsesResolvedUpstreamCredential(t *testing.T) {
	f := setupPCFixture(t)
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "policy-check-key", r.Header.Get("X-RPC-Key"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]any{"type": "CALL", "from": f.userAddr, "to": f.contractAddr},
		})
	}))
	t.Cleanup(node.Close)
	f.srv.proxy = proxy.New(node.URL)
	f.srv.jsonrpcProcessor = &JSONRPCProcessor{
		defaultRPCAPIKey:       "policy-check-key",
		defaultRPCAPIKeyHeader: "X-RPC-Key",
	}

	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.True(t, decodePolicyCheckResponse(t, w).Allowed)
}

func TestValidatePolicyCheckVisibleTo(t *testing.T) {
	validContractCall := dryRunRPCBlock{
		Method: "eth_sendTransaction",
		Params: []any{map[string]any{
			"to": "0x000000000000000000000000000000000000ac51", "data": "0x12345678",
		}},
	}

	t.Run("rejects more than 32 recipients", func(t *testing.T) {
		op := validContractCall
		entries := make([]any, visibleToMaxSize+1)
		for i := range entries {
			entries[i] = fmt.Sprintf("did:example:recipient-%d", i)
		}
		op.Params[0].(map[string]any)["visibleTo"] = entries
		reason, err := validatePolicyCheckVisibleTo(op)
		require.NoError(t, err)
		assert.Equal(t, ReasonInvalidRequestShape, reason)
	})

	t.Run("rejects plain value transfers", func(t *testing.T) {
		op := dryRunRPCBlock{Method: "eth_sendTransaction", Params: []any{map[string]any{
			"to": "0x000000000000000000000000000000000000ac51", "value": "0x1", "visibleTo": []any{"did:example:recipient"},
		}}}
		reason, err := validatePolicyCheckVisibleTo(op)
		require.NoError(t, err)
		assert.Equal(t, ReasonInvalidRequestShape, reason)
	})

	t.Run("deduplicates valid recipients before the cap", func(t *testing.T) {
		op := validContractCall
		entries := make([]any, visibleToMaxSize+1)
		for i := range entries {
			entries[i] = "did:example:recipient"
		}
		op.Params[0].(map[string]any)["visibleTo"] = entries
		reason, err := validatePolicyCheckVisibleTo(op)
		require.NoError(t, err)
		assert.Empty(t, reason)
	})
}

// TestPolicyCheck_DeploymentRequiresClaim: a tx with no `to` is a deployment,
// gated on the deploy claim regardless of method allowlist.
func TestPolicyCheck_DeploymentRequiresClaim(t *testing.T) {
	f := setupPCFixture(t)
	ctx := context.Background()

	// Not drCreateGroup: it creates its own GroupAccess row, and group_access
	// has UNIQUE(group_id), so a second CreateGroupAccess is a duplicate-key
	// error rather than an update. Build the group directly instead.
	deployGroup := uuid.New().String()
	require.NoError(t, f.srv.db.CreateGroup(ctx, &rbac.Group{
		ID: deployGroup, OrgID: f.orgA, Slug: "pc-deployer", Name: "pc-deployer", Depth: 0, Path: "pc-deployer",
	}))
	require.NoError(t, f.srv.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: deployGroup, AllowedMethods: []string{"eth_sendTransaction"}, Claims: []rbac.Claim{rbac.ClaimDeploy},
	}))
	deployerDID := "did:pc:deployer"
	drCreateUserInGroup(t, f.srv.db, deployerDID, deployGroup)

	deployOp := map[string]any{
		"method": "eth_sendTransaction",
		"params": []any{map[string]any{"data": "0x600a600055"}},
	}

	t.Run("no deploy claim, denied", func(t *testing.T) {
		w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
			"subject":   map[string]any{"did": f.userDID}, // orgA participant, no deploy claim
			"operation": deployOp,
		})
		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
		assert.False(t, decodePolicyCheckResponse(t, w).Allowed)
	})

	t.Run("deploy claim, allowed", func(t *testing.T) {
		w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
			"subject":   map[string]any{"did": deployerDID},
			"operation": deployOp,
		})
		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
		assert.True(t, decodePolicyCheckResponse(t, w).Allowed)
	})
}

// TestPolicyCheck_RawSendTransactionMatchesEnforcement verifies that
// eth_sendRawTransaction uses the decoded target for access control.
func TestPolicyCheck_RawSendTransactionMatchesEnforcement(t *testing.T) {
	f := setupPCFixture(t)
	ctx := context.Background()

	// Not drCreateGroup; see TestPolicyCheck_DeploymentRequiresClaim.
	senderGroup := uuid.New().String()
	require.NoError(t, f.srv.db.CreateGroup(ctx, &rbac.Group{
		ID: senderGroup, OrgID: f.orgA, Slug: "pc-sender", Name: "pc-sender", Depth: 0, Path: "pc-sender",
	}))
	require.NoError(t, f.srv.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: senderGroup, AllowedMethods: []string{"eth_sendTransaction"},
	}))
	senderDID := "did:pc:sender"
	drCreateUserInGroup(t, f.srv.db, senderDID, senderGroup)

	grantedAddr := "0x000000000000000000000000000000000000ac41"
	ungrantedAddr := "0x000000000000000000000000000000000000ac42"
	drCreateGrant(t, f.srv.db, drCreateContract(t, f.srv.db, f.orgA, grantedAddr, "ACGranted"), senderGroup)
	drCreateContract(t, f.srv.db, f.orgA, ungrantedAddr, "ACUngranted")

	tests := []struct {
		name      string
		to        string
		wantAllow bool
	}{
		{"granted contract", grantedAddr, true},
		{"contract the group has no grant on", ungrantedAddr, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			to := common.HexToAddress(tc.to)
			rawTx, sender := pcSignedRawTx(t, &to, []byte{0xab, 0xcd, 0xab, 0xcd})
			require.NoError(t, f.srv.db.SystemLinkEthAddress(ctx, senderDID, sender))
			w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
				"subject": map[string]any{"did": senderDID},
				"operation": map[string]any{
					"method": "eth_sendRawTransaction",
					"params": []any{rawTx},
				},
			})
			require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
			assert.Equal(t, tc.wantAllow, decodePolicyCheckResponse(t, w).Allowed)
		})
	}
}

func TestPolicyCheck_MalformedRawTransactionBadRequestAndAudited(t *testing.T) {
	f := setupPCFixture(t)
	op := map[string]any{
		"method": "eth_sendRawTransaction",
		"params": []any{"0xnotrealhex"},
	}
	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": op,
	})
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid operation")

	var reason string
	require.NoError(t, f.srv.db.Conn().QueryRowContext(context.Background(), `
		SELECT reason FROM policy_check_log
		 WHERE subject_did = $1 AND method = 'eth_sendRawTransaction' ORDER BY created_at DESC LIMIT 1`,
		f.userDID,
	).Scan(&reason))
	assert.Equal(t, "decode_error", reason)
}

// TestPolicyCheck_AuditWriteFailureIsFailClosed mirrors
// TestDryRun_RawSendTransactionMalformedAudit's "audit write failure is fail
// closed" case, adapted to this table's allowed BOOLEAN column: a temporary
// CHECK constraint rejects any deny-decision insert, forcing the audit write
// to fail on a genuine deny, and the handler must answer 500 with NO verdict
// rather than let the deny leak through despite the broken audit trail.
func TestPolicyCheck_AuditWriteFailureIsFailClosed(t *testing.T) {
	f := setupPCFixture(t)
	ctx := context.Background()
	conn := f.srv.db.Conn()

	_, err := conn.ExecContext(ctx, `
		ALTER TABLE policy_check_log
		ADD CONSTRAINT policy_check_log_reject_deny_test
		CHECK (allowed = true) NOT VALID`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, dropErr := conn.ExecContext(context.Background(), `
			ALTER TABLE policy_check_log
			DROP CONSTRAINT IF EXISTS policy_check_log_reject_deny_test`)
		assert.NoError(t, dropErr)
	})

	otherAddr := "0x000000000000000000000000000000000000ac88"
	op := pcBalanceOfCallOp(f.contractAddr, otherAddr) // denied by the param rule
	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": op,
	})

	require.Equal(t, http.StatusInternalServerError, w.Code, "body: %s", w.Body.String())
	assert.JSONEq(t, `{"error":"internal error"}`, w.Body.String())

	// Scoped by params_hash, not just subject+method, so this stays correct
	// even if some other test's row for the same subject/method survives.
	wantHash := dryRunParamsHash(op["method"].(string), op["params"].([]any))
	var count int
	require.NoError(t, conn.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM policy_check_log
		 WHERE subject_did = $1 AND params_hash = $2`,
		f.userDID, wantHash,
	).Scan(&count))
	assert.Zero(t, count, "the denied verdict must never be persisted once the audit write itself failed")
}

// ---------------------------------------------------------------- audit ---

func TestPolicyCheck_AuditRowRecordsCallerAndSubject(t *testing.T) {
	f := setupPCFixture(t)
	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	require.Equal(t, http.StatusOK, w.Code)

	var callerAuthMethod, method, paramsHash string
	var allowed bool
	require.NoError(t, f.srv.db.Conn().QueryRowContext(context.Background(), `
		SELECT caller_auth_method, method, params_hash, allowed FROM policy_check_log
		 WHERE subject_did = $1 ORDER BY created_at DESC LIMIT 1`,
		f.userDID,
	).Scan(&callerAuthMethod, &method, &paramsHash, &allowed))
	assert.Equal(t, "admin_token", callerAuthMethod)
	assert.Equal(t, "eth_call", method)
	assert.True(t, allowed)
	assert.Len(t, paramsHash, 64)
}

func TestPolicyCheck_AuditRowRecordsSubjectAddressForAddressPath(t *testing.T) {
	f := setupPCFixture(t)
	w := policyCheckPost(t, f.srv, "admin_token", map[string]any{
		"subject":   map[string]any{"address": f.userAddr},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	require.Equal(t, http.StatusOK, w.Code)

	var subjectDID, subjectAddr string
	require.NoError(t, f.srv.db.Conn().QueryRowContext(context.Background(), `
		SELECT subject_did, subject_address FROM policy_check_log
		 WHERE subject_address = $1 ORDER BY created_at DESC LIMIT 1`,
		strings.ToLower(f.userAddr),
	).Scan(&subjectDID, &subjectAddr))
	assert.Equal(t, f.userDID, subjectDID, "address resolved to the right DID before the row was written")
	assert.Equal(t, strings.ToLower(f.userAddr), subjectAddr)
}

// ------------------------------------------------------ reason sanitizer ---

// Every AccessCheckResult.Reason the rbac package can currently produce that
// is not one of the known categories must collapse to "denied" rather than
// reaching a caller verbatim.
func TestSanitizePolicyCheckReason_CollapsesUnknownReasons(t *testing.T) {
	unknownReasons := []string{
		"multiple organizations: use /rpc/:org_id to specify which org",
		"access denied",
		"user has no organization membership",
		"contract deployment missing bytecode",
		rbac.ErrContractAccessDenied,
		"function eth_call not allowed on contract 0xabc",
		"function selector required: contract 0xabc has function-level restrictions",
		"proxy upgrade denied: some nested reason",
	}
	for _, r := range unknownReasons {
		t.Run(r, func(t *testing.T) {
			assert.Equal(t, "denied", sanitizePolicyCheckReason(r))
		})
	}
}

func TestSanitizePolicyCheckReason_PassesKnownCategoriesThrough(t *testing.T) {
	// NOTE: "method not allowed" as a literal substring is the pattern
	// sanitizeDryRunReason itself checks for, but access.go's actual reason
	// strings interpolate the method name in the middle ("method %s not
	// allowed"), so that literal substring is never produced by real
	// deny reasons today. This test proves the mapping logic itself is
	// correct, independent of whether access.go currently reaches it.
	known := map[string]string{
		"method not allowed for this account":         "method_not_allowed",
		"no access to this resource":                  "denied",
		"rate limit exceeded":                         "rate_limited",
		"compliance check failed":                     "compliance",
		"upstream error contacting node":              "upstream_error",
		"failed to decode raw transaction: malformed": "decode_error",
		"user is banned":                              "user_banned",
	}
	for input, want := range known {
		t.Run(input, func(t *testing.T) {
			assert.Equal(t, want, sanitizePolicyCheckReason(input))
		})
	}
}

// mustUserIDByDID looks up a user's internal UUID by DID for tests that need
// to attach a SECOND membership to an already-created fixture user.
func mustUserIDByDID(t *testing.T, database interface {
	GetUserByExternalID(ctx context.Context, externalID string) (*rbac.User, error)
}, did string) string {
	t.Helper()
	u, err := database.GetUserByExternalID(context.Background(), did)
	require.NoError(t, err)
	require.NotNil(t, u)
	return u.ID
}

// pcSignedRawTx mirrors drSignedRawTx (admin_dry_run_test.go): a signed legacy
// tx as hex, so tests reach the production RLP decode and sender recovery.
func pcSignedRawTx(t *testing.T, to *common.Address, data []byte) (string, string) {
	t.Helper()
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	tx := types.NewTx(&types.LegacyTx{
		Nonce: 0, GasPrice: big.NewInt(1_000_000_000), Gas: 100_000,
		To: to, Value: big.NewInt(0), Data: data,
	})
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(1)), key)
	require.NoError(t, err)
	raw, err := signed.MarshalBinary()
	require.NoError(t, err)
	return "0x" + hex.EncodeToString(raw), crypto.PubkeyToAddress(key.PublicKey).Hex()
}
