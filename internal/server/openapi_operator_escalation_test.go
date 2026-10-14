package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/metrics"
	"privacy-proxy/internal/rbac"
)

// Operator-token privilege-separation confirming test (RD-1173 / RD-1175).
//
// RD-1132 restricts OPERATOR_API_TOKEN from tenant data. The guarantee is
// enforced ONLY by per-handler denyOperator* / requireSuperAdmin calls:
// orgScopingMiddleware waves operator_token straight through, and the
// require*InScope helpers early-return true for any auth_method != "jwt_admin".
// So a handler that omits an explicit operator gate imposes NO restriction on
// the operator token.
//
// This test drives the REAL operator credential (X-Admin-Token == the
// configured OPERATOR_API_TOKEN) from a private-network address, so it
// exercises the actual adminAuthMiddleware → auth_method="operator_token"
// path, then asserts each tenant/fleet endpoint DENIES it with 403.
//
// It runs on a Server with nil handler dependencies: if the operator gate is
// present, the handler returns 403 at the guard before touching any nil dep;
// if the gate is ABSENT, the handler proceeds and returns 500 (nil-dep panic,
// recovered by gin) or 400 — anything but 403. So a non-403 here is proof the
// operator reached past the intended boundary.
//
// STATUS: passes on this branch — RD-1173's operator-token guards ship in this
// same PR. Each tenant/fleet case below WAS a confirmed escalation before those
// guards were added; this is the regression guard that ships with the fix and
// keeps them closed (it would fail again if any guard were removed).
func TestOperatorTokenDeniedOnTenantAndFleetEndpoints_RD1173(t *testing.T) {
	const operatorToken = "operator-token-under-test"

	prevMode := gin.Mode()
	gin.SetMode(gin.TestMode)
	defer gin.SetMode(prevMode)

	s := &Server{
		config: &config.Config{
			ReadProfile:      rbac.ReadProfileStandard,
			Environment:      "production",
			AdminAPIToken:    "full-admin-token-under-test",
			OperatorAPIToken: operatorToken,
		},
		metrics:         metrics.NewNoop(),
		authRateLimiter: NewAuthRateLimiter(DevAuthRateLimiterConfig()),
	}
	defer s.authRateLimiter.Stop()
	router := s.setupRouter()

	// A non-default org id: the deny helpers intentionally exempt the default
	// org (system infra), so escalation must be probed against a tenant org.
	const org = "11111111-1111-1111-1111-111111111111"

	cases := []struct {
		name, method, path, body string
		finding                  string
	}{
		// F1 — disclosure surface (read + mutate) cross-org.
		{"disclosure list requests", "GET", "/api/v1/admin/disclosure/requests?org_id=" + org, "", "F1"},
		{"disclosure list grants", "GET", "/api/v1/admin/disclosure/grants?org_id=" + org, "", "F1"},
		{"disclosure get request", "GET", "/api/v1/admin/disclosure/requests/req-123", "", "F1"},
		{"disclosure create request", "POST", "/api/v1/admin/disclosure/requests", `{"target_user_id":"u","org_id":"` + org + `","reason":"x"}`, "F1"},
		{"disclosure delete request", "DELETE", "/api/v1/admin/disclosure/requests/req-123", "", "F1"},
		{"disclosure revoke grant", "POST", "/api/v1/admin/disclosure/grants/g-123/revoke", "", "F1"},
		{"disclosure check-access oracle", "GET", "/api/v1/admin/disclosure/check-access?requester_did=did:x&target_user_did=did:y", "", "F1"},
		// F2 — user ban/KYC/delete cluster-wide.
		{"user update (ban/kyc)", "PUT", "/api/v1/admin/users/user-123", `{"banned":true}`, "F2"},
		{"user delete", "DELETE", "/api/v1/admin/users/user-123", "", "F2"},
		// F3 — cluster-wide collision list.
		{"eth-address collisions", "GET", "/api/v1/admin/eth-addresses/collisions", "", "F3"},
		// F4 — claim into any org.
		{"contract claim", "POST", "/api/v1/admin/orgs/" + org + "/contracts/claim", `{"address":"0x0000000000000000000000000000000000000001","deployment_tx_hash":"0x` + strings.Repeat("0", 63) + `1"}`, "F4"},
		// F5 — batch-delete-preview enumeration.
		{"group batch-delete-preview", "POST", "/api/v1/admin/orgs/" + org + "/groups/batch-delete-preview", `{"group_ids":["g-1"]}`, "F5"},
		// F6 — global (fleet) sanctions add/remove.
		{"global sanction add", "POST", "/api/v1/admin/compliance/sanctions", `{"address":"0x0000000000000000000000000000000000000002","reason":"x"}`, "F6"},
		{"global sanction remove", "DELETE", "/api/v1/admin/compliance/sanctions/s-123", "", "F6"},
		// checkContractsOnChain — tenant contract inventory read.
		{"contracts sync-check", "POST", "/api/v1/admin/orgs/" + org + "/contracts/sync-check", `{}`, "F3b"},

		// POSITIVE CONTROLS — endpoints that ALREADY carry the operator gate.
		// These MUST return 403 under this exact harness; if they don't, the
		// test methodology (403=guarded, non-403=escalation) is invalid and
		// every finding above is suspect. They prove the harness discriminates.
		{"CONTROL createContract (denyOperatorOrgScoped)", "POST", "/api/v1/admin/orgs/" + org + "/contracts", `{"address":"0x0000000000000000000000000000000000000003","name":"c"}`, "CONTROL"},
		{"CONTROL listContracts (denyOperatorTenantRead)", "GET", "/api/v1/admin/orgs/" + org + "/contracts", "", "CONTROL"},
		{"CONTROL listSessions (requireSuperAdmin)", "GET", "/api/v1/admin/sessions", "", "CONTROL"},
		{"CONTROL azure-tenants (requireSuperAdmin)", "GET", "/api/v1/admin/azure-tenants", "", "CONTROL"},
	}

	for _, tc := range cases {
		t.Run(tc.finding+" "+tc.name, func(t *testing.T) {
			var bodyRdr *strings.Reader
			if tc.body != "" {
				bodyRdr = strings.NewReader(tc.body)
			} else {
				bodyRdr = strings.NewReader("")
			}
			req := httptest.NewRequest(tc.method, tc.path, bodyRdr)
			req.Header.Set("X-Admin-Token", operatorToken)
			req.Header.Set("Content-Type", "application/json")
			// Private-network source so localhostOnlyMiddleware admits the
			// request and we actually reach the operator gate under test.
			req.RemoteAddr = "127.0.0.1:54321"

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code == http.StatusForbidden {
				return // correctly denied — guard present
			}
			t.Errorf("[%s] %s %s: operator token got %d, want 403 — the operator reached past the tenant/fleet boundary (nil-dep 500 or 400 both mean the guard is absent). body=%s",
				tc.finding, tc.method, tc.path, w.Code, truncate(w.Body.String(), 120))
		})
	}
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
