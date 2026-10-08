package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Client trace value visibility. The call tree is returned to every viewer who
// passes the trace access checks, but each internal-call value only to a
// viewer who may read the private storage of the contract that produced it,
// exactly as a direct eth_getStorageAt would decide:
//
//   - a nested frame's input and value were produced by the parent frame's
//     storage context;
//   - its output and revert data by its own storage context;
//   - the top frame and the tree shape are always shown.
//
// Shape used throughout: Payroll reads a private slot and calls
// Token.transfer(employee, salary); Token answers with a value from its own
// private slot.

const (
	payrollPaySel  = "0xbd0af85d"
	salaryMarker   = "5a1a12"
	tokenOutMarker = "7e3c1d"
	topOutputValue = "0x0000000000000000000000000000000000000000000000000000000000000001"
	traceRevertMsg = "transfer refused"
)

var valueTraceMethods = append(append([]string{}, traceMethods...), "eth_getStorageAt")

func transferInput(employee string) string {
	return "0xa9059cbb" + strings.Repeat("0", 24) + strings.TrimPrefix(employee, "0x") +
		strings.Repeat("0", 64-len(salaryMarker)) + salaryMarker
}

func payInput(token, employee string) string {
	return payrollPaySel + strings.Repeat("0", 24) + strings.TrimPrefix(token, "0x") +
		strings.Repeat("0", 24) + strings.TrimPrefix(employee, "0x")
}

// addGroupInOrg puts an existing user into another group of the same org.
func addGroupInOrg(t *testing.T, ctx context.Context, ts *testServerRBAC, orgID, userID string, claims []rbac.Claim, methods []string) string {
	t.Helper()
	groupID := uuid.New().String()
	insertGroupRawSQL(t, ctx, ts.db, groupID, orgID, "tv-"+groupID[:8], "Trace Values", "tv-"+groupID[:8])
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{ID: uuid.New().String(), GroupID: groupID, Claims: claims, AllowedMethods: methods}))
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.New().String(), UserID: userID, GroupID: groupID, Source: rbac.MembershipSourceAdmin}))
	return groupID
}

type payrollFixture struct {
	c                       *traceCanary
	proc                    *JSONRPCProcessor
	ts                      *testServerRBAC
	u                       traceUser
	me, payroll, token, emp string
}

// newPayrollFixture registers Payroll and Token in one org. adminOf names the
// contracts the viewer administers (through a group with the admin claim);
// every other contract is granted through a group without claims. methods is
// the viewer's method allowlist in both groups.
func newPayrollFixture(t *testing.T, adminOf map[string]bool, methods []string) *payrollFixture {
	t.Helper()
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	f := &payrollFixture{c: c, proc: proc, ts: ts, me: fixedAddr(0x51), payroll: fixedAddr(0x52), token: fixedAddr(0x53), emp: fixedAddr(0x54)}
	f.u = newTraceUser(t, ctx, ts, "", nil, methods, f.me)
	adminGroup := addGroupInOrg(t, ctx, ts, f.u.orgID, f.u.userID, []rbac.Claim{rbac.ClaimAdmin}, methods)
	for name, addr := range map[string]string{"payroll": f.payroll, "token": f.token} {
		group := f.u.groupID
		if adminOf[name] {
			group = adminGroup
		}
		addContract(t, ctx, ts, f.u.orgID, addr, group)
	}
	f.setTrace(map[string]any{
		"type": "CALL", "from": f.me, "to": f.payroll, "value": "0x0", "input": payInput(f.token, f.emp), "output": topOutputValue,
		"calls": []any{map[string]any{
			"type": "CALL", "from": f.payroll, "to": f.token, "value": "0x0", "gas": "0x9000", "gasUsed": "0x100",
			"input": transferInput(f.emp), "output": "0x" + strings.Repeat("0", 64-len(tokenOutMarker)) + tokenOutMarker,
			"error": "execution reverted", "revertReason": traceRevertMsg,
		}},
	})
	return f
}

func (f *payrollFixture) setTrace(body map[string]any) {
	f.c.mu.Lock()
	defer f.c.mu.Unlock()
	f.c.txFrom, f.c.txTo, f.c.txIn = f.me, f.payroll, payInput(f.token, f.emp)
	f.c.callTracerBody = body
}

func (f *payrollFixture) trace(t *testing.T, method string) (*ProcessResult, map[string]any) {
	t.Helper()
	params := []any{map[string]any{"from": f.me, "to": f.payroll, "data": payInput(f.token, f.emp)}, "latest"}
	if method == "debug_traceTransaction" {
		params = []any{traceHash} // a replay of the viewer's own mined tx
	}
	res := f.proc.Process(context.Background(), traceReq(f.u.did, f.u.orgID, method, params...))
	require.Nil(t, res.Error, "%s must be served: %+v", method, res.Error)
	var env struct {
		Result map[string]any `json:"result"`
	}
	require.NoError(t, json.Unmarshal(res.ResponseBody, &env))
	return res, env.Result
}

// canReadStorageDirectly is the direct-read twin: eth_getStorageAt on a
// private slot of addr, as the same viewer in the same org.
func (f *payrollFixture) canReadStorageDirectly(addr string) bool {
	res := f.proc.Process(context.Background(), traceReq(f.u.did, f.u.orgID, "eth_getStorageAt", addr, "0x0", "latest"))
	return res.Error == nil
}

func firstCall(t *testing.T, root map[string]any) map[string]any {
	t.Helper()
	calls, _ := root["calls"].([]any)
	require.Len(t, calls, 1, "the call tree is always returned: %v", root)
	child, _ := calls[0].(map[string]any)
	return child
}

func TestTraceValues_PayrollToken(t *testing.T) {
	cases := []struct {
		name                    string
		adminOf                 map[string]bool
		inputShown, outputShown bool
		redacted                []any
	}{
		{"grant only", nil, false, false, []any{"input", "value", "output", "revertReason"}},
		{"admin of payroll", map[string]bool{"payroll": true}, true, false, []any{"output", "revertReason"}},
		{"admin of token", map[string]bool{"token": true}, false, true, []any{"input", "value"}},
		{"admin of both", map[string]bool{"payroll": true, "token": true}, true, true, nil},
	}
	for _, tc := range cases {
		for _, method := range []string{"debug_traceCall", "debug_traceTransaction"} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				f := newPayrollFixture(t, tc.adminOf, valueTraceMethods)
				res, root := f.trace(t, method)
				body := string(res.ResponseBody)

				// The top frame is always shown in full.
				assert.Equal(t, payInput(f.token, f.emp), root["input"])
				assert.Equal(t, topOutputValue, root["output"])
				assert.NotContains(t, root, "redacted")

				// The tree shape, addressing, gas and error string are always shown.
				child := firstCall(t, root)
				assert.Equal(t, "CALL", child["type"])
				assert.Equal(t, f.payroll, child["from"])
				assert.Equal(t, f.token, child["to"])
				assert.Equal(t, "0x9000", child["gas"])
				assert.Equal(t, "execution reverted", child["error"])

				// Values follow the contract that produced them, checked on the
				// raw body so no encoding can carry them.
				assert.Equal(t, tc.inputShown, strings.Contains(body, salaryMarker), "nested input: %s", body)
				_, hasValue := child["value"]
				assert.Equal(t, tc.inputShown, hasValue, "nested value: %s", body)
				assert.Equal(t, tc.outputShown, strings.Contains(body, tokenOutMarker), "nested output: %s", body)
				assert.Equal(t, tc.outputShown, strings.Contains(body, traceRevertMsg), "nested revert reason: %s", body)
				if tc.redacted == nil {
					assert.NotContains(t, child, "redacted")
				} else {
					assert.Equal(t, tc.redacted, child["redacted"])
				}

				// The invariant: a value is shown iff the viewer could read the
				// producing contract's storage directly.
				assert.Equal(t, tc.inputShown, f.canReadStorageDirectly(f.payroll), "input visibility must match a direct storage read of Payroll")
				assert.Equal(t, tc.outputShown, f.canReadStorageDirectly(f.token), "output visibility must match a direct storage read of Token")
			})
		}
	}
}

// An org admin may read every org contract's storage, so sees every value.
func TestTraceValues_OrgAdminSeesValues(t *testing.T) {
	f := newPayrollFixture(t, nil, valueTraceMethods)
	ctx := context.Background()
	_, err := f.ts.db.Conn().ExecContext(ctx, `UPDATE groups SET is_org_admin = true WHERE id = $1`, f.u.groupID)
	require.NoError(t, err)
	require.NoError(t, f.ts.rbacAccessCtrl.InvalidateGroup(ctx, f.u.groupID))

	res, _ := f.trace(t, "debug_traceCall")
	body := string(res.ResponseBody)
	assert.Contains(t, body, salaryMarker)
	assert.Contains(t, body, tokenOutMarker)
	assert.NotContains(t, body, "redacted")
}

// The admin claim without eth_getStorageAt on the allowlist does not let the
// viewer read storage directly, so the trace shows no values either.
func TestTraceValues_AdminWithoutStorageReadMethodSeesNoValues(t *testing.T) {
	f := newPayrollFixture(t, map[string]bool{"payroll": true, "token": true}, traceMethods)
	res, _ := f.trace(t, "debug_traceCall")
	body := string(res.ResponseBody)
	assert.NotContains(t, body, salaryMarker)
	assert.NotContains(t, body, tokenOutMarker)
	assert.False(t, f.canReadStorageDirectly(f.payroll))
}

// A DELEGATECALL parent runs the implementation's code against the proxy's
// storage: the proxy's admin sees the values produced there, the
// implementation's admin does not.
func TestTraceValues_DelegatecallParentUsesStorageContext(t *testing.T) {
	for _, tc := range []struct {
		name       string
		adminOf    string
		inputShown bool
	}{
		{"admin of proxy", "proxy", true},
		{"admin of implementation", "impl", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTraceCanary(t)
			proc, ts := setupTraceProcessor(t, c)
			ctx := context.Background()
			me, proxyAddr, impl, token := fixedAddr(0x61), fixedAddr(0x62), fixedAddr(0x63), fixedAddr(0x64)
			u := newTraceUser(t, ctx, ts, "", nil, valueTraceMethods, me)
			adminGroup := addGroupInOrg(t, ctx, ts, u.orgID, u.userID, []rbac.Claim{rbac.ClaimAdmin}, valueTraceMethods)
			grant := map[string]string{"proxy": u.groupID, "impl": u.groupID}
			grant[tc.adminOf] = adminGroup
			addContract(t, ctx, ts, u.orgID, proxyAddr, grant["proxy"])
			addContract(t, ctx, ts, u.orgID, impl, grant["impl"])
			addContract(t, ctx, ts, u.orgID, token, u.groupID)
			c.callTracerBody = map[string]any{
				"type": "CALL", "from": me, "to": proxyAddr, "input": "0x01",
				"calls": []any{map[string]any{
					"type": "DELEGATECALL", "from": proxyAddr, "to": impl, "input": "0x01", "output": "0x" + strings.Repeat("0", 58) + "abcdef",
					"calls": []any{map[string]any{"type": "CALL", "from": proxyAddr, "to": token, "input": transferInput(fixedAddr(0x65)), "output": "0x"}},
				}},
			}

			res := proc.Process(ctx, traceReq(u.did, u.orgID, "debug_traceCall", map[string]any{"from": me, "to": proxyAddr, "data": "0x01"}, "latest"))
			require.Nil(t, res.Error, "%+v", res.Error)
			body := string(res.ResponseBody)
			assert.Equal(t, tc.inputShown, strings.Contains(body, salaryMarker), "the inner call's input belongs to the proxy's storage context: %s", body)
			assert.Equal(t, tc.inputShown, strings.Contains(body, "abcdef"), "the delegated frame's output belongs to the proxy's storage context: %s", body)
		})
	}
}

// View-as judges values as the impersonated user, not the admin viewing.
func TestTraceValues_ViewAsJudgedAsImpersonatedUser(t *testing.T) {
	srv := setupImpersonationTestServer(t)
	c := newTraceCanary(t)
	srv.jsonrpcProcessor = newTraceProcessor(t, srv.testServerRBAC, c)
	ctx := context.Background()
	me, payroll, token, emp := fixedAddr(0x71), fixedAddr(0x72), fixedAddr(0x73), fixedAddr(0x74)
	u := newTraceUser(t, ctx, srv.testServerRBAC, "", nil, valueTraceMethods, me) // grants, no admin claim
	addContract(t, ctx, srv.testServerRBAC, u.orgID, payroll, u.groupID)
	addContract(t, ctx, srv.testServerRBAC, u.orgID, token, u.groupID)
	c.mu.Lock()
	c.txFrom, c.txTo, c.txIn = me, payroll, payInput(token, emp)
	c.callTracerBody = map[string]any{
		"type": "CALL", "from": me, "to": payroll, "input": payInput(token, emp),
		"calls": []any{map[string]any{"type": "CALL", "from": payroll, "to": token, "input": transferInput(emp), "output": "0x" + tokenOutMarker}},
	}
	c.mu.Unlock()

	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 9, "method": "debug_traceTransaction", "params": []any{traceHash}})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, impersonatePath(u.did, u.orgID, "/rpc"), strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Auth-Method", "jwt_admin")
	req.Header.Set("X-Test-Admin-Subject", "did:privado:tv-viewas-admin")
	req.Header.Set("X-Test-Admin-Org-IDs", u.orgID)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())
	assert.Contains(t, w.Body.String(), token, "the call tree is shown")
	assert.NotContains(t, w.Body.String(), salaryMarker, "values are judged as the impersonated user")
	assert.NotContains(t, w.Body.String(), tokenOutMarker)
}

// The positive twin: when the impersonated user is admin of both contracts,
// View-as shows the values, although the admin viewing is not a member at all.
func TestTraceValues_ViewAsShowsValuesTheUserMaySee(t *testing.T) {
	srv := setupImpersonationTestServer(t)
	c := newTraceCanary(t)
	srv.jsonrpcProcessor = newTraceProcessor(t, srv.testServerRBAC, c)
	ctx := context.Background()
	me, payroll, token, emp := fixedAddr(0x81), fixedAddr(0x82), fixedAddr(0x83), fixedAddr(0x84)
	u := newTraceUser(t, ctx, srv.testServerRBAC, "", []rbac.Claim{rbac.ClaimAdmin}, valueTraceMethods, me)
	addContract(t, ctx, srv.testServerRBAC, u.orgID, payroll, u.groupID)
	addContract(t, ctx, srv.testServerRBAC, u.orgID, token, u.groupID)
	c.mu.Lock()
	c.txFrom, c.txTo, c.txIn = me, payroll, payInput(token, emp)
	c.callTracerBody = map[string]any{
		"type": "CALL", "from": me, "to": payroll, "input": payInput(token, emp),
		"calls": []any{map[string]any{"type": "CALL", "from": payroll, "to": token, "input": transferInput(emp), "output": "0x" + tokenOutMarker}},
	}
	c.mu.Unlock()

	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 9, "method": "debug_traceTransaction", "params": []any{traceHash}})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, impersonatePath(u.did, u.orgID, "/rpc"), strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Auth-Method", "jwt_admin")
	req.Header.Set("X-Test-Admin-Subject", "did:privado:tv-viewas-admin")
	req.Header.Set("X-Test-Admin-Org-IDs", u.orgID)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())
	assert.Contains(t, w.Body.String(), salaryMarker, "judged as the impersonated user, who administers Payroll")
	assert.Contains(t, w.Body.String(), tokenOutMarker, "and Token")
	assert.NotContains(t, w.Body.String(), "redacted")
}
