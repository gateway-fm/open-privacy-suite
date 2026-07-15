package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/rbac"
)

// mpValidationABI is a PaymentRegistry-shaped ABI with flat outputs on
// getPaymentInfo (amount is uint256 → NOT an address; payer/payee are).
const mpValidationABI = `[
  {"type":"function","name":"createPayment","stateMutability":"nonpayable",
   "inputs":[{"name":"paymentIdentifier","type":"string"},{"name":"payee","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[]},
  {"type":"function","name":"completePayment","stateMutability":"nonpayable",
   "inputs":[{"name":"paymentIdentifier","type":"string"}],"outputs":[]},
  {"type":"function","name":"getPaymentInfo","stateMutability":"view",
   "inputs":[{"name":"paymentIdentifier","type":"string"}],
   "outputs":[{"name":"amount","type":"uint256"},{"name":"payer","type":"address"},{"name":"payee","type":"address"}]}
]`

// putMethodPolicyRaw PUTs a raw request body to the method-policies endpoint and
// returns (status, body). Raw so we can also exercise malformed-JSON paths.
func putMethodPolicyRaw(t *testing.T, ts *testServerContractProof, orgID, addr string, raw []byte) (int, string) {
	t.Helper()
	url := fmt.Sprintf("/api/orgs/%s/contracts/%s/method-policies", orgID, addr)
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// putMethodPolicy marshals {"method_policies": policy} and PUTs it.
func putMethodPolicy(t *testing.T, ts *testServerContractProof, orgID, addr string, policy any) (int, string) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"method_policies": policy})
	require.NoError(t, err)
	return putMethodPolicyRaw(t, ts, orgID, addr, raw)
}

// TestUpdateContractMethodPolicies_Validation drives the REAL admin HTTP handler
// with the kinds of JSON a frontend (structured wizard OR raw editor) can send,
// and asserts the backend rejects every malformed / ABI-mismatched policy with
// 400 (and accepts a valid one). This is the "frontend JSON → backend
// validation" path end to end — ShouldBindJSON + ParseMethodPolicyDocument
// (strict, unknown-field-rejecting) + ValidateForClient against the contract's
// registered ABI — not the engine function in isolation. Runs in CI (no anvil:
// validation never calls the node).
func TestUpdateContractMethodPolicies_Validation(t *testing.T) {
	ts := setupTestServerForContractProof(t)
	orgID := createTestOrgForProof(t, ts, "mp-validation-org")
	ctx := context.Background()

	addr := "0xabcabcabcabcabcabcabcabcabcabcabcabcabca"
	require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{
		ID: uuid.New().String(), OrgID: orgID, Address: addr, Name: "PaymentRegistry",
		ABI: mpValidationABI, Metadata: map[string]any{},
	}))
	noABIAddr := "0xdddddddddddddddddddddddddddddddddddddddd"
	require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{
		ID: uuid.New().String(), OrgID: orgID, Address: noABIAddr, Name: "NoABI", Metadata: map[string]any{},
	}))

	rec := func(cap, acc any) map[string]any {
		return map[string]any{"records": map[string]any{"payment": map[string]any{"capture": cap, "access": acc}}}
	}
	validCapture := []any{map[string]any{
		"method": "createPayment(string,address,uint256)", "key": map[string]any{"source": "param", "index": 0},
		"remember": map[string]any{"payer": map[string]any{"source": "sender", "merge": "set_once"}},
	}}
	reader := func(allow []any) []any {
		return []any{map[string]any{"method": "getPaymentInfo(string)", "key": map[string]any{"source": "param", "index": 0}, "allow": allow, "onNoRecord": "deny", "else": "deny"}}
	}

	// Positive control: a valid policy is accepted and persisted.
	t.Run("valid policy accepted", func(t *testing.T) {
		st, body := putMethodPolicy(t, ts, orgID, addr, rec(validCapture, reader([]any{map[string]any{"callerIn": []string{"payer"}}})))
		require.Equal(t, http.StatusOK, st, "body: %s", body)
	})

	bad := []struct {
		name   string
		policy any
		want   string // substring of the 400 body ("" = only status matters)
	}{
		{
			name:   "writer method not in ABI",
			policy: rec([]any{map[string]any{"method": "ghostWriter(string)", "key": map[string]any{"source": "param", "index": 0}, "remember": map[string]any{"payer": map[string]any{"source": "sender", "merge": "set_once"}}}}, reader([]any{map[string]any{"callerIn": []string{"payer"}}})),
			want:   "not found in ABI",
		},
		{
			name:   "reader method not in ABI",
			policy: rec(validCapture, []any{map[string]any{"method": "ghostReader(string)", "key": map[string]any{"source": "param", "index": 0}, "allow": []any{map[string]any{"callerIn": []string{"payer"}}}, "onNoRecord": "deny", "else": "deny"}}),
			want:   "not found in ABI",
		},
		{
			name:   "capture key param index out of range",
			policy: rec([]any{map[string]any{"method": "completePayment(string)", "key": map[string]any{"source": "param", "index": 9}, "remember": map[string]any{"payer": map[string]any{"source": "sender", "merge": "set_once"}}}}, reader([]any{map[string]any{"callerIn": []string{"payer"}}})),
			want:   "out of range",
		},
		{
			name:   "remembered param index out of range",
			policy: rec([]any{map[string]any{"method": "createPayment(string,address,uint256)", "key": map[string]any{"source": "param", "index": 0}, "remember": map[string]any{"payee": map[string]any{"source": "param", "index": 9, "merge": "set_once"}}}}, reader([]any{map[string]any{"callerIn": []string{"payee"}}})),
			want:   "out of range",
		},
		{
			name:   "return path is not an address output",
			policy: rec(validCapture, reader([]any{map[string]any{"callerIn": map[string]any{"source": "return", "paths": []string{"amount"}, "kind": "address"}}})),
			want:   "not an address output",
		},
		{
			name:   "callerIn references an uncaptured, non-literal field",
			policy: rec(validCapture, reader([]any{map[string]any{"callerIn": []string{"ghost"}}})),
			want:   "neither a captured field",
		},
		{
			name:   "numeric where on a non-numeric field",
			policy: rec(validCapture, reader([]any{map[string]any{"callerIn": []string{"payer"}, "where": map[string]any{"field": "payer", "op": "gte", "value": "1"}}})),
			want:   "requires a numeric field",
		},
		{
			name:   "visibleTo captured as set_once",
			policy: rec([]any{map[string]any{"method": "createPayment(string,address,uint256)", "key": map[string]any{"source": "param", "index": 0}, "remember": map[string]any{"aud": map[string]any{"source": "visibleTo", "merge": "set_once"}}}}, reader([]any{map[string]any{"callerIn": []string{"aud"}}})),
			want:   "must use merge",
		},
		{
			name:   "literal-shaped capture field name (final-audit HIGH)",
			policy: rec([]any{map[string]any{"method": "createPayment(string,address,uint256)", "key": map[string]any{"source": "param", "index": 0}, "remember": map[string]any{"did:x:y": map[string]any{"source": "sender", "merge": "set_once"}}}}, reader([]any{map[string]any{"callerIn": []string{"did:x:y"}}})),
			want:   "must not look like a DID/address literal",
		},
		{
			name:   "unknown field inside a record (strict parse)",
			policy: map[string]any{"records": map[string]any{"payment": map[string]any{"capture": validCapture, "access": reader([]any{map[string]any{"callerIn": []string{"payer"}}}), "EVIL": 1}}},
			want:   "malformed method policy document",
		},
		{
			name:   "method_policies is a scalar, not a document",
			policy: "not a policy document",
			want:   "malformed method policy document",
		},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			st, body := putMethodPolicy(t, ts, orgID, addr, tc.policy)
			require.Equal(t, http.StatusBadRequest, st, "expected 400, body: %s", body)
			if tc.want != "" {
				require.Contains(t, body, tc.want, "400 body should explain the failure")
			}
		})
	}

	// Syntactically malformed outer JSON → ShouldBindJSON rejects.
	t.Run("malformed request body", func(t *testing.T) {
		st, body := putMethodPolicyRaw(t, ts, orgID, addr, []byte(`{"method_policies": {`))
		require.Equal(t, http.StatusBadRequest, st, "body: %s", body)
	})

	// A contract with no registered ABI cannot have a policy set.
	t.Run("no ABI registered rejected", func(t *testing.T) {
		st, body := putMethodPolicy(t, ts, orgID, noABIAddr, rec(validCapture, reader([]any{map[string]any{"callerIn": []string{"payer"}}})))
		require.Equal(t, http.StatusBadRequest, st, "body: %s", body)
		require.Contains(t, body, "ABI", "should tell the operator to register the ABI first")
	})

	// Clearing a policy (null) is always allowed, even with no ABI.
	t.Run("clear policy allowed with null", func(t *testing.T) {
		st, body := putMethodPolicyRaw(t, ts, orgID, addr, []byte(`{"method_policies": null}`))
		require.Equal(t, http.StatusOK, st, "body: %s", body)
	})

	// No client-facing error should ever leak an internal detail (RD-934):
	// every 400 reason is derived from the admin's own submitted policy + ABI.
	t.Run("400 reasons carry no internal leakage markers", func(t *testing.T) {
		st, body := putMethodPolicy(t, ts, orgID, addr, rec(validCapture, reader([]any{map[string]any{"callerIn": []string{"ghost"}}})))
		require.Equal(t, http.StatusBadRequest, st)
		for _, marker := range []string{"pgx", "sql:", "/Users/", "goroutine", "internal/"} {
			require.NotContains(t, body, marker, "client error must be opaque")
		}
	})
}
