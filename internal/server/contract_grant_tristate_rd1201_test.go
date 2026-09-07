package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// RD-1200/RD-1201 (PR #409 review): `functions` on a contract grant is a
// public tri-state contract — null means "all functions", [] means "none"
// (an events-only grant), a non-empty array means "only these" — and the
// three states must survive create → update → read round trips AT THE WIRE
// LEVEL. Asserting on raw JSON (not Go structs) is the point: a Go []T can
// hold the nil/empty distinction while the HTTP layer or the store flattens
// it, which is exactly the regression this guards against.

// grantFunctionsRaw extracts the literal JSON of the "functions" property
// from a serialized grant.
func grantFunctionsRaw(t *testing.T, grantJSON []byte) string {
	t.Helper()
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(grantJSON, &m))
	raw, ok := m["functions"]
	require.True(t, ok, "functions key must always be serialized (tri-state): %s", grantJSON)
	return string(raw)
}

func TestContractGrantFunctionsTriState_RoundTrip_RD1201(t *testing.T) {
	f := setupEventRulesFixture(t)

	post := func(t *testing.T, body map[string]any) []byte {
		t.Helper()
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost,
			"/api/orgs/"+f.orgID+"/contracts/"+f.contractAddress+"/grants", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
		return w.Body.Bytes()
	}
	putRaw := func(t *testing.T, groupID, rawBody string) []byte {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut,
			"/api/orgs/"+f.orgID+"/contracts/"+f.contractAddress+"/grants/"+groupID,
			bytes.NewReader([]byte(rawBody)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		return w.Body.Bytes()
	}
	listFunctionsFor := func(t *testing.T, groupID string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet,
			"/api/orgs/"+f.orgID+"/contracts/"+f.contractAddress+"/grants", nil)
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var grants []map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &grants))
		for _, g := range grants {
			var gid string
			require.NoError(t, json.Unmarshal(g["group_id"], &gid))
			if gid == groupID {
				raw, ok := g["functions"]
				require.True(t, ok, "functions key missing from listed grant")
				return string(raw)
			}
		}
		t.Fatalf("grant for group %s not found in list", groupID)
		return ""
	}

	// Create with functions ABSENT → null on the wire ("all functions").
	created := post(t, map[string]any{"group_id": f.groupID})
	require.Equal(t, "null", grantFunctionsRaw(t, created),
		"create without functions must serialize functions: null (all)")
	require.Equal(t, "null", listFunctionsFor(t, f.groupID),
		"list must agree with create: null (all)")

	// Update to [] → "no functions" (events-only) must NOT collapse into null.
	updated := putRaw(t, f.groupID, `{"functions": []}`)
	require.Equal(t, "[]", grantFunctionsRaw(t, updated),
		"functions [] (none) must round-trip as [], not null")
	require.Equal(t, "[]", listFunctionsFor(t, f.groupID),
		"the store must preserve the nil/empty distinction across a read")

	// Update to a non-empty rule list.
	updated = putRaw(t, f.groupID, `{"functions": [{"selector": "transfer(address,uint256)"}]}`)
	var got struct {
		Functions []struct {
			Selector string `json:"selector"`
		} `json:"functions"`
	}
	require.NoError(t, json.Unmarshal(updated, &got))
	require.Len(t, got.Functions, 1)
	require.Equal(t, "transfer(address,uint256)", got.Functions[0].Selector)

	// Update with functions ABSENT → no change (still the rule list).
	updated = putRaw(t, f.groupID, `{}`)
	require.NoError(t, json.Unmarshal(updated, &got))
	require.Len(t, got.Functions, 1, "absent functions key must mean no change")

	// Update with EXPLICIT null → cleared back to "all functions".
	updated = putRaw(t, f.groupID, `{"functions": null}`)
	require.Equal(t, "null", grantFunctionsRaw(t, updated),
		"explicit functions: null must clear back to all")
	require.Equal(t, "null", listFunctionsFor(t, f.groupID))
}

// The generated OpenAPI document must declare the tri-state: the server
// really emits `functions: null`, so the schema has to admit null or a
// generated client will reject a valid response. `make api-spec` applies
// this via cmd/api-spec-postprocess; this test fails if that step is ever
// dropped from the pipeline (the committed spec is the pipeline's output —
// the CI drift gate keeps them in lockstep).
func TestOpenAPIDeclaresNullableGrantFunctions_RD1201(t *testing.T) {
	raw, err := os.ReadFile("apispec/swagger.json")
	require.NoError(t, err)
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Type json.RawMessage `json:"type"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	require.NoError(t, json.Unmarshal(raw, &spec))

	for _, schema := range []string{
		"privacy-proxy_internal_rbac.ContractGrant",
		// RD-1265 moved the transport models to internal/apimodels and
		// exported them; swag names schemas after the declaring package.
		"privacy-proxy_internal_apimodels.ContractGrantCreateRequest",
		"privacy-proxy_internal_apimodels.ContractGrantUpdateRequest",
	} {
		s, ok := spec.Components.Schemas[schema]
		require.True(t, ok, "schema %s missing from spec", schema)
		prop, ok := s.Properties["functions"]
		require.True(t, ok, "schema %s has no functions property", schema)
		var types []string
		require.NoError(t, json.Unmarshal(prop.Type, &types),
			"schema %s functions.type must be a type LIST (array+null), got %s", schema, prop.Type)
		require.Contains(t, types, "array", "schema %s", schema)
		require.Contains(t, types, "null",
			"schema %s: functions must be declared nullable — did cmd/api-spec-postprocess run in make api-spec?", schema)
	}
}
