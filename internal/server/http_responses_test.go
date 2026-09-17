package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/policydsl"
)

// RD-934 rule 4: only errors whose text is written for the caller reach the
// wire. A driver/internal error must become the opaque fallback.
func TestRespondClientErrorKeepsUntypedErrorsOpaque(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"untyped", errors.New(`pq: relation "internal_table" does not exist password=secret`), "invalid request"},
		{"server validation", clientErrorf("frame %d: calldata is longer than the %d-character limit", 2, 10), "frame 2: calldata is longer than the 10-character limit"},
		{"prefixed typed", clientErrorWithPrefix("stored policy is unreadable", mustValidationError(t)), "stored policy is unreadable: " + mustValidationError(t).Error()},
		{"prefixed untyped", clientErrorWithPrefix("stored policy is unreadable", errors.New("dial tcp 10.0.0.1:5432: connection refused")), "stored policy is unreadable"},
		{"source", mustSourceError(t), "document must be 1..1048576 bytes"},
		{"conflict", db.ConfigurationConflict("execution policy: %s", mustValidationError(t)), "configuration conflict: execution policy: " + mustValidationError(t).Error()},
		{"conflict hides untyped cause", db.ConfigurationConflict("registry import requires repair: %w", errors.New("pq: duplicate key value violates unique constraint contracts_pkey")), "configuration conflict: registry import requires repair: internal error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(response)
			respondClientError(c, http.StatusBadRequest, tc.err, "invalid request", "test")
			require.Equal(t, http.StatusBadRequest, response.Code)
			require.JSONEq(t, `{"error":`+mustJSONString(tc.want)+`}`, response.Body.String())
			require.NotContains(t, response.Body.String(), "secret")
			require.NotContains(t, response.Body.String(), "pq:")
			require.NotContains(t, response.Body.String(), "10.0.0.1")
		})
	}
}

func mustValidationError(t *testing.T) error {
	t.Helper()
	_, err := policydsl.Parse([]byte("{"))
	require.Error(t, err)
	var typed *policydsl.ValidationError
	require.ErrorAs(t, err, &typed)
	return err
}

func mustSourceError(t *testing.T) error {
	t.Helper()
	_, err := configuration.Parse(nil)
	require.Error(t, err)
	var typed *configuration.SourceError
	require.ErrorAs(t, err, &typed)
	return err
}

func mustJSONString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
