package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/apimodels"
)

func TestConfigurationContextReportsCurrentApprovalEligibility(t *testing.T) {
	f := configurationAPI(t)
	for _, test := range []struct {
		token, kind string
		approve     bool
	}{{f.readonly, "service", false}, {f.service, "service", false}, {f.admin, "human", true}} {
		response := f.request(t, test.token, http.MethodGet, f.base()+"/context", nil)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		var out apimodels.ConfigurationContext
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &out))
		require.NotEmpty(t, out.Viewer.PrincipalID)
		require.Equal(t, test.kind, out.Viewer.PrincipalKind)
		require.Equal(t, test.approve, out.Viewer.CanActivate)
	}
}
