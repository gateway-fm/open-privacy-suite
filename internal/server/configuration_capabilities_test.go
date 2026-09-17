package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/policydsl"
)

func TestConfigurationContextReportsCapabilitiesAndMissingCompiler(t *testing.T) {
	f := configurationAPI(t)
	for _, available := range []bool{true, false} {
		f.server.policyCompiler = policydsl.NewCompiler()
		if !available {
			f.server.policyCompiler.Path = filepath.Join(t.TempDir(), "missing-solc")
		}
		response := f.request(t, f.readonly, http.MethodGet, f.base()+"/context", nil)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		var body struct {
			Capabilities struct {
				APIVersion       string   `json:"apiVersion"`
				Kinds            []string `json:"kinds"`
				HumanOnlyKinds   []string `json:"humanOnlyKinds"`
				ApprovalModes    []string `json:"approvalModes"`
				MaxDocumentBytes int      `json:"maxDocumentBytes"`
				Compiler         struct {
					Version   string `json:"version"`
					Available bool   `json:"available"`
				} `json:"compiler"`
			} `json:"capabilities"`
		}
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
		require.Equal(t, configuration.APIVersion, body.Capabilities.APIVersion)
		require.Equal(t, []string{"groups", "contract-registry", "compliance", "approvers", "execution-rules"}, body.Capabilities.Kinds)
		require.Equal(t, []string{"approvers", "platform"}, body.Capabilities.HumanOnlyKinds)
		require.Equal(t, []string{"human", "trusted-ci"}, body.Capabilities.ApprovalModes)
		require.Equal(t, configuration.MaxDocumentBytes, body.Capabilities.MaxDocumentBytes)
		require.Equal(t, policydsl.SolidityVersion, body.Capabilities.Compiler.Version)
		require.Equal(t, available, body.Capabilities.Compiler.Available)
	}
}
