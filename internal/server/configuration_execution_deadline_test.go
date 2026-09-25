package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/policydsl"
)

func TestConfigurationExecutionSubmissionOutlivesOrdinaryWriteDeadline(t *testing.T) {
	f := configurationAPI(t)
	path := "/api/v1/admin/orgs/" + f.orgID + "/configuration/execution-rules"
	contextResponse := f.request(t, f.readonly, http.MethodGet, path+"/context", nil)
	require.Equal(t, http.StatusOK, contextResponse.Code, contextResponse.Body.String())
	var view apimodels.ConfigurationContext
	require.NoError(t, json.Unmarshal(contextResponse.Body.Bytes(), &view))

	// Use a real socket: ResponseRecorder cannot expose the server's expired
	// write deadline. Even this small set takes longer to compile than 50ms.
	srv := httptest.NewUnstartedServer(f.router)
	srv.Config.WriteTimeout = 50 * time.Millisecond
	srv.Start()
	defer srv.Close()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+path+"/revisions", bytes.NewReader(view.Source))
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+f.readonly)
	request.Header.Set("Content-Type", "application/json")
	client := srv.Client()
	client.Timeout = 30 * time.Second
	response, err := client.Do(request)
	require.NoError(t, err, "the compiled draft response must reach the author")
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, response.StatusCode, string(body))
	var revision apimodels.ConfigurationRevision
	require.NoError(t, json.Unmarshal(body, &revision))
	set, err := policydsl.DecodeArtifactSet(revision.Artifact)
	require.NoError(t, err)
	require.Greater(t, len(set.Groups), 1)
}
