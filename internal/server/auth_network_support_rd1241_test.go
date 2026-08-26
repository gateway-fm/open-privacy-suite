package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	privadoauth "privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1241: when a wallet's iden3 network has no registered state resolver, the
// iden3 library rejects the proof with "<blockchain>:<network> resolver not
// found". That is the "network not configured on this deployment" case, and it
// deserves a legible outcome rather than being lumped in with a generic
// verification failure.
//
// The extraction must be conservative: the library error can carry dialled RPC
// endpoints and other internal topology, none of which may reach the
// (unauthenticated) caller — RD-934 / RD-1178.
func TestUnsupportedNetworkFromVerifyError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		network string
		ok      bool
	}{
		{
			name:    "bare library error",
			err:     fmt.Errorf("billions:main resolver not found"),
			network: "billions:main",
			ok:      true,
		},
		{
			name:    "wrapped by the auth library",
			err:     fmt.Errorf("failed to verify state: %w", fmt.Errorf("billions:main resolver not found")),
			network: "billions:main",
			ok:      true,
		},
		{
			name:    "a different network",
			err:     fmt.Errorf("linea:main resolver not found"),
			network: "linea:main",
			ok:      true,
		},
		{
			name: "error carrying an RPC endpoint still yields only the network",
			err: fmt.Errorf("Post \"https://internal-rpc.example.invalid/v1/secret-key\": dial tcp: lookup failed: "+
				"%w", fmt.Errorf("billions:main resolver not found")),
			network: "billions:main",
			ok:      true,
		},
		{
			name: "unrelated verification failure is not a network problem",
			err:  fmt.Errorf("invalid proof: gist root does not match"),
			ok:   false,
		},
		{
			name: "phrase without a well-formed network is not matched",
			err:  fmt.Errorf("state resolver not found"),
			ok:   false,
		},
		{
			name: "nil error",
			err:  nil,
			ok:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			network, ok := unsupportedNetworkFromVerifyError(tc.err)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.network, network)
			// Whatever we extracted must be a bare "blockchain:network" token —
			// never a URL, never a sentence.
			if ok {
				assert.NotContains(t, network, "/")
				assert.NotContains(t, network, " ")
			}
		})
	}
}

// The wallet gets told which network is unsupported (it is the wallet's own
// network, so that is zero disclosure) but never the raw library text and never
// the RPC endpoint the resolver would have dialled.
func TestHandleAuthCallback_UnsupportedNetwork(t *testing.T) {
	srv, _ := setupTestServerForAuth(t)
	defer srv.db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/request", srv.handleAuthRequest)
	router.POST("/auth/callback", srv.handleAuthCallback)

	req1 := httptest.NewRequest("POST", "/auth/request", nil)
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	var authReqResp AuthRequestResponse
	require.NoError(t, json.Unmarshal(w1.Body.Bytes(), &authReqResp))

	const secretRPC = "https://internal-rpc.example.invalid/v1/super-secret-key"
	mockVerifier := srv.privadoVerifier.(*mockPrivadoVerifier)
	mockVerifier.verifyWithProofDataFunc = func(ctx context.Context, jwzToken string, ar *protocol.AuthorizationRequestMessage, verifierID string) (*privadoauth.VerificationResult, error) {
		return nil, fmt.Errorf("Post %q: dial tcp: %w", secretRPC, fmt.Errorf("billions:main resolver not found"))
	}

	jsonBody, _ := json.Marshal(map[string]any{"token": "some.jwz.token"})
	req2 := httptest.NewRequest("POST", "/auth/callback?session="+authReqResp.SessionID, bytes.NewReader(jsonBody))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	require.Equal(t, http.StatusUnauthorized, w2.Code)
	body := w2.Body.String()

	// Names the network, so an operator reading a customer's screenshot can act.
	assert.Contains(t, body, "billions:main")
	// RD-934 / RD-1178: no internal topology, no raw library phrasing.
	assert.NotContains(t, body, secretRPC)
	assert.NotContains(t, body, "internal-rpc.example.invalid")
	assert.NotContains(t, body, "resolver not found")
	assert.NotContains(t, body, "dial tcp")

	var resp UnsupportedNetworkError
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &resp))
	assert.Equal(t, "network_not_supported", resp.Error)
	assert.Equal(t, "billions:main", resp.Network)
	assert.NotEmpty(t, resp.Message)
}

// A generic verification failure must keep its existing opaque shape — this
// change must not turn every failure into a network report.
func TestHandleAuthCallback_GenericFailureStaysOpaque(t *testing.T) {
	srv, _ := setupTestServerForAuth(t)
	defer srv.db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/request", srv.handleAuthRequest)
	router.POST("/auth/callback", srv.handleAuthCallback)

	req1 := httptest.NewRequest("POST", "/auth/request", nil)
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	var authReqResp AuthRequestResponse
	require.NoError(t, json.Unmarshal(w1.Body.Bytes(), &authReqResp))

	mockVerifier := srv.privadoVerifier.(*mockPrivadoVerifier)
	mockVerifier.verifyWithProofDataFunc = func(ctx context.Context, jwzToken string, ar *protocol.AuthorizationRequestMessage, verifierID string) (*privadoauth.VerificationResult, error) {
		return nil, fmt.Errorf("invalid proof: gist root mismatch for issuer did:iden3:privado:main:xyz")
	}

	jsonBody, _ := json.Marshal(map[string]any{"token": "some.jwz.token"})
	req2 := httptest.NewRequest("POST", "/auth/callback?session="+authReqResp.SessionID, bytes.NewReader(jsonBody))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	require.Equal(t, http.StatusUnauthorized, w2.Code)
	body := w2.Body.String()
	assert.Contains(t, body, "verification failed")
	assert.NotContains(t, body, "network_not_supported")
	assert.NotContains(t, body, "gist root")
	assert.NotContains(t, body, "did:iden3")
}

// The login UI must not advertise a network this deployment cannot verify, so
// /auth/providers reports the registered iden3 networks alongside the providers.
func TestHandleAuthProviders_ReportsNetworks(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newVerifier := func(t *testing.T, extra ...privadoauth.NetworkResolver) *privadoauth.PrivadoVerifier {
		t.Helper()
		v, err := privadoauth.NewPrivadoVerifier(
			"https://rpc-mainnet.privado.id", "", privadoauth.PrivadoMainnetStateContract, extra...)
		require.NoError(t, err)
		return v
	}

	tests := []struct {
		name     string
		verifier PrivadoVerifier
		networks []string
	}{
		{
			name: "billions configured is advertised",
			verifier: newVerifier(t, privadoauth.NetworkResolver{
				Key:           "billions:main",
				RPCURL:        "https://billions.example/rpc",
				StateContract: privadoauth.BillionsMainnetStateContract,
			}),
			networks: []string{"billions:main", "privado:main"},
		},
		{
			name:     "billions unconfigured is not advertised",
			verifier: newVerifier(t),
			networks: []string{"privado:main"},
		},
		{
			name:     "no verifier advertises nothing",
			verifier: nil,
			networks: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{config: &config.Config{Environment: "development"}}
			if tc.verifier != nil {
				s.privadoVerifier = tc.verifier
			}
			router := gin.New()
			router.GET("/api/v1/auth/providers", s.handleAuthProviders)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/auth/providers", nil))
			require.Equal(t, http.StatusOK, w.Code)

			var resp ProvidersResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, tc.networks, resp.Networks)
			assert.Contains(t, resp.Providers, "privado", "provider list must stay unchanged")
			// No RPC endpoints in a public response.
			assert.NotContains(t, strings.Join(resp.Networks, ","), "http")
		})
	}
}
