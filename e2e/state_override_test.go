package e2e

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"privacy-proxy/internal/testutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1305 — end-to-end proof that the proxy rejects a state/code override on
// eth_call against a live node, even for a user who is granted on the target
// contract, while a plain eth_call to the same contract still passes through.
//
// Reuses the tiered-storage fixture (setupStorageAccessTest): the read user
// has eth_call allowed and a grant on setup.contractAddr.

func buildEthCallWithStateOverrideBody(contractAddr string) []byte {
	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params": []any{
			map[string]any{"to": contractAddr, "data": "0x"},
			"latest",
			// A non-empty code override is an unsupported simulation option.
			map[string]any{contractAddr: map[string]any{"code": "0x00"}},
		},
		"id": 1,
	}
	body, _ := json.Marshal(reqBody)
	return body
}

func TestE2E_StateOverrideRejected(t *testing.T) {
	if os.Getenv("E2E_NODE_URL") == "" {
		// Use a test-owned node unless the harness supplies one explicitly.
		t.Setenv("ANVIL_URL", "")
		nodeURL, cleanupNode := testutil.SetupAnvilContainer(t)
		t.Cleanup(cleanupNode)
		t.Setenv("E2E_NODE_URL", nodeURL)
	}
	mockVerifier := &mockPrivadoVerifier{userDID: "did:privado:storage_read_user"}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	setup := setupStorageAccessTest(t, srv.DB())
	accessToken := getJWTToken(t, serverURL, setup.readUserDID)

	t.Run("eth_call with state override is denied opaquely", func(t *testing.T) {
		body := buildEthCallWithStateOverrideBody(setup.contractAddr)
		resp, respBody := doRPCRequest(t, serverURL, accessToken, body)

		assert.Equal(t, http.StatusNotFound, resp.StatusCode,
			"eth_call carrying a state override must be denied with opaque 404; got: %s", string(respBody))
		assertOpaqueErrorBody(t, respBody, "override", "code", "storage")
	})

	t.Run("plain eth_call to the same contract still passes through", func(t *testing.T) {
		body := buildEthCallBody(setup.contractAddr, "0x")
		resp, respBody := doRPCRequest(t, serverURL, accessToken, body)

		require.Equal(t, http.StatusOK, resp.StatusCode,
			"plain eth_call must reach the test node successfully: %s", string(respBody))
		var result struct {
			Result *string         `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		require.NoError(t, json.Unmarshal(respBody, &result))
		require.True(t, len(result.Error) == 0 || string(result.Error) == "null", "unexpected node error: %s", result.Error)
		require.NotNil(t, result.Result, "node response must contain a successful result")
		assert.Equal(t, "0x", *result.Result, "the DB-registered fixture address has no deployed code")
	})
}
