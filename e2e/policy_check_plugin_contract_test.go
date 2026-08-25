//go:build mockauth

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// pluginPolicyCheckPayload is the request body emitted by an external policy client.
//
// This test pins the public wire shape. A payload that derives no target can
// otherwise produce a plausible denial instead of an input error.
//
// The %s placeholders are the two addresses the fixture below registers.
const pluginPolicyCheckPayload = `{"subject":{"address":"%s"},"operation":{"method":"eth_sendTransaction","params":[{"from":"%s","to":"%s","data":"%s","value":"0x0"}]}}`

// transfer(address,uint256) with two argument words, i.e. a selector-bearing payload.
const pluginTransferCalldata = "0xa9059cbb" +
	"00000000000000000000000000000000000000000000000000000000000000ff" +
	"0000000000000000000000000000000000000000000000000000000000000001"

// TestPolicyCheckAcceptsRPCPayload proves that the endpoint derives the target
// and function selector from the JSON-RPC payload.
func TestPolicyCheckAcceptsRPCPayload(t *testing.T) {
	const adminToken = "pc-plugin-contract-token"
	srv, serverURL, cleanup := setupPolicyCheckE2E(t, adminToken, "")
	defer cleanup()
	database := srv.DB()
	ctx := context.Background()

	orgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{
		ID: orgID, Slug: "pc-plugin-org", Name: "PC Plugin Org", Settings: map[string]any{},
	}))

	// The originator on the source chain, linked to a DID on this chain. This link is the whole
	// point of the address-subject path: the plugin knows an address and nothing else.
	originator := "0x00000000000000000000000000000000000a11ce"
	originatorDID := "did:pc-plugin:originator"
	groupID := createGroup(t, database, orgID, "pc-plugin-group", nil, false)
	attachAllowedMethods(t, database, groupID, []string{"eth_sendTransaction"})
	createUserInGroup(t, database, originatorDID, groupID)
	require.NoError(t, database.SystemLinkEthAddress(ctx, originatorDID, originator))

	grantedDest := "0x00000000000000000000000000000000000b0b00"
	ungrantedDest := "0x00000000000000000000000000000000000dead0"
	grantedID := createContract(t, database, orgID, grantedDest, "PCPluginGranted")
	createContract(t, database, orgID, ungrantedDest, "PCPluginUngranted")
	createGrant(t, database, grantedID, groupID)

	// An address the plugin might legitimately see but that this chain knows nothing about.
	unknownOriginator := "0x00000000000000000000000000000000000f0f0f"

	tests := []struct {
		name        string
		from        string
		to          string
		data        string
		wantAllowed bool
	}{
		{"granted contract, selector-bearing calldata", originator, grantedDest, pluginTransferCalldata, true},
		{"granted contract, bare value transfer", originator, grantedDest, "0x", true},
		{"contract this org holds but has not granted", originator, ungrantedDest, pluginTransferCalldata, false},
		{"originator unknown to this chain", unknownOriginator, grantedDest, pluginTransferCalldata, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(pluginPolicyCheckPayload, tc.from, tc.from, tc.to, tc.data)
			allowed, reason := postRawPolicyCheck(t, serverURL, adminToken, body)
			require.Equal(t, tc.wantAllowed, allowed, "reason=%q", reason)
			if !tc.wantAllowed {
				// The plugin surfaces this straight into a peer-visible abort reason, so it must
				// stay a short category and never carry RBAC internals.
				require.NotEmpty(t, reason)
				require.Less(t, len(reason), 120)
				require.NotContains(t, strings.ToLower(reason), "sql")
				require.NotContains(t, strings.ToLower(reason), "organization")
			}
		})
	}
}

// TestPolicyCheckDerivesSelectorFromRPCPayload verifies function-level rules.
func TestPolicyCheckDerivesSelectorFromRPCPayload(t *testing.T) {
	const adminToken = "pc-plugin-selector-token"
	srv, serverURL, cleanup := setupPolicyCheckE2E(t, adminToken, "")
	defer cleanup()
	database := srv.DB()
	ctx := context.Background()

	orgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{
		ID: orgID, Slug: "pc-selector-org", Name: "PC Selector Org", Settings: map[string]any{},
	}))

	originator := "0x00000000000000000000000000000000000a11ce"
	originatorDID := "did:pc-plugin:selector"
	groupID := createGroup(t, database, orgID, "pc-selector-group", nil, false)
	attachAllowedMethods(t, database, groupID, []string{"eth_sendTransaction"})
	createUserInGroup(t, database, originatorDID, groupID)
	require.NoError(t, database.SystemLinkEthAddress(ctx, originatorDID, originator))

	dest := "0x00000000000000000000000000000000000b0b00"
	contractID := createContract(t, database, orgID, dest, "PCSelectorGated")
	createGrantWithFunctionRule(t, database, contractID, groupID, "0xa9059cbb")

	allowed, _ := postRawPolicyCheck(t, serverURL, adminToken,
		fmt.Sprintf(pluginPolicyCheckPayload, originator, originator, dest, pluginTransferCalldata))
	require.True(t, allowed, "the permitted selector must be allowed")

	// approve(address,uint256): same contract, same subject, different selector.
	const approveCalldata = "0x095ea7b3" +
		"00000000000000000000000000000000000000000000000000000000000000ff" +
		"0000000000000000000000000000000000000000000000000000000000000001"
	allowed, reason := postRawPolicyCheck(t, serverURL, adminToken,
		fmt.Sprintf(pluginPolicyCheckPayload, originator, originator, dest, approveCalldata))
	require.False(t, allowed, "a selector outside the rule must deny (RD-435), reason=%q", reason)
}

// createGrantWithFunctionRule restricts a grant to a single selector, the shape that makes the
// server's own selector derivation load-bearing.
func createGrantWithFunctionRule(t *testing.T, database *db.DB, contractID, groupID, selector string) {
	t.Helper()
	require.NoError(t, database.CreateContractGrant(context.Background(), &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID,
		GroupID:    groupID,
		Functions:  []rbac.FunctionRule{{Selector: selector}},
	}))
}

func postRawPolicyCheck(t *testing.T, serverURL, token, rawBody string) (bool, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/v1/admin/policy-check", bytes.NewReader([]byte(rawBody)))
	require.NoError(t, err)
	req.Header.Set("X-Admin-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "plugin payload was not understood by the server")
	var out struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out.Allowed, out.Reason
}
