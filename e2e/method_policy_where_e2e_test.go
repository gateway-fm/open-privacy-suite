//go:build mockauth

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/rbac"
)

// adminJSON does an admin API call and returns status + body. setupE2E runs the
// admin API in dev mode (no ADMIN_API_TOKEN configured), where auth_method=="" →
// both requireSuperAdmin and denyOperatorOrgScoped/denyOperatorTenantRead pass;
// so no X-Admin-Token header is sent (sending a non-matching one would 401). The
// method-policy endpoints are tier-2 org-admin; dev mode satisfies that tier.
func adminJSON(t *testing.T, method, url string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, r)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// TestMethodPolicy_Where_And_Simulate_E2E exercises Example 4 (where-conditions)
// AND the simulate endpoint end-to-end against a real PaymentRegistry: a
// compliance DID may read only large payments; the simulator predicts the
// decision without a node call.
func TestMethodPolicy_Where_And_Simulate_E2E(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	database := srv.DB()
	ctx := context.Background()

	regABIJSON := mustReadTestdata(t, "PaymentRegistry.abi.json")
	bytecode := strings.TrimSpace(mustReadTestdata(t, "PaymentRegistry.bin"))
	parsedABI, err := abi.JSON(strings.NewReader(regABIJSON))
	require.NoError(t, err)
	contractAddr := deployToAnvilDirect(t, anvilAccount0, bytecode)

	// org + group + personas (alice=payer, compliance=desk, diana=unrelated).
	orgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "w-" + orgID[:8], Name: "W", Settings: map[string]any{}}))
	groupID := uuid.New().String()
	require.NoError(t, database.CreateGroup(ctx, &rbac.Group{ID: groupID, OrgID: orgID, Slug: "g", Name: "payment"}))
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, Claims: []rbac.Claim{},
		AllowedMethods: []string{"eth_call", "eth_sendTransaction", "eth_getTransactionReceipt"},
	}))
	personas := map[string]*mpPersona{
		"alice":      {did: "did:test:alice", addr: anvilAccount0},
		"compliance": {did: "did:test:compliance", addr: anvilAccount2},
		"diana":      {did: "did:test:diana", addr: anvilAccount3},
	}
	for _, p := range personas {
		u := &rbac.User{ID: uuid.New().String(), ExternalID: p.did, KYC: true}
		require.NoError(t, database.CreateUser(ctx, u))
		require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.New().String(), UserID: u.ID, GroupID: groupID}))
		require.NoError(t, database.SystemLinkEthAddress(ctx, p.did, p.addr))
		p.token = getJWTToken(t, serverURL, p.did)
	}
	require.NoError(t, database.CreateContract(ctx, &rbac.Contract{
		ID: uuid.New().String(), OrgID: orgID, Address: strings.ToLower(contractAddr), Name: "PaymentRegistry", ABI: regABIJSON, Metadata: map[string]any{},
	}))
	require.NoError(t, database.CreateContractGrant(ctx, &rbac.ContractGrant{ID: uuid.New().String(), ContractID: mpContractID(t, database, contractAddr), GroupID: groupID}))

	// Provision the where-policy via the tier-2 org-admin endpoint (exercises the
	// handler + ABI validation, not just the DB).
	wherePolicy := map[string]any{"records": map[string]any{"payment": map[string]any{
		"capture": []any{map[string]any{
			"method": "createPayment(string,address,uint256)",
			"key":    map[string]any{"source": "param", "index": 0},
			"remember": map[string]any{
				"payer":  map[string]any{"source": "sender", "merge": "set_once"},
				"amount": map[string]any{"source": "param", "index": 2, "merge": "set_once"},
			},
		}},
		"access": []any{map[string]any{
			"method": "getPaymentInfo(string)",
			"key":    map[string]any{"source": "param", "index": 0},
			"allow": []any{
				map[string]any{"callerIn": []string{"payer"}},
				map[string]any{"callerIn": []string{"did:test:compliance"}, "where": map[string]any{"field": "amount", "op": "gte", "value": "1000000"}},
			},
			"onNoRecord": "deny", "else": "deny",
		}},
	}}}
	st, body := adminJSON(t, "PUT", serverURL+"/api/v1/admin/orgs/"+orgID+"/contracts/"+contractAddr+"/method-policies",
		map[string]any{"method_policies": wherePolicy})
	require.Equal(t, http.StatusOK, st, "policy PUT failed: %s", body)

	// Two payments: PAY-BIG (>=1M) and PAY-SMALL (<1M).
	sendCreate := func(id string, amount int64) {
		data, e := parsedABI.Pack("createPayment", id, common.HexToAddress(anvilAccount1), big.NewInt(amount))
		require.NoError(t, e)
		h := sendTxWithVisibleTo(t, serverURL, orgID, personas["alice"].token, map[string]any{
			"from": personas["alice"].addr, "to": contractAddr, "data": "0x" + common.Bytes2Hex(data), "gas": "0x100000",
		}, nil)
		require.Equal(t, "0x1", waitForReceipt(t, serverURL, orgID, personas["alice"].token, h)["status"])
	}
	sendCreate("PAY-BIG", 2000000)
	sendCreate("PAY-SMALL", 500000)
	waitForCapture(t, database, orgID, strings.ToLower(contractAddr), "payment", "PAY-BIG")
	waitForCapture(t, database, orgID, strings.ToLower(contractAddr), "payment", "PAY-SMALL")

	readAs := func(p *mpPersona, id string) map[string]any {
		data, _ := parsedABI.Pack("getPaymentInfo", id)
		return jsonRPCCall(t, serverURL, orgID, p.token, "eth_call",
			[]any{map[string]any{"from": p.addr, "to": contractAddr, "data": "0x" + common.Bytes2Hex(data)}, "latest"})
	}

	// where in action: compliance reads the big payment, is denied the small one.
	require.Nil(t, readAs(personas["compliance"], "PAY-BIG")["error"], "compliance must read the large payment (where amount>=1M)")
	require.NotNil(t, readAs(personas["compliance"], "PAY-SMALL")["error"], "compliance must be denied the small payment (where fails)")
	// payer reads both regardless of amount; unrelated denied both.
	require.Nil(t, readAs(personas["alice"], "PAY-SMALL")["error"], "payer must read own small payment")
	require.NotNil(t, readAs(personas["diana"], "PAY-BIG")["error"], "unrelated denied")

	// Simulator predicts the same, without a node call.
	simulate := func(callerDID, key string) methodPolicySimResp {
		st, body := adminJSON(t, "POST", serverURL+"/api/v1/admin/orgs/"+orgID+"/contracts/"+contractAddr+"/method-policies/simulate",
			map[string]any{"method": "getPaymentInfo(string)", "record_key": key, "caller_did": callerDID})
		require.Equal(t, http.StatusOK, st, "simulate failed: %s", body)
		var out methodPolicySimResp
		require.NoError(t, json.Unmarshal(body, &out))
		return out
	}
	require.Equal(t, "allow", simulate("did:test:compliance", "PAY-BIG").Result, "sim: compliance allowed on big")
	require.Equal(t, "deny", simulate("did:test:compliance", "PAY-SMALL").Result, "sim: compliance denied on small")
	require.Equal(t, "allow", simulate("did:test:alice", "PAY-SMALL").Result, "sim: payer allowed")
	require.Equal(t, "deny", simulate("did:test:diana", "PAY-BIG").Result, "sim: unrelated denied")
	// admit-set is disclosed to the tier-2 org admin.
	require.Contains(t, simulate("did:test:alice", "PAY-BIG").Captured["payer"], "did:test:alice")
}

type methodPolicySimResp struct {
	Result   string              `json:"result"`
	Captured map[string][]string `json:"captured"`
}
