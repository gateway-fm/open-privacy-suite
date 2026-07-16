//go:build mockauth

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// Anvil deterministic accounts 2 & 3 (0 & 1 are defined in create2_test.go).
const (
	anvilAccount2 = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
	anvilAccount3 = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
)

// The Partior getPaymentInfo policy: capture payer(sender)/payee(param1)/
// audience(visibleTo) on createPayment; gate getPaymentInfo by those fields or
// the returned payer/payee.
const partiorMethodPolicy = `{
  "records": {
    "payment": {
      "capture": [
        {"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},
         "remember":{
           "payer":{"source":"sender","merge":"set_once"},
           "payee":{"source":"param","index":1,"merge":"set_once"},
           "audience":{"source":"visibleTo","merge":"union"}}}
      ],
      "access": [
        {"method":"getPaymentInfo(string)","key":{"source":"param","index":0},
         "allow":[
           {"callerIn":["payer","payee","audience"]},
           {"callerIn":{"source":"return","paths":["payer","payee"],"kind":"address"}}
         ],
         "onNoRecord":"deny","else":"deny"}
      ]
    }
  }
}`

// TestMethodPolicy_PartiorS5_E2E is the definitive RD-1206 test: a real
// PaymentRegistry on anvil, a real method policy, real signed sends through the
// proxy, and the reconciler promoting captures — asserting the Partior S5
// matrix (payer/payee/settlement read, unrelated denied), parameter-bound.
func TestMethodPolicy_PartiorS5_E2E(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	database := srv.DB()
	ctx := context.Background()

	regABIJSON := mustReadTestdata(t, "PaymentRegistry.abi.json")
	bytecode := strings.TrimSpace(mustReadTestdata(t, "PaymentRegistry.bin"))
	parsedABI, err := abi.JSON(strings.NewReader(regABIJSON))
	require.NoError(t, err)

	// 1. Deploy PaymentRegistry straight to anvil (deploy is not the unit under test).
	contractAddr := deployToAnvilDirect(t, anvilAccount0, bytecode)
	t.Logf("PaymentRegistry deployed at %s", contractAddr)

	// 2. RBAC + policy setup at the DB level.
	orgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "s5-" + orgID[:8], Name: "S5", Settings: map[string]any{}}))
	groupID := uuid.New().String()
	require.NoError(t, database.CreateGroup(ctx, &rbac.Group{ID: groupID, OrgID: orgID, Slug: "g", Name: "payment"}))
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, Claims: []rbac.Claim{},
		AllowedMethods: []string{"eth_call", "eth_sendTransaction", "eth_getTransactionReceipt", "eth_getTransactionByHash"},
	}))

	type persona struct{ did, addr, token string }
	personas := map[string]*persona{
		"alice":   {did: "did:test:alice", addr: anvilAccount0},   // payer
		"bob":     {did: "did:test:bob", addr: anvilAccount1},     // payee
		"charlie": {did: "did:test:charlie", addr: anvilAccount2}, // settlement (audience)
		"diana":   {did: "did:test:diana", addr: anvilAccount3},   // unrelated
	}
	for _, p := range personas {
		u := &rbac.User{ID: uuid.New().String(), ExternalID: p.did, KYC: true}
		require.NoError(t, database.CreateUser(ctx, u))
		require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.New().String(), UserID: u.ID, GroupID: groupID}))
		require.NoError(t, database.SystemLinkEthAddress(ctx, p.did, p.addr))
		p.token = getJWTToken(t, serverURL, p.did)
	}

	// contract + ABI + grant (all functions) + method policy
	contract := &rbac.Contract{ID: uuid.New().String(), OrgID: orgID, Address: strings.ToLower(contractAddr), Name: "PaymentRegistry", ABI: regABIJSON, Metadata: map[string]any{}}
	require.NoError(t, database.CreateContract(ctx, contract))
	require.NoError(t, database.CreateContractGrant(ctx, &rbac.ContractGrant{ID: uuid.New().String(), ContractID: contract.ID, GroupID: groupID}))
	require.NoError(t, database.UpdateContractMethodPolicies(ctx, contract.ID, []byte(partiorMethodPolicy)))

	// 3. createPayment(PAY-1, bob, 1000) as alice, visibleTo=[charlie].
	createData, err := parsedABI.Pack("createPayment", "PAY-1", common.HexToAddress(personas["bob"].addr), big.NewInt(1000))
	require.NoError(t, err)
	txHash := sendTxWithVisibleTo(t, serverURL, orgID, personas["alice"].token, map[string]any{
		"from": personas["alice"].addr, "to": contractAddr, "data": "0x" + common.Bytes2Hex(createData), "gas": "0x100000",
	}, []string{personas["charlie"].did})
	rc := waitForReceipt(t, serverURL, orgID, personas["alice"].token, txHash)
	require.Equal(t, "0x1", rc["status"], "createPayment must succeed")

	// 4. Wait for the reconciler to promote the capture (5s tick).
	waitForCapture(t, database, orgID, strings.ToLower(contractAddr), "payment", "PAY-1")

	// 5. getPaymentInfo(PAY-1) per persona.
	readData, err := parsedABI.Pack("getPaymentInfo", "PAY-1")
	require.NoError(t, err)
	readHex := "0x" + common.Bytes2Hex(readData)
	getInfo := func(p *persona) map[string]any {
		return jsonRPCCall(t, serverURL, orgID, p.token, "eth_call",
			[]any{map[string]any{"from": p.addr, "to": contractAddr, "data": readHex}, "latest"})
	}

	assertAllowed := func(name string, resp map[string]any) {
		if resp["error"] != nil {
			t.Fatalf("%s: expected allow, got error %v", name, resp["error"])
		}
		res, _ := resp["result"].(string)
		require.NotEmpty(t, res, "%s: empty result", name)
		require.NotEqual(t, "0x", res, "%s: result blanked", name)
	}
	assertDenied := func(name string, resp map[string]any) {
		if resp["error"] == nil {
			t.Fatalf("%s: expected deny, got result %v", name, resp["result"])
		}
	}

	assertAllowed("alice(payer)", getInfo(personas["alice"]))          // capture sender
	assertAllowed("bob(payee)", getInfo(personas["bob"]))              // capture param
	assertAllowed("charlie(settlement)", getInfo(personas["charlie"])) // capture visibleTo audience
	assertDenied("diana(unrelated)", getInfo(personas["diana"]))       // matches nothing

	// 6. Parameter-bound: alice reading a different, uncaptured key is denied
	//    (no capture rows; the record doesn't exist so the return carries zero
	//    addresses).
	otherData, err := parsedABI.Pack("getPaymentInfo", "PAY-UNKNOWN")
	require.NoError(t, err)
	otherResp := jsonRPCCall(t, serverURL, orgID, personas["alice"].token, "eth_call",
		[]any{map[string]any{"from": personas["alice"].addr, "to": contractAddr, "data": "0x" + common.Bytes2Hex(otherData)}, "latest"})
	assertDenied("alice(other record)", otherResp)
}

// --- helpers ---

func mustReadTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err, "read testdata/%s", name)
	return string(b)
}

// deployToAnvilDirect deploys bytecode straight to anvil (bypassing the proxy),
// using an unlocked account, and returns the deployed contract address.
func deployToAnvilDirect(t *testing.T, from, bytecode string) string {
	t.Helper()
	send := anvilDirect(t, "eth_sendTransaction", []any{map[string]any{"from": from, "data": bytecode, "gas": "0x300000"}})
	txHash, _ := send["result"].(string)
	require.NotEmpty(t, txHash, "deploy tx hash; resp=%v", send)
	for i := 0; i < 50; i++ {
		rc := anvilDirect(t, "eth_getTransactionReceipt", []any{txHash})
		if m, ok := rc["result"].(map[string]any); ok && m != nil {
			addr, _ := m["contractAddress"].(string)
			require.NotEmpty(t, addr, "deploy receipt missing contractAddress")
			return addr
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("deploy never mined")
	return ""
}

func anvilDirect(t *testing.T, method string, params []any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	resp, err := http.Post("http://localhost:8545", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// sendTxWithVisibleTo posts eth_sendTransaction through the proxy with a
// top-level visibleTo (RD-1163) and returns the tx hash.
func sendTxWithVisibleTo(t *testing.T, serverURL, orgID, token string, txObj map[string]any, visibleTo []string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "eth_sendTransaction",
		"params": []any{txObj}, "visibleTo": visibleTo,
	})
	req, _ := http.NewRequest("POST", serverURL+"/rpc/"+orgID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out), "send resp: %s", raw)
	require.Nil(t, out["error"], "createPayment send error: %v", out["error"])
	h, _ := out["result"].(string)
	require.NotEmpty(t, h, "no tx hash: %s", raw)
	return h
}

// waitForCapture polls until the reconciler has promoted the payer capture for
// the record (bounded — the tick is 5s).
func waitForCapture(t *testing.T, database *db.DB, orgID, contractAddr, recordType, key string) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < 40; i++ { // up to ~20s
		caps, err := database.GetRecordCaptures(ctx, orgID, contractAddr, recordType, key)
		require.NoError(t, err)
		hasPayer := false
		for _, c := range caps {
			if c.Field == "payer" {
				hasPayer = true
			}
		}
		if hasPayer {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("capture never promoted for record " + key)
}
