package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Creation-shaped eth_call / eth_estimateGas (no `to`) against a real node.
//
// A call object without `to` makes the node execute `data` as
// contract-creation code. The proxy treats that shape as a deployment: it
// needs an authenticated caller holding the `deploy` claim, and the call is
// traced so every internal frame is validated against the caller's
// organizations before anything is forwarded.
//
// Fixtures are deployed straight to the node (not through the proxy) and then
// registered to their organizations, so the only proxied requests are the
// ones under test.

// creationSecretForeign / creationSecretOwn are the storage values the two
// fixture contracts hold. Neither starts with 0xEF (EIP-3541), so a creation
// call that returns them as "runtime code" is valid on the node.
const (
	creationSecretForeign = "5ec2e70000000000000000000000000000000000000000000000000000000b0b"
	creationSecretOwn     = "5ec2e70000000000000000000000000000000000000000000000000000000a0a"
	creationFundedAccount = "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720" // anvil account 9
)

// storageGetterInitcode deploys a contract that stores `secret` in slot 0 and
// whose runtime code returns slot 0 for any call.
//
//	constructor: PUSH32 secret PUSH1 0 SSTORE; CODECOPY runtime; RETURN runtime
//	runtime:     PUSH1 0 SLOAD PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN
func storageGetterInitcode(secret string) string {
	runtime := "600054600052602060" + "00f3"  // 11 bytes
	prefix := "7f" + secret + "600055"        // 36 bytes
	copier := "600b603060003960" + "0b6000f3" // 12 bytes; runtime starts at 48 (0x30)
	return "0x" + prefix + copier + runtime
}

// staticcallReaderInitcode is creation code that STATICCALLs `target` and
// returns the 32-byte answer as its "runtime code".
func staticcallReaderInitcode(target string) string {
	addr := strings.TrimPrefix(strings.ToLower(target), "0x")
	return "0x" +
		"6312345678" + "60e01b" + "600052" + // mstore(0, selector << 224)
		"6020" + "6000" + "6004" + "6000" + // retSize retOffset argsSize argsOffset
		"73" + addr + "5a" + "fa" + "50" + // PUSH20 target GAS STATICCALL POP
		"6020" + "6000" + "f3" // RETURN(0, 32)
}

// constantRuntime returns 42 for any call.
const constantRuntime = "602a60005260206000f3"

// createAndCallInitcode is creation code that deploys a child with the given
// runtime code, STATICCALLs it and returns the child's 32-byte answer — the
// shape of a constructor that deploys a helper and calls it.
func createAndCallInitcode(childRuntime string) string {
	runtimeLen := len(childRuntime) / 2
	childInit := fmt.Sprintf("60%02x600c60003960%02x6000f3", runtimeLen, runtimeLen) + childRuntime
	childLen := len(childInit) / 2
	return "0x" +
		fmt.Sprintf("60%02x601f600039", childLen) + // CODECOPY child initcode (at offset 31) to mem[0]
		fmt.Sprintf("60%02x60006000f0", childLen) + // CREATE(value 0, mem[0], len)
		"6020600060006000" + "84" + "5afa50" + // STATICCALL(gas, child, 0, 0, 0, 32)
		"60206000f3" + // RETURN(0, 32)
		childInit
}

// nodeRPC posts a JSON-RPC request straight to the node.
func nodeRPC(t *testing.T, nodeURL, method string, params []any) (json.RawMessage, error) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	require.NoError(t, err)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(nodeURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	if out.Error != nil {
		t.Fatalf("node %s error: %s", method, out.Error.Message)
	}
	return out.Result, nil
}

// deployOnNode deploys initcode from a funded node account (not through the
// proxy) and returns the created contract address.
func deployOnNode(t *testing.T, nodeURL, initcode string) string {
	t.Helper()
	raw, err := nodeRPC(t, nodeURL, "eth_sendTransaction", []any{map[string]any{
		"from": creationFundedAccount, "data": initcode, "gas": "0x100000",
	}})
	require.NoError(t, err)
	var txHash string
	require.NoError(t, json.Unmarshal(raw, &txHash))
	for i := 0; i < 50; i++ {
		raw, err = nodeRPC(t, nodeURL, "eth_getTransactionReceipt", []any{txHash})
		require.NoError(t, err)
		var receipt struct {
			ContractAddress string `json:"contractAddress"`
			Status          string `json:"status"`
		}
		if string(raw) != "null" {
			require.NoError(t, json.Unmarshal(raw, &receipt))
			require.Equal(t, "0x1", receipt.Status, "fixture deployment failed")
			return strings.ToLower(receipt.ContractAddress)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no receipt for fixture deployment %s", txHash)
	return ""
}

// proxyRPC posts a JSON-RPC request to the proxy's org-scoped endpoint.
func proxyRPC(t *testing.T, serverURL, orgID, token, method string, params []any) (int, string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	require.NoError(t, err)
	return proxyRPCBody(t, serverURL, orgID, token, string(body))
}

// proxyRPCBody posts a raw JSON-RPC body to the proxy's org-scoped endpoint.
func proxyRPCBody(t *testing.T, serverURL, orgID, token, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, serverURL+"/rpc/"+orgID, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(respBody)
}

func creationTestOrg(t *testing.T, database *db.DB, slug string) string {
	t.Helper()
	orgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(context.Background(), &rbac.Organization{
		ID: orgID, Slug: slug + "-" + orgID[:8], Name: slug, Settings: map[string]any{},
	}))
	return orgID
}

func TestE2E_CreationShapedCallIsDeployGatedAndTraced(t *testing.T) {
	nodeURL := os.Getenv("E2E_NODE_URL")
	if nodeURL == "" {
		nodeURL = "http://localhost:8545"
	}
	if _, err := nodeRPC(t, nodeURL, "eth_chainId", []any{}); err != nil {
		if os.Getenv("E2E_NODE_URL") == "" {
			t.Skipf("no node at %s (set E2E_NODE_URL): %v", nodeURL, err)
		}
		t.Fatalf("E2E_NODE_URL %s unreachable: %v", nodeURL, err)
	}
	// Fixtures are deployed from an unlocked dev account (Anvil's defaults).
	if raw, _ := nodeRPC(t, nodeURL, "eth_accounts", []any{}); !strings.Contains(strings.ToLower(string(raw)), strings.ToLower(creationFundedAccount)) {
		t.Skipf("node at %s has no unlocked %s (needs Anvil's default accounts)", nodeURL, creationFundedAccount)
	}

	// The harness leaves RUNTIME_TRACING_ETH_CALL_ENABLED off; calls without
	// `to` are traced regardless, like send-side deployments.
	verifier := &mockPrivadoVerifier{}
	srv, serverURL, _ := setupE2EWithVerifier(t, verifier)
	database := srv.DB()

	foreignAddr := deployOnNode(t, nodeURL, storageGetterInitcode(creationSecretForeign))
	ownAddr := deployOnNode(t, nodeURL, storageGetterInitcode(creationSecretOwn))

	orgA := creationTestOrg(t, database, "creation-a")
	orgB := creationTestOrg(t, database, "creation-b")
	createContract(t, database, orgB, foreignAddr, "ForeignGetter")
	ownContractID := createContract(t, database, orgA, ownAddr, "OwnGetter")

	callMethods := []string{"eth_call", "eth_estimateGas", "eth_createAccessList"}
	readersGroup := createGroup(t, database, orgA, "readers", []rbac.Claim{}, false)
	attachAllowedMethods(t, database, readersGroup, callMethods)
	createGrant(t, database, ownContractID, readersGroup)
	deployersGroup := createGroup(t, database, orgA, "deployers", []rbac.Claim{rbac.ClaimDeploy}, false)
	attachAllowedMethods(t, database, deployersGroup, callMethods)

	// did:test:* keeps mock login (mockauth builds) from also enrolling the
	// users in the dev-admin org, so each user has exactly org A.
	readerDID := "did:test:rd1323-reader"
	deployerDID := "did:test:rd1323-deployer"
	createUserInGroup(t, database, readerDID, readersGroup)
	createUserInGroup(t, database, deployerDID, deployersGroup)
	deployerEOA := "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266" // anvil account 0
	require.NoError(t, database.SystemLinkEthAddress(context.Background(), deployerDID, deployerEOA))

	verifier.userDID = readerDID
	readerToken := getJWTToken(t, serverURL, readerDID)
	verifier.userDID = deployerDID
	deployerToken := getJWTToken(t, serverURL, deployerDID)
	require.NotEmpty(t, readerToken)
	require.NotEmpty(t, deployerToken)

	readForeign := staticcallReaderInitcode(foreignAddr)
	readOwn := staticcallReaderInitcode(ownAddr)

	t.Run("member without deploy claim is refused before the node", func(t *testing.T) {
		for _, method := range callMethods {
			status, body := proxyRPC(t, serverURL, orgA, readerToken, method,
				[]any{map[string]any{"data": readForeign}, "latest"})
			require.NotEqual(t, http.StatusOK, status, "%s: %s", method, body)
			require.NotContains(t, body, creationSecretForeign, method)
		}
	})

	t.Run("deploy holder reading another org's contract is refused by the trace", func(t *testing.T) {
		for _, method := range callMethods {
			status, body := proxyRPC(t, serverURL, orgA, deployerToken, method,
				[]any{map[string]any{"data": readForeign}, "latest"})
			require.Equal(t, http.StatusForbidden, status, "%s: %s", method, body)
			require.NotContains(t, body, creationSecretForeign, method)
			require.NotContains(t, body, strings.TrimPrefix(foreignAddr, "0x"), method)
		}
	})

	// Anvil runs `input` when both fields are present; the checked code must
	// be the code the node runs, so a disagreeing pair is refused.
	// Geth matches `To` to `to` and keeps the last one, so with `To: null`
	// last it would run the creation code; the proxy refuses the ambiguous
	// object even for a member granted the visible `to`. Raw body: key order
	// matters on the wire.
	t.Run("granted member with a case-variant null To is refused", func(t *testing.T) {
		status, body := proxyRPC(t, serverURL, orgA, readerToken, "eth_call",
			[]any{map[string]any{"to": ownAddr, "data": "0x12345678"}, "latest"})
		require.Equal(t, http.StatusOK, status, "control: the plain targeted call is allowed: %s", body)

		raw := `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"` + ownAddr +
			`","data":"` + readForeign + `","To":null},"latest"]}`
		status, body = proxyRPCBody(t, serverURL, orgA, readerToken, raw)
		require.NotEqual(t, http.StatusOK, status, body)
		require.NotContains(t, body, creationSecretForeign)
	})

	t.Run("deploy holder with data and input disagreeing is refused", func(t *testing.T) {
		status, body := proxyRPC(t, serverURL, orgA, deployerToken, "eth_call",
			[]any{map[string]any{"data": "0x", "input": readForeign}, "latest"})
		require.NotEqual(t, http.StatusOK, status, body)
		require.NotContains(t, body, creationSecretForeign)
	})

	t.Run("deploy holder reading an own-org contract is answered", func(t *testing.T) {
		status, body := proxyRPC(t, serverURL, orgA, deployerToken, "eth_call",
			[]any{map[string]any{"data": readOwn}, "latest"})
		require.Equal(t, http.StatusOK, status, body)
		require.Contains(t, body, creationSecretOwn)
	})

	t.Run("deploy holder whose creation code deploys and calls a child is answered", func(t *testing.T) {
		status, body := proxyRPC(t, serverURL, orgA, deployerToken, "eth_call",
			[]any{map[string]any{"data": createAndCallInitcode(constantRuntime)}, "latest"})
		require.Equal(t, http.StatusOK, status, body)
		require.Contains(t, body, strings.Repeat("0", 62)+`2a"`)
	})

	t.Run("deploy holder whose created child reads another org is refused", func(t *testing.T) {
		childRuntime := strings.TrimPrefix(staticcallReaderInitcode(foreignAddr), "0x")
		status, body := proxyRPC(t, serverURL, orgA, deployerToken, "eth_call",
			[]any{map[string]any{"data": createAndCallInitcode(childRuntime)}, "latest"})
		require.Equal(t, http.StatusForbidden, status, body)
		require.NotContains(t, body, creationSecretForeign)
	})

	t.Run("deploy holder estimating a plain constructor is answered", func(t *testing.T) {
		status, body := proxyRPC(t, serverURL, orgA, deployerToken, "eth_estimateGas",
			[]any{map[string]any{"data": storageGetterInitcode(creationSecretOwn)}})
		require.Equal(t, http.StatusOK, status, body)
		require.Contains(t, body, `"result":"0x`)
	})

	// A deployment pre-flight (Foundry / Hardhat style) names the deployer
	// as `from`; like any traced read, it must be one of the caller's linked
	// addresses.
	t.Run("deploy holder estimating from a linked address is answered", func(t *testing.T) {
		status, body := proxyRPC(t, serverURL, orgA, deployerToken, "eth_estimateGas",
			[]any{map[string]any{"from": deployerEOA, "data": storageGetterInitcode(creationSecretOwn)}})
		require.Equal(t, http.StatusOK, status, body)
		require.Contains(t, body, `"result":"0x`)
	})

	t.Run("deploy holder estimating from an unlinked address is refused", func(t *testing.T) {
		status, body := proxyRPC(t, serverURL, orgA, deployerToken, "eth_estimateGas",
			[]any{map[string]any{"from": creationFundedAccount, "data": storageGetterInitcode(creationSecretOwn)}})
		require.Equal(t, http.StatusBadRequest, status, body)
	})

	t.Run("anonymous caller is refused", func(t *testing.T) {
		status, body := proxyRPC(t, serverURL, orgA, "", "eth_call",
			[]any{map[string]any{"data": readForeign}, "latest"})
		require.NotEqual(t, http.StatusOK, status, body)
		require.NotContains(t, body, creationSecretForeign)
	})
}
