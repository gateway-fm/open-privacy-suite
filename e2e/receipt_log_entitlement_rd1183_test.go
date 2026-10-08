//go:build mockauth

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server"
)

// RD-1183 acceptance-level coverage: the log-entitled receipt admission must
// hold on the COMPLETE authenticated RPC path — HTTP request, JWT auth, RBAC
// method check, upstream fetch, response filtering — not only in the
// FilterReceiptLogsWithEventRules helper (covered by the unit tests in
// internal/server/event_log_filter_rd1183_test.go).
//
// Scenario: a tx on an org contract emits two Transfer logs. The viewer is
// NOT a participant (not the tx from/to) but holds an event rule admitting
// logs whose `from` param is their own address:
//   - viewer  → receipt ADMITTED: envelope (from/to/status/gasUsed) visible,
//     logs filtered to the one entitled entry, logsBloom zeroed;
//   - a same-org user whose grant matches nothing → null (not admitted);
//   - a deployment receipt is NEVER admitted to a non-participant, even if a
//     log matches (contractAddress must not leak).

const (
	rd1183TxHash       = "0x1183118311831183118311831183118311831183118311831183118311831183"
	rd1183DeployTxHash = "0x2183218321832183218321832183218321832183218321832183218321832183"
	rd1183BlockHash    = "0x3183318331833183318331833183318331833183318331833183318331833183"
	// keccak256("Transfer(address,address,uint256)")
	rd1183TransferTopic0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
)

// The contract must carry an ABI: the RD-875 deny-when-no-ABI gate drops
// event logs of ABI-less contracts before any event rule can admit them.
const rd1183ERC20ABI = `[
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}
]`

func rd1183PadTopic(addr string) string {
	return "0x" + strings.Repeat("0", 24) + strings.ToLower(strings.TrimPrefix(addr, "0x"))
}

func rd1183Log(contractAddr, txHash string, logIndex int, fromAddr, toAddr string) map[string]any {
	return map[string]any{
		"address":          contractAddr,
		"topics":           []string{rd1183TransferTopic0, rd1183PadTopic(fromAddr), rd1183PadTopic(toAddr)},
		"data":             "0x" + strings.Repeat("0", 64),
		"blockNumber":      "0x10",
		"transactionHash":  txHash,
		"transactionIndex": "0x0",
		"blockHash":        rd1183BlockHash,
		"logIndex":         fmt.Sprintf("0x%x", logIndex),
		"removed":          false,
	}
}

func TestReceiptLogEntitlement_FullRPCPath_RD1183(t *testing.T) {
	contractAddr := "0x6183618361836183618361836183618361836183"
	deployedAddr := "0x7183718371837183718371837183718371837183"
	senderAddr := "0xaaaa000000000000000000000000000000001183"
	viewerAddr := "0xbbbb000000000000000000000000000000001183"
	strangerAddr := "0xcccc000000000000000000000000000000001183"
	otherAddr := "0xdddd000000000000000000000000000000001183"

	// Normal receipt: sender → contract, one log entitled to the viewer
	// (Transfer from=viewer) and one that is not (Transfer from=other).
	receipt := map[string]any{
		"transactionHash":   rd1183TxHash,
		"transactionIndex":  "0x0",
		"blockHash":         rd1183BlockHash,
		"blockNumber":       "0x10",
		"from":              senderAddr,
		"to":                contractAddr,
		"cumulativeGasUsed": "0x5208",
		"gasUsed":           "0x5208",
		"effectiveGasPrice": "0x1",
		"status":            "0x1",
		"type":              "0x2",
		"logsBloom":         "0x" + strings.Repeat("ff", 256),
		"logs": []map[string]any{
			rd1183Log(contractAddr, rd1183TxHash, 0, viewerAddr, otherAddr),
			rd1183Log(contractAddr, rd1183TxHash, 1, otherAddr, senderAddr),
		},
	}
	// Deployment receipt (to=null, contractAddress set). Its log is crafted to
	// match the viewer's event rule so the test proves the DEPLOYMENT
	// exclusion is what blocks admission, not a mere log mismatch.
	deployReceipt := map[string]any{
		"transactionHash":   rd1183DeployTxHash,
		"transactionIndex":  "0x1",
		"blockHash":         rd1183BlockHash,
		"blockNumber":       "0x10",
		"from":              senderAddr,
		"to":                nil,
		"contractAddress":   deployedAddr,
		"cumulativeGasUsed": "0x5208",
		"gasUsed":           "0x5208",
		"effectiveGasPrice": "0x1",
		"status":            "0x1",
		"type":              "0x2",
		"logsBloom":         "0x" + strings.Repeat("ff", 256),
		"logs": []map[string]any{
			rd1183Log(contractAddr, rd1183DeployTxHash, 0, viewerAddr, otherAddr),
		},
	}

	// --- Upstream mock node: canned JSON-RPC, single or batch. -------------
	answer := func(req map[string]any) map[string]any {
		id := req["id"]
		method, _ := req["method"].(string)
		res := func(v any) map[string]any {
			return map[string]any{"jsonrpc": "2.0", "id": id, "result": v}
		}
		switch method {
		case "eth_chainId":
			return res("0x7a69")
		case "net_version":
			return res("31337")
		case "eth_blockNumber":
			return res("0x10")
		case "eth_getTransactionReceipt":
			params, _ := req["params"].([]any)
			if len(params) > 0 {
				switch strings.ToLower(fmt.Sprint(params[0])) {
				case rd1183TxHash:
					return res(receipt)
				case rd1183DeployTxHash:
					return res(deployReceipt)
				}
			}
			return res(nil)
		case "eth_getTransactionByHash":
			params, _ := req["params"].([]any)
			if len(params) > 0 && strings.EqualFold(fmt.Sprint(params[0]), rd1183TxHash) {
				return res(map[string]any{
					"hash": rd1183TxHash, "from": senderAddr, "to": contractAddr,
					"blockHash": rd1183BlockHash, "blockNumber": "0x10",
					"value": "0x0", "input": "0x", "nonce": "0x0",
					"gas": "0x5208", "gasPrice": "0x1", "transactionIndex": "0x0",
				})
			}
			return res(nil)
		default:
			return res(nil)
		}
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		trimmed := bytes.TrimSpace(body)
		if len(trimmed) > 0 && trimmed[0] == '[' {
			var reqs []map[string]any
			_ = json.Unmarshal(trimmed, &reqs)
			out := make([]map[string]any, 0, len(reqs))
			for _, rq := range reqs {
				out = append(out, answer(rq))
			}
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		var rq map[string]any
		_ = json.Unmarshal(trimmed, &rq)
		_ = json.NewEncoder(w).Encode(answer(rq))
	}))
	defer upstream.Close()

	// --- Server against the mock upstream (same shape as the create2 env). --
	dbURL, dbCleanup := db.SetupTestContainer(t)
	t.Cleanup(dbCleanup)

	database, err := db.New(dbURL)
	require.NoError(t, err)
	require.NoError(t, db.ResetTestDatabase(database))

	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	serverURL := fmt.Sprintf("http://localhost:%d", port)

	cfg := &config.Config{
		ReadProfile:           rbac.ReadProfileStandard,
		NodeURL:               upstream.URL,
		DatabaseURL:           dbURL,
		AuditDatabaseURL:      dbURL,
		AuditAdminDatabaseURL: dbURL,
		PrivadoRPCURL:         "https://rpc-mainnet.privado.id",
		IPFSGateway:           "https://ipfs-proxy-cache.privado.id",
		JWTSecret:             "test-secret-rd1183",
		JWTRefreshSecret:      "test-refresh-secret-rd1183",
		VerifierID:            "did:privado:verifier:test",
		BaseURL:               serverURL,
		Environment:           "development",
		AllowMockLogin:        true,
		DisableCoinGecko:      true,
	}
	srv, err := server.NewWithVerifier(cfg, &mockPrivadoVerifier{})
	require.NoError(t, err)
	require.NoError(t, db.ResetTestDatabase(srv.DB()))
	go func() { _ = srv.Run(fmt.Sprintf(":%d", port)) }()
	t.Cleanup(func() { srv.Stop(); database.Close() })
	for i := 0; ; i++ {
		resp, err := http.Get(serverURL + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		require.Less(t, i, 50, "server failed to start")
		time.Sleep(100 * time.Millisecond)
	}

	// --- Seed: one org, a contract with per-group event rules. --------------
	ctx := context.Background()
	orgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{
		ID: orgID, Slug: "rd1183-org", Name: "RD-1183 Org", Settings: map[string]any{},
	}))

	now := time.Now()
	contractID := uuid.New().String()
	require.NoError(t, database.CreateContract(ctx, &rbac.Contract{
		ID: contractID, OrgID: orgID, Address: contractAddr,
		Name: "RD-1183 Token", DeployedAt: &now, ABI: rd1183ERC20ABI,
	}))

	mkUser := func(did, addr, groupSlug string, rules *rbac.EventRulesField) {
		groupID := uuid.New().String()
		require.NoError(t, database.CreateGroup(ctx, &rbac.Group{
			ID: groupID, OrgID: orgID, Slug: groupSlug, Name: groupSlug,
		}))
		require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
			ID: uuid.New().String(), GroupID: groupID,
			AllowedMethods: []string{"eth_getTransactionReceipt"},
			Claims:         []rbac.Claim{},
		}))
		user := &rbac.User{
			ID: uuid.New().String(), ExternalID: did,
			KYC: true, Banned: false, Metadata: map[string]any{},
		}
		require.NoError(t, database.CreateUser(ctx, user))
		require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{
			ID: uuid.New().String(), UserID: user.ID, GroupID: groupID,
			Source: rbac.MembershipSourceAdmin,
		}))
		require.NoError(t, database.SystemLinkEthAddress(ctx, did, addr))
		require.NoError(t, database.CreateContractGrant(ctx, &rbac.ContractGrant{
			ID: uuid.New().String(), ContractID: contractID, GroupID: groupID,
			EventRules: rules,
		}))
	}

	viewerDID := "did:test:rd1183_viewer"
	strangerDID := "did:test:rd1183_stranger"
	// Viewer: entitled to Transfer logs whose from-param is their own address.
	mkUser(viewerDID, viewerAddr, "rd1183-viewers", &rbac.EventRulesField{Rules: []rbac.EventRule{{
		Topic0: rd1183TransferTopic0,
		Name:   "Transfer",
		ParamRules: []rbac.ParamRule{
			{Index: 0, MustBe: "self"},
		},
	}}})
	// Stranger: same org, same method access, a grant whose rule can never
	// match these logs (their address appears in none of them).
	mkUser(strangerDID, strangerAddr, "rd1183-strangers", &rbac.EventRulesField{Rules: []rbac.EventRule{{
		Topic0: rd1183TransferTopic0,
		Name:   "Transfer",
		ParamRules: []rbac.ParamRule{
			{Index: 0, MustBe: "self"},
		},
	}}})

	viewerJWT := getJWTTokenForCreate2(t, serverURL, viewerDID)
	strangerJWT := getJWTTokenForCreate2(t, serverURL, strangerDID)

	rpcResult := func(t *testing.T, jwt, txHash string) json.RawMessage {
		t.Helper()
		reqBody, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 7,
			"method": "eth_getTransactionReceipt", "params": []string{txHash},
		})
		req, err := http.NewRequest(http.MethodPost, serverURL+"/", bytes.NewReader(reqBody))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected HTTP status: %s", string(body))
		var envelope struct {
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		require.NoError(t, json.Unmarshal(body, &envelope))
		require.Empty(t, string(envelope.Error), "unexpected RPC error: %s", string(envelope.Error))
		return envelope.Result
	}

	t.Run("entitled non-participant gets envelope with filtered logs", func(t *testing.T) {
		raw := rpcResult(t, viewerJWT, rd1183TxHash)
		require.NotEqual(t, "null", strings.TrimSpace(string(raw)),
			"RD-1183: a viewer entitled to a log must receive the receipt")

		var got struct {
			From      string           `json:"from"`
			To        string           `json:"to"`
			Status    string           `json:"status"`
			GasUsed   string           `json:"gasUsed"`
			LogsBloom string           `json:"logsBloom"`
			Logs      []map[string]any `json:"logs"`
		}
		require.NoError(t, json.Unmarshal(raw, &got))
		require.Equal(t, senderAddr, strings.ToLower(got.From), "envelope from must be revealed")
		require.Equal(t, contractAddr, strings.ToLower(got.To), "envelope to must be revealed")
		require.Equal(t, "0x1", got.Status)
		require.Equal(t, "0x5208", got.GasUsed)
		require.Equal(t, "0x"+strings.Repeat("0", 512), got.LogsBloom,
			"logsBloom must be zeroed once logs are filtered")

		require.Len(t, got.Logs, 1, "only the entitled log may be returned")
		topics, ok := got.Logs[0]["topics"].([]any)
		require.True(t, ok)
		require.Equal(t, rd1183PadTopic(viewerAddr), topics[1],
			"the surviving log must be the one the viewer's rule matches")
	})

	t.Run("non-entitled same-org viewer gets null", func(t *testing.T) {
		raw := rpcResult(t, strangerJWT, rd1183TxHash)
		require.Equal(t, "null", strings.TrimSpace(string(raw)),
			"a viewer entitled to none of the logs must not receive the receipt")
	})

	t.Run("deployment receipt is not admitted to a non-participant", func(t *testing.T) {
		raw := rpcResult(t, viewerJWT, rd1183DeployTxHash)
		require.Equal(t, "null", strings.TrimSpace(string(raw)),
			"deployment receipts must stay hidden (contractAddress would leak)")
	})
}
