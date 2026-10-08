//go:build mockauth

package e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server"
)

// RD-1300 acceptance on the COMPLETE authenticated RPC path (HTTP, JWT, RBAC
// method allowlist, upstream fetch, response filtering): with the per-contract
// visibleTo unlock enabled, an eligible viewer listed on a transaction receives
// that transaction's logs from the flagged contract exactly as emitted —
// through eth_getLogs and eth_getTransactionReceipt — while an unlisted
// transaction stays on the ordinary rules and the method allowlist still gates
// each RPC method.

const (
	rd1300ListedTx   = "0x1300130013001300130013001300130013001300130013001300130013001300"
	rd1300UnlistedTx = "0x2300230023002300230023002300230023002300230023002300230023002300"
	rd1300BlockHash  = "0x3300330033003300330033003300330033003300330033003300330033003300"
	rd1300PaymentABI = `[{"anonymous":false,"type":"event","name":"PaymentMade","inputs":[
		{"indexed":true,"name":"payer","type":"address"},
		{"indexed":false,"name":"intermediary","type":"address"},
		{"indexed":false,"name":"amount","type":"uint256"}]}]`
)

func keccakHexRD1300(sig string) string { return hex.EncodeToString(crypto.Keccak256([]byte(sig))) }

func rd1300PadTopic(addr string) string {
	return "0x" + strings.Repeat("0", 24) + strings.ToLower(strings.TrimPrefix(addr, "0x"))
}

func TestVisibleToUnlockFullPayload_FullRPCPath_RD1300(t *testing.T) {
	contractAddr := "0x6300630063006300630063006300630063006300"
	payerAddr := "0xaaaa000000000000000000000000000000001300"
	intermediaryAddr := "0xbbbb000000000000000000000000000000001300"
	recipientAddr := "0xcccc000000000000000000000000000000001300"
	topic0 := "0x" + keccakHexRD1300("PaymentMade(address,address,uint256)")
	data := "0x" + strings.TrimPrefix(rd1300PadTopic(intermediaryAddr), "0x") + strings.Repeat("0", 62) + "2a"

	mkLog := func(tx string) map[string]any {
		return map[string]any{
			"address": contractAddr, "topics": []string{topic0, rd1300PadTopic(payerAddr)}, "data": data,
			"blockNumber": "0x10", "blockHash": rd1300BlockHash, "transactionHash": tx,
			"transactionIndex": "0x0", "logIndex": "0x0", "removed": false,
		}
	}
	receipt := map[string]any{
		"transactionHash": rd1300ListedTx, "transactionIndex": "0x0", "blockHash": rd1300BlockHash,
		"blockNumber": "0x10", "from": payerAddr, "to": contractAddr, "cumulativeGasUsed": "0x5208",
		"gasUsed": "0x5208", "effectiveGasPrice": "0x1", "status": "0x1", "type": "0x2",
		"logsBloom": "0x" + strings.Repeat("ff", 256), "logs": []map[string]any{mkLog(rd1300ListedTx)},
	}

	answer := func(req map[string]any) map[string]any {
		id := req["id"]
		method, _ := req["method"].(string)
		res := func(v any) map[string]any { return map[string]any{"jsonrpc": "2.0", "id": id, "result": v} }
		switch method {
		case "eth_chainId":
			return res("0x7a69")
		case "net_version":
			return res("31337")
		case "eth_blockNumber":
			return res("0x10")
		case "eth_getLogs":
			return res([]map[string]any{mkLog(rd1300ListedTx), mkLog(rd1300UnlistedTx)})
		case "eth_getTransactionReceipt":
			params, _ := req["params"].([]any)
			if len(params) > 0 && strings.EqualFold(fmt.Sprint(params[0]), rd1300ListedTx) {
				return res(receipt)
			}
			return res(nil)
		case "eth_getTransactionByHash":
			params, _ := req["params"].([]any)
			if len(params) > 0 {
				h := strings.ToLower(fmt.Sprint(params[0]))
				return res(map[string]any{"hash": h, "from": payerAddr, "to": contractAddr, "blockHash": rd1300BlockHash,
					"blockNumber": "0x10", "value": "0x0", "input": "0x", "nonce": "0x0", "gas": "0x5208",
					"gasPrice": "0x1", "transactionIndex": "0x0"})
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
		NodeURL: upstream.URL, DatabaseURL: dbURL, AuditDatabaseURL: dbURL, AuditAdminDatabaseURL: dbURL,
		PrivadoRPCURL: "https://rpc-mainnet.privado.id", IPFSGateway: "https://ipfs-proxy-cache.privado.id",
		JWTSecret: "test-secret-rd1300", JWTRefreshSecret: "test-refresh-secret-rd1300",
		VerifierID: "did:privado:verifier:test", BaseURL: serverURL, Environment: "development",
		AllowMockLogin: true, DisableCoinGecko: true,
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

	// --- Seed: one org, a flagged contract, three viewers. ------------------
	ctx := context.Background()
	orgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "rd1300-org", Name: "RD-1300 Org", Settings: map[string]any{}}))
	now := time.Now()
	contractID := uuid.New().String()
	require.NoError(t, database.CreateContract(ctx, &rbac.Contract{
		ID: contractID, OrgID: orgID, Address: contractAddr, Name: "Payments", DeployedAt: &now, ABI: rd1300PaymentABI,
	}))
	require.NoError(t, database.UpdateContractAllowVisibleToUnlock(ctx, contractID, true))

	mkUser := func(did, addr, groupSlug string, methods []string) {
		groupID := uuid.New().String()
		require.NoError(t, database.CreateGroup(ctx, &rbac.Group{ID: groupID, OrgID: orgID, Slug: groupSlug, Name: groupSlug}))
		require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{ID: uuid.New().String(), GroupID: groupID, AllowedMethods: methods, Claims: []rbac.Claim{}}))
		user := &rbac.User{ID: uuid.New().String(), ExternalID: did, KYC: true, Metadata: map[string]any{}}
		require.NoError(t, database.CreateUser(ctx, user))
		require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.New().String(), UserID: user.ID, GroupID: groupID, Source: rbac.MembershipSourceAdmin}))
		if addr != "" {
			require.NoError(t, database.SystemLinkEthAddress(ctx, did, addr))
		}
		// Deny-all event rules: only the unlock can admit these logs.
		require.NoError(t, database.CreateContractGrant(ctx, &rbac.ContractGrant{ID: uuid.New().String(), ContractID: contractID, GroupID: groupID, EventRules: &rbac.EventRulesField{}}))
	}
	recipientDID := "did:test:rd1300_recipient"
	receiptOnlyDID := "did:test:rd1300_receipt_only"
	unlistedDID := "did:test:rd1300_unlisted"
	mkUser(recipientDID, recipientAddr, "rd1300-recipients", []string{"eth_getLogs", "eth_getTransactionReceipt"})
	mkUser(receiptOnlyDID, "", "rd1300-receipt-only", []string{"eth_getTransactionReceipt"})
	mkUser(unlistedDID, "", "rd1300-unlisted", []string{"eth_getLogs", "eth_getTransactionReceipt"})
	require.NoError(t, database.SaveTxVisibility(ctx, rd1300ListedTx, []string{recipientDID, receiptOnlyDID}, "did:test:rd1300_payer", orgID))

	rpc := func(t *testing.T, jwt, method string, params any) (json.RawMessage, json.RawMessage) {
		t.Helper()
		reqBody, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 9, "method": method, "params": params})
		req, err := http.NewRequest(http.MethodPost, serverURL+"/", bytes.NewReader(reqBody))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var env struct {
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		require.NoError(t, json.Unmarshal(body, &env), "body: %s", string(body))
		return env.Result, env.Error
	}
	type wireLog struct {
		Address         string   `json:"address"`
		Topics          []string `json:"topics"`
		Data            string   `json:"data"`
		TransactionHash string   `json:"transactionHash"`
	}
	getLogsParams := []any{map[string]any{"address": contractAddr, "fromBlock": "0x0", "toBlock": "latest"}}
	exact := wireLog{Address: contractAddr, Topics: []string{topic0, rd1300PadTopic(payerAddr)}, Data: data, TransactionHash: rd1300ListedTx}

	recipientJWT := getJWTTokenForCreate2(t, serverURL, recipientDID)
	receiptOnlyJWT := getJWTTokenForCreate2(t, serverURL, receiptOnlyDID)
	unlistedJWT := getJWTTokenForCreate2(t, serverURL, unlistedDID)

	t.Run("eth_getLogs: listed tx exact, unlisted tx dropped", func(t *testing.T) {
		res, rpcErr := rpc(t, recipientJWT, "eth_getLogs", getLogsParams)
		require.Empty(t, string(rpcErr))
		var logs []wireLog
		require.NoError(t, json.Unmarshal(res, &logs))
		require.Equal(t, []wireLog{exact}, logs, "the payer topic and the intermediary in data must be returned unmasked")
	})
	t.Run("eth_getTransactionReceipt: listed tx log exact", func(t *testing.T) {
		res, rpcErr := rpc(t, recipientJWT, "eth_getTransactionReceipt", []string{rd1300ListedTx})
		require.Empty(t, string(rpcErr))
		var r struct {
			Logs []wireLog `json:"logs"`
		}
		require.NoError(t, json.Unmarshal(res, &r))
		require.Equal(t, []wireLog{exact}, r.Logs)
	})
	t.Run("method allowlist still gates eth_getLogs for a listed, eligible viewer", func(t *testing.T) {
		res, rpcErr := rpc(t, receiptOnlyJWT, "eth_getLogs", getLogsParams)
		require.NotEmpty(t, string(rpcErr), "eth_getLogs must be denied by the group's method allowlist; got result %s", string(res))
		res, rpcErr = rpc(t, receiptOnlyJWT, "eth_getTransactionReceipt", []string{rd1300ListedTx})
		require.Empty(t, string(rpcErr))
		var r struct {
			Logs []wireLog `json:"logs"`
		}
		require.NoError(t, json.Unmarshal(res, &r))
		require.Equal(t, []wireLog{exact}, r.Logs, "the allowed method returns the unlocked payload")
	})
	t.Run("eligible but unlisted viewer gets nothing", func(t *testing.T) {
		res, rpcErr := rpc(t, unlistedJWT, "eth_getLogs", getLogsParams)
		require.Empty(t, string(rpcErr))
		require.JSONEq(t, `[]`, string(res))
		res, rpcErr = rpc(t, unlistedJWT, "eth_getTransactionReceipt", []string{rd1300ListedTx})
		require.Empty(t, string(rpcErr))
		require.Equal(t, "null", strings.TrimSpace(string(res)))
	})
}
