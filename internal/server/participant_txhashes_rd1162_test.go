package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
)

// RD-1162 getLogs participant path.
//
// Log entries do not carry the emitting tx's sender, so the eth_getLogs path
// resolves it via a batched upstream eth_getTransactionByHash
// (JSONRPCProcessor.buildParticipantTxHashes) and marks txs whose from/to is one
// of the caller's linked addresses. FilterEventLogs then admits address-less
// own-tx logs (bounded by contract-grant access). These tests exercise that
// resolution glue against an in-process fake node (no Docker), closing the
// coverage gap flagged in RD-1162 (buildParticipantTxHashes was untested).

type txFromTo struct{ from, to, input string }

// fakeTxByHashNode serves a batched eth_getTransactionByHash: for each requested
// hash it returns {hash, from, to} from txs (or a null result for unknown hashes).
func fakeTxByHashNode(t *testing.T, txs map[string]txFromTo) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var batch []struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params []string        `json:"params"`
		}
		if err := json.Unmarshal(body, &batch); err != nil {
			http.Error(w, "bad batch", http.StatusBadRequest)
			return
		}
		out := make([]map[string]any, 0, len(batch))
		for _, req := range batch {
			var hash string
			if len(req.Params) > 0 {
				hash = req.Params[0]
			}
			entry := map[string]any{"jsonrpc": "2.0", "id": req.ID}
			if tx, ok := txs[strings.ToLower(hash)]; ok {
				entry["result"] = map[string]any{"hash": hash, "from": tx.from, "to": tx.to, "input": tx.input}
			} else {
				entry["result"] = nil
			}
			out = append(out, entry)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
}

func getLogsRPCResponse(logs []map[string]any) []byte {
	arr, _ := json.Marshal(logs)
	return []byte(`{"jsonrpc":"2.0","id":1,"result":` + string(arr) + `}`)
}

func TestBuildParticipantTxHashes_ResolvesParticipants_RD1162(t *testing.T) {
	user := "0xabc1234567890123456789012345678901234567"
	other := "0x9999999999999999999999999999999999999999"
	contract := "0xcontract0000000000000000000000000000001"
	txFrom := "0x" + strings.Repeat("a", 64)     // from = user
	txNone := "0x" + strings.Repeat("b", 64)     // user uninvolved
	txTo := "0x" + strings.Repeat("c", 64)       // to = user
	txUnknown := "0x" + strings.Repeat("d", 64)  // node has no such tx
	txCalldata := "0x" + strings.Repeat("e", 64) // user only appears in calldata

	srv := fakeTxByHashNode(t, map[string]txFromTo{
		txFrom:     {from: user, to: contract},
		txNone:     {from: other, to: other},
		txTo:       {from: other, to: user},
		txCalldata: {from: other, to: contract, input: "0xa9059cbb" + strings.Repeat("0", 24) + strings.TrimPrefix(user, "0x") + fmt.Sprintf("%064x", 1)},
	})
	defer srv.Close()
	p := &JSONRPCProcessor{readProfile: rbac.ReadProfileStandard, proxy: proxy.New(srv.URL)}

	resp := getLogsRPCResponse([]map[string]any{
		{"address": contract, "topics": []string{"0xevt"}, "transactionHash": txFrom},
		{"address": contract, "topics": []string{"0xevt"}, "transactionHash": txNone},
		{"address": contract, "topics": []string{"0xevt"}, "transactionHash": txTo},
		{"address": contract, "topics": []string{"0xevt"}, "transactionHash": txUnknown},
		{"address": contract, "topics": []string{"0xevt"}, "transactionHash": txCalldata},
	})

	got := p.buildParticipantTxHashes([]string{user}, resp)
	if !got[txFrom] {
		t.Errorf("tx with from=user must be a participant tx")
	}
	if !got[txTo] {
		t.Errorf("tx with to=user must be a participant tx")
	}
	if got[txNone] {
		t.Errorf("tx the user is not part of must NOT be a participant tx")
	}
	if got[txUnknown] {
		t.Errorf("tx the node cannot resolve must NOT be a participant tx")
	}
	if got[txCalldata] {
		t.Errorf("an address named only in calldata must not expand transaction participation")
	}
	if len(got) != 2 {
		t.Errorf("expected exactly 2 participant txs, got %d: %v", len(got), got)
	}
}

func TestBuildParticipantTxHashes_FailClosed_RD1162(t *testing.T) {
	user := "0xabc1234567890123456789012345678901234567"
	contract := "0xcontract0000000000000000000000000000001"
	tx := "0x" + strings.Repeat("a", 64)
	resp := getLogsRPCResponse([]map[string]any{
		{"address": contract, "topics": []string{"0xevt"}, "transactionHash": tx},
	})

	t.Run("no linked addresses -> empty (upstream not consulted)", func(t *testing.T) {
		p := &JSONRPCProcessor{readProfile: rbac.ReadProfileStandard, proxy: proxy.New("http://127.0.0.1:1")}
		if got := p.buildParticipantTxHashes(nil, resp); len(got) != 0 {
			t.Errorf("want empty, got %v", got)
		}
	})

	t.Run("upstream unreachable -> empty (fail-closed)", func(t *testing.T) {
		down := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := down.URL
		down.Close() // connection refused on Forward
		p := &JSONRPCProcessor{readProfile: rbac.ReadProfileStandard, proxy: proxy.New(url)}
		if got := p.buildParticipantTxHashes([]string{user}, resp); len(got) != 0 {
			t.Errorf("want empty on upstream error, got %v", got)
		}
	})

	t.Run("unparseable upstream response -> empty (fail-closed)", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}))
		defer srv.Close()
		p := &JSONRPCProcessor{readProfile: rbac.ReadProfileStandard, proxy: proxy.New(srv.URL)}
		if got := p.buildParticipantTxHashes([]string{user}, resp); len(got) != 0 {
			t.Errorf("want empty on unparseable response, got %v", got)
		}
	})

	t.Run("over the unique-tx cap -> empty (skips resolution)", func(t *testing.T) {
		// A node that would mark EVERY tx as the user's — if the cap didn't fire,
		// we'd get participantResolveMaxTxs+1 participants. It must return empty.
		manyLogs := make([]map[string]any, 0, participantResolveMaxTxs+1)
		allTxs := make(map[string]txFromTo, participantResolveMaxTxs+1)
		for i := 0; i <= participantResolveMaxTxs; i++ { // 257 unique
			h := fmt.Sprintf("0x%064x", i)
			manyLogs = append(manyLogs, map[string]any{"address": contract, "topics": []string{"0xevt"}, "transactionHash": h})
			allTxs[h] = txFromTo{from: user, to: contract}
		}
		srv := fakeTxByHashNode(t, allTxs)
		defer srv.Close()
		p := &JSONRPCProcessor{readProfile: rbac.ReadProfileStandard, proxy: proxy.New(srv.URL)}
		if got := p.buildParticipantTxHashes([]string{user}, getLogsRPCResponse(manyLogs)); len(got) != 0 {
			t.Errorf("over-cap response must skip participant resolution and return empty, got %d", len(got))
		}
	})
}

// TestGetLogsParticipantPath_AddresslessOwnTxLogAdmitted_RD1162 is the full
// eth_getLogs path: resolve senders (buildParticipantTxHashes) → FilterEventLogs.
// The caller sees the address-less log of their OWN tx on a granted contract,
// while an equivalent log from a tx they did not participate in stays dropped.
func TestGetLogsParticipantPath_AddresslessOwnTxLogAdmitted_RD1162(t *testing.T) {
	user := "0xabc1234567890123456789012345678901234567"
	other := "0x9999999999999999999999999999999999999999"
	granted := "0xcontract0000000000000000000000000000001"
	txMine := "0x" + strings.Repeat("a", 64)
	txOther := "0x" + strings.Repeat("b", 64)
	eventTopic0 := "0xddd0000000000000000000000000000000000000000000000000000000000000"
	recordKey := "0x1111111111111111111111111111111111111111111111111111111111111111"

	srv := fakeTxByHashNode(t, map[string]txFromTo{
		txMine:  {from: user, to: granted},
		txOther: {from: other, to: granted},
	})
	defer srv.Close()
	p := &JSONRPCProcessor{readProfile: rbac.ReadProfileStandard, proxy: proxy.New(srv.URL)}

	// granted contract, nil EventRules → deny-all baseline (address-less log is
	// denied without participant admission).
	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			granted: {Claims: []rbac.Claim{}},
		},
	}

	resp := getLogsRPCResponse([]map[string]any{
		{"address": granted, "topics": []string{eventTopic0, recordKey}, "data": "0x", "transactionHash": txMine},
		{"address": granted, "topics": []string{eventTopic0, recordKey}, "data": "0x", "transactionHash": txOther},
	})

	participants := p.buildParticipantTxHashes([]string{user}, resp)
	visCtx := &rbac.TxVisibilityContext{ParticipantTxHashes: participants}
	got := FilterLogsWithEventRules(rbac.ReadProfileStandard, resp, []string{user}, perms, &testABIProviderServer{}, visCtx, nil)

	var out struct {
		Result []struct {
			TransactionHash string `json:"transactionHash"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("output not valid JSON: %v\nraw: %s", err, got)
	}
	if len(out.Result) != 1 {
		t.Fatalf("expected only the participant's own-tx address-less log; got %d logs\nraw: %s", len(out.Result), got)
	}
	if !strings.EqualFold(out.Result[0].TransactionHash, txMine) {
		t.Errorf("admitted log should belong to the participant's own tx %s, got %s", txMine, out.Result[0].TransactionHash)
	}
}
