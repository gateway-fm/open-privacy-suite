package nodeapproval

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// besuFixture returns the calls-V3 golden tree as the Besu plugin would report it:
// the geth-shaped call tree plus code hashes instead of prestate code.
func besuFixture(t *testing.T) (calls object, codeHashes map[string]string, want common.Hash) {
	t.Helper()
	data, err := os.ReadFile("testdata/call-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var v object
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.UseNumber()
	if err = d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	codeHashes = map[string]string{}
	for address, account := range obj(v["pre"]) {
		codeHashes[strings.ToLower(address)] = crypto.Keccak256Hash(common.FromHex(str(obj(account)["code"]))).Hex()
	}
	return obj(v["calls"]), codeHashes, common.HexToHash(str(v["expected_calls"]))
}

func besuServer(t *testing.T, respond func(raw string) any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			ID     any
			Method string
			Params []json.RawMessage
		}
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Error(err)
			return
		}
		var result any
		switch q.Method {
		case "eth_chainId":
			result = "0x7a69"
		case "ops_prepareApproval":
			var raw string
			_ = json.Unmarshal(q.Params[0], &raw)
			result = respond(raw)
		default:
			t.Error("unexpected RPC in Besu mode", q.Method)
		}
		_ = json.NewEncoder(w).Encode(object{"jsonrpc": "2.0", "id": q.ID, "result": result})
	}))
}

// rootedAt rewrites the golden tree's root frame to the signed transaction's envelope, as the
// plugin would report it, and returns the fingerprint that tree encodes to.
func rootedAt(t *testing.T, calls object, tx *types.Transaction, codeHashes map[string]string) (object, common.Hash) {
	t.Helper()
	from, _ := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
	rooted := object{}
	for k, v := range calls {
		rooted[k] = v
	}
	rooted["from"], rooted["to"], rooted["input"], rooted["value"] = from.Hex(), tx.To().Hex(), hexutil.Encode(tx.Data()), hexutil.EncodeBig(tx.Value())
	codes := map[string]common.Hash{}
	for a, h := range codeHashes {
		codes[a] = common.HexToHash(h)
	}
	hash, _, err := callFingerprintWithCodes(rooted, codes)
	if err != nil {
		t.Fatal(err)
	}
	return rooted, hash
}

func signedCall(t *testing.T) (*types.Transaction, string) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	to := common.HexToAddress("0x1111111111111111111111111111111111111111")
	tx, err := types.SignTx(types.NewTransaction(0, to, big.NewInt(0), 100000, big.NewInt(1), []byte{0x12, 0x34, 0x56, 0x78}), types.NewEIP155Signer(big.NewInt(31337)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	return tx, hexutil.Encode(raw)
}

func TestPrepareBesuRecomputesAndBindsThePluginFingerprint(t *testing.T) {
	t.Setenv("OPS_APPROVAL_NODE", "besu")
	calls, codeHashes, want := besuFixture(t)
	tx, raw := signedCall(t)
	calls, want = rootedAt(t, calls, tx, codeHashes)
	server := besuServer(t, func(got string) any {
		if got != raw {
			t.Error("plugin must receive the exact signed bytes")
		}
		return object{"hashMode": 3, "chainId": "0x7a69", "txHash": tx.Hash().Hex(), "fingerprint": want.Hex(), "calls": calls, "codeHashes": codeHashes, "status": "success"}
	})
	defer server.Close()
	s, err := NewPreflight(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, err := s.Prepare(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Approval.HashMode != HashCalls || p.Approval.Fingerprint != want || p.Approval.TxHash != tx.Hash() || p.Approval.ChainID != 31337 {
		t.Fatalf("approval not bound to the recomputed fingerprint: %+v", p.Approval)
	}
	if len(p.Trace.CallTargets) != 4 || p.PlainValueTransfer || len(p.SurvivingCreations) != 0 {
		t.Fatalf("trace not derived from the plugin tree: %+v", p.Trace)
	}
	if h, err := p.GetCodeHash(context.Background(), "0x2222222222222222222222222222222222222222"); err != nil || h != codeHashes["0x2222222222222222222222222222222222222222"] {
		t.Fatal("code hashes must come from the plugin snapshot", h, err)
	}
}

func TestPrepareBesuFailsClosedOnDisagreementOrLifecycle(t *testing.T) {
	t.Setenv("OPS_APPROVAL_NODE", "besu")
	calls, codeHashes, want := besuFixture(t)
	tx, raw := signedCall(t)
	calls, want = rootedAt(t, calls, tx, codeHashes)
	type refusal struct {
		response object
		reason   string // substring of the expected error
	}
	prepared := func(overrides object) object {
		r := object{"hashMode": 3, "chainId": "0x7a69", "txHash": tx.Hash().Hex(), "fingerprint": want.Hex(), "calls": calls, "codeHashes": codeHashes}
		for k, v := range overrides {
			r[k] = v
		}
		return r
	}
	cases := map[string]refusal{
		"fingerprint disagreement": {prepared(object{"fingerprint": common.HexToHash("0x01").Hex()}), "disagrees"},
		"other transaction":        {prepared(object{"txHash": common.HexToHash("0x02").Hex()}), "does not describe"},
		"strict mode":              {prepared(object{"hashMode": 0}), "does not describe"},
		"wrong chain":              {prepared(object{"chainId": "0x1"}), "does not describe"},
		"missing code hash":        {prepared(object{"codeHashes": map[string]string{}}), "missing executed code"},
		"malformed code hash":      {prepared(object{"codeHashes": map[string]string{"0x1111111111111111111111111111111111111111": "0x12"}}), "malformed"},
	}
	// A CREATE below the root is a lifecycle execution: refused by the encoder, not the envelope check.
	lifecycle := object{}
	for k, v := range calls {
		lifecycle[k] = v
	}
	child := object{}
	for k, v := range obj(calls["calls"].([]any)[0]) {
		child[k] = v
	}
	child["type"] = "CREATE"
	lifecycle["calls"] = append([]any{child}, calls["calls"].([]any)[1:]...)
	cases["lifecycle"] = refusal{prepared(object{"calls": lifecycle}), errCallLifecycle.Error()}
	// The plugin must have simulated the signed transaction itself: root frame ≠ signed envelope.
	for field, value := range map[string]any{"from": "0x" + strings.Repeat("99", 20), "to": "0x" + strings.Repeat("98", 20), "input": "0x00", "value": "0x1", "type": "STATICCALL"} {
		other := object{}
		for k, v := range calls {
			other[k] = v
		}
		other[field] = value
		codes := map[string]common.Hash{}
		hashes := map[string]string{}
		for a, h := range codeHashes {
			codes[a] = common.HexToHash(h)
			hashes[a] = h
		}
		if field == "to" {
			codes[strings.ToLower(value.(string))] = codes["0x1111111111111111111111111111111111111111"]
			hashes[strings.ToLower(value.(string))] = hashes["0x1111111111111111111111111111111111111111"]
		}
		selfConsistent, _, err := callFingerprintWithCodes(other, codes)
		if err != nil {
			t.Fatal(err)
		}
		cases["root "+field] = refusal{prepared(object{"fingerprint": selfConsistent.Hex(), "calls": other, "codeHashes": hashes}), "root frame"}
	}
	for name, c := range cases {
		server := besuServer(t, func(string) any { return c.response })
		s, err := NewPreflight(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.Prepare(context.Background(), raw)
		if err == nil || !strings.Contains(err.Error(), c.reason) {
			t.Fatalf("%s: want refusal containing %q, got %v", name, c.reason, err)
		}
		s.Close()
		server.Close()
	}
}

func TestPrepareBesuMarksPlainValueTransfers(t *testing.T) {
	t.Setenv("OPS_APPROVAL_NODE", "besu")
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	to := common.HexToAddress("0x" + strings.Repeat("ee", 20))
	tx, err := types.SignTx(types.NewTransaction(0, to, big.NewInt(1), 21000, big.NewInt(1), nil), types.NewEIP155Signer(big.NewInt(31337)), key)
	if err != nil {
		t.Fatal(err)
	}
	rawBytes, _ := tx.MarshalBinary()
	raw := hexutil.Encode(rawBytes)
	empty := crypto.Keccak256Hash(nil).Hex()
	calls := object{"type": "CALL", "from": strings.ToLower(from.Hex()), "to": strings.ToLower(to.Hex()), "input": "0x", "value": "0x1", "calls": []any{}}
	codes := map[string]common.Hash{strings.ToLower(to.Hex()): crypto.Keccak256Hash(nil)}
	want, _, err := callFingerprintWithCodes(calls, codes)
	if err != nil {
		t.Fatal(err)
	}
	server := besuServer(t, func(string) any {
		return object{"hashMode": 3, "chainId": "0x7a69", "txHash": tx.Hash().Hex(), "fingerprint": want.Hex(), "calls": calls, "codeHashes": map[string]string{strings.ToLower(to.Hex()): empty}}
	})
	defer server.Close()
	s, err := NewPreflight(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, err := s.Prepare(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if !p.PlainValueTransfer || !p.NoCodeRecipients[strings.ToLower(to.Hex())] {
		t.Fatalf("EOA transfer not recognised: %+v", p)
	}
}

func TestBesuModeRefusesStrictHashModeAtStartup(t *testing.T) {
	t.Setenv("OPS_APPROVAL_NODE", "besu")
	t.Setenv("OPS_APPROVAL_HASH_MODE", "strict")
	if _, err := NewPreflight("http://127.0.0.1:1"); err == nil {
		t.Fatal("besu + strict must fail at construction, not per request")
	}
}

func TestPrepareBesuRejectsUnknownNodeSetting(t *testing.T) {
	t.Setenv("OPS_APPROVAL_NODE", "nethermind")
	if _, err := NewPreflight("http://127.0.0.1:1"); err == nil {
		t.Fatal("unknown node kind must not silently select a mode")
	}
}
