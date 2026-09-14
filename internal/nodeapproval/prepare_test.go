package nodeapproval

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestPrepareBindsDeploymentNonceAndUsesOnePinnedSnapshot(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	const nonce = uint64(1<<53 + 3) // Beyond exact float64 integer precision.
	tx, err := types.SignTx(types.NewContractCreation(nonce, big.NewInt(7), 1000000, big.NewInt(2000000000), []byte{0x60, 0}), types.NewEIP155Signer(big.NewInt(31337)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	v := lifeFixture("CREATE")
	obj(v["calls"])["from"] = from.Hex()
	// A contract nonce must also survive JSON numeric decoding exactly.
	obj(obj(v["pre"])[lifeContract])["nonce"] = json.Number("9007199254740995")
	traces := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		case "eth_getHeaderByNumber":
			result = object{"hash": "0x" + strings.Repeat("11", 32)}
		case "debug_traceCall":
			traces++
			var args, opts object
			var block string
			_ = json.Unmarshal(q.Params[0], &args)
			_ = json.Unmarshal(q.Params[1], &block)
			_ = json.Unmarshal(q.Params[2], &opts)
			if args["to"] != nil || args["value"] != "0x7" {
				t.Errorf("lost deploy/value: %+v", args)
			}
			if block != "0x"+strings.Repeat("11", 32) {
				t.Error("unpinned trace", block)
			}
			if obj(obj(opts["stateOverrides"])[from.Hex()])["nonce"] != hexutil.EncodeUint64(nonce) {
				t.Error("nonce override missing or rounded", opts)
			}
			if opts["tracer"] == "muxTracer" {
				result = object{"callTracer": v["calls"], "prestateTracer": v["pre"]}
			} else {
				result = v["diff"]
			}
		default:
			t.Error("unexpected RPC", q.Method)
		}
		_ = json.NewEncoder(w).Encode(object{"jsonrpc": "2.0", "id": q.ID, "result": result})
	}))
	defer server.Close()
	s, err := NewPreflight(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, err := s.Prepare(context.Background(), hexutil.Encode(raw))
	if err != nil {
		t.Fatal(err)
	}
	if p.Approval.HashMode != HashStrict {
		t.Fatal("deployment must retain strict approval")
	}
	if traces != 2 || !p.Trace.HasCreate {
		t.Fatal("missing canonical deployment trace", traces, p.Trace)
	}
	if p.Approval.Fingerprint != hashFixture(t, v) {
		t.Fatal("integer precision lost")
	}
}

func TestCreationSetsExcludeCollisionsAndTemporaryContracts(t *testing.T) {
	v := lifeFixture("CREATE")
	_, trace, err := Fingerprint(obj(v["calls"]), obj(v["pre"]), obj(v["diff"]))
	if err != nil {
		t.Fatal(err)
	}
	fresh, surviving := creationSets(trace, obj(v["pre"]), obj(v["diff"]))
	if !fresh[lifeContract] || !surviving[lifeContract] {
		t.Fatal("live creation missing")
	}
	delete(obj(obj(v["diff"])["post"]), lifeContract)
	fresh, surviving = creationSets(trace, obj(v["pre"]), obj(v["diff"]))
	if !fresh[lifeContract] || surviving[lifeContract] {
		t.Fatal("temporary creation must not be registered")
	}
	obj(obj(v["pre"])[lifeContract])["code"] = "0x6000"
	fresh, _ = creationSets(trace, obj(v["pre"]), obj(v["diff"]))
	if fresh[lifeContract] {
		t.Fatal("collision cannot grant existing code")
	}
}
