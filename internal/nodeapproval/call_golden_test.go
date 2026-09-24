package nodeapproval

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"
)

func TestCallGoldenAndModeAuthentication(t *testing.T) {
	makeCall := func(kind, from, to, input string) object {
		return object{"type": kind, "from": from, "to": to, "input": input, "value": "0x7", "gas": "0xffff", "gasUsed": "0x10"}
	}
	v := fixture(t)
	first := makeCall("CALL", lifeContract, lifeRecipient, "0x00ff")
	delegate := makeCall("DELEGATECALL", lifeRecipient, lifeContract, "0x12345678")
	delegate["error"] = "caught"
	first["calls"] = []any{delegate}
	obj(v["calls"])["calls"] = []any{first, makeCall("STATICCALL", lifeContract, lifeRecipient, "0x")}
	obj(v["pre"])[lifeRecipient] = object{"code": "0x6001"}
	v["expected_calls"] = callHash(t, v).Hex()
	path := "testdata/call-v3.json"
	if os.Getenv("OPS_WRITE_CALL_GOLDEN") == "1" {
		data, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved object
	if err = json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if callHash(t, saved).Hex() != str(saved["expected_calls"]) {
		t.Fatal("Go/Rust call fixture changed")
	}
	want := callHash(t, v)
	for _, change := range []string{"order", "parent", "kind", "input", "value", "failure", "count"} {
		changed := cloneLife(v)
		root := obj(changed["calls"])
		children := root["calls"].([]any)
		child := obj(children[0])
		nested := obj(child["calls"].([]any)[0])
		switch change {
		case "order":
			children[0], children[1] = children[1], children[0]
		case "parent":
			child["calls"] = []any{}
			root["calls"] = append(children, nested)
		case "kind":
			nested["type"] = "CALLCODE"
		case "input":
			nested["input"] = "0x1111"
		case "value":
			nested["value"] = "0x8"
		case "failure":
			delete(nested, "error")
		case "count":
			root["calls"] = append(children, cloneLife(child))
		}
		if callHash(t, changed) == want {
			t.Fatal("missed nested", change)
		}
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	a := Approval{ChainID: 31337, HashMode: HashCalls, Fingerprint: want}
	b, err := goldenSigner(key).SignBatch([]Approval{a, {ChainID: 31337, HashMode: HashStrict, Fingerprint: want}}, DefaultApprovalTTL)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("OPS_WRITE_CALL_GOLDEN") == "1" {
		data, _ = json.MarshalIndent(b, "", "  ")
		if err = os.WriteFile("testdata/call-batch.json", data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	signed := ed25519.Sign(key, a.Message())
	a.HashMode = HashStrict
	if ed25519.Verify(key.Public().(ed25519.PublicKey), a.Message(), signed) {
		t.Fatal("hash mode not signed")
	}
	a.HashMode = 42
	if _, err = SignBatch(key, []Approval{a}); err == nil {
		t.Fatal("unknown mode accepted")
	}
	for _, kind := range []string{"CREATE", "CREATE2", "SELFDESTRUCT"} {
		f := lifeFixture(kind)
		_, _, mode, err := fingerprintForMode(HashCalls, obj(f["calls"]), obj(f["pre"]), obj(f["diff"]))
		if err != nil || mode != HashStrict {
			t.Fatal("lifecycle did not retain strict mode", kind, mode, err)
		}
	}
}
