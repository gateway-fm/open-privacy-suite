package nodeapproval

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func fixture(t *testing.T) object {
	t.Helper()
	data, e := os.ReadFile("testdata/fingerprint.json")
	if e != nil {
		t.Fatal(e)
	}
	var v object
	if e = json.Unmarshal(data, &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func hashFixture(t *testing.T, v object) common.Hash {
	t.Helper()
	h, _, e := Fingerprint(obj(v["calls"]), obj(v["pre"]), obj(v["diff"]))
	if e != nil {
		t.Fatal(e)
	}
	return h
}
func TestFingerprintConformanceAndSensitivity(t *testing.T) {
	original := fixture(t)
	want := common.HexToHash(str(original["expected"]))
	if h := hashFixture(t, original); h != want {
		t.Fatalf("Go/Rust mismatch: %s != %s", h, want)
	}
	for _, field := range []string{"gas", "gasUsed"} {
		v := fixture(t)
		obj(v["calls"])[field] = "0x9999"
		if hashFixture(t, v) != want {
			t.Fatal("gas metadata changed fingerprint")
		}
	}
	for _, field := range []string{"input", "output", "to"} {
		v := fixture(t)
		obj(v["calls"])[field] = "0x" + "2222222222222222222222222222222222222222"
		if hashFixture(t, v) == want {
			t.Fatal("call change missed", field)
		}
	}
	for _, side := range []string{"pre", "post"} {
		v := fixture(t)
		a := "0x1111111111111111111111111111111111111111"
		k := "0x" + "0000000000000000000000000000000000000000000000000000000000000000"
		if side == "pre" {
			obj(obj(obj(v["pre"])[a])["storage"])[k] = "0x9"
		} else {
			obj(obj(obj(obj(v["diff"])["post"])[a])["storage"])[k] = "0x9"
		}
		if hashFixture(t, v) == want {
			t.Fatal("state change missed", side)
		}
	}
	v := fixture(t)
	obj(v["calls"])["calls"] = []any{object{"type": "STATICCALL", "from": "0x1111111111111111111111111111111111111111", "to": "0x2222222222222222222222222222222222222222", "input": "0x", "output": "0x"}}
	if hashFixture(t, v) == want {
		t.Fatal("no-write nested call missed")
	}
	v = fixture(t)
	obj(v["calls"])["type"] = "AUTHCALL"
	if _, _, e := Fingerprint(obj(v["calls"]), obj(v["pre"]), obj(v["diff"])); e == nil {
		t.Fatal("unknown operation accepted")
	}
}

func TestQueueIsBounded(t *testing.T) {
	s := &Service{signer: NewEd25519Signer("default", make([]byte, 32)), queue: make(chan Approval, 1), lanes: []*lane{readyLane(0)}}
	p := &Prepared{}
	if e := s.Enqueue(p); e != nil {
		t.Fatal(e)
	}
	if e := s.Enqueue(p); e == nil {
		t.Fatal("full queue accepted")
	}
}
