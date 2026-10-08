package nodeapproval

import (
	"encoding/json"
	"testing"
)

const lifeSender = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const lifeContract = "0x1111111111111111111111111111111111111111"
const lifeRecipient = "0x2222222222222222222222222222222222222222"

func lifeFixture(kind string) object {
	return object{
		"calls": object{"type": kind, "from": lifeSender, "to": lifeContract, "input": "0x6000", "output": "0x6001", "value": "0x7"},
		"pre": object{
			lifeSender:   object{"balance": "0x64", "nonce": float64(0)},
			lifeContract: object{"balance": "0x0", "nonce": float64(0), "code": "0x"},
		},
		"diff": object{
			"pre": object{lifeSender: object{"balance": "0x64", "nonce": float64(0)}},
			"post": object{
				lifeSender:   object{"balance": "0x5d", "nonce": float64(1)},
				lifeContract: object{"balance": "0x7", "nonce": float64(1), "code": "0x6001", "storage": object{"0x0": "0x9"}},
			},
		},
	}
}

func cloneLife(v object) object {
	b, _ := json.Marshal(v)
	var out object
	_ = json.Unmarshal(b, &out)
	return out
}

func TestValueAndLifecycleFingerprint(t *testing.T) {
	for _, kind := range []string{"CALL", "CREATE", "CREATE2", "SELFDESTRUCT"} {
		t.Run(kind, func(t *testing.T) {
			v := lifeFixture(kind)
			_, trace, err := Fingerprint(obj(v["calls"]), obj(v["pre"]), obj(v["diff"]))
			if err != nil {
				t.Fatal(err)
			}
			if trace.HasCreate != (kind == "CREATE") || trace.HasCreate2 != (kind == "CREATE2") {
				t.Fatal("creation must reach the OPS deploy-claim gate", trace)
			}
			want := hashFixture(t, v)
			for _, field := range []string{"balance", "code", "nonce"} {
				changed := cloneLife(v)
				post := obj(obj(obj(changed["diff"])["post"])[lifeContract])
				if field == "nonce" {
					post[field] = float64(2)
				} else {
					post[field] = "0x09"
				}
				if hashFixture(t, changed) == want {
					t.Fatalf("missed post-%s", field)
				}
			}
			changed := cloneLife(v)
			obj(v["calls"])["value"] = "0x8"
			if hashFixture(t, v) == hashFixture(t, changed) {
				t.Fatal("missed call value")
			}
		})
	}
}

func TestNativeRecipientAndDeletionAffectFingerprint(t *testing.T) {
	v := lifeFixture("CALL")
	obj(v["calls"])["value"] = "0x0"
	obj(v["pre"])[lifeRecipient] = object{"balance": "0x10"}
	obj(obj(v["diff"])["pre"])[lifeRecipient] = object{"balance": "0x10"}
	obj(obj(v["diff"])["post"])[lifeRecipient] = object{"balance": "0x11"}
	want := hashFixture(t, v)
	obj(obj(obj(v["diff"])["post"])[lifeRecipient])["balance"] = "0x12"
	if hashFixture(t, v) == want {
		t.Fatal("missed balance change of account without code")
	}
	v = lifeFixture("CALL")
	obj(v["calls"])["value"] = "0x0"
	obj(v["pre"])[lifeContract] = object{"code": "0x6001", "nonce": float64(1), "storage": object{"0x0": "0x9"}}
	want = hashFixture(t, v)
	obj(obj(v["diff"])["pre"])[lifeContract] = obj(v["pre"])[lifeContract]
	delete(obj(obj(v["diff"])["post"]), lifeContract)
	if hashFixture(t, v) == want {
		t.Fatal("missed contract deletion")
	}
}

func TestFailedCreateAndCaughtDestructionStayInTrace(t *testing.T) {
	v := fixture(t)
	obj(v["calls"])["calls"] = []any{
		object{"type": "CREATE2", "from": lifeContract, "input": "0x6000", "error": "collision"},
		object{"type": "CALL", "from": lifeContract, "to": lifeRecipient, "error": "execution reverted", "calls": []any{
			object{"type": "SELFDESTRUCT", "from": lifeRecipient, "to": lifeContract, "value": "0x7"},
		}},
	}
	_, trace, err := Fingerprint(obj(v["calls"]), obj(v["pre"]), obj(v["diff"]))
	if err != nil {
		t.Fatal(err)
	}
	if !trace.HasCreate2 {
		t.Fatal("caught failure bypassed deploy permission")
	}
	want := hashFixture(t, v)
	children := obj(v["calls"])["calls"].([]any)
	obj(obj(children[1])["calls"].([]any)[0])["to"] = lifeSender
	if hashFixture(t, v) == want {
		t.Fatal("caught destruction beneficiary was ignored")
	}
}

func TestCancunNoopSelfDestructTrace(t *testing.T) {
	v := fixture(t)
	child := object{"type": "SELFDESTRUCT", "from": "0x0000000000000000000000000000000000000000"}
	obj(v["calls"])["calls"] = []any{child}
	// Pinned Reth emits a marker with no journal transfer for Cancun self-to-self.
	want := hashFixture(t, v)
	child["from"], child["to"], child["value"] = lifeContract, lifeContract, "0x0"
	if hashFixture(t, v) != want {
		t.Fatal("no-op selfdestruct must preserve its execution context")
	}
	delete(child, "to") // A partial real transfer is not the known no-op marker.
	if _, _, err := Fingerprint(obj(v["calls"]), obj(v["pre"]), obj(v["diff"])); err == nil {
		t.Fatal("incomplete transfer accepted")
	}
}
