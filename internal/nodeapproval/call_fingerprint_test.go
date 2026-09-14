package nodeapproval

import (
	"github.com/ethereum/go-ethereum/common"
	"strings"
	"testing"
)

func callHash(t *testing.T, v object) common.Hash {
	t.Helper()
	h, _, err := CallFingerprint(obj(v["calls"]), obj(v["pre"]))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestCallFingerprintAllowsCounterOutputsAndBalancesToChange(t *testing.T) {
	v := fixture(t)
	want := callHash(t, v)
	obj(obj(v["pre"])[lifeContract])["storage"] = object{"0x0": "0x100"}
	obj(obj(v["pre"])[lifeContract])["balance"] = "0x123"
	obj(obj(v["pre"])[lifeContract])["nonce"] = float64(123)
	obj(v["calls"])["output"] = "0x1234"
	obj(v["calls"])["logs"] = []any{object{"data": "0x1234"}}
	if callHash(t, v) != want {
		t.Fatal("ordinary counter/storage/output changes rejected")
	}
}

func TestCallFingerprintStillBindsCallsAndCode(t *testing.T) {
	for _, field := range []string{"from", "to", "input", "value", "error", "code"} {
		t.Run(field, func(t *testing.T) {
			v := fixture(t)
			want := callHash(t, v)
			switch field {
			case "from":
				obj(v["calls"])[field] = lifeRecipient
			case "to":
				obj(v["calls"])[field] = lifeSender
				obj(v["pre"])[lifeSender] = object{"code": "0x"}
			case "code":
				obj(obj(v["pre"])[lifeContract])[field] = "0x6002"
			case "error":
				obj(v["calls"])[field] = "execution reverted"
			default:
				obj(v["calls"])[field] = "0x1234"
			}
			if callHash(t, v) == want {
				t.Fatal("missed", field)
			}
		})
	}
}

func TestCallFingerprintRejectsMissingCodeAndLifecycle(t *testing.T) {
	v := fixture(t)
	delete(obj(v["pre"]), lifeContract)
	if _, _, err := CallFingerprint(obj(v["calls"]), obj(v["pre"])); err == nil {
		t.Fatal("missing code proof accepted")
	}
	for _, kind := range []string{"CREATE", "CREATE2", "SELFDESTRUCT", "AUTHCALL"} {
		v = fixture(t)
		obj(v["calls"])["calls"] = []any{object{"type": kind, "from": lifeContract, "to": lifeRecipient, "error": "caught"}}
		if _, _, err := CallFingerprint(obj(v["calls"]), obj(v["pre"])); err == nil {
			t.Fatal("unsupported lifecycle accepted", kind)
		}
	}
}

func TestCallFingerprintBoundsAndModeSelection(t *testing.T) {
	for _, tc := range []struct {
		setting string
		mode    uint8
		bad     bool
	}{{"", HashCalls, false}, {"calls", HashCalls, false}, {"strict", HashStrict, false}, {"ignore", 0, true}} {
		t.Setenv("OPS_APPROVAL_HASH_MODE", tc.setting)
		mode, err := configuredHashMode()
		if (err != nil) != tc.bad || (!tc.bad && mode != tc.mode) {
			t.Fatal(tc, mode, err)
		}
	}
	v := fixture(t)
	obj(v["calls"])["input"] = "0x" + strings.Repeat("00", 1<<20)
	if _, _, err := CallFingerprint(obj(v["calls"]), obj(v["pre"])); err == nil {
		t.Fatal("oversize input accepted")
	}
	v = fixture(t)
	root := obj(v["calls"])
	children := []any{}
	for i := 0; i < 128; i++ {
		children = append(children, cloneLife(root))
	}
	root["calls"] = children
	if _, _, err := CallFingerprint(root, obj(v["pre"])); err == nil {
		t.Fatal("oversize tree accepted")
	}
}
