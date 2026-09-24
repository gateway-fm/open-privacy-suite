package nodeapproval

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"io"
	"net"
	"os"
	"testing"
	"time"
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

func TestDeliveryUsesPersistentConnectionWithoutAck(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	seed := bytes.Repeat([]byte{7}, 32)
	s, e := New("http://127.0.0.1:1", listener.Addr().String(), seed)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	received := make(chan error, 2)
	go func() {
		c, e := listener.Accept()
		if e != nil {
			received <- e
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(time.Second))
		for i := 0; i < 2; i++ {
			var n uint32
			if e = binary.Read(c, binary.BigEndian, &n); e != nil {
				received <- e
				return
			}
			data := make([]byte, n)
			if _, e = io.ReadFull(c, data); e != nil {
				received <- e
				return
			}
			if len(data) < 64 || !bytes.HasPrefix(data, []byte("OPS_APPROVAL_BATCH_V2\x00")) {
				received <- io.ErrUnexpectedEOF
				return
			}
			message, sig := data[:len(data)-64], data[len(data)-64:]
			if !ed25519.Verify(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), message, sig) {
				received <- io.ErrUnexpectedEOF
				return
			}
			// Each 120-byte approval ends with the reserved field, which senders fill with zeros.
			header := 22 + 1 + int(message[22]) + 16 + 4 // domain, key id, issued_at, expires_at, count
			for item := message[header:]; len(item) >= 120; item = item[120:] {
				if !bytes.Equal(item[88:120], make([]byte, 32)) {
					received <- errors.New("the reserved field is not zero")
					return
				}
			}

			received <- nil
		}
	}()
	p := &Prepared{Approval: Approval{ChainID: 31337, TxHash: common.HexToHash("0x1234"), Fingerprint: common.HexToHash("0x5678")}}
	for i := 0; i < 2; i++ {
		if e = s.Enqueue(p); e != nil {
			t.Fatal(e)
		}
		select {
		case e := <-received:
			if e != nil {
				t.Fatalf("delivery failed: %v", e)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("singleton was not delivered immediately")
		}
	}
}
func TestQueueIsBounded(t *testing.T) {
	s := &Service{signer: NewEd25519Signer("default", make([]byte, 32)), queue: make(chan Approval, 1), done: make(chan struct{})}
	p := &Prepared{}
	if e := s.Enqueue(p); e != nil {
		t.Fatal(e)
	}
	if e := s.Enqueue(p); e == nil {
		t.Fatal("full queue accepted")
	}
}
