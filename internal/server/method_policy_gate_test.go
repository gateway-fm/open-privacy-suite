package server

import (
	"strings"
	"testing"
)

func TestExtractEthCallResultBytes(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string // hex without 0x, "" = nil
	}{
		{"ok", `{"jsonrpc":"2.0","id":1,"result":"0x00000000000000000000000000000000000000000000000000000000000004d2"}`, "00000000000000000000000000000000000000000000000000000000000004d2"},
		{"empty 0x", `{"jsonrpc":"2.0","id":1,"result":"0x"}`, ""},
		{"error response", `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"reverted"}}`, ""},
		{"null result", `{"jsonrpc":"2.0","id":1,"result":null}`, ""},
		{"non-hex", `{"jsonrpc":"2.0","id":1,"result":"nope"}`, ""},
		{"garbage", `not json`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractEthCallResultBytes([]byte(tc.body))
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("want nil, got %x", got)
				}
				return
			}
			gotHex := ""
			for _, b := range got {
				gotHex += byteHex(b)
			}
			if gotHex != tc.want {
				t.Fatalf("got %s want %s", gotHex, tc.want)
			}
		})
	}
}

func byteHex(b byte) string {
	const hexd = "0123456789abcdef"
	return string([]byte{hexd[b>>4], hexd[b&0x0f]})
}

func TestDenyMethodPolicy_PreservesID_Opaque(t *testing.T) {
	out := string(denyMethodPolicy([]byte(`{"jsonrpc":"2.0","id":42,"result":"0xdeadbeef"}`)))
	if !strings.Contains(out, `"id":42`) {
		t.Fatalf("id not preserved: %s", out)
	}
	if !strings.Contains(out, `-32000`) || !strings.Contains(out, `"error"`) {
		t.Fatalf("not an opaque error: %s", out)
	}
	// must not echo the original result or any record detail
	if strings.Contains(out, "deadbeef") {
		t.Fatalf("deny leaked the result: %s", out)
	}
}
