package policydsl

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
)

// TestFixtureSelectorsMatchABI pins the selector constants used by the other
// tests to the fixture ABI. Without it, editing the ABI would silently leave the
// constants pointing at functions that no longer exist, and the validation tests
// would start proving nothing.
func TestFixtureSelectorsMatchABI(t *testing.T) {
	parsed, err := abi.JSON(strings.NewReader(vaultABI))
	if err != nil {
		t.Fatalf("fixture ABI does not parse: %v", err)
	}

	want := map[string]string{
		"transfer":  selTransfer,
		"balanceOf": selBalanceOf,
		"note":      selNote,
	}

	if len(parsed.Methods) != len(want) {
		t.Fatalf("fixture ABI has %d methods, constants cover %d", len(parsed.Methods), len(want))
	}

	for name, wantSel := range want {
		m, ok := parsed.Methods[name]
		if !ok {
			t.Errorf("fixture ABI has no method %q", name)
			continue
		}
		got := "0x" + common0x(crypto.Keccak256([]byte(m.Sig))[:4])
		if got != wantSel {
			t.Errorf("%s: constant is %s, ABI gives %s", name, wantSel, got)
		}
	}
}

func common0x(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexdigits[c>>4], hexdigits[c&0x0f])
	}
	return string(out)
}
