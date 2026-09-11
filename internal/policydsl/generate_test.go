package policydsl

import (
	"strings"
	"testing"
)

// TestSolidityComment_CannotEscapeItsComment covers the case a naive replacer
// gets wrong: deleting the inner "*/" of "**//" leaves the outer characters
// adjacent and reconstitutes the very sequence that was being removed.
//
// The reachable input is a function signature taken from a registered ABI, so
// it is operator-influenced and has to hold for adversarial text.
func TestSolidityComment_CannotEscapeItsComment(t *testing.T) {
	inputs := []string{
		"transfer(address,uint256)",
		"*/",
		"**//",
		"a**//b",
		"/*",
		"//",
		"line\nbreak",
		"carriage\rreturn",
		"paragraph separator",
		"line separator",
		"back\\slash",
		"nul\x00byte",
	}

	for _, in := range inputs {
		got := solidityComment(in)
		for _, bad := range []string{"*", "/", "\\", "\n", "\r", " ", " ", "\x00"} {
			if strings.Contains(got, bad) {
				t.Errorf("solidityComment(%q) = %q, which still contains %q", in, got, bad)
			}
		}
	}
}

// TestSolidityComment_KeepsOrdinaryTextReadable checks the sanitiser is not so
// blunt that a reviewer cannot tell which rule a comment describes.
func TestSolidityComment_KeepsOrdinaryTextReadable(t *testing.T) {
	// Parentheses, commas and identifiers all survive; only the characters that
	// could open or close a comment are replaced.
	if got := solidityComment("transfer(address,uint256)"); got != "transfer(address,uint256)" {
		t.Errorf("an ordinary signature was altered: %q", got)
	}
	if got := solidityComment("grp_traders"); got != "grp_traders" {
		t.Errorf("an ordinary group name was altered: %q", got)
	}
}
