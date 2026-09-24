package policydsl

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// vaultABI is the fixture ABI for the storage contract. It carries two functions
// named transfer so that selector-only rule targets are exercised against a name
// that is genuinely ambiguous.
const vaultABI = `[
  {"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable"},
  {"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"},{"name":"memo","type":"string"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable"},
  {"type":"function","name":"balanceOf","inputs":[{"name":"owner","type":"address"}],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
  {"type":"function","name":"note","inputs":[{"name":"memo","type":"string"}],"outputs":[],"stateMutability":"nonpayable"}
]`

// libraryABI is the fixture ABI for the implementation account reached by
// delegatecall. It is deliberately a different document from vaultABI, so a test
// that confuses the two fails.
const libraryABI = `[
  {"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable"},
  {"type":"function","name":"cap","inputs":[{"name":"limit","type":"uint64"}],"outputs":[],"stateMutability":"nonpayable"}
]`

const (
	selTransfer     = "0xa9059cbb" // transfer(address,uint256)
	selTransferMemo = "0x56b8c724" // transfer(address,uint256,string)
	selBalanceOf    = "0x70a08231" // balanceOf(address)
	selNote         = "0x1b352c43" // note(string)
	selCap          = "0xab854a6a" // cap(uint64)

	vaultAddr = "0x1f98431c8ad98523631ae4a59f267346ea31f984"
	relayAddr = "0x2222222222222222222222222222222222222222"
	groupID   = "grp_traders"
	orgID     = "org_acme"
)

var libraryAddr = common.HexToAddress("0xDDDD000000000000000000000000000000000004")

func abiDigest(t testing.TB, abiText string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(abiText))
	return hex.EncodeToString(sum[:])
}

func testCatalog(t *testing.T) Catalog {
	t.Helper()
	return Catalog{
		Org:    orgID,
		Groups: map[string]struct{}{groupID: {}},
		Contracts: map[string]ContractInfo{
			vaultAddr:                          {ABI: vaultABI},
			strings.ToLower(libraryAddr.Hex()): {ABI: libraryABI},
		},
	}
}

// TestFixtureSelectorsMatchABI pins the selector constants used by the other
// tests to the fixture ABIs. Without it, editing an ABI would silently leave the
// constants pointing at functions that no longer exist, and the validation tests
// would start proving nothing.
func TestFixtureSelectorsMatchABI(t *testing.T) {
	// Signatures rather than names, because the fixture overloads transfer and a
	// name alone cannot identify which one a constant refers to.
	want := map[string]struct {
		abiText  string
		selector string
	}{
		"transfer(address,uint256)":        {vaultABI, selTransfer},
		"transfer(address,uint256,string)": {vaultABI, selTransferMemo},
		"balanceOf(address)":               {vaultABI, selBalanceOf},
		"note(string)":                     {vaultABI, selNote},
		"cap(uint64)":                      {libraryABI, selCap},
	}

	for sig, w := range want {
		got := "0x" + hex.EncodeToString(crypto.Keccak256([]byte(sig))[:4])
		if got != w.selector {
			t.Errorf("%s: constant is %s, keccak gives %s", sig, w.selector, got)
		}
		if !abiHasSelector(t, w.abiText, got) {
			t.Errorf("%s: selector %s is not present in its fixture ABI", sig, got)
		}
	}
}

// TestFixtureOverloadsHaveDistinctSelectors is the reason rules address
// selectors rather than names: the two transfer entries are different functions.
func TestFixtureOverloadsHaveDistinctSelectors(t *testing.T) {
	if selTransfer == selTransferMemo {
		t.Fatal("the overloaded transfer entries must have different selectors")
	}
	for _, sel := range []string{selTransfer, selTransferMemo} {
		if !abiHasSelector(t, vaultABI, sel) {
			t.Errorf("selector %s is missing from the vault ABI", sel)
		}
	}
}

func abiHasSelector(t *testing.T, abiText, selector string) bool {
	t.Helper()
	parsed, err := abi.JSON(strings.NewReader(abiText))
	if err != nil {
		t.Fatalf("fixture ABI does not parse: %v", err)
	}
	for _, m := range parsed.Methods {
		if "0x"+hex.EncodeToString(m.ID) == selector {
			return true
		}
	}
	return false
}
