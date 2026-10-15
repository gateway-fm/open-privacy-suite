package rbac

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

const indexedSelfABI = `[
 {"type":"event","name":"Transfer","anonymous":false,"inputs":[
  {"name":"from","type":"address","indexed":true},
  {"name":"to","type":"address","indexed":true},
  {"name":"value","type":"uint256","indexed":false}]},
 {"type":"event","name":"Keyed","anonymous":false,"inputs":[
  {"name":"key","type":"bytes32","indexed":true},
  {"name":"payee","type":"address","indexed":false}]},
 {"type":"event","name":"Anon","anonymous":true,"inputs":[
  {"name":"who","type":"address","indexed":true}]},
 {"type":"event","name":"Mixed","anonymous":false,"inputs":[
  {"name":"owners","type":"address[]","indexed":true},
  {"name":"id","type":"uint256","indexed":true}]}
]`

const (
	isTransferT0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef" // Transfer(address,address,uint256)
	isViewer     = "0xabc1234567890123456789012345678901234567"
	isOther      = "0x0000000000000000000000000000000000000bad"
)

func isTopic(addr string) string {
	return "0x" + strings.Repeat("0", 24) + strings.TrimPrefix(strings.ToLower(addr), "0x")
}

func isWord(n int) string {
	h := "0123456789abcdef"
	w := []byte(strings.Repeat("0", 64))
	for i := 63; n > 0 && i >= 0; i-- {
		w[i] = h[n&0xf]
		n >>= 4
	}
	return string(w)
}

func TestMatchIndexedSelf(t *testing.T) {
	linked := map[string]bool{isViewer: true}
	keyedT0 := "0x" + eventTopic0Hex(t, "Keyed(bytes32,address)")
	anonTopic := isTopic(isViewer)
	mixedT0 := "0x" + eventTopic0Hex(t, "Mixed(address[],uint256)")

	cases := []struct {
		name   string
		abi    string
		topics []string
		data   string
		want   bool
	}{
		{"viewer is indexed `from`", indexedSelfABI, []string{isTransferT0, isTopic(isViewer), isTopic(isOther)}, "0x" + isWord(1000), true},
		{"viewer is indexed `to`", indexedSelfABI, []string{isTransferT0, isTopic(isOther), isTopic(isViewer)}, "0x" + isWord(1), true},
		{"checksummed/upper-case topic still matches", indexedSelfABI, []string{isTransferT0, strings.ToUpper(isTopic(isViewer))[:2] + strings.ToUpper(isTopic(isViewer))[2:], isTopic(isOther)}, "0x" + isWord(1), true},
		{"viewer named in neither indexed param", indexedSelfABI, []string{isTransferT0, isTopic(isOther), isTopic(isOther)}, "0x" + isWord(1), false},
		{"viewer only in a NON-indexed address param", indexedSelfABI, []string{keyedT0, "0x" + isWord(7)}, "0x" + strings.TrimPrefix(isTopic(isViewer), "0x"), false},
		{"unknown ABI", "", []string{isTransferT0, isTopic(isViewer), isTopic(isOther)}, "0x" + isWord(1), false},
		{"unparseable ABI", "{not json", []string{isTransferT0, isTopic(isViewer), isTopic(isOther)}, "0x" + isWord(1), false},
		{"topic0 not in the ABI", indexedSelfABI, []string{"0x" + isWord(99), isTopic(isViewer), isTopic(isOther)}, "0x" + isWord(1), false},
		{"anonymous event (no signature topic)", indexedSelfABI, []string{anonTopic}, "0x", false},
		{"no topics", indexedSelfABI, nil, "0x", false},
		{"too few topics for the ABI", indexedSelfABI, []string{isTransferT0, isTopic(isViewer)}, "0x" + isWord(1), false},
		{"too many topics for the ABI", indexedSelfABI, []string{isTransferT0, isTopic(isViewer), isTopic(isOther), isTopic(isOther)}, "0x" + isWord(1), false},
		{"non-canonical address padding", indexedSelfABI, []string{isTransferT0, "0x" + strings.Repeat("0", 23) + "1" + strings.TrimPrefix(isViewer, "0x"), isTopic(isOther)}, "0x" + isWord(1), false},
		{"malformed topic hex", indexedSelfABI, []string{isTransferT0, "0xzz" + strings.Repeat("0", 62), isTopic(isViewer)}, "0x" + isWord(1), false},
		{"short topic", indexedSelfABI, []string{isTransferT0, isViewer, isTopic(isOther)}, "0x" + isWord(1), false},
		{"data does not decode (empty)", indexedSelfABI, []string{isTransferT0, isTopic(isViewer), isTopic(isOther)}, "0x", false},
		{"data does not decode (bad hex)", indexedSelfABI, []string{isTransferT0, isTopic(isViewer), isTopic(isOther)}, "0xnothex", false},
		{"data has an undeclared trailing word", indexedSelfABI, []string{isTransferT0, isTopic(isViewer), isTopic(isOther)}, "0x" + isWord(1) + isWord(2), false},
		{"indexed address[] is a hash, never a match", indexedSelfABI, []string{mixedT0, isTopic(isViewer), "0x" + isWord(5)}, "0x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewIndexedSelfMatcher()
			if got := m.Match(tc.abi, tc.topics, tc.data, linked); got != tc.want {
				t.Errorf("Match = %v, want %v", got, tc.want)
			}
			// Memoised second call agrees.
			if got := m.Match(tc.abi, tc.topics, tc.data, linked); got != tc.want {
				t.Errorf("memoised Match = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("no linked addresses never match", func(t *testing.T) {
		if NewIndexedSelfMatcher().Match(indexedSelfABI, []string{isTransferT0, isTopic(isViewer), isTopic(isOther)}, "0x"+isWord(1), nil) {
			t.Error("a viewer with no linked address matched")
		}
	})
	t.Run("nil matcher is safe and never matches", func(t *testing.T) {
		var m *IndexedSelfMatcher
		if m.Match(indexedSelfABI, []string{isTransferT0, isTopic(isViewer), isTopic(isOther)}, "0x"+isWord(1), linked) {
			t.Error("nil matcher matched")
		}
	})
}

func eventTopic0Hex(t *testing.T, sig string) string {
	t.Helper()
	return strings.TrimPrefix(crypto.Keccak256Hash([]byte(sig)).Hex(), "0x")
}

// An ABI may declare two events with the same signature and different indexed
// layouts (ERC-20 and ERC-721 Transfer share topic0). go-ethereum keeps both
// (renaming one), so the matcher must consider every candidate for topic0 and
// decide deterministically: the layout the log's shape fits is the one used.
func TestMatchIndexedSelf_DuplicateSignatureIsDeterministic(t *testing.T) {
	const dupABI = `[
 {"type":"event","name":"Transfer","anonymous":false,"inputs":[
  {"name":"from","type":"address","indexed":true},
  {"name":"to","type":"address","indexed":true},
  {"name":"value","type":"uint256","indexed":false}]},
 {"type":"event","name":"Transfer","anonymous":false,"inputs":[
  {"name":"from","type":"address","indexed":true},
  {"name":"to","type":"address","indexed":true},
  {"name":"tokenId","type":"uint256","indexed":true}]}
]`
	linked := map[string]bool{isViewer: true}
	erc20 := []string{isTransferT0, isTopic(isOther), isTopic(isViewer)}
	erc721 := []string{isTransferT0, isTopic(isOther), isTopic(isViewer), "0x" + isWord(7)}
	for i := 0; i < 64; i++ {
		m := NewIndexedSelfMatcher()
		if !m.Match(dupABI, erc20, "0x"+isWord(5), linked) {
			t.Fatalf("iteration %d: ERC-20-shaped Transfer naming the viewer not matched", i)
		}
		if !m.Match(dupABI, erc721, "0x", linked) {
			t.Fatalf("iteration %d: ERC-721-shaped Transfer naming the viewer not matched", i)
		}
		if m.Match(dupABI, []string{isTransferT0, isTopic(isOther), isTopic(isOther)}, "0x"+isWord(5), linked) {
			t.Fatalf("iteration %d: Transfer not naming the viewer matched", i)
		}
	}
}

// Indexed modifiers are absent from an event signature. If two registered
// layouts fit the same log but disagree about whether the viewer is named,
// the indexed-self rule cannot prove admission and must deny.
func TestMatchIndexedSelf_AmbiguousIndexedLayoutDenies(t *testing.T) {
	const ambiguousABI = `[
 {"type":"event","name":"Ambiguous","anonymous":false,"inputs":[
  {"name":"to","type":"address","indexed":true},
  {"name":"amount","type":"uint256","indexed":false}]},
 {"type":"event","name":"Ambiguous","anonymous":false,"inputs":[
  {"name":"to","type":"address","indexed":false},
  {"name":"amount","type":"uint256","indexed":true}]}
]`
	topics := []string{"0x" + eventTopic0Hex(t, "Ambiguous(address,uint256)"), isTopic(isViewer)}
	linked := map[string]bool{isViewer: true}
	for i := 0; i < 64; i++ {
		if NewIndexedSelfMatcher().Match(ambiguousABI, topics, "0x"+isWord(42), linked) {
			t.Fatalf("iteration %d: ambiguous event layout admitted", i)
		}
	}
}

// Even when both layouts name the viewer, they may disagree on which data
// word is an address. Field masking cannot safely select one of them.
func TestMatchIndexedSelf_AmbiguousDataAddressLayoutDenies(t *testing.T) {
	const ambiguousABI = `[
 {"type":"event","name":"Sensitive","anonymous":false,"inputs":[
  {"name":"viewer","type":"address","indexed":true},
  {"name":"secret","type":"address","indexed":false},
  {"name":"nonce","type":"uint256","indexed":true}]},
 {"type":"event","name":"Sensitive","anonymous":false,"inputs":[
  {"name":"viewer","type":"address","indexed":true},
  {"name":"secret","type":"address","indexed":true},
  {"name":"nonce","type":"uint256","indexed":false}]}
]`
	topics := []string{"0x" + eventTopic0Hex(t, "Sensitive(address,address,uint256)"), isTopic(isViewer), "0x" + isWord(7)}
	if NewIndexedSelfMatcher().Match(ambiguousABI, topics, isTopic(isOther), map[string]bool{isViewer: true}) {
		t.Fatal("ambiguous data-address layout admitted")
	}
}
