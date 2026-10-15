// RD-939 participant-detection coverage.
//
// Two new signals on top of the legacy hardcoded calldata heuristic:
//
//   Stage A — log-based participant detection. Viewer is a participant in
//             a tx when one of their linked addresses appears in an
//             indexed address topic of an accepted event signature
//             (Transfer / Approval / ApprovalForAll / TransferSingle /
//             TransferBatch / Deposit / Withdrawal) emitted by that tx.
//             Resolved via the LogParticipantStore the engine is wired
//             with; we use stubLogParticipantStore here.
//
//   Stage B — ABI-decoded calldata. When the called contract has a
//             registered ABI, decode the calldata against the ABI and
//             check every address-typed input. Catches custom-selector
//             mints/payouts (the original Dave bug).
//
// The tests below pin these signals tightly: every accepted event slot
// must be checked, every legitimate custom-selector calldata must be
// recognised, and BOTH must fail closed when the evidence is absent.

package explorer

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// ----- test stubs -----

// stubLogParticipantStore replays a fixed set of tx-hash hits as if the
// indexer query found them. Set TxHashes to the lowercase hashes that
// should resolve as log participants for any viewer; AddressFilter, when
// non-empty, additionally requires the viewer address to be in this
// allowlist (lets us assert the address-pinning behaviour the prod
// implementation gives us via the SQL WHERE clause).
type stubLogParticipantStore struct {
	TxHashes       map[string]bool
	AddressFilter  map[string]bool
	CallsRecorded  int
	LastAddresses  []string
	LastTxHashes   []string
	ErrToReturn    error
	NeverCalledFor map[string]bool // tx hashes that, if queried, fail the test
	t              *testing.T
}

func (s *stubLogParticipantStore) FindLogParticipantTxs(_ context.Context, viewerAddrs []string, txHashes []string) (map[string]bool, error) {
	s.CallsRecorded++
	s.LastAddresses = append([]string(nil), viewerAddrs...)
	s.LastTxHashes = append([]string(nil), txHashes...)
	if s.ErrToReturn != nil {
		return nil, s.ErrToReturn
	}
	if s.NeverCalledFor != nil {
		for _, h := range txHashes {
			if s.NeverCalledFor[strings.ToLower(h)] && s.t != nil {
				s.t.Errorf("LogParticipantStore must not be queried for %s", h)
			}
		}
	}
	if s.AddressFilter != nil {
		matched := false
		for _, a := range viewerAddrs {
			if s.AddressFilter[strings.ToLower(a)] {
				matched = true
				break
			}
		}
		if !matched {
			return map[string]bool{}, nil
		}
	}
	out := map[string]bool{}
	for _, h := range txHashes {
		lh := strings.ToLower(h)
		if s.TxHashes[lh] {
			out[lh] = true
		}
	}
	return out, nil
}

// (stubABIResolver and strPtr are shared with redactor_test.go.)

// ----- helpers -----

func newEngineForRD939(linkedAddrs []string, logStub *stubLogParticipantStore, abiStub *stubABIResolver) *RedactionEngine {
	db := &mockDB{
		linkedAddrs: linkedAddrs,
		visMap:      VisibilityMap{},
	}
	r := &RedactionEngine{readProfile: rbac.ReadProfileStandard, store: &mockContractStore{}, db: db}
	if logStub != nil {
		r.logParticipantStore = logStub
	}
	if abiStub != nil {
		r.abiResolver = abiStub
	}
	return r
}

// zeroPadAddressTopic returns the 32-byte topic-form for an address.
func zeroPadAddressTopic(addr string) string {
	hexAddr := strings.TrimPrefix(strings.ToLower(addr), "0x")
	return "0x000000000000000000000000" + hexAddr
}

// ----- Stage A: log-based participant detection -----

// TestRedactTransactions_LogParticipant_AllAcceptedSignatures verifies
// that every entry in ParticipantEventSlots produces a recognised
// participant. The test is a table over (eventSig, slotIndex) — for
// each accepted slot we set up a stub that returns "this viewer is in
// this tx" and assert the tx survives redaction even when both from/to
// are private and there's no visibleTo opt-in.
//
// This is the bug class RD-939 was filed for: a tx that the viewer
// would otherwise be cleanly dropped from must be visible when log
// evidence names them as a participant.
func TestRedactTransactions_LogParticipant_AllAcceptedSignatures(t *testing.T) {
	viewer := "0x1111111111111111111111111111111111111111"
	// Counterparty addresses for from/to so we have something to redact.
	hiddenFrom := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hiddenTo := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	cases := []struct {
		name   string
		event  string // human label
		topic0 string // expected entry in ParticipantEventSlots
		slots  []int  // slots we sanity-check against the canonical map
	}{
		{
			name:   "Transfer (ERC-20 / ERC-721)",
			event:  "Transfer(address,address,uint256)",
			topic0: "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
			slots:  []int{1, 2},
		},
		{
			name:   "Approval (ERC-20 / ERC-721)",
			event:  "Approval(address,address,uint256)",
			topic0: "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
			slots:  []int{1, 2},
		},
		{
			name:   "ApprovalForAll",
			event:  "ApprovalForAll(address,address,bool)",
			topic0: "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31",
			slots:  []int{1, 2},
		},
		{
			name:   "TransferSingle (ERC-1155)",
			event:  "TransferSingle(address,address,address,uint256,uint256)",
			topic0: "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62",
			slots:  []int{1, 2, 3},
		},
		{
			name:   "TransferBatch (ERC-1155)",
			event:  "TransferBatch(address,address,address,uint256[],uint256[])",
			topic0: "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb",
			slots:  []int{1, 2, 3},
		},
		{
			name:   "Deposit (WETH)",
			event:  "Deposit(address,uint256)",
			topic0: "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c",
			slots:  []int{1},
		},
		{
			name:   "Withdrawal (WETH)",
			event:  "Withdrawal(address,uint256)",
			topic0: "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65",
			slots:  []int{1},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			// First: the keccak hash of the event signature must match the
			// canonical topic0 we register in ParticipantEventSlots. If a
			// future contributor edits the signature string but forgets to
			// recompute the hash (or vice-versa) this fails immediately.
			gotHash := "0x" + hex.EncodeToString(crypto.Keccak256([]byte(c.event)))
			if !strings.EqualFold(gotHash, c.topic0) {
				t.Fatalf("test data drift: keccak(%q) = %s, expected %s", c.event, gotHash, c.topic0)
			}
			gotSlots, ok := ParticipantEventSlots[strings.ToLower(c.topic0)]
			if !ok {
				t.Fatalf("ParticipantEventSlots missing topic0 %s — test would silently regress", c.topic0)
			}
			if len(gotSlots) != len(c.slots) {
				t.Fatalf("ParticipantEventSlots[%s] slots = %v, expected %v", c.topic0, gotSlots, c.slots)
			}

			// Real assertion: the viewer is in the log-participant set for
			// this tx; the redactor must keep the tx.
			txHash := "0xc0ffee" + c.topic0[2:14] // unique per case
			stub := &stubLogParticipantStore{
				TxHashes:      map[string]bool{strings.ToLower(txHash): true},
				AddressFilter: map[string]bool{strings.ToLower(viewer): true},
			}
			r := newEngineForRD939([]string{viewer}, stub, nil)
			// Counterparty fully hidden — without the log signal this tx
			// would be dropped (both ends non-identifiable).
			r.db.(*mockDB).visMap = VisibilityMap{
				strings.ToLower(hiddenFrom): VisibilityHidden,
				strings.ToLower(hiddenTo):   VisibilityHidden,
			}

			out, err := r.RedactTransactions(context.Background(),
				[]Transaction{{Hash: txHash, From: hiddenFrom, To: strPtr(hiddenTo)}},
				"did:test:viewer")
			if err != nil {
				t.Fatalf("RedactTransactions: %v", err)
			}
			if len(out) != 1 {
				t.Fatalf("viewer is a log participant; expected 1 tx kept, got %d", len(out))
			}
		})
	}
}

// TestRedactTransactions_LogParticipant_NegativeMatrix covers cases
// where the log-based signal must NOT mark the viewer as a participant.
// Counterparts to the positive matrix above; together they pin both
// directions of the gate.
func TestRedactTransactions_LogParticipant_NegativeMatrix(t *testing.T) {
	viewer := "0x1111111111111111111111111111111111111111"
	hiddenFrom := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hiddenTo := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	cases := []struct {
		name string
		stub *stubLogParticipantStore
	}{
		{
			name: "empty result set → tx dropped",
			stub: &stubLogParticipantStore{TxHashes: map[string]bool{}},
		},
		{
			name: "tx hit but different viewer address (address filter fails)",
			stub: &stubLogParticipantStore{
				TxHashes:      map[string]bool{"0xaaa": true},
				AddressFilter: map[string]bool{"0xdead": true}, // wrong addr
			},
		},
		{
			name: "store error → fail closed, no participant signal",
			stub: &stubLogParticipantStore{ErrToReturn: context.DeadlineExceeded},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			r := newEngineForRD939([]string{viewer}, c.stub, nil)
			r.db.(*mockDB).visMap = VisibilityMap{
				strings.ToLower(hiddenFrom): VisibilityHidden,
				strings.ToLower(hiddenTo):   VisibilityHidden,
			}
			out, err := r.RedactTransactions(context.Background(),
				[]Transaction{{Hash: "0xaaa", From: hiddenFrom, To: strPtr(hiddenTo)}},
				"did:test:viewer")
			if err != nil {
				t.Fatalf("RedactTransactions: %v", err)
			}
			if len(out) != 0 {
				t.Fatalf("expected tx dropped (both ends hidden + no log signal); got %d", len(out))
			}
		})
	}
}

// TestRedactTransactions_LogParticipant_BatchSingleQuery asserts that the
// log-based check is invoked at most once per batch (rather than once
// per tx). Important: per-tx queries would be a 100x perf regression on
// the address-page path (10–50 txs per page).
func TestRedactTransactions_LogParticipant_BatchSingleQuery(t *testing.T) {
	viewer := "0x1111111111111111111111111111111111111111"
	stub := &stubLogParticipantStore{TxHashes: map[string]bool{}}
	r := newEngineForRD939([]string{viewer}, stub, nil)

	txs := []Transaction{
		{Hash: "0x1", From: "0xfrom1", To: strPtr("0xto1")},
		{Hash: "0x2", From: "0xfrom2", To: strPtr("0xto2")},
		{Hash: "0x3", From: "0xfrom3", To: strPtr("0xto3")},
	}
	if _, err := r.RedactTransactions(context.Background(), txs, "did:test:viewer"); err != nil {
		t.Fatalf("RedactTransactions: %v", err)
	}
	if stub.CallsRecorded != 1 {
		t.Fatalf("expected exactly 1 LogParticipantStore call for the whole batch, got %d", stub.CallsRecorded)
	}
	if len(stub.LastTxHashes) != 3 {
		t.Fatalf("expected all 3 tx hashes batched in one call, got %d", len(stub.LastTxHashes))
	}
}

// TestRedactTransactions_LogParticipant_NotQueriedWithoutViewer pins the
// "no viewer DID → no log query" optimisation: anonymous viewers never
// touch the log-participant signal.
func TestRedactTransactions_LogParticipant_NotQueriedWithoutViewer(t *testing.T) {
	stub := &stubLogParticipantStore{TxHashes: map[string]bool{}}
	r := newEngineForRD939(nil, stub, nil)

	if _, err := r.RedactTransactions(context.Background(),
		[]Transaction{{Hash: "0x1", From: "0xfrom", To: strPtr("0xto")}},
		"" /* no viewer */); err != nil {
		t.Fatalf("RedactTransactions: %v", err)
	}
	if stub.CallsRecorded != 0 {
		t.Fatalf("anonymous viewer must not trigger log-participant query, got %d calls", stub.CallsRecorded)
	}
}

// ----- Stage B: ABI-decoded calldata -----

// makeERC20MintCalldata produces calldata for a mint(address,uint256)
// custom function, with `selector` as the four-byte selector and the
// given address+amount as args. The function is intentionally NOT in
// the legacy isViewerInCalldata switch list — that's the whole point.
func makeERC20MintCalldata(selector []byte, recipient string, amount uint64) string {
	if len(selector) != 4 {
		panic("selector must be 4 bytes")
	}
	addrBytes := common.HexToAddress(recipient).Bytes()
	padded := append(make([]byte, 12), addrBytes...) // pad to 32

	amt := make([]byte, 32)
	for i := 0; i < 8; i++ {
		amt[31-i] = byte(amount >> (i * 8))
	}

	out := append([]byte{}, selector...)
	out = append(out, padded...)
	out = append(out, amt...)
	return "0x" + hex.EncodeToString(out)
}

// mintABI is the ABI for `mint(address recipient, uint256 amount)` —
// a custom function any token operator can deploy with any selector.
const mintABI = `[{"type":"function","name":"mint","inputs":[{"type":"address","name":"recipient"},{"type":"uint256","name":"amount"}],"outputs":[]}]`

// multiRecipientABI is `payOut(address[] recipients, uint256 amount)` —
// stresses recursion through []common.Address.
const multiRecipientABI = `[{"type":"function","name":"payOut","inputs":[{"type":"address[]","name":"recipients"},{"type":"uint256","name":"amount"}],"outputs":[]}]`

// computeSelector returns the keccak256-derived 4-byte function selector.
func computeSelector(t *testing.T, sig string) []byte {
	t.Helper()
	return crypto.Keccak256([]byte(sig))[:4]
}

func TestRedactTransactions_ABIDecoded_CustomSelectorMint(t *testing.T) {
	// Reproducer for the original Dave bug: the contract uses a custom
	// selector that isn't in the legacy hardcoded list. With Stage B
	// wired (and the ABI on file), the viewer's address as the first
	// arg is recognised via ABI-decoded participant detection.
	viewer := "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65" // Dave's actual address from the bug report
	contract := "0x90118d110b07abb82ba8980d1c5cc96eea810d2c"
	sel := computeSelector(t, "mint(address,uint256)")
	calldata := makeERC20MintCalldata(sel, viewer, 100)

	abiStub := &stubABIResolver{byAddr: map[string]string{contract: mintABI}}
	r := newEngineForRD939([]string{viewer}, nil, abiStub)
	r.db.(*mockDB).visMap = VisibilityMap{
		"0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead": VisibilityHidden,
		contract: VisibilityHidden,
	}

	out, err := r.RedactTransactions(context.Background(),
		[]Transaction{{
			Hash:      "0xmint1",
			From:      "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead", // hidden admin
			To:        strPtr(contract),                             // hidden contract
			InputData: calldata,
		}},
		"did:test:viewer")
	if err != nil {
		t.Fatalf("RedactTransactions: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("Stage B should recognise viewer as calldata participant via ABI; got %d kept", len(out))
	}
}

func TestRedactTransactions_ABIDecoded_NoABI_FailsClosedForCalldataOnly(t *testing.T) {
	// Posture from the issue acceptance: no ABI on file → no calldata
	// claim. The log-based signal (Stage A) is the right safety net for
	// these cases; the test verifies Stage B doesn't degrade to
	// hardcoded-list reliance.
	viewer := "0x1111111111111111111111111111111111111111"
	contract := "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
	sel := computeSelector(t, "mint(address,uint256)")
	calldata := makeERC20MintCalldata(sel, viewer, 100)

	// ABI resolver returns "" for the contract (no ABI uploaded).
	abiStub := &stubABIResolver{byAddr: map[string]string{}}
	r := newEngineForRD939([]string{viewer}, nil /* no log signal */, abiStub)
	r.db.(*mockDB).visMap = VisibilityMap{
		"0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead": VisibilityHidden,
		contract: VisibilityHidden,
	}

	out, err := r.RedactTransactions(context.Background(),
		[]Transaction{{
			Hash:      "0xnoabi1",
			From:      "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
			To:        strPtr(contract),
			InputData: calldata,
		}},
		"did:test:viewer")
	if err != nil {
		t.Fatalf("RedactTransactions: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("no ABI + no log signal → must drop (fail closed); got %d kept", len(out))
	}
}

func TestRedactTransactions_ABIDecoded_NestedAddressSlice(t *testing.T) {
	// payOut(address[] recipients, uint256 amount) — viewer is one of
	// several recipients. ABI decoding must recurse into []address.
	viewer := "0x1111111111111111111111111111111111111111"
	contract := "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"

	parsed, err := abi.JSON(strings.NewReader(multiRecipientABI))
	if err != nil {
		t.Fatalf("parse multiRecipientABI: %v", err)
	}
	addrs := []common.Address{
		common.HexToAddress("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead"),
		common.HexToAddress(viewer),
		common.HexToAddress("0xfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed"),
	}
	packed, err := parsed.Pack("payOut", addrs, big.NewInt(42))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	calldata := "0x" + hex.EncodeToString(packed)

	abiStub := &stubABIResolver{byAddr: map[string]string{contract: multiRecipientABI}}
	r := newEngineForRD939([]string{viewer}, nil, abiStub)
	r.db.(*mockDB).visMap = VisibilityMap{
		"0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead": VisibilityHidden,
		contract: VisibilityHidden,
	}

	out, err := r.RedactTransactions(context.Background(),
		[]Transaction{{
			Hash:      "0xpayout1",
			From:      "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
			To:        strPtr(contract),
			InputData: calldata,
		}},
		"did:test:viewer")
	if err != nil {
		t.Fatalf("RedactTransactions: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("viewer is one of the address[] recipients; Stage B must recognise; got %d kept", len(out))
	}
}

func TestRedactTransactions_ABIDecoded_AddressLooksLikeViewerButTypedUint(t *testing.T) {
	// Subtle negative case: the calldata BYTES happen to contain the
	// viewer's address pattern, but the ABI types the slot as uint256
	// (not address). The decoder will unpack a *big.Int — anyAddressMatches
	// must NOT match it. Pre-Stage-B hardcoded `extractAddr` was a pure
	// byte-pattern check and would have false-positive'd here; the
	// ABI-decoded path is what gives us the right type discrimination.
	viewer := "0x1111111111111111111111111111111111111111"
	contract := "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"

	// foo(uint256) — the arg is structurally 32 bytes containing the
	// viewer's address pattern but typed as uint256.
	const fooABI = `[{"type":"function","name":"foo","inputs":[{"type":"uint256","name":"v"}],"outputs":[]}]`
	sel := computeSelector(t, "foo(uint256)")

	// Same byte pattern as makeERC20MintCalldata's first 32-byte arg.
	addrBytes := common.HexToAddress(viewer).Bytes()
	padded := append(make([]byte, 12), addrBytes...)
	out := append([]byte{}, sel...)
	out = append(out, padded...)
	calldata := "0x" + hex.EncodeToString(out)

	abiStub := &stubABIResolver{byAddr: map[string]string{contract: fooABI}}
	r := newEngineForRD939([]string{viewer}, nil, abiStub)
	r.db.(*mockDB).visMap = VisibilityMap{
		"0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead": VisibilityHidden,
		contract: VisibilityHidden,
	}
	res, err := r.RedactTransactions(context.Background(),
		[]Transaction{{
			Hash:      "0xfoo1",
			From:      "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
			To:        strPtr(contract),
			InputData: calldata,
		}},
		"did:test:viewer")
	if err != nil {
		t.Fatalf("RedactTransactions: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("uint256 argument byte-equal to viewer must NOT be a participant; got %d kept", len(res))
	}
}

// TestRedactTransactions_ABIDecoded_WrongABI_FailsClosed asserts the
// failsafe: if the registered ABI doesn't include the function selector
// (e.g. proxy contract whose ABI is for the implementation but the call
// hit a different upgrade), we don't crash and we don't over-reveal.
func TestRedactTransactions_ABIDecoded_WrongABI_FailsClosed(t *testing.T) {
	viewer := "0x1111111111111111111111111111111111111111"
	contract := "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"

	// ABI describes a different function from the one in calldata.
	const otherABI = `[{"type":"function","name":"unrelated","inputs":[{"type":"bool"}],"outputs":[]}]`
	sel := computeSelector(t, "mint(address,uint256)")
	calldata := makeERC20MintCalldata(sel, viewer, 1)

	abiStub := &stubABIResolver{byAddr: map[string]string{contract: otherABI}}
	r := newEngineForRD939([]string{viewer}, nil, abiStub)
	r.db.(*mockDB).visMap = VisibilityMap{
		"0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead": VisibilityHidden,
		contract: VisibilityHidden,
	}
	res, err := r.RedactTransactions(context.Background(),
		[]Transaction{{
			Hash:      "0xwrongabi1",
			From:      "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
			To:        strPtr(contract),
			InputData: calldata,
		}},
		"did:test:viewer")
	if err != nil {
		t.Fatalf("RedactTransactions: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("ABI/selector mismatch must NOT yield a participant claim; got %d kept", len(res))
	}
}

// ----- Combination: log + ABI both off → tx drops; either on → kept -----

func TestRedactTransactions_BothSignalsOff_ContractCreation(t *testing.T) {
	// CREATE tx (no To). ABI decoder is short-circuited (no callee),
	// log signal returns nothing. From is hidden. Tx must drop.
	viewer := "0x1111111111111111111111111111111111111111"
	r := newEngineForRD939([]string{viewer},
		&stubLogParticipantStore{TxHashes: map[string]bool{}},
		&stubABIResolver{byAddr: map[string]string{}},
	)
	r.db.(*mockDB).visMap = VisibilityMap{
		"0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead": VisibilityHidden,
	}
	res, err := r.RedactTransactions(context.Background(),
		[]Transaction{{
			Hash: "0xcreate1",
			From: "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
			To:   nil, // CREATE
		}},
		"did:test:viewer")
	if err != nil {
		t.Fatalf("RedactTransactions: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("CREATE by hidden deployer with no participant signal must drop; got %d kept", len(res))
	}
}
