package explorer

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"privacy-proxy/internal/rbac"
)

// mockDB implements Database for testing
type mockDB struct {
	visMap         VisibilityMap
	err            error
	linkedAddrs    []string        // addresses returned by GetLinkedAddresses
	eventAccessMap map[string]bool // addresses with event access
}

func (m *mockDB) GetBatchVisibility(_ context.Context, _ string, _ []string) (VisibilityMap, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.visMap, nil
}

func (m *mockDB) GetBatchVisibilityDetailed(_ context.Context, _ string, _ []string) (map[string]AddressVisibility, error) {
	if m.err != nil {
		return nil, m.err
	}
	res := make(map[string]AddressVisibility)
	for k, v := range m.visMap {
		reason := ReasonPublicAddress
		switch v {
		case VisibilityFull:
			reason = ReasonPublicAddress
		case VisibilityHidden, VisibilityRedacted:
			reason = ReasonNoAccess
		case VisibilityPseudonymous:
			// Pseudonymous level is only produced by disclosure-grant resolution
			// (no other code path in GetBatchVisibility emits it). Tests that
			// need to model a pseudonymous address get the grant reason
			// automatically — anything richer (RBAC, own, etc) must go through
			// newEngineDetailed to set the reason explicitly.
			reason = ReasonDisclosureGrant
		}
		res[k] = AddressVisibility{Level: v, Reason: reason}
	}
	return res, nil
}

func (m *mockDB) GetLinkedAddresses(_ context.Context, _ string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.linkedAddrs, nil
}

func (m *mockDB) GetBatchEventAccess(_ context.Context, _ string, addrs []string) (map[string]bool, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.eventAccessMap == nil {
		return make(map[string]bool), nil
	}
	result := make(map[string]bool)
	for _, a := range addrs {
		if m.eventAccessMap[strings.ToLower(a)] {
			result[strings.ToLower(a)] = true
		}
	}
	return result, nil
}

// mockContractStore implements ContractStore for testing
type mockContractStore struct {
	contracts map[string]*Contract // keyed by lowercase address
}

func (m *mockContractStore) GetContract(_ context.Context, address string) (*Contract, error) {
	if m.contracts == nil {
		return nil, nil
	}
	c := m.contracts[strings.ToLower(address)]
	return c, nil
}

func newEngine(visMap VisibilityMap) *RedactionEngine {
	return &RedactionEngine{readProfile: rbac.ReadProfileStandard, store: nil, db: &mockDB{visMap: visMap}}
}

func newEngineWithLinkedAddrs(visMap VisibilityMap, linkedAddrs []string) *RedactionEngine {
	return &RedactionEngine{readProfile: rbac.ReadProfileStandard, store: nil, db: &mockDB{visMap: visMap, linkedAddrs: linkedAddrs}}
}

func newEngineWithStore(visMap VisibilityMap, store ContractStore) *RedactionEngine {
	return &RedactionEngine{readProfile: rbac.ReadProfileStandard, store: store, db: &mockDB{visMap: visMap}}
}

func newEngineErr(err error) *RedactionEngine {
	return &RedactionEngine{readProfile: rbac.ReadProfileStandard, store: nil, db: &mockDB{err: err}}
}

// eventTopic0 computes keccak256 of an event signature, returning "0x"-prefixed hex.
func eventTopic0(sig string) string {
	return "0x" + hex.EncodeToString(crypto.Keccak256([]byte(sig)))
}

// encodeAddress encodes an Ethereum address as a zero-padded 32-byte hex string (no 0x prefix).
func encodeAddressSlot(addr string) string {
	addr = strings.TrimPrefix(strings.ToLower(addr), "0x")
	return strings.Repeat("0", 24) + strings.ToLower(addr)
}

// encodeUint256Slot encodes a uint256 value as a 32-byte zero-padded hex string (no 0x prefix).
func encodeUint256Slot(val uint64) string {
	return strings.Repeat("0", 56) + hex.EncodeToString([]byte{
		byte(val >> 56), byte(val >> 48), byte(val >> 40), byte(val >> 32),
		byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val),
	})
}

func strPtr(s string) *string { return &s }

// ---------------------------------------------------------------------------
// RedactTransactions
// ---------------------------------------------------------------------------

func TestRedactTransactions_Empty(t *testing.T) {
	engine := newEngine(nil)
	result, err := engine.RedactTransactions(context.Background(), nil, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestRedactTransactions_FullVisibility(t *testing.T) {
	addr1 := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	addr2 := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	txs := []Transaction{
		{Hash: "0x01", From: addr1, To: strPtr(addr2), Value: "1000", InputData: "0xdeadbeef"},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].From != addr1 {
		t.Errorf("From mismatch: %s", result[0].From)
	}
	if *result[0].To != addr2 {
		t.Errorf("To mismatch: %s", *result[0].To)
	}
	if result[0].Value != "1000" {
		t.Errorf("Value should be unchanged, got %s", result[0].Value)
	}
	if result[0].InputData != "0xdeadbeef" {
		t.Errorf("InputData should be unchanged, got %s", result[0].InputData)
	}
}

func TestRedactTransactions_HiddenFrom_DroppedForNonParticipant(t *testing.T) {
	// G10: non-participant, one side hidden → dropped
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: hidden from, non-participant → drop), got %d", len(result))
	}
}

func TestRedactTransactions_HiddenTo_DroppedForNonParticipant(t *testing.T) {
	// G10: non-participant, one side hidden → dropped
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityHidden,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: hidden to, non-participant → drop), got %d", len(result))
	}
}

func TestRedactTransactions_BothHidden_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityHidden,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 txs (both hidden → drop), got %d", len(result))
	}
}

func TestRedactTransactions_BothRedacted_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityRedacted,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 txs (both redacted → drop), got %d", len(result))
	}
}

func TestRedactTransactions_HiddenPlusRedacted_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 txs (hidden + redacted → drop), got %d", len(result))
	}
}

func TestRedactTransactions_BothHidden_AdminSees_FlagOn(t *testing.T) {
	// With the elevated audit view (ORG_ADMIN_VIEW_USER_TXS) on, an admin keeps
	// the both-sides-hidden row: addresses stay [PRIVATE], value is preserved
	// (consistent with the Transfer log the admin can already read), and the
	// reveal is counted for audit logging.
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		from: VisibilityHidden,
		to:   VisibilityHidden,
	})

	stats := &RedactStats{}
	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test",
		RedactOpts{ViewerIsAdmin: true, OrgAdminViewUserTxs: true, Stats: stats})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (admin sees both-hidden under flag), got %d", len(result))
	}
	if result[0].From != "[PRIVATE]" {
		t.Errorf("expected From [PRIVATE] (no real-address visibility), got %q", result[0].From)
	}
	if result[0].To == nil || *result[0].To != "[PRIVATE]" {
		t.Errorf("expected To [PRIVATE], got %v", result[0].To)
	}
	if string(result[0].Value) != "1000" {
		t.Errorf("expected value preserved (1000) under elevated audit view, got %q", result[0].Value)
	}
	if stats.AdminUserTxsRevealed != 1 {
		t.Errorf("expected 1 reveal counted, got %d", stats.AdminUserTxsRevealed)
	}
}

func TestRedactTransactions_BothHidden_AdminDropped_FlagOff(t *testing.T) {
	// Default (flag off): an admin does NOT see both-sides-hidden user↔user
	// rows — strict privacy, identical to non-admin behaviour. This is the
	// conservative default the deployment flag gates.
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		from: VisibilityHidden,
		to:   VisibilityHidden,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test",
		RedactOpts{ViewerIsAdmin: true}) // OrgAdminViewUserTxs defaults false
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected both-hidden row dropped for admin with flag off, got %d", len(result))
	}
}

func TestRedactTransactions_BothRedacted_AdminSees_FlagOn(t *testing.T) {
	// Redacted flavour of non-identifiable behaves the same as Hidden under the
	// elevated audit view.
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		from: VisibilityRedacted,
		to:   VisibilityRedacted,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test",
		RedactOpts{ViewerIsAdmin: true, OrgAdminViewUserTxs: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (admin sees both-redacted under flag), got %d", len(result))
	}
	if string(result[0].Value) != "1000" {
		t.Errorf("expected value preserved under elevated audit view, got %q", result[0].Value)
	}
}

func TestRedactTransactions_AdminFlagOn_NonAdminUnaffected(t *testing.T) {
	// The flag is inert for non-admins: a regular viewer still gets the
	// both-hidden drop even when the deployment flag is on.
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		from: VisibilityHidden,
		to:   VisibilityHidden,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test",
		RedactOpts{ViewerIsAdmin: false, OrgAdminViewUserTxs: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected both-hidden row dropped for non-admin regardless of flag, got %d", len(result))
	}
}

func TestRedactTransactions_RedactedPlusFull_DroppedForNonParticipant(t *testing.T) {
	// G10: non-participant, one side redacted → dropped
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityRedacted,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000", InputData: "0xdeadbeef"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: redacted from, non-participant → drop), got %d", len(result))
	}
}

func TestRedactTransactions_HiddenFrom_PublicTo_DroppedForNonParticipant(t *testing.T) {
	// G10: non-participant, one side hidden → dropped
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	errStr := "execution reverted"
	revertStr := "out of gas"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	txs := []Transaction{{
		Hash:         "0x01",
		From:         from,
		To:           strPtr(to),
		Value:        "1000",
		InputData:    "0xdeadbeef",
		Error:        &errStr,
		RevertReason: &revertStr,
	}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: hidden from, non-participant → drop), got %d", len(result))
	}
}

func TestRedactTransactions_HiddenTo_PublicFrom_DroppedForNonParticipant(t *testing.T) {
	// G10: non-participant, one side hidden → dropped
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityHidden,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000", InputData: "0xaa"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: hidden to, non-participant → drop), got %d", len(result))
	}
}

func TestRedactTransactions_RedactedFrom_DroppedForNonParticipant(t *testing.T) {
	// G10: non-participant, one side redacted → dropped
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	errStr := "execution reverted"
	revertStr := "out of gas"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityRedacted,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	txs := []Transaction{{
		Hash:         "0x01",
		From:         from,
		To:           strPtr(to),
		Value:        "1000",
		InputData:    "0xdeadbeef",
		Error:        &errStr,
		RevertReason: &revertStr,
	}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: redacted from, non-participant → drop), got %d", len(result))
	}
}

func TestRedactTransactions_RedactedTo_DroppedForNonParticipant(t *testing.T) {
	// G10: non-participant, one side redacted → dropped
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000", InputData: "0xaa"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: redacted to, non-participant → drop), got %d", len(result))
	}
}

func TestRedactTransactions_PseudonymousAddress(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	// mockDB derives Reason=ReasonDisclosureGrant for VisibilityPseudonymous —
	// which is correct (pseudonymous only comes from grants) — and that's the
	// trigger for counterparty demotion below.
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityPseudonymous,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "500"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	expectedFromPseudonym := GeneratePseudonym(from, nil)
	if result[0].From != expectedFromPseudonym {
		t.Errorf("From should be pseudonym %q, got %q", expectedFromPseudonym, result[0].From)
	}
	// Counterparty (To) must ALSO be pseudonymised: the disclosure-grant lens
	// applies to the whole tx, not just the granted address — otherwise the
	// counterparty's real address leaks alongside the granted party's
	// pseudonym, defeating the limited-audit-lens promise.
	expectedToPseudonym := GeneratePseudonym(to, nil)
	if result[0].To == nil || *result[0].To != expectedToPseudonym {
		t.Errorf("To (counterparty) should be pseudonymised under pseudonymous-grant lens %q, got %v", expectedToPseudonym, result[0].To)
	}
	// Value not stripped for pseudonymous
	if result[0].Value != "500" {
		t.Errorf("Value should be unchanged for pseudonymous, got %s", result[0].Value)
	}
}

// TestRedactTransactions_PseudonymousGrant_DemotesPublicCounterparty
// pins the exact scenario behind the user-reported leak: a viewer with a
// pseudonymous disclosure grant on one address sees a tx where the
// counterparty is a public contract (e.g. USDC, a precompile, an
// org-public contract). Pre-fix the contract's real address appeared
// in the regular tx-list render alongside the granted target's
// Address-XXXX — defeating the limited-audit-lens promise. The grant
// page (getGrantTransactions) already rendered the same tx with the
// contract as External-XXXX; this test makes the regular path consistent.
func TestRedactTransactions_PseudonymousGrant_DemotesPublicCounterparty(t *testing.T) {
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"            // pseudonymously disclosed to viewer
	publicContract := "0xcccccccccccccccccccccccccccccccccccccccc" // e.g. USDC — viewer sees it everywhere else

	engine := newEngineDetailed(
		VisibilityMap{bob: VisibilityPseudonymous, publicContract: VisibilityFull},
		map[string]AddressVisibility{
			bob:            {Level: VisibilityPseudonymous, Reason: ReasonDisclosureGrant, Visible: true},
			publicContract: {Level: VisibilityFull, Reason: ReasonPublicAddress, Visible: true},
		},
		nil,
	)

	txs := []Transaction{{Hash: "0x01", From: bob, To: strPtr(publicContract), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:eve")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].From != GeneratePseudonym(bob, nil) {
		t.Errorf("From: expected Bob's pseudonym, got %q", result[0].From)
	}
	if result[0].To == nil || *result[0].To != GeneratePseudonym(publicContract, nil) {
		t.Errorf("To (public contract): expected pseudonym under grant lens, got %v — this is the leak the test catches", result[0].To)
	}
}

// TestRedactTransactions_PseudonymousGrant_ParticipantOverrideWins
// pins that direct participants STILL see real counterparty addresses
// even when there's a pseudonymous grant on the other party — the
// participant already knows who they sent to / received from via their
// own wallet, so the grant's anonymisation lens is moot.
func TestRedactTransactions_PseudonymousGrant_ParticipantOverrideWins(t *testing.T) {
	viewerOwn := "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" // viewer's own address
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"       // pseudonymously disclosed

	engine := newEngineDetailed(
		VisibilityMap{viewerOwn: VisibilityFull, bob: VisibilityPseudonymous},
		map[string]AddressVisibility{
			viewerOwn: {Level: VisibilityFull, Reason: ReasonOwnAddress, Visible: true},
			bob:       {Level: VisibilityPseudonymous, Reason: ReasonDisclosureGrant, Visible: true},
		},
		[]string{viewerOwn}, // linked to viewerDID — drives the participant-override path
	)

	txs := []Transaction{{Hash: "0x01", From: viewerOwn, To: strPtr(bob), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:eve")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].From != viewerOwn {
		t.Errorf("From (viewer's own): expected real address, got %q — participant override must keep own addr visible", result[0].From)
	}
	// Counterparty: participant override revealed it; the grant's
	// pseudonymisation still applies though (Bob is at VisibilityPseudonymous
	// in the visibility map, and applyRedaction renders the pseudonym). The
	// row is rendered with Bob's pseudonym, NOT real address, because the
	// underlying visibility is Pseudonymous.
	if result[0].To == nil || *result[0].To != GeneratePseudonym(bob, nil) {
		t.Errorf("To (Bob): expected pseudonym (per Bob's own visibility), got %v", result[0].To)
	}
}

func TestRedactTransactions_NilTo(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: nil, Value: "0"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (nil to is fine), got %d", len(result))
	}
	if result[0].To != nil {
		t.Errorf("To should remain nil")
	}
}

func TestRedactTransactions_DBError(t *testing.T) {
	engine := newEngineErr(errors.New("db unavailable"))
	txs := []Transaction{{Hash: "0x01", From: "0xaa", To: strPtr("0xbb")}}
	_, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err == nil {
		t.Error("expected error from DB")
	}
}

func TestRedactTransactions_MultipleTxsMixed(t *testing.T) {
	// G10: non-participant txs with any hidden/redacted side are dropped.
	// Only Full<->Full survives for non-participants.
	addrFull := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	addrHidden := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	addrRedacted := "0xcccccccccccccccccccccccccccccccccccccccc"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityHidden,
		"0xcccccccccccccccccccccccccccccccccccccccc": VisibilityRedacted,
	})

	txs := []Transaction{
		{Hash: "0x01", From: addrFull, To: strPtr(addrFull)},     // keep (both Full)
		{Hash: "0x02", From: addrFull, To: strPtr(addrHidden)},   // drop (G10: hidden to, non-participant)
		{Hash: "0x03", From: addrFull, To: strPtr(addrRedacted)}, // drop (G10: redacted to, non-participant)
		{Hash: "0x04", From: addrHidden, To: strPtr(addrFull)},   // drop (G10: hidden from, non-participant)
		{Hash: "0x05", From: addrHidden, To: strPtr(addrHidden)}, // drop (both hidden)
	}

	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (only 0x01 Full<->Full survives), got %d", len(result))
	}
	if result[0].Hash != "0x01" {
		t.Errorf("surviving tx should be 0x01, got %s", result[0].Hash)
	}
}

// ---------------------------------------------------------------------------
// Nonce redaction
// ---------------------------------------------------------------------------

func u64ptr(n uint64) *uint64 { return &n }

func TestRedactTransactions_HiddenFrom_NilsNonce(t *testing.T) {
	// Viewer is the receiver (participant), sender is hidden.
	// Nonce of hidden sender must be nil even when revealed via participant override.
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		from: VisibilityHidden,
		to:   VisibilityFull,
	}, []string{to}) // viewer is the receiver

	nonce := u64ptr(42)
	txs := []Transaction{
		{Hash: "0x01", From: from, To: strPtr(to), Value: "100", Nonce: nonce},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].Nonce != nil {
		t.Errorf("nonce must be nil when sender is base-hidden (participant override), got %v", *result[0].Nonce)
	}
}

func TestRedactTransactions_HiddenTo_PreservesNonce(t *testing.T) {
	// Viewer is the sender (participant). Receiver is hidden.
	// Sender's own nonce should be preserved (their base level is Full).
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		from: VisibilityFull,
		to:   VisibilityHidden,
	}, []string{from}) // viewer is the sender

	nonce := u64ptr(7)
	txs := []Transaction{
		{Hash: "0x01", From: from, To: strPtr(to), Value: "100", Nonce: nonce},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].Nonce == nil || *result[0].Nonce != 7 {
		t.Errorf("nonce should be preserved when sender (viewer) is Full, got %v", result[0].Nonce)
	}
}

func TestRedactTransactions_RedactedFrom_NilsNonce(t *testing.T) {
	// Viewer is the receiver (participant). Sender is redacted.
	// Nonce of redacted sender must be nil even via participant override.
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		from: VisibilityRedacted,
		to:   VisibilityFull,
	}, []string{to}) // viewer is the receiver

	nonce := u64ptr(99)
	txs := []Transaction{
		{Hash: "0x01", From: from, To: strPtr(to), Value: "200", Nonce: nonce},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].Nonce != nil {
		t.Errorf("nonce must be nil when sender is base-redacted, got %v", *result[0].Nonce)
	}
}

// ---------------------------------------------------------------------------
// RedactTransfers
// ---------------------------------------------------------------------------

func TestRedactTransfers_Empty(t *testing.T) {
	engine := newEngine(nil)
	result, err := engine.RedactTransfers(context.Background(), nil, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil")
	}
}

func TestRedactTransfers_HiddenFrom_KeepsWithPrivate(t *testing.T) {
	// G10: non-participant viewer, one side hidden → transfer dropped.
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "100"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 transfers (G10: hidden from, non-participant → drop), got %d", len(result))
	}
}

func TestRedactTransfers_MintFromZeroAddressSurvivesForVisibleRecipient(t *testing.T) {
	// The zero address is a protocol constant, not a private counterparty. A
	// mint must remain visible when its recipient is visible; otherwise the
	// transaction can expose its Transfer log/category while the derived
	// ERC-20 transfer row disappears.
	const zeroAddress = "0x0000000000000000000000000000000000000000"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{to: VisibilityFull})

	transfers := []TokenTransfer{{ID: 1, From: zeroAddress, To: to, Value: "250000000000000000000"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("mint from the zero address to a visible recipient must survive, got %d rows", len(result))
	}
	if result[0].From != zeroAddress || result[0].To != to || result[0].Value != transfers[0].Value {
		t.Fatalf("mint transfer changed unexpectedly: %+v", result[0])
	}
}

func TestRedactTransfers_BothHidden_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityHidden,
	})

	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "100"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 transfers (both hidden → drop), got %d", len(result))
	}
}

func TestRedactTransfers_BothRedacted_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityRedacted,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "100"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 transfers (both redacted → drop), got %d", len(result))
	}
}

func TestRedactTransfers_HiddenPlusRedacted_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "100"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 transfers (hidden + redacted → drop), got %d", len(result))
	}
}

func TestRedactTransfers_BothHidden_AdminSees_FlagOn(t *testing.T) {
	// With the elevated audit view on, the both-sides-hidden transfer row is
	// kept for the admin (fixing the /tokens/:address/transfers count-vs-empty
	// contradiction). Addresses stay [PRIVATE]; the amount is preserved —
	// consistent with the Transfer log the admin already sees — and the reveal
	// is counted.
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		from: VisibilityHidden,
		to:   VisibilityHidden,
	})

	stats := &RedactStats{}
	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "100"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test",
		RedactOpts{ViewerIsAdmin: true, OrgAdminViewUserTxs: true, Stats: stats})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 transfer (admin sees both-hidden under flag), got %d", len(result))
	}
	if result[0].From != "[PRIVATE]" || result[0].To != "[PRIVATE]" {
		t.Errorf("expected both addresses [PRIVATE], got from=%q to=%q", result[0].From, result[0].To)
	}
	if string(result[0].Value) != "100" {
		t.Errorf("expected amount preserved (100) under elevated audit view, got %q", result[0].Value)
	}
	if stats.AdminUserTxsRevealed != 1 {
		t.Errorf("expected 1 reveal counted, got %d", stats.AdminUserTxsRevealed)
	}
}

func TestRedactTransfers_BothHidden_AdminDropped_FlagOff(t *testing.T) {
	// Default (flag off): admin does not see both-sides-hidden transfers.
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		from: VisibilityHidden,
		to:   VisibilityHidden,
	})

	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "100"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test",
		RedactOpts{ViewerIsAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected both-hidden transfer dropped for admin with flag off, got %d", len(result))
	}
}

func TestRedactTransfers_BothRedacted_AdminSees_FlagOn(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		from: VisibilityRedacted,
		to:   VisibilityRedacted,
	})

	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "100"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test",
		RedactOpts{ViewerIsAdmin: true, OrgAdminViewUserTxs: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 transfer (admin sees both-redacted under flag), got %d", len(result))
	}
	if string(result[0].Value) != "100" {
		t.Errorf("expected amount preserved under elevated audit view, got %q", result[0].Value)
	}
}

func TestRedactInternalTransactions_BothHidden_AdminSees_FlagOn(t *testing.T) {
	// Internal-tx lists get the same elevated audit view as top-level txs:
	// both-hidden rows are kept (addresses [PRIVATE], value preserved, reveal
	// counted) so the internal-txn tab does not contradict its count for the
	// admin under the flag.
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		from: VisibilityHidden,
		to:   VisibilityHidden,
	})

	stats := &RedactStats{}
	itxs := []InternalTransaction{{ID: 1, TxHash: "0x01", From: from, To: strPtr(to), Value: "500"}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test",
		RedactOpts{ViewerIsAdmin: true, OrgAdminViewUserTxs: true, Stats: stats})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 internal tx (admin sees both-hidden under flag), got %d", len(result))
	}
	if result[0].From != "[PRIVATE]" || result[0].To == nil || *result[0].To != "[PRIVATE]" {
		t.Errorf("expected both addresses [PRIVATE], got from=%q to=%v", result[0].From, result[0].To)
	}
	if string(result[0].Value) != "500" {
		t.Errorf("expected value preserved (500) under elevated audit view, got %q", result[0].Value)
	}
	if stats.AdminUserTxsRevealed != 1 {
		t.Errorf("expected 1 reveal counted, got %d", stats.AdminUserTxsRevealed)
	}
}

func TestRedactInternalTransactions_BothHidden_AdminDropped_FlagOff(t *testing.T) {
	// Default (flag off): both-hidden internal txs are dropped even for admins.
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		from: VisibilityHidden,
		to:   VisibilityHidden,
	})

	itxs := []InternalTransaction{{ID: 1, TxHash: "0x01", From: from, To: strPtr(to), Value: "500"}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test",
		RedactOpts{ViewerIsAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected both-hidden internal tx dropped with flag off, got %d", len(result))
	}
}

func TestRedactTransfers_HiddenFrom_PublicTo_ShowsPrivate(t *testing.T) {
	// G10: non-participant viewer, from is hidden → transfer dropped.
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "500"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 transfers (G10: hidden from, non-participant → drop), got %d", len(result))
	}
}

func TestRedactTransfers_RedactedStripsValue(t *testing.T) {
	// G10: non-participant viewer, to is redacted → transfer dropped.
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "500"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 transfers (G10: redacted to, non-participant → drop), got %d", len(result))
	}
}

func TestRedactTransfers_FullVisibilityUnchanged(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "999"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 transfer, got %d", len(result))
	}
	if result[0].From != from || result[0].To != to || result[0].Value != "999" {
		t.Errorf("transfer should be unchanged: %+v", result[0])
	}
}

func TestRedactTransfers_DBError(t *testing.T) {
	engine := newEngineErr(errors.New("db error"))
	transfers := []TokenTransfer{{ID: 1, From: "0xaa", To: "0xbb"}}
	_, err := engine.RedactTransfers(context.Background(), transfers, "did:test")
	if err == nil {
		t.Error("expected error")
	}
}

// TestRedactTransfers_Pseudonymous pins the matrix row for token transfers
// under a pseudonymous-level disclosure grant: the addr the viewer has a
// grant on must be substituted with its Address-XXXX alias, while the
// other party (here, full) stays as-is. Value is preserved for
// pseudonymous (compliance audits need amounts).
func TestRedactTransfers_Pseudonymous(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		from: VisibilityPseudonymous,
		to:   VisibilityFull,
	})

	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "777"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 transfer, got %d", len(result))
	}
	expectedFromPseudonym := GeneratePseudonym(from, nil)
	if result[0].From != expectedFromPseudonym {
		t.Errorf("From should be pseudonym %q, got %q", expectedFromPseudonym, result[0].From)
	}
	// Counterparty pseudonymised under the grant lens — see the parallel
	// rationale in TestRedactTransactions_PseudonymousAddress. mockDB
	// derives Reason=ReasonDisclosureGrant for VisibilityPseudonymous,
	// which triggers the demotion.
	expectedToPseudonym := GeneratePseudonym(to, nil)
	if result[0].To != expectedToPseudonym {
		t.Errorf("To (counterparty) should be pseudonymised under pseudonymous-grant lens %q, got %q", expectedToPseudonym, result[0].To)
	}
	if result[0].Value != "777" {
		t.Errorf("Value must NOT be stripped for pseudonymous transfers (compliance audits need amounts), got %s", result[0].Value)
	}
}

// ---------------------------------------------------------------------------
// RedactInternalTransactions
// ---------------------------------------------------------------------------

func TestRedactInternalTransactions_Empty(t *testing.T) {
	engine := newEngine(nil)
	result, err := engine.RedactInternalTransactions(context.Background(), nil, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil")
	}
}

func TestRedactInternalTransactions_HiddenFrom_KeepsWithPrivate(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	input := "0xdeadbeef"
	output := "0x01"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	itxs := []InternalTransaction{{ID: 1, From: from, To: strPtr(to), Value: "100", Input: &input, Output: &output}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 (hidden from, public to → keep), got %d", len(result))
	}
	itx := result[0]
	if itx.From != "[PRIVATE]" {
		t.Errorf("From should be [PRIVATE], got %s", itx.From)
	}
	if *itx.To != to {
		t.Errorf("To should be unchanged, got %s", *itx.To)
	}
	if itx.Value != "" {
		t.Errorf("Value should be stripped, got %s", itx.Value)
	}
	if itx.Input != nil {
		t.Errorf("Input should be nil")
	}
	if itx.Output != nil {
		t.Errorf("Output should be nil")
	}
}

func TestRedactInternalTransactions_BothHidden_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityHidden,
	})

	itxs := []InternalTransaction{{ID: 1, From: from, To: strPtr(to), Value: "100"}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 (both hidden → drop), got %d", len(result))
	}
}

func TestRedactInternalTransactions_BothRedacted_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityRedacted,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	itxs := []InternalTransaction{{ID: 1, From: from, To: strPtr(to), Value: "100"}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 (both redacted → drop), got %d", len(result))
	}
}

func TestRedactInternalTransactions_HiddenPlusRedacted_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	itxs := []InternalTransaction{{ID: 1, From: from, To: strPtr(to), Value: "100"}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 (hidden + redacted → drop), got %d", len(result))
	}
}

func TestRedactInternalTransactions_HiddenFrom_PublicTo_ShowsPrivate(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	input := "0xdeadbeef"
	output := "0x01"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	itxs := []InternalTransaction{{ID: 1, From: from, To: strPtr(to), Value: "200", Input: &input, Output: &output}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	itx := result[0]
	if itx.From != "[PRIVATE]" {
		t.Errorf("From should be [PRIVATE], got %s", itx.From)
	}
	if *itx.To != to {
		t.Errorf("To should be unchanged, got %s", *itx.To)
	}
	if itx.Value != "" {
		t.Errorf("Value should be stripped, got %s", itx.Value)
	}
	if itx.Input != nil {
		t.Errorf("Input should be nil")
	}
	if itx.Output != nil {
		t.Errorf("Output should be nil")
	}
}

// TestRedactInternalTransactions_Pseudonymous pins the matrix row for
// internal txs under a pseudonymous-level disclosure grant: from is
// substituted with Address-XXXX, value preserved, input/output preserved.
func TestRedactInternalTransactions_Pseudonymous(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	input := "0xdeadbeef"
	output := "0x01"
	engine := newEngine(VisibilityMap{
		from: VisibilityPseudonymous,
		to:   VisibilityFull,
	})

	itxs := []InternalTransaction{{ID: 1, From: from, To: strPtr(to), Value: "888", Input: &input, Output: &output}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	itx := result[0]
	expectedFromPseudonym := GeneratePseudonym(from, nil)
	if itx.From != expectedFromPseudonym {
		t.Errorf("From should be pseudonym %q, got %q", expectedFromPseudonym, itx.From)
	}
	// Counterparty pseudonymised under the grant lens (see
	// TestRedactTransactions_PseudonymousAddress for the rationale).
	expectedToPseudonym := GeneratePseudonym(to, nil)
	if itx.To == nil || *itx.To != expectedToPseudonym {
		t.Errorf("To (counterparty) should be pseudonymised under grant lens %q, got %v", expectedToPseudonym, itx.To)
	}
	if itx.Value != "888" {
		t.Errorf("Value must NOT be stripped for pseudonymous, got %s", itx.Value)
	}
}

func TestRedactInternalTransactions_RedactedStripsData(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	input := "0xdeadbeef"
	output := "0x01"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	itxs := []InternalTransaction{{ID: 1, From: from, To: strPtr(to), Value: "100", Input: &input, Output: &output}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	itx := result[0]
	if *itx.To != "[PRIVATE]" {
		t.Errorf("To should be [PRIVATE], got %s", *itx.To)
	}
	if itx.Value != "" {
		t.Errorf("Value should be stripped, got %s", itx.Value)
	}
	if itx.Input != nil {
		t.Errorf("Input should be nil")
	}
	if itx.Output != nil {
		t.Errorf("Output should be nil")
	}
}

func TestRedactInternalTransactions_NilTo(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
	})

	itxs := []InternalTransaction{{ID: 1, From: from, To: nil, Value: "0"}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0].To != nil {
		t.Errorf("To should remain nil")
	}
}

// ---------------------------------------------------------------------------
// RedactLogs
// ---------------------------------------------------------------------------

func TestRedactLogs_Empty(t *testing.T) {
	engine := newEngine(nil)
	result, err := engine.RedactLogs(context.Background(), nil, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil")
	}
}

func TestRedactLogs_HiddenDrops(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
	})

	topic := "0xdeadbeef"
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "somedata"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 logs, got %d", len(result))
	}
}

func TestRedactLogs_RedactedNoGrantDropped(t *testing.T) {
	// A registered contract the viewer has no grant on resolves to
	// VisibilityRedacted / ReasonNoAccess. Under the shared decision engine
	// (RD-1214) such a log is DROPPED — matching the RPC (access==nil → drop),
	// not kept as a [PRIVATE] stub. Pre-RD-1214 the explorer kept the stub,
	// which leaked the log's existence and diverged from the RPC.
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityRedacted,
	})

	topic0 := "0xabcd"
	topic1 := "0x1234"
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic0, Topic1: &topic1, Data: "encoded_data"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("no-grant (Redacted) log must be dropped, got %d", len(result))
	}
}

func TestRedactLogs_FullUnchanged(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
	})

	topic := "0xabcd"
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "0xff"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0].Address != addr {
		t.Errorf("Address should be unchanged, got %s", result[0].Address)
	}
	if *result[0].Topic0 != topic {
		t.Errorf("Topic0 should be unchanged, got %s", *result[0].Topic0)
	}
	if result[0].Data != "0xff" {
		t.Errorf("Data should be unchanged, got %s", result[0].Data)
	}
}

func TestRedactLogs_DBError(t *testing.T) {
	engine := newEngineErr(errors.New("db error"))
	logs := []Log{{ID: 1, Address: "0xaa", Data: "data"}}
	_, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// EventRuleChecker tri-state (RD-888)
// ---------------------------------------------------------------------------

// stubEventRuleChecker returns a fixed EventRulesResolution per contract
// address, used to exercise the tri-state semantics in Phase 4 of
// RedactLogsWithOpts. A contract address with no entry resolves to
// `EventRulesResolution{}` — Wildcard=false, Rules=nil — which is the
// deny-all state per the RD-888 contract.
type stubEventRuleChecker struct {
	byAddr map[string]EventRulesResolution
}

func (s *stubEventRuleChecker) GetEventRulesForContract(_ context.Context, _ string, addr string) EventRulesResolution {
	return s.byAddr[strings.ToLower(addr)]
}

// TestRedactLogs_EventRules_NilDenies pins the RD-888 fix: when the
// checker resolves to the deny-all state (zero-value resolution), the
// log must be dropped even if the contract is otherwise visible. This is
// the bug the explorer had pre-RD-888 — it treated nil rules as
// allow-all, opposite to the RPC layer's deny-by-default semantics.
func TestRedactLogs_EventRules_NilDenies(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	engine.SetEventRuleChecker(&stubEventRuleChecker{
		byAddr: map[string]EventRulesResolution{
			addr: {}, // zero value ⇒ deny-all
		},
	})

	topic := eventTopic0("Transfer(address,address,uint256)")
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "0x"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 logs (nil rules ⇒ deny-all per RD-888), got %d", len(result))
	}
}

// TestRedactLogs_EventRules_WildcardPasses confirms the wildcard branch
// of the tri-state — all logs pass regardless of topic0.
func TestRedactLogs_EventRules_WildcardPasses(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	engine.SetEventRuleChecker(&stubEventRuleChecker{
		byAddr: map[string]EventRulesResolution{
			addr: {Wildcard: true},
		},
	})

	t1 := eventTopic0("Transfer(address,address,uint256)")
	t2 := eventTopic0("Approval(address,address,uint256)")
	logs := []Log{
		{ID: 1, Address: addr, Topic0: &t1, Data: "0x"},
		{ID: 2, Address: addr, Topic0: &t2, Data: "0x"},
		{ID: 3, Address: addr, Topic0: nil, Data: "0x"}, // anonymous; wildcard still passes
	}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 3 {
		t.Errorf("expected 3 logs (wildcard), got %d", len(result))
	}
}

// TestRedactLogs_EventRules_AllowlistMatches keeps only listed topic0s.
func TestRedactLogs_EventRules_AllowlistMatches(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	transferTopic := eventTopic0("Transfer(address,address,uint256)")
	approvalTopic := eventTopic0("Approval(address,address,uint256)")

	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	engine.SetEventRuleChecker(&stubEventRuleChecker{
		byAddr: map[string]EventRulesResolution{
			addr: {Rules: []EventRuleInfo{{Topic0: transferTopic}}},
		},
	})

	logs := []Log{
		{ID: 1, Address: addr, Topic0: &transferTopic, Data: "0x"}, // listed: passes
		{ID: 2, Address: addr, Topic0: &approvalTopic, Data: "0x"}, // not listed: dropped
	}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 log (allowlist), got %d", len(result))
	}
	if *result[0].Topic0 != transferTopic {
		t.Errorf("expected Transfer to pass, got %s", *result[0].Topic0)
	}
}

// TestRedactLogs_EventRules_AllowlistBlocksAnonymous: anonymous events
// (no topic0) are blocked when in allowlist mode, matching RPC semantics
// (rbac.FilterEventLogs:141).
func TestRedactLogs_EventRules_AllowlistBlocksAnonymous(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	transferTopic := eventTopic0("Transfer(address,address,uint256)")

	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	engine.SetEventRuleChecker(&stubEventRuleChecker{
		byAddr: map[string]EventRulesResolution{
			addr: {Rules: []EventRuleInfo{{Topic0: transferTopic}}},
		},
	})

	logs := []Log{{ID: 1, Address: addr, Topic0: nil, Data: "0x"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 logs (anonymous blocked in allowlist mode), got %d", len(result))
	}
}

// TestRedactLogs_EventRules_NoCheckerWiredKeepsLogs is a fixture
// affordance for the unit-test universe — when a test constructs a
// RedactionEngine via newEngine(...) and skips SetEventRuleChecker,
// the redactor falls back to "no event-rule enforcement" (visibility
// + participant override still apply). That fallback is **only** for
// tests; production startup (`server.wireExplorerRedactor`) wires a
// real checker, and the integration test
// `TestExplorerRedactorWiring_FullStack` will fail if anyone disables
// that wiring path.
func TestRedactLogs_EventRules_NoCheckerWiredKeepsLogs(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	// No SetEventRuleChecker call — checker remains nil.

	topic := eventTopic0("Transfer(address,address,uint256)")
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "0x"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Errorf("checker not wired: expected log to pass (Phase 4 skipped), got %d logs", len(result))
	}
}

// TestRedactLogs_EventRules_ParamRules_SelfPasses pins the post-audit
// fix that ParamRules on EventRuleInfo are honoured. With a rule
// {topic0:Transfer, params:[{0,self}]} only logs whose first param
// encodes the viewer's linked address survive — same OR semantics as
// rbac.FilterEventLogs.
func TestRedactLogs_EventRules_ParamRules_SelfPasses(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	viewerAddr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{addr: VisibilityFull}, []string{viewerAddr})
	transferTopic := eventTopic0("Transfer(address,address,uint256)")
	engine.SetEventRuleChecker(&stubEventRuleChecker{
		byAddr: map[string]EventRulesResolution{
			addr: {Rules: []EventRuleInfo{{
				Topic0:     transferTopic,
				ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}},
			}}},
		},
	})
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{addr: testEventABI}})

	viewerTopic := zeroPadAddrToTopicLocal(viewerAddr)
	otherTopic := zeroPadAddrToTopicLocal("0xcccccccccccccccccccccccccccccccccccccccc")
	logs := []Log{
		{ID: 1, Address: addr, Topic0: &transferTopic, Topic1: &viewerTopic, Data: "0x"},
		{ID: 2, Address: addr, Topic0: &transferTopic, Topic1: &otherTopic, Data: "0x"},
	}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].ID != 1 {
		t.Errorf("self-on-param-0: expected only ID=1 to pass, got %v", logIDs(result))
	}
}

// TestRedactLogs_EventRules_ParamRules_VisibleToFallback covers the
// RPC-parity fallback: when the topic0 matches a rule but the param
// constraints fail, the parent tx's visibleTo (visibleTxHashes opt)
// extends access — same as rbac.FilterEventLogs:171-174.
func TestRedactLogs_EventRules_ParamRules_VisibleToFallback(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	viewerAddr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{addr: VisibilityFull}, []string{viewerAddr})
	transferTopic := eventTopic0("Transfer(address,address,uint256)")
	engine.SetEventRuleChecker(&stubEventRuleChecker{
		byAddr: map[string]EventRulesResolution{
			addr: {Rules: []EventRuleInfo{{
				Topic0:     transferTopic,
				ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}},
			}}},
		},
	})
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{addr: testEventABI}})

	otherTopic := zeroPadAddrToTopicLocal("0xcccccccccccccccccccccccccccccccccccccccc")
	sharedTxHash := "0xabc123"
	logs := []Log{
		{ID: 1, Address: addr, TxHash: sharedTxHash, Topic0: &transferTopic, Topic1: &otherTopic, Data: "0x"},
	}
	// The fallback needs a genuine listing (ListedTxHashes, RD-1307).
	result, err := engine.RedactLogsWithOpts(context.Background(), logs, "did:test", &RedactOpts{
		VisibleTxHashes: map[string]bool{sharedTxHash: true},
		ListedTxHashes:  map[string]bool{sharedTxHash: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Errorf("visibleTo fallback: expected 1 log to pass (param failed but tx shared), got %d", len(result))
	}

	// A tx that is only in VisibleTxHashes (e.g. the RD-1009 transfer
	// union) is not a listing: the failed param rule stands.
	result, err = engine.RedactLogsWithOpts(context.Background(), logs, "did:test", &RedactOpts{
		VisibleTxHashes: map[string]bool{sharedTxHash: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("union-only tx must not trigger the param-rule fallback, got %d logs", len(result))
	}
}

// TestRedactLogs_EventRules_ParamRules_VisibleToOnlyHelpsIfTopic0Matches
// — visibleTo does NOT bypass topic0 mismatch. This mirrors
// rbac.FilterEventLogs:171 which checks `eventTopic0Matches` first.
func TestRedactLogs_EventRules_ParamRules_VisibleToOnlyHelpsIfTopic0Matches(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	transferTopic := eventTopic0("Transfer(address,address,uint256)")
	approvalTopic := eventTopic0("Approval(address,address,uint256)")
	engine.SetEventRuleChecker(&stubEventRuleChecker{
		byAddr: map[string]EventRulesResolution{
			addr: {Rules: []EventRuleInfo{{Topic0: transferTopic}}},
		},
	})
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{addr: testEventABI}})

	logs := []Log{{ID: 1, Address: addr, TxHash: "0xshared", Topic0: &approvalTopic, Data: "0x"}}
	result, err := engine.RedactLogsWithOpts(context.Background(), logs, "did:test", &RedactOpts{
		VisibleTxHashes: map[string]bool{"0xshared": true},
		ListedTxHashes:  map[string]bool{"0xshared": true}, // a genuine listing, so only the rule under test can deny (RD-1307)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("visibleTo must NOT bypass topic0 mismatch — got %d logs", len(result))
	}
}

// TestRedactLogs_OrdinaryVisibleTo_NoGrantEmitter_RD1208 pins the explorer
// half of RD-1208: ordinary (non-unlock) visibleTo must not grant a no-grant
// viewer access to a contract's event logs. Grant eligibility is load-bearing
// (REDACTION_SPEC §3.7.1 / RD-874).
//
// State modelled: a REGISTERED org contract with no grant resolves to
// VisibilityRedacted/ReasonNoAccess (GetBatchVisibilityDetailed) — grant
// holders resolve to VisibilityFull, and VisibilityHidden is an unregistered
// address / EOA. So the no-grant emitter is VisibilityRedacted, NOT Hidden.
func TestRedactLogs_OrdinaryVisibleTo_NoGrantEmitter_RD1208(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	topic := eventTopic0("PrivateTransfer(address,address,uint256)")

	// Isolating the visibility/visibleTo layer (no event-rule checker wired):
	// ordinary visibleTo must NOT upgrade the no-grant emitter to Full. The
	// emitting contract renders [PRIVATE]; its real address must never leak.
	// Before the fix the visibleTo level-up promoted Redacted->Full and the
	// emitter (and its payload) rendered in the clear.
	t.Run("no-grant emitter dropped, not revealed via visibleTo", func(t *testing.T) {
		// Under the shared decision engine (RD-1214) a no-grant emitter is
		// DROPPED, matching the RPC (access==nil → drop) — not kept as a
		// [PRIVATE] stub. Ordinary visibleTo does not rescue it.
		engine := newEngine(VisibilityMap{addr: VisibilityRedacted})
		logs := []Log{{ID: 1, Address: addr, TxHash: "0xshared", Topic0: &topic, Data: "0x"}}
		result, err := engine.RedactLogsWithOpts(context.Background(), logs, "did:test", &RedactOpts{
			VisibleTxHashes: map[string]bool{"0xshared": true},
			ListedTxHashes:  map[string]bool{"0xshared": true}, // a genuine listing, so only the rule under test can deny (RD-1307)
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 0 {
			t.Fatalf("ordinary visibleTo must not admit a no-grant emitter (RD-1208/RD-1214), got %d logs", len(result))
		}
	})

	// Production config (wireExplorerRedactor wires the event-rule checker):
	// a no-grant emitter resolves to deny-all, so the log is dropped entirely.
	// Ordinary visibleTo must not rescue it.
	t.Run("no-grant emitter dropped in production", func(t *testing.T) {
		engine := newEngine(VisibilityMap{addr: VisibilityRedacted})
		engine.SetEventRuleChecker(&stubEventRuleChecker{}) // no entry => deny-all
		logs := []Log{{ID: 1, Address: addr, TxHash: "0xshared", Topic0: &topic, Data: "0x"}}
		result, err := engine.RedactLogsWithOpts(context.Background(), logs, "did:test", &RedactOpts{
			VisibleTxHashes: map[string]bool{"0xshared": true},
			ListedTxHashes:  map[string]bool{"0xshared": true}, // a genuine listing, so only the rule under test can deny (RD-1307)
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 0 {
			t.Errorf("ordinary visibleTo must not rescue a no-grant emitter's log in production (RD-1208), got %d logs", len(result))
		}
	})
}

// TestRedactLogs_GetLinkedAddressesError_Propagates pins the audit
// fix for finding #5 — pre-fix the redactor swallowed
// GetLinkedAddresses errors via `if err == nil` and silently treated
// the viewer as having no linked addresses, breaking participant
// override and "self" param-rule constraints. Now the error
// propagates to the caller as a 500.
func TestRedactLogs_GetLinkedAddressesError_Propagates(t *testing.T) {
	engine := newEngine(VisibilityMap{})
	engine.db = &mockDBLinkedErr{mockDB: mockDB{visMap: VisibilityMap{}}}

	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	topic := eventTopic0("Transfer(address,address,uint256)")
	_, err := engine.RedactLogs(context.Background(), []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "0x"}}, "did:test")
	if err == nil {
		t.Error("expected GetLinkedAddresses error to propagate; got nil")
	}
}

// mockDBLinkedErr returns an error from GetLinkedAddresses. All other
// methods inherit from the embedded mockDB.
type mockDBLinkedErr struct {
	mockDB
}

func (m *mockDBLinkedErr) GetLinkedAddresses(_ context.Context, _ string) ([]string, error) {
	return nil, errors.New("simulated DB failure")
}

// zeroPadAddrToTopicLocal pads a 20-byte address to a 32-byte topic
// value (left-pad zeros). Local helper kept here so the unit-test
// file doesn't pull in test fixtures from the server package.
func zeroPadAddrToTopicLocal(addr string) string {
	a := strings.ToLower(strings.TrimPrefix(addr, "0x"))
	return "0x" + strings.Repeat("0", 64-len(a)) + a
}

// logIDs returns the IDs of the supplied logs in order — small
// helper for assertion error messages.
func logIDs(logs []Log) []int64 {
	out := make([]int64, len(logs))
	for i, l := range logs {
		out[i] = l.ID
	}
	return out
}

// ---------------------------------------------------------------------------
// ABIResolver + deny-when-no-ABI gate (RD-889)
// ---------------------------------------------------------------------------

// stubABIResolver returns a fixed ABI string per contract address. Empty
// string means "no resolvable ABI" — the deny-gate trigger.
type stubABIResolver struct {
	byAddr map[string]string
}

func (s *stubABIResolver) Resolve(_ context.Context, address string) string {
	return s.byAddr[strings.ToLower(address)]
}

// TestRedactLogs_ABIGate_DeniesWhenNoABI is the RD-889 fix. Without a
// resolvable ABI, the explorer cannot decode non-indexed address
// parameters in event data, so private addresses there would leak. The
// gate drops the log to match rbac.FilterEventLogs (RD-875).
func TestRedactLogs_ABIGate_DeniesWhenNoABI(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{
		// addr deliberately absent ⇒ Resolve returns ""
	}})

	topic := eventTopic0("Transfer(address,address,uint256)")
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "0x"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 logs (no ABI ⇒ deny), got %d", len(result))
	}
}

// TestRedactLogs_ABIGate_AllowsWhenABIPresent confirms the gate is the
// only new restriction — existing redaction behaviour is unchanged when
// an ABI is resolvable.
func TestRedactLogs_ABIGate_AllowsWhenABIPresent(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{
		addr: `[{"type":"event","name":"Transfer","inputs":[]}]`,
	}})

	topic := eventTopic0("Transfer(address,address,uint256)")
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "0x"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 log (ABI present), got %d", len(result))
	}
}

// TestRedactLogs_ABIGate_NoResolverWiredKeepsLegacyBehaviour preserves
// pre-RD-889 behaviour for callers that haven't wired the resolver
// (unit tests, older integrations). Without the resolver, Phase 3 falls
// back to ContractStore and the deny gate is disabled. Production
// server startup wires the resolver — see server.go.
func TestRedactLogs_ABIGate_NoResolverWiredKeepsLegacyBehaviour(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	// No SetABIResolver call.

	topic := eventTopic0("Transfer(address,address,uint256)")
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "0x"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Errorf("legacy path: expected 1 log (gate disabled when resolver not wired), got %d", len(result))
	}
}

// TestRedactLogs_ABIGate_PreservesHiddenDrop checks the gate is layered
// correctly with the existing visibility check — Hidden logs are dropped
// before the gate fires, and the gate doesn't accidentally resurface
// them.
func TestRedactLogs_ABIGate_PreservesHiddenDrop(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{addr: VisibilityHidden})
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{
		addr: `[{"type":"event","name":"Transfer","inputs":[]}]`, // ABI present
	}})

	topic := eventTopic0("Transfer(address,address,uint256)")
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "0x"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 logs (Hidden drops before ABI gate), got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// AdminContractsResolver bypass (RD-890)
// ---------------------------------------------------------------------------

// stubAdminContractsResolver returns a fixed admin map per (viewerDID,
// addresses) call. Used to exercise the admin-bypass path that mirrors
// rbac.FilterEventLogs's isAdminByContract behaviour.
type stubAdminContractsResolver struct {
	admin map[string]bool
}

func (s *stubAdminContractsResolver) Resolve(_ context.Context, _ string, _ []string) map[string]bool {
	out := make(map[string]bool, len(s.admin))
	for k, v := range s.admin {
		out[k] = v
	}
	return out
}

// TestRedactLogs_AdminBypass_OverridesABIGate is the RD-890 fix.
// A tier-2/tier-3 admin viewer sees logs from a contract with no
// resolvable ABI — matches rbac.FilterEventLogs at the RPC layer. Pre-
// RD-890, the explorer was strictly stricter than RPC for admins.
func TestRedactLogs_AdminBypass_OverridesABIGate(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	// ABI not resolvable — without admin bypass, RD-889 gate would drop.
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{}})
	engine.SetAdminContractsResolver(&stubAdminContractsResolver{
		admin: map[string]bool{addr: true},
	})

	topic := eventTopic0("Transfer(address,address,uint256)")
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "0x"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Errorf("admin bypass: expected 1 log (admin sees logs even without ABI), got %d", len(result))
	}
}

// TestRedactLogs_AdminBypass_PerContractScoping confirms the bypass is
// scoped to specific contracts: admin on Contract A doesn't get logs
// from Contract B if B has no ABI. Mirrors rbac.FilterEventLogs's
// per-contract isAdminByContract map.
func TestRedactLogs_AdminBypass_PerContractScoping(t *testing.T) {
	addrA := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	addrB := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		addrA: VisibilityFull,
		addrB: VisibilityFull,
	})
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{}}) // both contracts no ABI
	engine.SetAdminContractsResolver(&stubAdminContractsResolver{
		admin: map[string]bool{addrA: true}, // admin on A only
	})

	topic := eventTopic0("Transfer(address,address,uint256)")
	logs := []Log{
		{ID: 1, Address: addrA, Topic0: &topic, Data: "0x"}, // admin → passes
		{ID: 2, Address: addrB, Topic0: &topic, Data: "0x"}, // not admin → dropped by ABI gate
	}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 log (admin on A only), got %d", len(result))
	}
	if strings.ToLower(result[0].Address) != addrA {
		t.Errorf("expected log from %s, got %s", addrA, result[0].Address)
	}
}

// TestRedactLogs_AdminBypass_NoResolverWiredKeepsGate preserves the
// pre-RD-890 behaviour for callers that haven't wired the admin
// resolver — the ABI gate fires for everyone including admins. Matches
// the explorer-stricter-than-RPC asymmetry that RD-890 closes when the
// resolver IS wired.
func TestRedactLogs_AdminBypass_NoResolverWiredKeepsGate(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{}}) // no ABI
	// No SetAdminContractsResolver call.

	topic := eventTopic0("Transfer(address,address,uint256)")
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "0x"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("no resolver: expected 0 logs (gate fires without admin signal), got %d", len(result))
	}
}

// TestRedactLogs_AdminBypass_DoesNotResurfaceHidden — admin bypass on
// the ABI gate must NOT undo a Hidden visibility drop. Layering check.
func TestRedactLogs_AdminBypass_DoesNotResurfaceHidden(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{addr: VisibilityHidden})
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{}})
	engine.SetAdminContractsResolver(&stubAdminContractsResolver{
		admin: map[string]bool{addr: true},
	})

	topic := eventTopic0("Transfer(address,address,uint256)")
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "0x"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("Hidden + admin: expected 0 logs (Hidden drops before any bypass fires), got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// RedactLogs — ABI-based Data Field scanning
// ---------------------------------------------------------------------------

// testABI is a minimal ABI JSON for event: PrivateTransfer(address indexed from, address to, uint256 value)
// topic0 = keccak256("PrivateTransfer(address,address,uint256)")
// data   = abi.encode(to address, value) — 32 bytes for address + 32 bytes for uint256
const testEventABI = `[{"type":"event","name":"PrivateTransfer","inputs":[{"name":"from","type":"address","indexed":true},{"name":"to","type":"address","indexed":false},{"name":"value","type":"uint256","indexed":false}]}]`

func TestRedactLogs_ABIDataPrivateAddress_Zeroed(t *testing.T) {
	emitter := "0xcccccccccccccccccccccccccccccccccccccccc"
	privateAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	topic0 := eventTopic0("PrivateTransfer(address,address,uint256)")

	// data = abi.encode(privateAddr, 1000)
	dataHex := "0x" + encodeAddressSlot(privateAddr) + encodeUint256Slot(1000)
	zeroedSlot := strings.Repeat("0", 64)

	store := &mockContractStore{contracts: map[string]*Contract{
		emitter: {Address: emitter, ABI: []byte(testEventABI)},
	}}
	engine := newEngineWithStore(VisibilityMap{
		emitter:     VisibilityFull,
		privateAddr: VisibilityRedacted,
	}, store)

	logs := []Log{{ID: 1, Address: emitter, Topic0: &topic0, Data: dataHex}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 log, got %d", len(result))
	}
	// The address slot (first 32 bytes) should be zeroed; value slot unchanged.
	expectedData := "0x" + zeroedSlot + encodeUint256Slot(1000)
	if result[0].Data != expectedData {
		t.Errorf("expected data %q, got %q", expectedData, result[0].Data)
	}
}

func TestRedactLogs_ABIDataPublicAddress_Unchanged(t *testing.T) {
	emitter := "0xcccccccccccccccccccccccccccccccccccccccc"
	publicAddr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	topic0 := eventTopic0("PrivateTransfer(address,address,uint256)")

	dataHex := "0x" + encodeAddressSlot(publicAddr) + encodeUint256Slot(500)

	store := &mockContractStore{contracts: map[string]*Contract{
		emitter: {Address: emitter, ABI: []byte(testEventABI)},
	}}
	engine := newEngineWithStore(VisibilityMap{
		emitter:    VisibilityFull,
		publicAddr: VisibilityFull,
	}, store)

	logs := []Log{{ID: 1, Address: emitter, Topic0: &topic0, Data: dataHex}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 log, got %d", len(result))
	}
	if result[0].Data != dataHex {
		t.Errorf("data should be unchanged for public address, got %q", result[0].Data)
	}
}

func TestRedactLogs_NoABI_DataUnchanged(t *testing.T) {
	emitter := "0xcccccccccccccccccccccccccccccccccccccccc"
	topic0 := eventTopic0("PrivateTransfer(address,address,uint256)")
	dataHex := "0x" + encodeAddressSlot("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") + encodeUint256Slot(999)

	// Store returns nil contract (no ABI registered)
	store := &mockContractStore{contracts: map[string]*Contract{}}
	engine := newEngineWithStore(VisibilityMap{
		emitter: VisibilityFull,
	}, store)

	logs := []Log{{ID: 1, Address: emitter, Topic0: &topic0, Data: dataHex}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 log, got %d", len(result))
	}
	if result[0].Data != dataHex {
		t.Errorf("data should be unchanged when no ABI is registered, got %q", result[0].Data)
	}
}

func TestRedactLogs_UnknownTopic0_DataUnchanged(t *testing.T) {
	emitter := "0xcccccccccccccccccccccccccccccccccccccccc"
	unknownTopic0 := "0x" + strings.Repeat("ab", 32) // not a matching event
	dataHex := "0x" + encodeAddressSlot("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") + encodeUint256Slot(1)

	store := &mockContractStore{contracts: map[string]*Contract{
		emitter: {Address: emitter, ABI: []byte(testEventABI)},
	}}
	engine := newEngineWithStore(VisibilityMap{
		emitter: VisibilityFull,
	}, store)

	logs := []Log{{ID: 1, Address: emitter, Topic0: &unknownTopic0, Data: dataHex}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 log, got %d", len(result))
	}
	if result[0].Data != dataHex {
		t.Errorf("data should be unchanged when topic0 does not match any event, got %q", result[0].Data)
	}
}

// ---------------------------------------------------------------------------
// RedactLogs — participant override
// ---------------------------------------------------------------------------

// TestRedactLogs_Participant_NoGrantContract_StaysRedacted_RD1208 replaces the
// former ParticipantOverride_SeeOwnLogs test, which asserted the pre-RD-1162
// UNBOUNDED behavior (a participant sees a no-grant contract's log in the
// clear). Participant admission is now GRANT-BOUNDED, mirroring
// rbac.FilterEventLogs (RD-1162, `access != nil`): a registered contract with
// NO grant (VisibilityRedacted/ReasonNoAccess) stays redacted for a mere tx
// participant — a tx that internally touched a contract the viewer has no grant
// on must not leak its event payload. (The RPC drops the log outright; the
// explorer currently keeps the row field-redacted — the full drop / one-engine
// unification is RD-1214.)
func TestRedactLogs_Participant_NoGrantContract_StaysRedacted_RD1208(t *testing.T) {
	contractAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	eveAddr := "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	topic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		contractAddr: VisibilityRedacted, // registered, no grant → ReasonNoAccess
	}, []string{eveAddr})

	logs := []Log{{
		ID: 1, Address: contractAddr, TxHash: "0xabc",
		Topic0: &topic0, Data: "0x0000000000000000000000000000000000000000000000000000000002faf080",
	}}

	// Whether or not Eve is a participant, the no-grant contract's log is
	// DROPPED (RD-1214: matches the RPC access==nil drop; pre-RD-1214 the
	// explorer kept a [PRIVATE] stub). Being the tx sender does NOT grant
	// access to a contract she holds no grant on.
	for _, tc := range []struct {
		name             string
		participantAddrs []string
	}{
		{"non-participant", nil},
		{"participant (was revealed pre-fix)", []string{eveAddr, contractAddr}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := engine.RedactLogs(context.Background(), logs, "did:test:eve", tc.participantAddrs...)
			if err != nil {
				t.Fatal(err)
			}
			if len(result) != 0 {
				t.Fatalf("no-grant contract log must be dropped, got %d", len(result))
			}
		})
	}
}

func TestRedactLogs_NonParticipant_NoGrantDropped(t *testing.T) {
	// Mallory is NOT a participant (her linked addr matches neither from/to) and
	// has no grant on the emitting contract (Redacted). The log is DROPPED
	// (RD-1214: no-grant → drop, matching the RPC; pre-RD-1214 the explorer kept
	// a stripped [PRIVATE] stub for non-participants).
	contractAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	senderAddr := "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	malloryAddr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	topic0 := "0xddf252ad"

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		contractAddr: VisibilityRedacted,
	}, []string{malloryAddr})

	logs := []Log{{ID: 1, Address: contractAddr, Topic0: &topic0, Data: "0xdata"}}

	result, err := engine.RedactLogs(context.Background(), logs, "did:test:mallory", senderAddr, contractAddr)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("no-grant contract log must be dropped for a non-participant, got %d", len(result))
	}
}

// TestRedactLogs_EmbeddedAddressMetadata_NoLeak_RD1214 pins the confirmed
// metadata-key leak. The viewer holds a grant on the EMITTER (Full → log
// admitted) but has NO access to a third party's address embedded in a topic
// (Redacted/ReasonNoAccess). The topic slot is zeroed — but pre-fix the redactor
// still called setMeta(realAddr) and, because masterMeta carries a reason for
// every resolved address (including no_access), wrote AddressMetadata[realAddr]
// = "no_access". That hands the viewer the very address the zeroing hid, as a
// metadata KEY. The fix: emit metadata only for addresses that remain
// identifiable in the output (Full). A zeroed address gets no metadata entry.
func TestRedactLogs_EmbeddedAddressMetadata_NoLeak_RD1214(t *testing.T) {
	emitter := "0x1111111111111111111111111111111111111111"
	embedded := "0x9999999999999999999999999999999999999999" // third party, no access
	topic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	topic1 := "0x" + encodeAddressSlot(embedded)

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		emitter:  VisibilityFull,     // grant on emitter → log admitted
		embedded: VisibilityRedacted, // no access to the embedded third party
	}, nil) // viewer has no linked addresses → not a participant

	logs := []Log{{ID: 1, Address: emitter, TxHash: "0xtx", Topic0: &topic0, Topic1: &topic1}}

	// sender/receiver are unrelated to the viewer → non-participant.
	result, err := engine.RedactLogs(context.Background(), logs, "did:test:viewer",
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("log with grant on emitter must be admitted, got %d", len(result))
	}
	got := result[0]

	// The embedded address must be zeroed in the topic.
	zero := "0x" + strings.Repeat("0", 64)
	if got.Topic1 == nil || *got.Topic1 != zero {
		t.Errorf("topic1 must be zeroed to hide the embedded address, got %v", got.Topic1)
	}

	// LEAK CHECK: the real embedded address must NOT appear as a metadata key.
	for k := range got.AddressMetadata {
		if strings.EqualFold(k, embedded) {
			t.Errorf("LEAK (RD-1214): hidden embedded address %s exposed as addressMetadata key (reason=%q) despite the topic being zeroed",
				embedded, got.AddressMetadata[k])
		}
	}
}

// TestRedactLogs_EmbeddedAddressMetadata_VisibleKept_RD1214 is the
// anti-over-redaction guard (the RD-1144 lesson): an embedded address the viewer
// IS entitled to see must remain in the topic AND keep its metadata reason. The
// leak fix must not strip legitimately-visible addresses.
func TestRedactLogs_EmbeddedAddressMetadata_VisibleKept_RD1214(t *testing.T) {
	emitter := "0x1111111111111111111111111111111111111111"
	embedded := "0x9999999999999999999999999999999999999999" // visible to the viewer
	topic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	topic1 := "0x" + encodeAddressSlot(embedded)

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		emitter:  VisibilityFull,
		embedded: VisibilityFull, // viewer is entitled to this address
	}, nil)

	logs := []Log{{ID: 1, Address: emitter, TxHash: "0xtx", Topic0: &topic0, Topic1: &topic1}}

	result, err := engine.RedactLogs(context.Background(), logs, "did:test:viewer",
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("admitted log expected, got %d", len(result))
	}
	got := result[0]

	// A visible embedded address is left intact in the topic.
	if got.Topic1 == nil || !strings.EqualFold(*got.Topic1, topic1) {
		t.Errorf("visible embedded address must be preserved in topic1, got %v want %s", got.Topic1, topic1)
	}
	// ...and keeps a metadata reason so the UI can explain why it is shown.
	if _, ok := got.AddressMetadata[strings.ToLower(embedded)]; !ok {
		t.Errorf("visible embedded address must retain its metadata reason (anti-over-redaction), got %v", got.AddressMetadata)
	}
}

func TestRedactLogs_ParticipantOverride_HiddenStillDropped(t *testing.T) {
	// Even with participant override, Hidden logs should stay dropped.
	// (Hidden = completely invisible, not just redacted)
	contractAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	eveAddr := "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	topic0 := "0xddf252ad"

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		contractAddr: VisibilityHidden,
	}, []string{eveAddr})

	logs := []Log{{ID: 1, Address: contractAddr, Topic0: &topic0, Data: "0xdata"}}

	result, err := engine.RedactLogs(context.Background(), logs, "did:test:eve", eveAddr, contractAddr)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("Hidden logs should still be dropped even with participant override, got %d", len(result))
	}
}

// TestRedactLogs_Participant_NoGrantEmitter_GrantBounded_RD1208 pins the
// participant half of the RPC↔explorer symmetry fix: participant admission is
// GRANT-BOUNDED. A registered contract with NO grant resolves to
// VisibilityRedacted/ReasonNoAccess; being a tx participant must NOT upgrade it
// to Full — a tx that internally touched a contract the viewer has no grant on
// must not leak that contract's event payload. This mirrors rbac.FilterEventLogs,
// whose participant bypass is bounded by `access != nil`
// (TestFilterEventLogs_ParticipantBounds_RD1162). A GRANTED emitter (Full) is
// unaffected — the participant still sees it. (Full RPC/explorer unification is
// tracked by RD-1214.)
func TestRedactLogs_Participant_NoGrantEmitter_GrantBounded_RD1208(t *testing.T) {
	granted := "0x1111111111111111111111111111111111111111" // viewer holds a grant → Full
	noGrant := "0x2222222222222222222222222222222222222222" // registered, no grant → Redacted/ReasonNoAccess
	eve := "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	topic := eventTopic0("PrivateTransfer(address,address,uint256)")

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		granted: VisibilityFull,
		noGrant: VisibilityRedacted,
	}, []string{eve})

	logs := []Log{
		{ID: 1, Address: granted, TxHash: "0xtx", Topic0: &topic, Data: "0x"},
		{ID: 2, Address: noGrant, TxHash: "0xtx", Topic0: &topic, Data: "0x"},
	}
	// Eve is a participant of the tx (from/to = eve/granted).
	result, err := engine.RedactLogsWithOpts(context.Background(), logs, "did:test:eve", nil, eve, granted)
	if err != nil {
		t.Fatal(err)
	}
	got := map[int64]Log{}
	for _, l := range result {
		got[l.ID] = l
	}
	// Granted emitter: participant still sees it (Full — topic preserved).
	if l, ok := got[1]; !ok || l.Topic0 == nil {
		t.Error("granted emitter: participant must still see the log")
	}
	// No-grant emitter: must NOT be revealed at Full for a participant.
	if l, ok := got[2]; ok && strings.EqualFold(l.Address, noGrant) {
		t.Errorf("participant must not reveal a no-grant emitter at Full (RD-1208/RD-1162); leaked %s", l.Address)
	}
}

// ---------------------------------------------------------------------------
// RedactLogs — comprehensive visibility matrix
// ---------------------------------------------------------------------------

func TestRedactLogs_VisibilityMatrix(t *testing.T) {
	// Addresses
	publicContract := "0x1111111111111111111111111111111111111111"
	redactedContract := "0x2222222222222222222222222222222222222222"
	hiddenContract := "0x3333333333333333333333333333333333333333"
	aliceAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"   // tx sender
	bobAddr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"     // tx receiver
	malloryAddr := "0xcccccccccccccccccccccccccccccccccccccccc" // not a participant

	topic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	data := "0x00000000000000000000000000000000000000000000000000000000deadbeef"

	// 3 logs from 3 contracts with different visibility
	makeLogs := func() []Log {
		return []Log{
			{ID: 1, Address: publicContract, TxHash: "0xtx1", Topic0: &topic0, Data: data},
			{ID: 2, Address: redactedContract, TxHash: "0xtx1", Topic0: &topic0, Data: data},
			{ID: 3, Address: hiddenContract, TxHash: "0xtx1", Topic0: &topic0, Data: data},
		}
	}

	visMap := VisibilityMap{
		publicContract:   VisibilityFull,
		redactedContract: VisibilityRedacted,
		hiddenContract:   VisibilityHidden,
	}

	// parent tx: alice → bob
	parentFrom := aliceAddr
	parentTo := bobAddr

	// Under the shared decision engine (RD-1214) the no-grant emitter
	// (redactedContract, VisibilityRedacted / ReasonNoAccess) is DROPPED for
	// every non-admin viewer — matching the RPC (access==nil → drop).
	// Participation / visibleTo never resurrect it. So a non-admin viewer sees
	// exactly one log: the public (Full) contract's. hidden is always dropped.
	cases := []struct {
		name             string
		viewerDID        string
		linkedAddrs      []string
		participantAddrs []string
	}{
		{"anonymous, no participant context", "", nil, nil},
		{"anonymous, with participant addrs (should not help)", "", nil, []string{parentFrom, parentTo}},
		{"alice (sender), no participant context", "did:test:alice", []string{aliceAddr}, nil},
		{"alice (sender), with participant context", "did:test:alice", []string{aliceAddr}, []string{parentFrom, parentTo}},
		{"bob (receiver), with participant context", "did:test:bob", []string{bobAddr}, []string{parentFrom, parentTo}},
		{"mallory (non-participant), with participant context", "did:test:mallory", []string{malloryAddr}, []string{parentFrom, parentTo}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := newEngineWithLinkedAddrs(visMap, tc.linkedAddrs)
			result, err := engine.RedactLogs(context.Background(), makeLogs(), tc.viewerDID, tc.participantAddrs...)
			if err != nil {
				t.Fatal(err)
			}
			if len(result) != 1 {
				t.Fatalf("expected 1 log (public only; redacted no-grant + hidden dropped), got %d", len(result))
			}
			l := result[0]
			if strings.ToLower(l.Address) != publicContract {
				t.Fatalf("only the public (Full) contract's log should survive, got %s", l.Address)
			}
			if l.Topic0 == nil || *l.Topic0 != topic0 || l.Data != data {
				t.Error("public contract log should be fully preserved")
			}
		})
	}

	// Admin sees Full on all contracts (via GetBatchVisibility) → all three logs.
	t.Run("admin (contract is Full for them)", func(t *testing.T) {
		adminEngine := newEngine(VisibilityMap{
			publicContract:   VisibilityFull,
			redactedContract: VisibilityFull,
			hiddenContract:   VisibilityFull,
		})
		result, err := adminEngine.RedactLogs(context.Background(), makeLogs(), "did:test:admin")
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 3 {
			t.Fatalf("admin should see all 3 logs, got %d", len(result))
		}
		for _, l := range result {
			if l.Topic0 == nil || *l.Topic0 != topic0 || l.Data != data {
				t.Errorf("admin should see all topics/data, log %d", l.ID)
			}
		}
	})
}

func TestRedactLogs_MultipleContractsMixedVisibility(t *testing.T) {
	// A tx triggers logs from 4 contracts; the viewer is a tx participant.
	// Participant admission is GRANT-BOUNDED (RD-1208/RD-1162) and, under the
	// shared engine (RD-1214), a no-grant emitter is DROPPED (not kept-stripped).
	// So only the contract the viewer has a grant on (Full) survives; the
	// no-grant contracts (Redacted) and the unregistered/foreign one (Hidden)
	// are all dropped — even though the viewer is a participant.
	userAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fullContract := "0x1111111111111111111111111111111111111111"
	redactedA := "0x2222222222222222222222222222222222222222"
	redactedB := "0x3333333333333333333333333333333333333333"
	hiddenContract := "0x4444444444444444444444444444444444444444"

	topic0 := "0xabcdef"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		fullContract:   VisibilityFull,
		redactedA:      VisibilityRedacted,
		redactedB:      VisibilityRedacted,
		hiddenContract: VisibilityHidden,
	}, []string{userAddr})

	logs := []Log{
		{ID: 1, Address: fullContract, Topic0: &topic0, Data: "0xfull"},
		{ID: 2, Address: redactedA, Topic0: &topic0, Data: "0xredA"},
		{ID: 3, Address: redactedB, Topic0: &topic0, Data: "0xredB"},
		{ID: 4, Address: hiddenContract, Topic0: &topic0, Data: "0xhidden"},
	}

	// With participant context: user is the tx sender.
	result, err := engine.RedactLogs(context.Background(), logs, "did:test:user", userAddr, redactedA)
	if err != nil {
		t.Fatal(err)
	}

	// Only full(1) survives; redactedA(2)/redactedB(3) (no grant) and hidden(4)
	// are dropped.
	if len(result) != 1 {
		t.Fatalf("expected 1 log (only the granted contract's), got %d", len(result))
	}
	l := result[0]
	if l.ID != 1 || strings.ToLower(l.Address) != fullContract {
		t.Fatalf("only the full (granted) contract's log should survive, got ID=%d addr=%s", l.ID, l.Address)
	}
	if l.Topic0 == nil || *l.Topic0 != topic0 || l.Data != "0xfull" {
		t.Error("full contract log should be preserved in the clear")
	}
}

func TestRedactLogs_ParticipantIsReceiver(t *testing.T) {
	// The viewer is the TO of the parent tx (receiving a transfer) but has NO
	// grant on the emitting contract (VisibilityRedacted = ReasonNoAccess).
	// Participant admission is grant-bounded (RD-1208/RD-1162): the log is kept
	// but STRIPPED, not revealed. (Pre-fix it was revealed via the participant
	// override.)
	contractAddr := "0x2222222222222222222222222222222222222222"
	senderAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	receiverAddr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	topic0 := "0xddf252ad"

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		contractAddr: VisibilityRedacted,
	}, []string{receiverAddr})

	logs := []Log{{ID: 1, Address: contractAddr, Topic0: &topic0, Data: "0xdata"}}

	result, err := engine.RedactLogs(context.Background(), logs, "did:test:receiver", senderAddr, receiverAddr)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("no-grant contract log must be dropped for a receiver participant (RD-1214), got %d", len(result))
	}
}

func TestRedactLogs_NoLinkedAddresses(t *testing.T) {
	// Authenticated user with no linked ETH addresses and no grant on the
	// emitting contract (Redacted). Not a participant (no addresses to match),
	// no grant → the log is DROPPED (RD-1214: no-grant → drop, matching the RPC).
	contractAddr := "0x2222222222222222222222222222222222222222"
	senderAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	topic0 := "0xddf252ad"

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		contractAddr: VisibilityRedacted,
	}, nil) // no linked addresses

	logs := []Log{{ID: 1, Address: contractAddr, Topic0: &topic0, Data: "0xdata"}}

	result, err := engine.RedactLogs(context.Background(), logs, "did:test:noaddr", senderAddr, contractAddr)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("no-grant contract log must be dropped, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// RedactAddress
// ---------------------------------------------------------------------------

func TestRedactAddress_Full(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
	})

	result, err := engine.RedactAddress(context.Background(), addr, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != addr {
		t.Errorf("expected %s, got %s", addr, result)
	}
}

func TestRedactAddress_Redacted(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityRedacted,
	})

	result, err := engine.RedactAddress(context.Background(), addr, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != "[PRIVATE]" {
		t.Errorf("expected [PRIVATE], got %s", result)
	}
}

func TestRedactAddress_Pseudonymous(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityPseudonymous,
	})

	result, err := engine.RedactAddress(context.Background(), addr, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	expected := GeneratePseudonym(addr, nil)
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestRedactAddress_Hidden(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
	})

	result, err := engine.RedactAddress(context.Background(), addr, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != "[PRIVATE]" {
		t.Errorf("expected [PRIVATE] for hidden, got %s", result)
	}
}

func TestRedactAddress_DBError(t *testing.T) {
	engine := newEngineErr(errors.New("db error"))
	result, err := engine.RedactAddress(context.Background(), "0xaa", "did:test")
	if err == nil {
		t.Error("expected error")
	}
	if result != "[REDACTED]" {
		t.Errorf("expected [REDACTED] fallback on error, got %s", result)
	}
}

// ---------------------------------------------------------------------------
// RedactTokenHolders
// ---------------------------------------------------------------------------

func TestRedactTokenHolders_Empty(t *testing.T) {
	engine := newEngine(nil)
	result, err := engine.RedactTokenHolders(context.Background(), nil, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil")
	}
}

func TestRedactTokenHolders_HiddenDrops(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
	})

	holders := []TokenHolder{{Address: addr, Balance: "100"}}
	result, err := engine.RedactTokenHolders(context.Background(), holders, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 holders, got %d", len(result))
	}
}

func TestRedactTokenHolders_RedactedMasksAddressAndStripsBalance(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityRedacted,
	})

	holders := []TokenHolder{{Address: addr, Balance: "200", Percentage: 5.5}}
	result, err := engine.RedactTokenHolders(context.Background(), holders, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0].Address != "[PRIVATE]" {
		t.Errorf("Address should be [PRIVATE], got %s", result[0].Address)
	}
	// Balance and percentage stripped for redacted holders — reveals financial position
	if result[0].Balance != "" {
		t.Errorf("Balance should be stripped for redacted holder, got %s", result[0].Balance)
	}
	if result[0].Percentage != 0 {
		t.Errorf("Percentage should be 0 for redacted holder, got %f", result[0].Percentage)
	}
}

func TestRedactTokenHolders_PseudonymousPreservesBalance(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityPseudonymous,
	})

	holders := []TokenHolder{{Address: addr, Balance: "500", Percentage: 12.3}}
	result, err := engine.RedactTokenHolders(context.Background(), holders, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	expectedPseudonym := GeneratePseudonym(addr, nil)
	if result[0].Address != expectedPseudonym {
		t.Errorf("Address should be pseudonym %q, got %q", expectedPseudonym, result[0].Address)
	}
	// Balance preserved for pseudonymous — pattern analysis is the use case
	if result[0].Balance != "500" {
		t.Errorf("Balance should be preserved for pseudonymous holder, got %s", result[0].Balance)
	}
	if result[0].Percentage != 12.3 {
		t.Errorf("Percentage should be preserved for pseudonymous holder, got %f", result[0].Percentage)
	}
}

func TestRedactTokenHolders_FullUnchanged(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
	})

	holders := []TokenHolder{{Address: addr, Balance: "300", Percentage: 10.0}}
	result, err := engine.RedactTokenHolders(context.Background(), holders, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0].Address != addr {
		t.Errorf("Address should be unchanged, got %s", result[0].Address)
	}
}

func TestRedactTokenHolders_DBError(t *testing.T) {
	engine := newEngineErr(errors.New("db error"))
	holders := []TokenHolder{{Address: "0xaa", Balance: "1"}}
	_, err := engine.RedactTokenHolders(context.Background(), holders, "did:test")
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// applyRedaction (via RedactAddress — indirect testing)
// ---------------------------------------------------------------------------

func TestApplyRedaction_DefaultFallback(t *testing.T) {
	// An address not in the map returns zero value VisibilityLevel (""),
	// which hits the default case in applyRedaction and returns "[PRIVATE]"
	engine := newEngine(VisibilityMap{}) // empty map
	result, err := engine.RedactAddress(context.Background(), "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != "[PRIVATE]" {
		t.Errorf("unknown visibility should default to [PRIVATE], got %s", result)
	}
}

// ---------------------------------------------------------------------------
// Participant visibility — viewer sees counterparty in their own transactions
// ---------------------------------------------------------------------------

func TestRedactTransactions_ParticipantSeesCounterparty(t *testing.T) {
	// Alice (viewer) sends to Bob. Bob's address is hidden globally,
	// but Alice should see Bob's address because Alice is the sender.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityFull,
		bob:   VisibilityHidden,
	}, []string{alice})

	txs := []Transaction{
		{Hash: "0x01", From: alice, To: strPtr(bob), Value: "1000", InputData: "0xdeadbeef"},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].From != alice {
		t.Errorf("From should be unchanged, got %s", result[0].From)
	}
	if *result[0].To != bob {
		t.Errorf("To should be Bob's real address (participant visibility), got %s", *result[0].To)
	}
	// Value and input should be preserved since both sides are now VisibilityFull
	if result[0].Value != "1000" {
		t.Errorf("Value should be preserved for participant, got %s", result[0].Value)
	}
	if result[0].InputData != "0xdeadbeef" {
		t.Errorf("InputData should be preserved for participant, got %s", result[0].InputData)
	}
}

func TestRedactTransactions_ParticipantSeesCounterparty_Receiver(t *testing.T) {
	// Bob (viewer) receives from Alice. Alice's address is hidden globally,
	// but Bob should see Alice's address because Bob is the receiver.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityHidden,
		bob:   VisibilityFull,
	}, []string{bob})

	nonce := u64ptr(42)
	txs := []Transaction{
		{Hash: "0x01", From: alice, To: strPtr(bob), Value: "500", Nonce: nonce},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].From != alice {
		t.Errorf("From should be Alice's real address (participant visibility), got %s", result[0].From)
	}
	if *result[0].To != bob {
		t.Errorf("To should be unchanged, got %s", *result[0].To)
	}
	if result[0].Value != "500" {
		t.Errorf("Value should be preserved for participant, got %s", result[0].Value)
	}
	// Nonce must be stripped — the sender is base-level hidden, and nonce reveals
	// their lifetime tx count. The participant override shows the address, not metadata.
	if result[0].Nonce != nil {
		t.Errorf("Nonce must be nil when sender is base-level hidden (participant override), got %v", *result[0].Nonce)
	}
}

func TestRedactTransactions_ParticipantNonceStripped_SenderViewing(t *testing.T) {
	// Alice (viewer, sender) sends to Bob (hidden). Alice sees Bob's address
	// via participant visibility, but Alice's own nonce should be preserved
	// (it's her own nonce, not private from her).
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityFull,
		bob:   VisibilityHidden,
	}, []string{alice})

	nonce := u64ptr(10)
	txs := []Transaction{
		{Hash: "0x01", From: alice, To: strPtr(bob), Value: "100", Nonce: nonce},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	// Alice's own nonce should be preserved — it's her own data
	if result[0].Nonce == nil || *result[0].Nonce != 10 {
		t.Errorf("Sender's own nonce should be preserved, got %v", result[0].Nonce)
	}
}

func TestRedactTransactions_ParticipantNonceStripped_ReceiverViewingRedactedSender(t *testing.T) {
	// Bob (viewer, receiver) sees tx from Alice (redacted). Alice's nonce must be stripped.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityRedacted,
		bob:   VisibilityFull,
	}, []string{bob})

	nonce := u64ptr(99)
	txs := []Transaction{
		{Hash: "0x01", From: alice, To: strPtr(bob), Value: "200", Nonce: nonce},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].Nonce != nil {
		t.Errorf("Nonce must be nil when sender is base-level redacted (participant override), got %v", *result[0].Nonce)
	}
}

func TestRedactTransactions_NonParticipantDoesNotSeeHiddenAddresses(t *testing.T) {
	// G10: Charlie (viewer) is not a participant. Alice is hidden.
	// Under G10, the tx is dropped entirely for non-participants.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	charlie := "0xcccccccccccccccccccccccccccccccccccccccc"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityHidden,
		bob:   VisibilityFull,
	}, []string{charlie})

	nonce := u64ptr(7)
	txs := []Transaction{
		{Hash: "0x01", From: alice, To: strPtr(bob), Value: "1000", Nonce: nonce},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:charlie")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: non-participant, hidden from → drop), got %d", len(result))
	}
}

func TestRedactTransactions_ParticipantVisibilityDoesNotLeakToOtherTxs(t *testing.T) {
	// Alice (viewer) is participant in tx1 (Alice -> Bob) but NOT in tx2 (Carol -> Bob).
	// Bob is hidden globally. Under G10, tx2 is dropped (non-participant, hidden to).
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	carol := "0xcccccccccccccccccccccccccccccccccccccccc"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityFull,
		bob:   VisibilityHidden,
		carol: VisibilityFull,
	}, []string{alice})

	nonce5 := u64ptr(5)
	nonce8 := u64ptr(8)
	txs := []Transaction{
		{Hash: "0x01", From: alice, To: strPtr(bob), Value: "100", Nonce: nonce5}, // Alice is participant
		{Hash: "0x02", From: carol, To: strPtr(bob), Value: "200", Nonce: nonce8}, // Alice is NOT participant → dropped (G10)
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (tx2 dropped under G10), got %d", len(result))
	}

	// tx1: Alice is participant (sender), Bob should be visible
	tx1 := result[0]
	if tx1.Hash != "0x01" {
		t.Fatalf("expected tx1 hash 0x01, got %s", tx1.Hash)
	}
	if *tx1.To != bob {
		t.Errorf("tx1: To should be Bob's real address (participant), got %s", *tx1.To)
	}
	if tx1.Value != "100" {
		t.Errorf("tx1: Value should be preserved for participant, got %s", tx1.Value)
	}
	// Alice is the sender — her own nonce should be preserved (baseFromLevel is Full)
	if tx1.Nonce == nil || *tx1.Nonce != 5 {
		t.Errorf("tx1: Sender's own nonce should be preserved, got %v", tx1.Nonce)
	}
}

// ---------------------------------------------------------------------------
// Calldata-level participant detection — ERC20 transfer recipients
// ---------------------------------------------------------------------------

func TestRedactTransactions_CalldataParticipant_ERC20Transfer(t *testing.T) {
	// Alice sends ERC20 transfer to Dave via contract. Tx-level to = contract.
	// Dave's address is in the calldata (transfer(address,uint256)).
	// Dave should be detected as participant and see Alice's address + value.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dave := "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"
	contract := "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9"

	// transfer(address,uint256) selector = 0xa9059cbb
	// Dave's address padded to 32 bytes + amount
	calldata := "0xa9059cbb00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a650000000000000000000000000000000000000000000000056bc75e2d63100000"

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice:    VisibilityHidden,
		dave:     VisibilityFull,
		contract: VisibilityFull,
	}, []string{dave})

	contractStr := contract
	nonce := uint64(5)
	txs := []Transaction{{
		Hash:      "0x01",
		From:      alice,
		To:        &contractStr,
		Value:     "1000",
		InputData: calldata,
		Nonce:     &nonce,
	}}

	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:dave")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (Dave is calldata participant), got %d", len(result))
	}

	// Dave should see Alice's real address (participant override)
	if result[0].From != alice {
		t.Errorf("expected From=%s (participant sees counterparty), got %s", alice, result[0].From)
	}
	// Value should be preserved (participant sees value)
	if result[0].Value == "0" || result[0].Value == "" {
		t.Errorf("expected value preserved for participant, got %q", result[0].Value)
	}
}

func TestRedactTransactions_CalldataParticipant_TransferFrom(t *testing.T) {
	// transferFrom(alice, dave, amount) — Dave is param 1 (to)
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dave := "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"
	contract := "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9"

	// transferFrom(address,address,uint256) selector = 0x23b872dd
	calldata := "0x23b872dd000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a650000000000000000000000000000000000000000000000056bc75e2d63100000"

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice:    VisibilityHidden,
		dave:     VisibilityFull,
		contract: VisibilityFull,
	}, []string{dave})

	contractStr := contract
	txs := []Transaction{{
		Hash:      "0x02",
		From:      "0xspender", // spender is a third party
		To:        &contractStr,
		Value:     "500",
		InputData: calldata,
	}}

	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:dave")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (Dave is transferFrom recipient), got %d", len(result))
	}
}

func TestRedactTransactions_CalldataParticipant_NonParticipantStillHidden(t *testing.T) {
	// G10: Charlie is NOT in the calldata or tx-level from/to.
	// Alice (from) is hidden. Under G10, dropped for non-participant Charlie.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dave := "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"
	charlie := "0x90f79bf6eb2c4f870365e785982e1f101e93b906"
	contract := "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9"

	calldata := "0xa9059cbb00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a650000000000000000000000000000000000000000000000056bc75e2d63100000"

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice:    VisibilityHidden,
		dave:     VisibilityHidden,
		charlie:  VisibilityFull,
		contract: VisibilityFull,
	}, []string{charlie})

	contractStr := contract
	txs := []Transaction{{
		Hash:      "0x03",
		From:      alice,
		To:        &contractStr,
		Value:     "1000",
		InputData: calldata,
	}}

	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:charlie")
	if err != nil {
		t.Fatal(err)
	}

	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: non-participant, hidden from → drop), got %d", len(result))
	}
}

func TestIsViewerInCalldata(t *testing.T) {
	dave := "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"
	addrs := map[string]bool{dave: true}

	tests := []struct {
		name      string
		inputData string
		expect    bool
	}{
		{"ERC20 transfer to viewer", "0xa9059cbb00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a650000000000000000000000000000000000000000000000056bc75e2d63100000", true},
		{"ERC20 transfer to someone else", "0xa9059cbb000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000000000000000000056bc75e2d63100000", false},
		{"transferFrom with viewer as to", "0x23b872dd000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a650000000000000000000000000000000000000000000000056bc75e2d63100000", true},
		{"transferFrom with viewer as from", "0x23b872dd00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a65000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000000000000000000056bc75e2d63100000", true},
		{"approve with viewer as spender", "0x095ea7b300000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a650000000000000000000000000000000000000000000000056bc75e2d63100000", true},
		{"ERC20 transfer no 0x prefix (DB format)", "a9059cbb00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a650000000000000000000000000000000000000000000000056bc75e2d63100000", true},
		{"unknown selector", "0xdeadbeef00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a65", false},
		{"empty input", "0x", false},
		{"too short", "0xa9059cbb", false},
		{"no input", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isViewerInCalldata(tt.inputData, addrs)
			if got != tt.expect {
				t.Errorf("isViewerInCalldata(%s) = %v, want %v", tt.name, got, tt.expect)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RedactTransfers — Participant visibility override
// ---------------------------------------------------------------------------

func TestRedactTransfers_ParticipantSeesCounterparty_Sender(t *testing.T) {
	// Alice (viewer) is the sender (From). Bob (To) is hidden globally,
	// but Alice should see Bob's address and the transfer value because
	// Alice is a participant.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityFull,
		bob:   VisibilityHidden,
	}, []string{alice})

	transfers := []TokenTransfer{{ID: 1, From: alice, To: bob, Value: "750"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 transfer, got %d", len(result))
	}
	tr := result[0]
	if tr.From != alice {
		t.Errorf("From should be unchanged, got %s", tr.From)
	}
	if tr.To != bob {
		t.Errorf("To should be Bob's real address (participant visibility), got %s", tr.To)
	}
	if tr.Value != "750" {
		t.Errorf("Value should be preserved for participant, got %s", tr.Value)
	}
}

func TestRedactTransfers_ParticipantSeesCounterparty_Receiver(t *testing.T) {
	// Bob (viewer) is the receiver (To). Alice (From) is hidden globally,
	// but Bob should see Alice's address and the transfer value because
	// Bob is a participant.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityHidden,
		bob:   VisibilityFull,
	}, []string{bob})

	transfers := []TokenTransfer{{ID: 1, From: alice, To: bob, Value: "300"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 transfer, got %d", len(result))
	}
	tr := result[0]
	if tr.From != alice {
		t.Errorf("From should be Alice's real address (participant visibility), got %s", tr.From)
	}
	if tr.To != bob {
		t.Errorf("To should be unchanged, got %s", tr.To)
	}
	if tr.Value != "300" {
		t.Errorf("Value should be preserved for participant, got %s", tr.Value)
	}
}

func TestRedactTransfers_NonParticipantDoesNotSeeHiddenTransfer(t *testing.T) {
	// G10: Charlie (viewer) is not a participant. Alice (From) is hidden.
	// Non-participant with one side hidden → transfer dropped entirely.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	charlie := "0xcccccccccccccccccccccccccccccccccccccccc"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityHidden,
		bob:   VisibilityFull,
	}, []string{charlie})

	transfers := []TokenTransfer{{ID: 1, From: alice, To: bob, Value: "500"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:charlie")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 transfers (G10: hidden from, non-participant → drop), got %d", len(result))
	}
}

func TestRedactTransfers_ParticipantBothHidden_StillVisible(t *testing.T) {
	// Alice (viewer) is the sender (From). Both Alice and Bob are hidden
	// in the visibility map. With participant override, both should become
	// visible and the transfer should be kept with value preserved.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityHidden,
		bob:   VisibilityHidden,
	}, []string{alice})

	transfers := []TokenTransfer{{ID: 1, From: alice, To: bob, Value: "1000"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 transfer (participant override prevents drop), got %d", len(result))
	}
	tr := result[0]
	if tr.From != alice {
		t.Errorf("From should be Alice's real address (participant visibility), got %s", tr.From)
	}
	if tr.To != bob {
		t.Errorf("To should be Bob's real address (participant visibility), got %s", tr.To)
	}
	if tr.Value != "1000" {
		t.Errorf("Value should be preserved for participant, got %s", tr.Value)
	}
}

// ---------------------------------------------------------------------------
// RedactInternalTransactions — Participant visibility override
// ---------------------------------------------------------------------------

func TestRedactInternalTransactions_ParticipantSeesCounterparty_Sender(t *testing.T) {
	// Alice (viewer) is From. Bob (To) is hidden globally, but Alice
	// should see Bob's address and all data because Alice is a participant.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	input := "0xdeadbeef"
	output := "0x01"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityFull,
		bob:   VisibilityHidden,
	}, []string{alice})

	itxs := []InternalTransaction{{ID: 1, From: alice, To: strPtr(bob), Value: "400", Input: &input, Output: &output}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 internal tx, got %d", len(result))
	}
	itx := result[0]
	if itx.From != alice {
		t.Errorf("From should be unchanged, got %s", itx.From)
	}
	if *itx.To != bob {
		t.Errorf("To should be Bob's real address (participant visibility), got %s", *itx.To)
	}
	if itx.Value != "400" {
		t.Errorf("Value should be preserved for participant, got %s", itx.Value)
	}
	if itx.Input == nil || *itx.Input != "0xdeadbeef" {
		t.Errorf("Input should be preserved for participant, got %v", itx.Input)
	}
	if itx.Output == nil || *itx.Output != "0x01" {
		t.Errorf("Output should be preserved for participant, got %v", itx.Output)
	}
}

func TestRedactInternalTransactions_ParticipantSeesCounterparty_Receiver(t *testing.T) {
	// Bob (viewer) is To. Alice (From) is hidden globally, but Bob
	// should see Alice's address and all data because Bob is a participant.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	input := "0xcafebabe"
	output := "0xff"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityHidden,
		bob:   VisibilityFull,
	}, []string{bob})

	itxs := []InternalTransaction{{ID: 1, From: alice, To: strPtr(bob), Value: "600", Input: &input, Output: &output}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 internal tx, got %d", len(result))
	}
	itx := result[0]
	if itx.From != alice {
		t.Errorf("From should be Alice's real address (participant visibility), got %s", itx.From)
	}
	if *itx.To != bob {
		t.Errorf("To should be unchanged, got %s", *itx.To)
	}
	if itx.Value != "600" {
		t.Errorf("Value should be preserved for participant, got %s", itx.Value)
	}
	if itx.Input == nil || *itx.Input != "0xcafebabe" {
		t.Errorf("Input should be preserved for participant, got %v", itx.Input)
	}
	if itx.Output == nil || *itx.Output != "0xff" {
		t.Errorf("Output should be preserved for participant, got %v", itx.Output)
	}
}

func TestRedactInternalTransactions_NonParticipantDoesNotSeeHidden(t *testing.T) {
	// Charlie (viewer) is not a participant. Alice (From) is hidden.
	// Charlie should see [PRIVATE] for Alice, Value stripped, Input/Output nil.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	charlie := "0xcccccccccccccccccccccccccccccccccccccccc"
	input := "0xdeadbeef"
	output := "0x01"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityHidden,
		bob:   VisibilityFull,
	}, []string{charlie})

	itxs := []InternalTransaction{{ID: 1, From: alice, To: strPtr(bob), Value: "250", Input: &input, Output: &output}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:charlie")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 internal tx, got %d", len(result))
	}
	itx := result[0]
	if itx.From != "[PRIVATE]" {
		t.Errorf("From should be [PRIVATE] for non-participant, got %s", itx.From)
	}
	if *itx.To != bob {
		t.Errorf("To should be unchanged, got %s", *itx.To)
	}
	if itx.Value != "" {
		t.Errorf("Value should be stripped (one side hidden, non-participant), got %s", itx.Value)
	}
	if itx.Input != nil {
		t.Errorf("Input should be nil for non-participant with hidden side")
	}
	if itx.Output != nil {
		t.Errorf("Output should be nil for non-participant with hidden side")
	}
}

// RD-1122: the tx originator sees their direct counterparty consistently across
// nested trace frames (it is already shown at the tx/Overview level), while a
// foreign-org contract reached only deep in the trace stays [PRIVATE]. This
// asserts BOTH the fix (counterparty no longer over-redacted) and the per-side
// cross-org guard (the non-parent side of a frame is never revealed).
func TestRedactInternalTransactions_ParentParticipantRevealsCounterpartyAcrossNestedFrames_RD1122(t *testing.T) {
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"     // viewer + parent `from`
	cpty := "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"    // parent `to`, private
	pub := "0xdddddddddddddddddddddddddddddddddddddddd"     // public contract
	foreign := "0xffffffffffffffffffffffffffffffffffffffff" // foreign-org, private, NOT a parent party

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		bob:     VisibilityFull,
		cpty:    VisibilityRedacted,
		pub:     VisibilityFull,
		foreign: VisibilityRedacted,
	}, []string{bob})

	// Nested frames (sub-calls of the top bob->cpty call). Bob is a direct
	// from/to of NEITHER frame — only of the parent tx.
	itxs := []InternalTransaction{
		{ID: 1, TxHash: "0xtx", From: cpty, To: strPtr(pub)},     // cpty -> public
		{ID: 2, TxHash: "0xtx", From: cpty, To: strPtr(foreign)}, // cpty -> foreign-org
	}
	opts := RedactOpts{ParentParticipants: []string{bob, cpty}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:bob", opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 internal txs, got %d", len(result))
	}
	// Frame 1: cpty (the originator's direct counterparty) is revealed instead
	// of [PRIVATE] — the over-redaction this ticket fixes.
	if result[0].From != cpty {
		t.Errorf("frame1 From: parent counterparty should be revealed (was over-redacted), got %s", result[0].From)
	}
	if result[0].To == nil || *result[0].To != pub {
		t.Errorf("frame1 To: public contract should be shown, got %v", result[0].To)
	}
	// Frame 2: cpty revealed (a parent party); foreign stays [PRIVATE] because it
	// is NOT a parent party — proves the per-side reveal closes no cross-org leak.
	if result[1].From != cpty {
		t.Errorf("frame2 From: parent counterparty should be revealed, got %s", result[1].From)
	}
	if result[1].To == nil || *result[1].To != "[PRIVATE]" {
		t.Errorf("frame2 To: foreign-org contract MUST stay [PRIVATE] (cross-org guard), got %v", result[1].To)
	}
}

// RD-1122: the parent-participant reveal is gated on the VIEWER being a parent
// participant (their linked EOA == parent from/to). A viewer who is not a
// parent party gets no reveal — the counterparty stays [PRIVATE].
func TestRedactInternalTransactions_ParentParticipantGateRequiresViewerParticipation_RD1122(t *testing.T) {
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cpty := "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
	pub := "0xdddddddddddddddddddddddddddddddddddddddd"
	charlie := "0xcccccccccccccccccccccccccccccccccccccccc" // viewer, NOT a parent party

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		bob:  VisibilityFull,
		cpty: VisibilityRedacted,
		pub:  VisibilityFull,
	}, []string{charlie})

	itxs := []InternalTransaction{
		{ID: 1, TxHash: "0xtx", From: cpty, To: strPtr(pub)},
	}
	opts := RedactOpts{ParentParticipants: []string{bob, cpty}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:charlie", opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 internal tx, got %d", len(result))
	}
	if result[0].From != "[PRIVATE]" {
		t.Errorf("non-participant viewer must NOT get the parent reveal; From should be [PRIVATE], got %s", result[0].From)
	}
}

// TestRedactTransactions_AnonymousViewerContractCreationScenario reproduces the
// exact bug: an anonymous user (Eve) sees 53 transactions including contract
// creations from org-owned deployers. After the fix, contract creations from
// hidden deployers are dropped.
func TestRedactTransactions_AnonymousViewerContractCreationScenario(t *testing.T) {
	orgDeployerAddr := "0xdeployer000000000000000000000000000000"
	publicEOA1 := "0xpublic1000000000000000000000000000000000"
	publicEOA2 := "0xpublic2000000000000000000000000000000000"

	db := &mockDB{
		visMap: VisibilityMap{
			orgDeployerAddr: VisibilityHidden, // org-owned, hidden from Eve
			publicEOA1:      VisibilityFull,   // public address
			publicEOA2:      VisibilityFull,   // public address
		},
	}
	engine := NewRedactionEngine(nil, db, rbac.ReadProfileStandard)

	to1 := publicEOA2
	txs := []Transaction{
		// Contract creation from org deployer — should be DROPPED
		{Hash: "0xdeploy1", From: orgDeployerAddr, To: nil},
		{Hash: "0xdeploy2", From: orgDeployerAddr, To: nil},
		{Hash: "0xdeploy3", From: orgDeployerAddr, To: nil},
		// Normal transfer between public addresses — should be KEPT
		{Hash: "0xtransfer1", From: publicEOA1, To: &to1},
	}

	result, err := engine.RedactTransactions(context.Background(), txs, "") // anonymous viewer
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 visible tx (the public transfer), got %d", len(result))
	}
	if len(result) > 0 && result[0].Hash != "0xtransfer1" {
		t.Errorf("expected the public transfer to survive, got hash=%s", result[0].Hash)
	}
}

// TestRedactTransactions_ContractCreationHiddenDeployer verifies that contract
// creation transactions from a hidden deployer are dropped entirely.
// This prevents leaking deployment activity, timing, and contract addresses.
func TestRedactTransactions_ContractCreationHiddenDeployer(t *testing.T) {
	deployerAddr := "0xdeployer000000000000000000000000000000"

	db := &mockDB{
		visMap: VisibilityMap{
			deployerAddr: VisibilityHidden,
		},
	}
	engine := NewRedactionEngine(nil, db, rbac.ReadProfileStandard)

	txs := []Transaction{
		{
			Hash: "0xdeploy1",
			From: deployerAddr,
			To:   nil, // contract creation
		},
	}

	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:eve")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected contract creation from hidden deployer to be dropped, got %d transactions", len(result))
	}
}

// TestRedactTransactions_ContractCreationVisibleDeployer verifies that contract
// creation transactions from a visible deployer are kept.
func TestRedactTransactions_ContractCreationVisibleDeployer(t *testing.T) {
	deployerAddr := "0xdeployer000000000000000000000000000000"

	db := &mockDB{
		visMap: VisibilityMap{
			deployerAddr: VisibilityFull,
		},
	}
	engine := NewRedactionEngine(nil, db, rbac.ReadProfileStandard)

	txs := []Transaction{
		{
			Hash: "0xdeploy1",
			From: deployerAddr,
			To:   nil,
		},
	}

	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected visible deployer's contract creation to be kept, got %d", len(result))
	}
}

// RD-1143: the deployed-contract address on a CREATE receipt is field-level
// redacted. With a PUBLIC deployer the row survives, but a private deployed
// contract's address must not leak to a non-participant.
func TestRedactTransactions_ContractAddress_RedactedForNonParticipant_RD1143(t *testing.T) {
	deployer := "0xdeployer000000000000000000000000000000" // public
	contract := "0xcontract000000000000000000000000000000" // private (Redacted)
	db := &mockDB{visMap: VisibilityMap{
		deployer: VisibilityFull,
		contract: VisibilityRedacted,
	}}
	engine := NewRedactionEngine(nil, db, rbac.ReadProfileStandard)
	txs := []Transaction{{Hash: "0xdeploy", From: deployer, To: nil, ContractAddress: strPtr(contract)}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:eve")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected row kept (public deployer), got %d", len(result))
	}
	if result[0].ContractAddress == nil || *result[0].ContractAddress != "[PRIVATE]" {
		t.Errorf("contractAddress must be [PRIVATE] for non-participant, got %v", result[0].ContractAddress)
	}
}

// RD-1143: the deployer (participant in their own CREATE) sees the real deployed
// contract address even when its standing visibility is Redacted.
func TestRedactTransactions_ContractAddress_DeployerSeesReal_RD1143(t *testing.T) {
	deployer := "0xdeployer000000000000000000000000000000"
	contract := "0xcontract000000000000000000000000000000"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		deployer: VisibilityHidden,   // private deployer
		contract: VisibilityRedacted, // standing-redacted contract
	}, []string{deployer}) // viewer's linked addr IS the deployer
	txs := []Transaction{{Hash: "0xdeploy", From: deployer, To: nil, ContractAddress: strPtr(contract)}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:deployer")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected deployer to see their own deploy, got %d", len(result))
	}
	if result[0].ContractAddress == nil || *result[0].ContractAddress != contract {
		t.Errorf("deployer must see real contractAddress, got %v", result[0].ContractAddress)
	}
}

// RD-1143 (admin-flag reconciliation): ORG_ADMIN_VIEW_USER_TXS reveals row
// existence + value but NOT the deployed-contract address — addresses are never
// revealed by the flag. Admin has no org access to the contract.
func TestRedactTransactions_ContractAddress_AdminFlagDoesNotReveal_RD1143(t *testing.T) {
	deployer := "0xdeployer000000000000000000000000000000"
	contract := "0xcontract000000000000000000000000000000"
	db := &mockDB{visMap: VisibilityMap{
		deployer: VisibilityHidden,
		contract: VisibilityRedacted, // admin has NO org access to it
	}}
	engine := NewRedactionEngine(nil, db, rbac.ReadProfileStandard)
	txs := []Transaction{{Hash: "0xdeploy", From: deployer, To: nil, Value: "42", ContractAddress: strPtr(contract)}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:admin",
		RedactOpts{ViewerIsAdmin: true, OrgAdminViewUserTxs: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("admin-flag should keep the deploy row, got %d", len(result))
	}
	if result[0].From != "[PRIVATE]" {
		t.Errorf("deployer should be [PRIVATE] under the flag, got %s", result[0].From)
	}
	if result[0].ContractAddress == nil || *result[0].ContractAddress != "[PRIVATE]" {
		t.Errorf("admin flag must NOT reveal contractAddress, got %v", result[0].ContractAddress)
	}
	if result[0].Value != "42" {
		t.Errorf("admin flag should preserve value, got %s", result[0].Value)
	}
}

// RD-1143 (admin-flag reconciliation): an admin WITH org access to the deployed
// contract (its visibility resolves Full) sees the real address legitimately,
// even though the deployer EOA stays [PRIVATE].
func TestRedactTransactions_ContractAddress_AdminWithContractAccessSeesReal_RD1143(t *testing.T) {
	deployer := "0xdeployer000000000000000000000000000000"
	contract := "0xcontract000000000000000000000000000000"
	db := &mockDB{visMap: VisibilityMap{
		deployer: VisibilityHidden, // deployer EOA private to the admin
		contract: VisibilityFull,   // admin has org access to the contract
	}}
	engine := NewRedactionEngine(nil, db, rbac.ReadProfileStandard)
	txs := []Transaction{{Hash: "0xdeploy", From: deployer, To: nil, ContractAddress: strPtr(contract)}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:admin",
		RedactOpts{ViewerIsAdmin: true, OrgAdminViewUserTxs: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected row kept, got %d", len(result))
	}
	if result[0].ContractAddress == nil || *result[0].ContractAddress != contract {
		t.Errorf("admin with contract access should see real contractAddress, got %v", result[0].ContractAddress)
	}
}

// ---------------------------------------------------------------------------
// AddressMetadata tests — verify the metadata map is populated with the correct
// visibility reason for each address in redacted transactions.
// ---------------------------------------------------------------------------

// mockDBDetailed is a mock that allows injecting specific AddressVisibility
// entries with fine-grained reasons (own_address, rbac_group_member, etc.).
type mockDBDetailed struct {
	visMap      VisibilityMap
	detailedMap map[string]AddressVisibility
	linkedAddrs []string
	err         error
}

func (m *mockDBDetailed) GetBatchVisibility(_ context.Context, _ string, _ []string) (VisibilityMap, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.visMap, nil
}

func (m *mockDBDetailed) GetBatchVisibilityDetailed(_ context.Context, _ string, _ []string) (map[string]AddressVisibility, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.detailedMap, nil
}

func (m *mockDBDetailed) GetLinkedAddresses(_ context.Context, _ string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.linkedAddrs, nil
}

func (m *mockDBDetailed) GetBatchEventAccess(_ context.Context, _ string, _ []string) (map[string]bool, error) {
	return make(map[string]bool), nil
}

func newEngineDetailed(visMap VisibilityMap, detailedMap map[string]AddressVisibility, linkedAddrs []string) *RedactionEngine {
	return &RedactionEngine{readProfile: rbac.ReadProfileStandard, store: nil, db: &mockDBDetailed{
		visMap:      visMap,
		detailedMap: detailedMap,
		linkedAddrs: linkedAddrs,
	}}
}

func TestRedactTransactions_AddressMetadata_OwnAddress(t *testing.T) {
	// When the viewer owns an address (own_address reason), the metadata should
	// reflect that.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{alice: VisibilityFull, bob: VisibilityFull},
		map[string]AddressVisibility{
			alice: {Level: VisibilityFull, Reason: ReasonOwnAddress},
			bob:   {Level: VisibilityFull, Reason: ReasonPublicAddress},
		},
		nil,
	)

	txs := []Transaction{{Hash: "0x01", From: alice, To: strPtr(bob), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].AddressMetadata == nil {
		t.Fatal("AddressMetadata should not be nil")
	}
	if result[0].AddressMetadata[alice] != ReasonOwnAddress {
		t.Errorf("expected own_address for alice, got %q", result[0].AddressMetadata[alice])
	}
	if result[0].AddressMetadata[bob] != ReasonPublicAddress {
		t.Errorf("expected public_address for bob, got %q", result[0].AddressMetadata[bob])
	}
}

func TestRedactTransactions_AddressMetadata_RBACGroupMember(t *testing.T) {
	// A contract granted via RBAC group membership should have rbac_group_member reason.
	viewer := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contract := "0xcccccccccccccccccccccccccccccccccccccccc"

	engine := newEngineDetailed(
		VisibilityMap{viewer: VisibilityFull, contract: VisibilityFull},
		map[string]AddressVisibility{
			viewer:   {Level: VisibilityFull, Reason: ReasonOwnAddress},
			contract: {Level: VisibilityFull, Reason: ReasonRBACGroupMember},
		},
		nil,
	)

	txs := []Transaction{{Hash: "0x01", From: viewer, To: strPtr(contract), Value: "500"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:viewer")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].AddressMetadata[contract] != ReasonRBACGroupMember {
		t.Errorf("expected rbac_group_member for contract, got %q", result[0].AddressMetadata[contract])
	}
}

func TestRedactTransactions_AddressMetadata_ParticipantOverride(t *testing.T) {
	// When the viewer is a participant and the counterparty is base-level hidden,
	// the metadata should show participant_override for the counterparty.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{alice: VisibilityFull, bob: VisibilityHidden},
		map[string]AddressVisibility{
			alice: {Level: VisibilityFull, Reason: ReasonOwnAddress},
			bob:   {Level: VisibilityHidden, Reason: ReasonNoAccess},
		},
		[]string{alice}, // alice is linked to the viewer
	)

	txs := []Transaction{{Hash: "0x01", From: alice, To: strPtr(bob), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	// Alice should see Bob's real address (participant override)
	if *result[0].To != bob {
		t.Errorf("expected Bob's real address via participant override, got %s", *result[0].To)
	}
	// Bob's metadata reason should be participant_override, not no_access
	if result[0].AddressMetadata[bob] != ReasonParticipantOverride {
		t.Errorf("expected participant_override for Bob, got %q", result[0].AddressMetadata[bob])
	}
	// Alice's metadata should still show own_address
	if result[0].AddressMetadata[alice] != ReasonOwnAddress {
		t.Errorf("expected own_address for Alice, got %q", result[0].AddressMetadata[alice])
	}
}

func TestRedactTransactions_AddressMetadata_NoAccess(t *testing.T) {
	// G10: When one side is hidden and the viewer is NOT a participant,
	// the tx is dropped entirely (not shown with [PRIVATE]).
	viewer := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hidden := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{viewer: VisibilityFull, hidden: VisibilityHidden},
		map[string]AddressVisibility{
			viewer: {Level: VisibilityFull, Reason: ReasonPublicAddress},
			hidden: {Level: VisibilityHidden, Reason: ReasonNoAccess},
		},
		nil, // no linked addresses — viewer is NOT a participant
	)

	txs := []Transaction{{Hash: "0x01", From: viewer, To: strPtr(hidden), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:outsider")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: non-participant, hidden to → drop), got %d", len(result))
	}
}

func TestRedactTransactions_AddressMetadata_DisclosureGrant(t *testing.T) {
	// When an address is visible via a disclosure grant, the metadata should
	// reflect disclosure_grant as the reason.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	disclosed := "0xdddddddddddddddddddddddddddddddddddddd"

	engine := newEngineDetailed(
		VisibilityMap{alice: VisibilityFull, disclosed: VisibilityFull},
		map[string]AddressVisibility{
			alice:     {Level: VisibilityFull, Reason: ReasonOwnAddress},
			disclosed: {Level: VisibilityFull, Reason: ReasonDisclosureGrant},
		},
		nil,
	)

	txs := []Transaction{{Hash: "0x01", From: alice, To: strPtr(disclosed), Value: "100"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].AddressMetadata[disclosed] != ReasonDisclosureGrant {
		t.Errorf("expected disclosure_grant for disclosed address, got %q", result[0].AddressMetadata[disclosed])
	}
}

func TestRedactTransactions_AddressMetadata_AlwaysPopulated(t *testing.T) {
	// Even for fully visible transactions, AddressMetadata should be non-nil and
	// contain entries for all involved addresses.
	addr1 := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	addr2 := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{addr1: VisibilityFull, addr2: VisibilityFull},
		map[string]AddressVisibility{
			addr1: {Level: VisibilityFull, Reason: ReasonOwnAddress},
			addr2: {Level: VisibilityFull, Reason: ReasonRBACGroupMember},
		},
		nil,
	)

	txs := []Transaction{{Hash: "0x01", From: addr1, To: strPtr(addr2), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].AddressMetadata == nil {
		t.Fatal("AddressMetadata must not be nil for redacted transactions")
	}
	if len(result[0].AddressMetadata) != 2 {
		t.Errorf("expected 2 entries in AddressMetadata, got %d", len(result[0].AddressMetadata))
	}
}

// TestRedactTransactions_ContractCreationRedactedDeployer verifies that redacted
// (not just hidden) deployers also get their contract creations dropped.
func TestRedactTransactions_ContractCreationRedactedDeployer(t *testing.T) {
	deployerAddr := "0xdeployer000000000000000000000000000000"

	db := &mockDB{
		visMap: VisibilityMap{
			deployerAddr: VisibilityRedacted,
		},
	}
	engine := NewRedactionEngine(nil, db, rbac.ReadProfileStandard)

	txs := []Transaction{
		{
			Hash: "0xdeploy1",
			From: deployerAddr,
			To:   nil,
		},
	}

	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:eve")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected contract creation from redacted deployer to be dropped, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// visible_to_grant label tests
// ---------------------------------------------------------------------------

func TestRedactTransactions_VisibleToGrant_SetsMetadata(t *testing.T) {
	// A tx is in VisibleTxHashes and the from address is Hidden.
	// The viewer is NOT a participant but has the visibleTo grant.
	// Expected: metadata for the from address is "visible_to_grant".
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{alice: VisibilityHidden, bob: VisibilityFull},
		map[string]AddressVisibility{
			alice: {Level: VisibilityHidden, Reason: ReasonNoAccess},
			bob:   {Level: VisibilityFull, Reason: ReasonPublicAddress},
		},
		nil, // no linked addresses — viewer is NOT a participant
	)

	txs := []Transaction{{Hash: "0xabc", From: alice, To: strPtr(bob), Value: "1000"}}
	opts := RedactOpts{VisibleTxHashes: map[string]bool{"0xabc": true}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:viewer", opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	// Alice's address should be revealed (visibleTo upgrade)
	if result[0].From != alice {
		t.Errorf("expected From=%s (visibleTo override), got %s", alice, result[0].From)
	}
	// Alice's metadata should be visible_to_grant
	if result[0].AddressMetadata[alice] != ReasonVisibleToGrant {
		t.Errorf("expected visible_to_grant for alice, got %q", result[0].AddressMetadata[alice])
	}
	// Bob's metadata should be public_address (from DB)
	if result[0].AddressMetadata[bob] != ReasonPublicAddress {
		t.Errorf("expected public_address for bob, got %q", result[0].AddressMetadata[bob])
	}
}

func TestRedactTransactions_VisibleToGrant_ParticipantTakesPrecedence(t *testing.T) {
	// Viewer is both a participant (sender) AND tx is in VisibleTxHashes.
	// participant_override should take precedence over visible_to_grant.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{alice: VisibilityFull, bob: VisibilityHidden},
		map[string]AddressVisibility{
			alice: {Level: VisibilityFull, Reason: ReasonOwnAddress},
			bob:   {Level: VisibilityHidden, Reason: ReasonNoAccess},
		},
		[]string{alice}, // alice is the viewer's linked address
	)

	txs := []Transaction{{Hash: "0xabc", From: alice, To: strPtr(bob), Value: "1000"}}
	opts := RedactOpts{VisibleTxHashes: map[string]bool{"0xabc": true}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:alice", opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	// Bob's metadata should be participant_override, NOT visible_to_grant
	if result[0].AddressMetadata[bob] != ReasonParticipantOverride {
		t.Errorf("expected participant_override for bob (participant beats visibleTo), got %q", result[0].AddressMetadata[bob])
	}
}

// ---------------------------------------------------------------------------
// G10 fix: non-participant drop tests
// ---------------------------------------------------------------------------

func TestRedactTransactions_G10_NonParticipantContractCallDropped(t *testing.T) {
	// from=Hidden, to=Full(contract), viewer not participant, not visibleTo.
	// G10 says: drop — the RPC layer would return null for this tx.
	sender := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contract := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{sender: VisibilityHidden, contract: VisibilityFull},
		map[string]AddressVisibility{
			sender:   {Level: VisibilityHidden, Reason: ReasonNoAccess},
			contract: {Level: VisibilityFull, Reason: ReasonRBACGroupMember},
		},
		nil, // no linked addresses — viewer is NOT a participant
	)

	txs := []Transaction{{Hash: "0x01", From: sender, To: strPtr(contract), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:outsider")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected tx to be dropped (G10: non-participant, one side hidden), got %d", len(result))
	}
}

func TestRedactTransactions_G10_ParticipantStillSees(t *testing.T) {
	// Same setup as above, but the viewer is the sender → participant → kept.
	sender := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contract := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{sender: VisibilityHidden, contract: VisibilityFull},
		map[string]AddressVisibility{
			sender:   {Level: VisibilityHidden, Reason: ReasonNoAccess},
			contract: {Level: VisibilityFull, Reason: ReasonRBACGroupMember},
		},
		[]string{sender}, // viewer IS the sender
	)

	txs := []Transaction{{Hash: "0x01", From: sender, To: strPtr(contract), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:sender")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (participant keeps it), got %d", len(result))
	}
	if result[0].From != sender {
		t.Errorf("expected From=%s (participant override), got %s", sender, result[0].From)
	}
}

func TestRedactTransactions_G10_VisibleToStillSees(t *testing.T) {
	// Same setup, but tx hash is in VisibleTxHashes → kept.
	sender := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contract := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{sender: VisibilityHidden, contract: VisibilityFull},
		map[string]AddressVisibility{
			sender:   {Level: VisibilityHidden, Reason: ReasonNoAccess},
			contract: {Level: VisibilityFull, Reason: ReasonRBACGroupMember},
		},
		nil, // viewer is NOT a participant
	)

	txs := []Transaction{{Hash: "0x01", From: sender, To: strPtr(contract), Value: "1000"}}
	opts := RedactOpts{VisibleTxHashes: map[string]bool{"0x01": true}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:viewer", opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (visibleTo override keeps it), got %d", len(result))
	}
}

func TestRedactTransactions_G10_BothFullStillVisible(t *testing.T) {
	// Both from and to are Full visibility, viewer is NOT a participant.
	// Both sides are identifiable → tx should NOT be dropped.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{alice: VisibilityFull, bob: VisibilityFull},
		map[string]AddressVisibility{
			alice: {Level: VisibilityFull, Reason: ReasonPublicAddress},
			bob:   {Level: VisibilityFull, Reason: ReasonRBACGroupMember},
		},
		nil, // no linked addresses — viewer is NOT a participant
	)

	txs := []Transaction{{Hash: "0x01", From: alice, To: strPtr(bob), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:outsider")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (both Full, no drop), got %d", len(result))
	}
	if result[0].From != alice {
		t.Errorf("expected From=%s, got %s", alice, result[0].From)
	}
	if *result[0].To != bob {
		t.Errorf("expected To=%s, got %s", bob, *result[0].To)
	}
}

func TestRedactTransactions_G10_CalldataParticipantStillSees(t *testing.T) {
	// Viewer is the ERC20 transfer recipient (in calldata, not tx-level to).
	// from=Hidden, to=contract(Full). Viewer is calldata participant → kept.
	sender := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dave := "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"
	contract := "0xcccccccccccccccccccccccccccccccccccccccc"

	// transfer(address,uint256) selector = 0xa9059cbb, Dave is param 0
	calldata := "0xa9059cbb00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a650000000000000000000000000000000000000000000000056bc75e2d63100000"

	engine := newEngineDetailed(
		VisibilityMap{sender: VisibilityHidden, dave: VisibilityFull, contract: VisibilityFull},
		map[string]AddressVisibility{
			sender:   {Level: VisibilityHidden, Reason: ReasonNoAccess},
			dave:     {Level: VisibilityFull, Reason: ReasonOwnAddress},
			contract: {Level: VisibilityFull, Reason: ReasonRBACGroupMember},
		},
		[]string{dave}, // Dave is the viewer
	)

	contractStr := contract
	txs := []Transaction{{
		Hash:      "0x01",
		From:      sender,
		To:        &contractStr,
		Value:     "1000",
		InputData: calldata,
	}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:dave")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (calldata participant keeps it), got %d", len(result))
	}
	// Sender's address should be revealed via participant override
	if result[0].From != sender {
		t.Errorf("expected From=%s (participant override), got %s", sender, result[0].From)
	}
}

// ---------------------------------------------------------------------------
// Token transfer event access stripping
// ---------------------------------------------------------------------------

func newEngineWithEventAccess(visMap VisibilityMap, eventAccess map[string]bool) *RedactionEngine {
	return &RedactionEngine{readProfile: rbac.ReadProfileStandard, store: nil, db: &mockDB{visMap: visMap, eventAccessMap: eventAccess}}
}

func TestRedactTransactions_TokenTransferStrippedWithoutEventAccess(t *testing.T) {
	contract := "0xcccccccccccccccccccccccccccccccccccccccc"
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	tests := []struct {
		name              string
		eventAccess       map[string]bool
		viewerIsAdmin     bool
		wantTransferCount int
		wantTokenTransfer bool
	}{
		{
			name:              "no event access strips token transfer info",
			eventAccess:       map[string]bool{},
			wantTransferCount: 0,
			wantTokenTransfer: false,
		},
		{
			name:              "with event access keeps token transfer info",
			eventAccess:       map[string]bool{contract: true},
			wantTransferCount: 3,
			wantTokenTransfer: true,
		},
		{
			name:              "admin bypasses event access check",
			eventAccess:       map[string]bool{},
			viewerIsAdmin:     true,
			wantTransferCount: 3,
			wantTokenTransfer: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := newEngineWithEventAccess(VisibilityMap{
				from:     VisibilityFull,
				contract: VisibilityFull,
			}, tt.eventAccess)

			txs := []Transaction{{
				Hash:               "0x01",
				From:               from,
				To:                 strPtr(contract),
				Value:              "1000",
				InputData:          "0xa9059cbb",
				TxCategories:       []string{"contract_call", "token_transfer"},
				TokenTransferCount: 3,
			}}

			var opts []RedactOpts
			if tt.viewerIsAdmin {
				opts = append(opts, RedactOpts{ViewerIsAdmin: true})
			}

			result, err := engine.RedactTransactions(context.Background(), txs, "did:test", opts...)
			if err != nil {
				t.Fatal(err)
			}
			if len(result) != 1 {
				t.Fatalf("expected 1 tx, got %d", len(result))
			}
			if result[0].TokenTransferCount != tt.wantTransferCount {
				t.Errorf("TokenTransferCount = %d, want %d", result[0].TokenTransferCount, tt.wantTransferCount)
			}
			hasTokenTransfer := false
			for _, c := range result[0].TxCategories {
				if c == "token_transfer" {
					hasTokenTransfer = true
				}
			}
			if hasTokenTransfer != tt.wantTokenTransfer {
				t.Errorf("token_transfer in categories = %v, want %v; categories = %v", hasTokenTransfer, tt.wantTokenTransfer, result[0].TxCategories)
			}
		})
	}
}

func TestRedactTransactions_TokenTransferStripped_RestoresContractCall(t *testing.T) {
	// When the only category is "token_transfer" and it gets stripped,
	// "contract_call" should be restored for transactions with a recipient.
	// Note: InputData may already be stripped by the redaction loop, so we
	// only check HasRecipient().
	contract := "0xcccccccccccccccccccccccccccccccccccccccc"
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	engine := newEngineWithEventAccess(VisibilityMap{
		from:     VisibilityFull,
		contract: VisibilityFull,
	}, map[string]bool{})

	txs := []Transaction{{
		Hash:               "0x01",
		From:               from,
		To:                 strPtr(contract),
		Value:              "0",
		TxCategories:       []string{"token_transfer"},
		TokenTransferCount: 1,
	}}

	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if len(result[0].TxCategories) != 1 || result[0].TxCategories[0] != "contract_call" {
		t.Errorf("expected categories=[contract_call], got %v", result[0].TxCategories)
	}
}

func TestRedactTransfers_DroppedWithoutEventAccess(t *testing.T) {
	tokenAddr := "0xcccccccccccccccccccccccccccccccccccccccc"
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	tests := []struct {
		name          string
		eventAccess   map[string]bool
		viewerIsAdmin bool
		wantCount     int
	}{
		{
			name:        "no event access drops transfers",
			eventAccess: map[string]bool{},
			wantCount:   0,
		},
		{
			name:        "with event access keeps transfers",
			eventAccess: map[string]bool{tokenAddr: true},
			wantCount:   1,
		},
		{
			name:          "admin bypasses event access check",
			eventAccess:   map[string]bool{},
			viewerIsAdmin: true,
			wantCount:     1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := newEngineWithEventAccess(VisibilityMap{
				from:      VisibilityFull,
				to:        VisibilityFull,
				tokenAddr: VisibilityFull,
			}, tt.eventAccess)

			transfers := []TokenTransfer{{
				TxHash:       "0x01",
				TokenAddress: tokenAddr,
				From:         from,
				To:           to,
				Value:        "1000",
			}}

			var opts []RedactOpts
			if tt.viewerIsAdmin {
				opts = append(opts, RedactOpts{ViewerIsAdmin: true})
			}

			result, err := engine.RedactTransfers(context.Background(), transfers, "did:test", opts...)
			if err != nil {
				t.Fatal(err)
			}
			if len(result) != tt.wantCount {
				t.Fatalf("expected %d transfers, got %d", tt.wantCount, len(result))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// M15 — Dynamic-payload event drop (security audit follow-up to RD-915)
// ---------------------------------------------------------------------------

// stubDynamicPayloadAllowedResolver returns a fixed allow-map per call.
// Used to drive the M15 opt-out branch on the redactor.
type stubDynamicPayloadAllowedResolver struct {
	allow map[string]bool
}

func (s *stubDynamicPayloadAllowedResolver) Resolve(_ context.Context, _ []string) map[string]bool {
	out := make(map[string]bool, len(s.allow))
	for k, v := range s.allow {
		out[k] = v
	}
	return out
}

// stubVisibleToUnlockResolver returns a fixed unlock map per call.
// Mirrors the RD-874 resolver wired in production for the explorer.
type stubVisibleToUnlockResolver struct {
	unlockable map[string]bool
}

func (s *stubVisibleToUnlockResolver) Resolve(_ context.Context, _ string, _ []string) map[string]bool {
	out := make(map[string]bool, len(s.unlockable))
	for k, v := range s.unlockable {
		out[k] = v
	}
	return out
}

// dynamicEventABI declares an event with one non-indexed `bytes`
// param. Mirrors the bridge / forwarder / smart-wallet patterns that
// pre-M15 could carry foreign-org addresses verbatim past the
// static-slot redactor.
//
// signature: Bridge(address indexed sender, bytes payload)
// topic0    = keccak256("Bridge(address,bytes)")
const dynamicEventABI = `[{"type":"event","name":"Bridge","inputs":[{"name":"sender","type":"address","indexed":true},{"name":"payload","type":"bytes","indexed":false}]}]`

// staticEventABI declares an event with no dynamic non-indexed param —
// the M15 drop must NOT fire here, mirroring the standard ERC-20
// Transfer / Approval shape.
const staticEventABI = `[{"type":"event","name":"Static","inputs":[{"name":"who","type":"address","indexed":true},{"name":"amount","type":"uint256","indexed":false}]}]`

// TestRedactLogs_M15_DynamicPayload_Drops pins the close-by-default
// behaviour: when the emitting contract's ABI declares a dynamic
// non-indexed param (`bytes`, `string`, dynamic array/struct) and no
// opt-out is in effect, the log is dropped for non-admin viewers — even
// when the contract is otherwise fully visible.
func TestRedactLogs_M15_DynamicPayload_Drops(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{addr: dynamicEventABI}})
	// Wildcard event rules so we're not blocked by the deny-all default
	// — we want to assert the M15 gate, not the event-rules check.
	engine.SetEventRuleChecker(&stubEventRuleChecker{
		byAddr: map[string]EventRulesResolution{addr: {Wildcard: true}},
	})
	engine.SetDynamicPayloadAllowedResolver(&stubDynamicPayloadAllowedResolver{
		allow: map[string]bool{}, // no opt-out
	})

	topic := eventTopic0("Bridge(address,bytes)")
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "0x"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("M15: expected 0 logs (dynamic payload, no opt-out), got %d", len(result))
	}
}

// TestRedactLogs_M15_OptOut_Passes confirms the per-contract opt-out
// branch — operators can flip `events_allow_dynamic_payload = true` on
// vetted contracts (ERC-20 `string symbol`, ERC-721 `string name`, etc.)
// and dynamic-payload events pass through.
func TestRedactLogs_M15_OptOut_Passes(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{addr: dynamicEventABI}})
	engine.SetEventRuleChecker(&stubEventRuleChecker{
		byAddr: map[string]EventRulesResolution{addr: {Wildcard: true}},
	})
	engine.SetDynamicPayloadAllowedResolver(&stubDynamicPayloadAllowedResolver{
		allow: map[string]bool{addr: true},
	})

	topic := eventTopic0("Bridge(address,bytes)")
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "0x"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Errorf("M15 opt-out: expected 1 log (opted out), got %d", len(result))
	}
}

// TestRedactLogs_M15_StaticEvent_Unaffected pins that events with no
// dynamic non-indexed params (standard ERC-20 Transfer / Approval
// shape) are NOT subject to the drop gate even without an opt-out.
func TestRedactLogs_M15_StaticEvent_Unaffected(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{addr: staticEventABI}})
	engine.SetEventRuleChecker(&stubEventRuleChecker{
		byAddr: map[string]EventRulesResolution{addr: {Wildcard: true}},
	})
	engine.SetDynamicPayloadAllowedResolver(&stubDynamicPayloadAllowedResolver{
		allow: map[string]bool{}, // no opt-out — irrelevant for static
	})

	topic := eventTopic0("Static(address,uint256)")
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "0x"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Errorf("M15 static: expected 1 log (static event, gate doesn't fire), got %d", len(result))
	}
}

// TestRedactLogs_M15_AdminBypass confirms tier-2 / tier-3 admin viewers
// see dynamic-payload events regardless of the opt-out flag — admin
// already has full access in the contract's owning org. Mirrors the
// rbac.FilterEventLogs isAdminByContract bypass.
func TestRedactLogs_M15_AdminBypass(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{addr: dynamicEventABI}})
	engine.SetEventRuleChecker(&stubEventRuleChecker{
		byAddr: map[string]EventRulesResolution{addr: {Wildcard: true}},
	})
	engine.SetDynamicPayloadAllowedResolver(&stubDynamicPayloadAllowedResolver{
		allow: map[string]bool{}, // no opt-out
	})
	engine.SetAdminContractsResolver(&stubAdminContractsResolver{
		admin: map[string]bool{addr: true},
	})

	topic := eventTopic0("Bridge(address,bytes)")
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "0x"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Errorf("M15 admin bypass: expected 1 log, got %d", len(result))
	}
}

// TestRedactLogs_M15_VisibleToUnlockBypass confirms the RD-874 visibleTo
// unlock branch bypasses M15 — the sender explicitly shared the tx
// with this viewer via visibleTo AND the contract is unlockable, so
// the per-tx unlock returns the log before the M15 gate fires. Pins
// the user-stated invariant: "visibleTo DIDs will still see the event."
func TestRedactLogs_M15_VisibleToUnlockBypass(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	txHash := "0xbridgetx"
	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{addr: dynamicEventABI}})
	engine.SetEventRuleChecker(&stubEventRuleChecker{
		byAddr: map[string]EventRulesResolution{addr: {Wildcard: true}},
	})
	engine.SetDynamicPayloadAllowedResolver(&stubDynamicPayloadAllowedResolver{
		allow: map[string]bool{}, // no opt-out
	})
	engine.SetVisibleToUnlockResolver(&stubVisibleToUnlockResolver{
		unlockable: map[string]bool{addr: true},
	})

	topic := eventTopic0("Bridge(address,bytes)")
	logs := []Log{{ID: 1, Address: addr, TxHash: txHash, Topic0: &topic, Data: "0x"}}
	// The unlock is keyed on the genuine listing (ListedTxHashes, RD-1307);
	// VisibleTxHashes alone (row survival) never unlocks.
	opts := &RedactOpts{VisibleTxHashes: map[string]bool{txHash: true}, ListedTxHashes: map[string]bool{txHash: true}}
	result, err := engine.RedactLogsWithOpts(context.Background(), logs, "did:test", opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Errorf("M15 visibleTo unlock: expected 1 log, got %d", len(result))
	}
	unionOnly := &RedactOpts{VisibleTxHashes: map[string]bool{txHash: true}}
	result, err = engine.RedactLogsWithOpts(context.Background(), logs, "did:test", unionOnly)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("a tx that is only in VisibleTxHashes (e.g. the RD-1009 union) must not unlock: expected 0 logs, got %d", len(result))
	}
}

// TestRedactLogs_M15_NoResolverDisablesGate is the test-ergonomics
// safety net: callers that haven't wired DynamicPayloadAllowedResolver
// see the gate disabled (legacy behaviour). Production startup MUST
// wire it via wireExplorerRedactor (covered by
// TestExplorerRedactorWiring_FullStack).
func TestRedactLogs_M15_NoResolverDisablesGate(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{addr: dynamicEventABI}})
	engine.SetEventRuleChecker(&stubEventRuleChecker{
		byAddr: map[string]EventRulesResolution{addr: {Wildcard: true}},
	})
	// No SetDynamicPayloadAllowedResolver call — allow map stays empty.
	// Without the resolver wired, the close-by-default allow map is
	// still empty so the gate still fires. This documents that the
	// gate is wired on by default — only the per-contract opt-out is
	// gated by resolver presence. Pre-M15 callers explicitly wanting
	// the old behaviour must wire a resolver returning all-true.
	topic := eventTopic0("Bridge(address,bytes)")
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "0x"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("M15 no resolver: expected 0 logs (close-by-default), got %d", len(result))
	}
}

// TestEventHasDynamicNonIndexedParam_TypeMatrix exercises the helper
// directly for the type matrix it must classify correctly.
func TestEventHasDynamicNonIndexedParam_TypeMatrix(t *testing.T) {
	cases := []struct {
		name     string
		abi      string
		sig      string
		expected bool
	}{
		{
			name:     "static_only_ERC20_Transfer",
			abi:      `[{"type":"event","name":"Transfer","inputs":[{"name":"from","type":"address","indexed":true},{"name":"to","type":"address","indexed":true},{"name":"value","type":"uint256","indexed":false}]}]`,
			sig:      "Transfer(address,address,uint256)",
			expected: false,
		},
		{
			name:     "non_indexed_bytes",
			abi:      `[{"type":"event","name":"E","inputs":[{"name":"a","type":"address","indexed":true},{"name":"b","type":"bytes","indexed":false}]}]`,
			sig:      "E(address,bytes)",
			expected: true,
		},
		{
			name:     "non_indexed_string",
			abi:      `[{"type":"event","name":"E","inputs":[{"name":"a","type":"string","indexed":false}]}]`,
			sig:      "E(string)",
			expected: true,
		},
		{
			name:     "non_indexed_dynamic_array",
			abi:      `[{"type":"event","name":"E","inputs":[{"name":"a","type":"uint256[]","indexed":false}]}]`,
			sig:      "E(uint256[])",
			expected: true,
		},
		{
			name:     "indexed_bytes_does_not_count",
			abi:      `[{"type":"event","name":"E","inputs":[{"name":"a","type":"bytes","indexed":true}]}]`,
			sig:      "E(bytes)",
			expected: false,
		},
		{
			name:     "fixed_bytes32_is_static",
			abi:      `[{"type":"event","name":"E","inputs":[{"name":"a","type":"bytes32","indexed":false}]}]`,
			sig:      "E(bytes32)",
			expected: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			topic := eventTopic0(tc.sig)
			got := eventHasDynamicNonIndexedParam([]byte(tc.abi), topic)
			if got != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}

// countingUnlockResolver counts Resolve calls (per-request DB cost).
type countingUnlockResolver struct {
	calls      int
	unlockable map[string]bool
}

func (c *countingUnlockResolver) Resolve(_ context.Context, _ string, _ []string) map[string]bool {
	c.calls++
	return c.unlockable
}

// TestRedactLogs_UnlockResolverSkippedWithoutListing (RD-1300): the unlock
// can only fire on a tx the viewer is listed on, so the eligibility resolver
// (several DB lookups) is not consulted for a page with no listed tx.
func TestRedactLogs_UnlockResolverSkippedWithoutListing(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{addr: VisibilityFull})
	engine.SetEventRuleChecker(&stubEventRuleChecker{byAddr: map[string]EventRulesResolution{addr: {Wildcard: true}}})
	resolver := &countingUnlockResolver{unlockable: map[string]bool{addr: true}}
	engine.SetVisibleToUnlockResolver(resolver)
	topic := eventTopic0("Ping()")
	logs := []Log{{ID: 1, Address: addr, TxHash: "0xtx", Topic0: &topic, Data: "0x"}}

	if _, err := engine.RedactLogsWithOpts(context.Background(), logs, "did:test", &RedactOpts{VisibleTxHashes: map[string]bool{"0xtx": true}}); err != nil {
		t.Fatal(err)
	}
	if resolver.calls != 0 {
		t.Fatalf("no listed tx: the unlock resolver must not be consulted, got %d calls", resolver.calls)
	}
	if _, err := engine.RedactLogsWithOpts(context.Background(), logs, "did:test", &RedactOpts{ListedTxHashes: map[string]bool{"0xtx": true}}); err != nil {
		t.Fatal(err)
	}
	if resolver.calls != 1 {
		t.Fatalf("listed tx: the unlock resolver must be consulted once, got %d calls", resolver.calls)
	}
}

// countingABIResolver counts Resolve calls per address.
type countingABIResolver struct {
	byAddr map[string]string
	calls  map[string]int
}

func (c *countingABIResolver) Resolve(_ context.Context, address string) string {
	a := strings.ToLower(address)
	c.calls[a]++
	return c.byAddr[a]
}

// TestRedactLogs_ABIResolvedOncePerEmitter (RD-1300): resolving the ABI and M15
// facts for every candidate log costs one ABI lookup per emitter per call —
// including an emitter that has no ABI — however many logs it emitted.
func TestRedactLogs_ABIResolvedOncePerEmitter(t *testing.T) {
	withABI := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	noABI := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{withABI: VisibilityFull, noABI: VisibilityFull})
	resolver := &countingABIResolver{byAddr: map[string]string{withABI: testEventABI}, calls: map[string]int{}}
	engine.SetABIResolver(resolver)
	engine.SetEventRuleChecker(&stubEventRuleChecker{byAddr: map[string]EventRulesResolution{
		withABI: {Wildcard: true}, noABI: {Wildcard: true},
	}})
	engine.SetAdminContractsResolver(&stubAdminContractsResolver{admin: map[string]bool{noABI: true}})
	topic := eventTopic0("Transfer(address,address,uint256)")
	data := "0x" + strings.Repeat("0", 63) + "1"
	var logs []Log
	for i := 0; i < 3; i++ {
		logs = append(logs,
			Log{ID: int64(2 * i), Address: withABI, TxHash: "0xtx", Topic0: &topic, Data: data},
			Log{ID: int64(2*i + 1), Address: noABI, TxHash: "0xtx", Topic0: &topic, Data: data},
		)
	}
	if _, err := engine.RedactLogs(context.Background(), logs, "did:test"); err != nil {
		t.Fatal(err)
	}
	if resolver.calls[withABI] != 1 || resolver.calls[noABI] != 1 {
		t.Fatalf("ABI lookups per emitter: %v, want exactly 1 each", resolver.calls)
	}
}
