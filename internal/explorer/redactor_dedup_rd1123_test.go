package explorer

import (
	"context"
	"strings"
	"sync"
	"testing"

	"privacy-proxy/internal/rbac"
)

// countingDB wraps the level + reason maps a test wants and counts how many
// times each Database method is invoked. It lets the RD-1123 dedup tests assert
// that each Redact* entry point issues exactly ONE visibility fetch (the
// detailed one) and ONE linked-address fetch per call — never the
// GetBatchVisibility + GetBatchVisibilityDetailed pair the pre-fix code issued.
//
// Behaviour is identical to the production stores in the dimension the redactor
// cares about: GetBatchVisibilityDetailed returns the same Level that
// GetBatchVisibility returns for every address (the real DB invariant the dedup
// relies on — see visibilityMapFromDetailed). The reason is derived the same way
// the package's mockDB derives it, so output comparisons stay faithful.
type countingDB struct {
	mu sync.Mutex

	visMap         VisibilityMap
	detailed       map[string]AddressVisibility
	linkedAddrs    []string
	eventAccessMap map[string]bool

	plainCalls       int
	detailedCalls    int
	linkedCalls      int
	eventAccessCalls int
}

func newCountingDB(visMap VisibilityMap, linkedAddrs []string) *countingDB {
	detailed := make(map[string]AddressVisibility, len(visMap))
	for addr, lvl := range visMap {
		reason := ReasonPublicAddress
		switch lvl {
		case VisibilityFull:
			reason = ReasonPublicAddress
		case VisibilityHidden, VisibilityRedacted:
			reason = ReasonNoAccess
		case VisibilityPseudonymous:
			reason = ReasonDisclosureGrant
		}
		detailed[addr] = AddressVisibility{Address: addr, Level: lvl, Reason: reason}
	}
	return &countingDB{visMap: visMap, detailed: detailed, linkedAddrs: linkedAddrs}
}

func (c *countingDB) GetBatchVisibility(_ context.Context, _ string, _ []string) (VisibilityMap, error) {
	c.mu.Lock()
	c.plainCalls++
	c.mu.Unlock()
	out := make(VisibilityMap, len(c.visMap))
	for k, v := range c.visMap {
		out[k] = v
	}
	return out, nil
}

func (c *countingDB) GetBatchVisibilityDetailed(_ context.Context, _ string, _ []string) (map[string]AddressVisibility, error) {
	c.mu.Lock()
	c.detailedCalls++
	c.mu.Unlock()
	out := make(map[string]AddressVisibility, len(c.detailed))
	for k, v := range c.detailed {
		out[k] = v
	}
	return out, nil
}

func (c *countingDB) GetLinkedAddresses(_ context.Context, _ string) ([]string, error) {
	c.mu.Lock()
	c.linkedCalls++
	c.mu.Unlock()
	return append([]string(nil), c.linkedAddrs...), nil
}

func (c *countingDB) GetBatchEventAccess(_ context.Context, _ string, addrs []string) (map[string]bool, error) {
	c.mu.Lock()
	c.eventAccessCalls++
	c.mu.Unlock()
	result := make(map[string]bool)
	for _, a := range addrs {
		if c.eventAccessMap[strings.ToLower(a)] {
			result[strings.ToLower(a)] = true
		}
	}
	return result, nil
}

// TestRedactor_RD1123_SingleVisibilityFetchPerCall is the dedup-count assertion.
// It renders the four data feeds that make up a tx-detail page (Overview /
// Internal txns / Transfers / Logs) for the SAME viewer and asserts that each
// Redact* entry point fetches visibility ONCE (the detailed superset) and never
// falls back to the separate GetBatchVisibility query. Pre-fix each of these
// issued GetBatchVisibility + GetBatchVisibilityDetailed (two visibility
// round-trips per call); post-fix it is one.
func TestRedactor_RD1123_SingleVisibilityFetchPerCall(t *testing.T) {
	const viewerDID = "did:viewer:rd1123"
	viewer := "0x1111111111111111111111111111111111111111"
	counterparty := "0x2222222222222222222222222222222222222222"
	contract := "0x3333333333333333333333333333333333333333"

	visMap := VisibilityMap{
		viewer:       VisibilityFull,
		counterparty: VisibilityFull,
		contract:     VisibilityFull,
	}

	db := newCountingDB(visMap, []string{viewer})
	engine := &RedactionEngine{readProfile: rbac.ReadProfileStandard, store: nil, db: db}

	ctx := context.Background()

	// Overview feed → RedactTransactions.
	if _, err := engine.RedactTransactions(ctx, []Transaction{
		{Hash: "0xtx", From: viewer, To: strPtr(counterparty), Value: "1000"},
	}, viewerDID); err != nil {
		t.Fatalf("RedactTransactions: %v", err)
	}
	// Internal txns feed → RedactInternalTransactions.
	if _, err := engine.RedactInternalTransactions(ctx, []InternalTransaction{
		{ID: 1, TxHash: "0xtx", From: viewer, To: strPtr(counterparty), Value: "1"},
	}, viewerDID); err != nil {
		t.Fatalf("RedactInternalTransactions: %v", err)
	}
	// Transfers feed → RedactTransfers.
	if _, err := engine.RedactTransfers(ctx, []TokenTransfer{
		{ID: 1, TxHash: "0xtx", TokenAddress: contract, From: viewer, To: counterparty, Value: "5"},
	}, viewerDID); err != nil {
		t.Fatalf("RedactTransfers: %v", err)
	}
	// Logs feed → RedactLogs.
	tr := eventTopic0("Transfer(address,address,uint256)")
	if _, err := engine.RedactLogs(ctx, []Log{
		{ID: 1, Address: contract, TxHash: "0xtx", Topic0: &tr, Data: "0x"},
	}, viewerDID); err != nil {
		t.Fatalf("RedactLogs: %v", err)
	}

	// Four Redact* calls, each must fetch the detailed visibility map exactly
	// once and never the plain GetBatchVisibility.
	if db.plainCalls != 0 {
		t.Errorf("GetBatchVisibility called %d times; want 0 (detailed map is the single source, RD-1123)", db.plainCalls)
	}
	if db.detailedCalls != 4 {
		t.Errorf("GetBatchVisibilityDetailed called %d times; want 4 (one per Redact* call)", db.detailedCalls)
	}
	// Linked addresses: one fetch per Redact* call. This is already once-per-call
	// pre-fix (the 3-4x in the issue is across the four SEPARATE HTTP requests
	// that compose the page, not within a single call); the assertion guards
	// against a regression that would re-introduce a per-call duplicate.
	if db.linkedCalls != 4 {
		t.Errorf("GetLinkedAddresses called %d times; want 4 (one per Redact* call)", db.linkedCalls)
	}
}

// TestRedactor_RD1123_LogsSingleFetchAcrossPhases asserts that RedactLogs — the
// most query-heavy entry point, with three visibility-resolution phases
// (emitting contracts, topic-embedded addresses, ABI data addresses) — issues
// exactly one visibility fetch per phase that needs one, and never the separate
// GetBatchVisibility. With a single visible contract and no extra embedded
// addresses, only Phase 1 runs ⇒ exactly one detailed fetch, zero plain fetches.
func TestRedactor_RD1123_LogsSingleFetchAcrossPhases(t *testing.T) {
	const viewerDID = "did:viewer:rd1123logs"
	contract := "0x4444444444444444444444444444444444444444"
	visMap := VisibilityMap{contract: VisibilityFull}

	db := newCountingDB(visMap, nil)
	engine := &RedactionEngine{readProfile: rbac.ReadProfileStandard, store: nil, db: db}

	tr := eventTopic0("Transfer(address,address,uint256)")
	if _, err := engine.RedactLogs(context.Background(), []Log{
		{ID: 1, Address: contract, TxHash: "0xtx", Topic0: &tr, Data: "0x"},
	}, viewerDID); err != nil {
		t.Fatalf("RedactLogs: %v", err)
	}

	if db.plainCalls != 0 {
		t.Errorf("RedactLogs GetBatchVisibility called %d times; want 0", db.plainCalls)
	}
	if db.detailedCalls != 1 {
		t.Errorf("RedactLogs GetBatchVisibilityDetailed called %d times; want 1 (Phase 1 only for this fixture)", db.detailedCalls)
	}
}

// TestRedactor_RD1123_DedupUsesDetailedLevels is the no-over-disclosure guard.
// It proves the redactor's base-level decisions are driven ENTIRELY by the
// (single) detailed fetch — not by the old separate GetBatchVisibility query.
// We feed a divergentDB whose plain GetBatchVisibility would report Full for a
// counterparty while the detailed map reports Hidden. A correct dedup uses the
// detailed Hidden level and drops the row (G10); a buggy implementation that
// still consulted GetBatchVisibility would leak the counterparty as Full.
//
// In production the two are always equal, so this can't change real behaviour;
// the divergence here exists only to assert which source the redactor reads.
func TestRedactor_RD1123_DedupUsesDetailedLevels(t *testing.T) {
	const viewerDID = "did:viewer:rd1123divergent"
	from := "0x5555555555555555555555555555555555555555"
	to := "0x6666666666666666666666666666666666666666"

	db := &divergentDB{
		// Plain map: would (wrongly) say both Full — the trap.
		plain: VisibilityMap{from: VisibilityFull, to: VisibilityFull},
		// Detailed map: the authoritative source post-dedup. `to` is Hidden.
		detailed: map[string]AddressVisibility{
			from: {Address: from, Level: VisibilityFull, Reason: ReasonPublicAddress},
			to:   {Address: to, Level: VisibilityHidden, Reason: ReasonNoAccess},
		},
	}
	engine := &RedactionEngine{readProfile: rbac.ReadProfileStandard, store: nil, db: db}

	// Viewer is NOT a participant (no linked addresses) → G10 applies: a row
	// with one Hidden side must be dropped. This only happens if the redactor
	// read the detailed (Hidden) level for `to`.
	out, err := engine.RedactTransactions(context.Background(), []Transaction{
		{Hash: "0xtx", From: from, To: strPtr(to), Value: "1000"},
	}, viewerDID)
	if err != nil {
		t.Fatalf("RedactTransactions: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected row dropped (detailed says `to` is Hidden, G10); got %d rows — redactor must be reading the stale plain map", len(out))
	}
	if db.plainCalls != 0 {
		t.Errorf("GetBatchVisibility must not be called by RedactTransactions post-dedup; got %d calls", db.plainCalls)
	}
}

// divergentDB deliberately returns DIFFERENT levels from GetBatchVisibility vs
// GetBatchVisibilityDetailed so a test can detect which one the redactor reads.
// Never used to model production (where they agree).
type divergentDB struct {
	plain       VisibilityMap
	detailed    map[string]AddressVisibility
	plainCalls  int
	linkedAddrs []string
}

func (d *divergentDB) GetBatchVisibility(_ context.Context, _ string, _ []string) (VisibilityMap, error) {
	d.plainCalls++
	out := make(VisibilityMap, len(d.plain))
	for k, v := range d.plain {
		out[k] = v
	}
	return out, nil
}

func (d *divergentDB) GetBatchVisibilityDetailed(_ context.Context, _ string, _ []string) (map[string]AddressVisibility, error) {
	out := make(map[string]AddressVisibility, len(d.detailed))
	for k, v := range d.detailed {
		out[k] = v
	}
	return out, nil
}

func (d *divergentDB) GetLinkedAddresses(_ context.Context, _ string) ([]string, error) {
	return append([]string(nil), d.linkedAddrs...), nil
}

func (d *divergentDB) GetBatchEventAccess(_ context.Context, _ string, _ []string) (map[string]bool, error) {
	return map[string]bool{}, nil
}
