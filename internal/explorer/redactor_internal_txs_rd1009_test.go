package explorer

import (
	"context"
	"testing"
)

// TestRedactInternalTransactions_UnionKeepsNoPrivateFrame_RD1009 replaces the
// RD-1009 follow-up pin under which RedactInternalTransactions honoured the
// parent-tx allowlist (VisibleTxHashes), so /transactions/:hash/internal kept
// every frame of a kept parent. RD-1316 narrows that: the transfer-participant union
// keeps the parent row only, and the parent's frames follow the ordinary frame
// rules, like its sibling transfers. A frame with both sides private is
// dropped even when the parent hash is in the union; only a genuine visibleTo
// listing (ListedTxHashes) of the parent keeps and reveals it.
func TestRedactInternalTransactions_UnionKeepsNoPrivateFrame_RD1009(t *testing.T) {
	const sharedTxHash = "0xdeadbeefcafebabe"

	// Internal-tx with both sides hidden to the viewer — the parent tx is in
	// VisibleTxHashes via the transfer-participant union.
	privFrom := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	privTo := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngine(VisibilityMap{
		privFrom: VisibilityHidden,
		privTo:   VisibilityHidden,
	})

	itxs := []InternalTransaction{{
		ID:     1,
		TxHash: sharedTxHash,
		From:   privFrom,
		To:     strPtr(privTo),
		Value:  "500",
	}}

	ctx := context.Background()

	// Union only: the parent row is kept elsewhere, this private frame is not.
	opts := RedactOpts{VisibleTxHashes: map[string]bool{sharedTxHash: true}}
	result, err := engine.RedactInternalTransactions(ctx, itxs, "did:viewer", opts)
	if err != nil {
		t.Fatalf("RedactInternalTransactions: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("RD-1316: the union must not keep a frame with both sides private, got %+v", result)
	}

	// A genuine share (ListedTxHashes) of the parent keeps the frame and
	// reveals its addresses, as before.
	opts.ListedTxHashes = map[string]bool{sharedTxHash: true}
	result, err = engine.RedactInternalTransactions(ctx, itxs, "did:viewer", opts)
	if err != nil {
		t.Fatalf("RedactInternalTransactions (listed): %v", err)
	}
	if len(result) != 1 || result[0].From != privFrom || result[0].To == nil || *result[0].To != privTo {
		t.Errorf("a genuinely shared parent reveals the frame's addresses, got %+v", result)
	}
}

// TestRedactInternalTransactions_NoVisibleTxHashes_StillDrops is the
// negative half: without the parent tx in VisibleTxHashes, the existing
// bothHidden drop continues to fire. Pinning the negative case so a
// future refactor doesn't unconditionally surface all internal txs.
func TestRedactInternalTransactions_NoVisibleTxHashes_StillDrops(t *testing.T) {
	privFrom := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	privTo := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngine(VisibilityMap{
		privFrom: VisibilityHidden,
		privTo:   VisibilityHidden,
	})

	itxs := []InternalTransaction{{
		ID:     1,
		TxHash: "0xunrelated",
		From:   privFrom,
		To:     strPtr(privTo),
		Value:  "500",
	}}

	// Empty VisibleTxHashes — strict-privacy drop should still fire.
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:viewer",
		RedactOpts{})
	if err != nil {
		t.Fatalf("RedactInternalTransactions: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected both-hidden internal tx dropped with no VisibleTxHashes, got %d", len(result))
	}
}
