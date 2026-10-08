package explorer

import (
	"context"
	"testing"
)

// TestCrossRedactorRowSurvival_RD1009 pins the post-fix cross-redactor
// consistency invariant: when a token-transfer survives because one of its
// participants is admin-visible, the parent transaction row must survive too.
// Pre-fix the two redactors evaluated `bothHidden` on different address sets
// (RedactTransactions on tx.from/tx.to where tx.to is the token contract,
// RedactTransfers on transfer.from/transfer.to), so a `wallet → USDC.transfer()`
// tx would be dropped from /transactions while its derived row showed up in
// /transfers — leaking the parent tx hash via TokenTransfer.TxHash anyway.
//
// The fix wires `buildVisibilityFilter` (server side) to union in the affected
// tx hashes via the new `FindTransferParticipantTxs` store method, so they
// flow into RedactOpts.VisibleTxHashes for the redactor. This test mimics
// that wiring at the redactor layer.
//
// MUTATION CHECK: removing the `VisibleTxHashes` entry below (i.e. simulating
// the pre-fix `buildVisibilityFilter`) must flip the assertion to "tx dropped"
// — the bothHidden branch in RedactTransactions kicks in. Re-add the entry
// and the tx survives. Documented in PR description.
func TestCrossRedactorRowSurvival_RD1009(t *testing.T) {
	// Fixture: an EOA wallet calls a token contract (both hidden to the admin
	// viewer). The token-transfer log credits an admin-visible orgmate.
	walletEOA := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tokenContract := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	visibleOrgMate := "0xcccccccccccccccccccccccccccccccccccccccc"

	// Admin viewer has Full visibility ONLY on the org-mate's address. The EOA
	// wallet and the private token contract are Hidden (the bug-trigger shape
	// described in RD-1009).
	visMap := VisibilityMap{
		walletEOA:      VisibilityHidden,
		tokenContract:  VisibilityHidden,
		visibleOrgMate: VisibilityFull,
	}
	engine := newEngine(visMap)

	// The same tx hash appears in both the tx row and its derived transfer row.
	const sharedTxHash = "0xdeadbeefcafebabe"

	txs := []Transaction{{
		Hash:  sharedTxHash,
		From:  walletEOA,
		To:    strPtr(tokenContract),
		Value: "0",
	}}
	transfers := []TokenTransfer{{
		TxHash:       sharedTxHash,
		LogIndex:     0,
		TokenAddress: tokenContract,
		From:         walletEOA,
		To:           visibleOrgMate,
		Value:        "1000",
	}}

	ctx := context.Background()

	// ---- Transfer-side: the row survives because the recipient is visible.
	// (Admin viewer; admin bypasses the per-contract event-access strip at the
	// end of RedactTransfers, which is unrelated to the cross-redactor bug.)
	gotTransfers, err := engine.RedactTransfers(ctx, transfers, "did:admin",
		RedactOpts{ViewerIsAdmin: true})
	if err != nil {
		t.Fatalf("RedactTransfers: %v", err)
	}
	if len(gotTransfers) != 1 {
		t.Fatalf("transfer drop pre-condition broken — expected 1 surviving transfer (recipient visible), got %d", len(gotTransfers))
	}
	// Cross-check that the transfer itself exposes the parent tx hash — this
	// is the privacy argument for the fix: unioning the hash into the tx
	// allowlist reveals nothing the transfer feed didn't already expose.
	if gotTransfers[0].TxHash != sharedTxHash {
		t.Fatalf("transfer row should expose parent tx hash via TokenTransfer.TxHash, got %q", gotTransfers[0].TxHash)
	}

	// Extract the surviving transfer's tx-hash set — this is exactly what
	// /transfers leaks to the viewer via TokenTransfer.TxHash.
	surfacedByTransfers := map[string]bool{}
	for _, t := range gotTransfers {
		surfacedByTransfers[t.TxHash] = true
	}

	// ---- Tx-side WITH the fix wired: buildVisibilityFilter unions the
	// transfer-derived hash into VisibleTxHashes, so RedactTransactions keeps
	// the row. The bothHidden branch is bypassed by the VisibleTxHashes
	// override.
	opts := RedactOpts{
		ViewerIsAdmin:   true,
		VisibleTxHashes: surfacedByTransfers, // <-- the RD-1009 fix wires this
	}
	gotTxs, err := engine.RedactTransactions(ctx, txs, "did:admin", opts)
	if err != nil {
		t.Fatalf("RedactTransactions: %v", err)
	}
	if len(gotTxs) != 1 {
		t.Fatalf("RD-1009 regression: tx dropped while its derived transfer surfaced. "+
			"expected 1 surviving tx (parent of admin-visible transfer), got %d", len(gotTxs))
	}
	if gotTxs[0].Hash != sharedTxHash {
		t.Errorf("wrong tx surfaced: got %q, want %q", gotTxs[0].Hash, sharedTxHash)
	}
	// RD-1316: the union keeps the row but reveals nothing. The transfer row
	// renders the wallet as [PRIVATE] too, so revealing it here would be new
	// disclosure (the pre-RD-1316 "privacy-equivalent" argument was wrong).
	if gotTxs[0].From != "[PRIVATE]" {
		t.Errorf("union-kept tx must not reveal the wallet, got From=%q", gotTxs[0].From)
	}
	if gotTxs[0].To == nil || *gotTxs[0].To != "[PRIVATE]" {
		t.Errorf("union-kept tx must not reveal the token contract, got To=%v", gotTxs[0].To)
	}
	if gotTransfers[0].From != "[PRIVATE]" {
		t.Errorf("the transfer row keeps the wallet private too, got %q", gotTransfers[0].From)
	}

	// ---- Invariant: surviving transfer tx-hashes ⊆ surviving tx hashes.
	// This is the cross-redactor consistency rule the new spec section
	// (REDACTION_SPEC.md §6 "Cross-redactor consistency") makes explicit.
	survivedTxs := map[string]bool{}
	for _, t := range gotTxs {
		survivedTxs[t.Hash] = true
	}
	for h := range surfacedByTransfers {
		if !survivedTxs[h] {
			t.Errorf("cross-redactor inconsistency: tx hash %q surfaced by /transfers but missing from /transactions", h)
		}
	}
}

// TestCrossRedactorRowSurvival_RD1009_FullVisibility is the negative half:
// when both tx sides are publicly visible, no VisibleTxHashes union is needed
// and both feeds carry the row by their normal paths. Pinning the negative
// case so future refactors don't silently change the meaning of the positive
// test by accident.
func TestCrossRedactorRowSurvival_RD1009_FullVisibility(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	token := "0xcccccccccccccccccccccccccccccccccccccccc"

	engine := newEngine(VisibilityMap{
		from:  VisibilityFull,
		to:    VisibilityFull,
		token: VisibilityFull,
	})

	const txHash = "0xfeedfacefeedface"
	txs := []Transaction{{Hash: txHash, From: from, To: strPtr(token), Value: "0"}}
	transfers := []TokenTransfer{{TxHash: txHash, TokenAddress: token, From: from, To: to, Value: "1000"}}

	ctx := context.Background()
	// No VisibleTxHashes — these survive on their own merits. Admin flag set
	// so RedactTransfers skips the per-contract event-access strip (irrelevant
	// to the cross-redactor invariant being pinned here).
	gotTxs, err := engine.RedactTransactions(ctx, txs, "did:viewer",
		RedactOpts{ViewerIsAdmin: true})
	if err != nil {
		t.Fatalf("RedactTransactions: %v", err)
	}
	gotTransfers, err := engine.RedactTransfers(ctx, transfers, "did:viewer",
		RedactOpts{ViewerIsAdmin: true})
	if err != nil {
		t.Fatalf("RedactTransfers: %v", err)
	}
	if len(gotTxs) != 1 {
		t.Errorf("full-visibility tx unexpectedly dropped, got %d", len(gotTxs))
	}
	if len(gotTransfers) != 1 {
		t.Errorf("full-visibility transfer unexpectedly dropped, got %d", len(gotTransfers))
	}
}
