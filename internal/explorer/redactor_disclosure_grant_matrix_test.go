package explorer

import (
	"context"
	"testing"
)

// This file pins the row-survival and field-rendering matrix for disclosure
// grants documented in /docs/security/privacy-requirements §"Disclosure
// Levels" and §"Row-survival rules per surface".
//
// Source-of-truth columns from the row-survival matrix (lines 189–196 of
// page.mdx) for a grant viewer who is NOT a direct participant and NOT a
// visibleTo recipient:
//
//	Grant level     | Row survives | Counterparty render
//	full            | yes          | real (regulatory subpoena reveal, audit-logged)
//	pseudonymous    | yes          | Address-XXXX  (lens)
//	redacted        | yes          | [PRIVATE]     (proof-of-activity)
//	none (no grant) | no (G10)     | n/a (row dropped)
//
// The same shape applies to all three redactors that render tx/transfer/
// internal-tx rows. We test each (redactor × grant-level) pair, plus the
// participant-override interaction and the GrantFullReveals audit-stat
// emission. Mutation note: removing the matching `case` arm in
// disclosureGrantLevel-driven switches in redactor.go causes the
// corresponding assertion below to fail with a meaningful diff.

// granted is the lower-case address used for the granted target across
// all matrix-conformance tests. Bob in the spec.
const grantedAddr = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// privateCounter is the lower-case address used for the otherwise-private
// counterparty (e.g. an unowned/foreign contract or wallet). Hidden to a
// non-grant viewer.
const privateCounterAddr = "0xcccccccccccccccccccccccccccccccccccccccc"

// viewerLinkedAddr is a third address used for the participant-override
// interaction tests: the viewer's own linked EOA. Participant override
// must trump the grant lens — see RedactTransactions docstring.
const viewerLinkedAddr = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

// expectedRender returns the address string the spec says the redactor
// must render for the granted target at the given grant level.
func expectedGrantedRender(level VisibilityLevel) string {
	switch level {
	case VisibilityFull:
		return grantedAddr
	case VisibilityPseudonymous:
		return GeneratePseudonym(grantedAddr, nil)
	case VisibilityRedacted:
		return "[PRIVATE]"
	default:
		return "[PRIVATE]"
	}
}

// expectedCounterpartyRender returns the address string the spec says the
// redactor must render for the otherwise-private counterparty under a
// grant of the given level. Per the matrix: Full → real, Pseudonymous →
// Address-XXXX, Redacted → [PRIVATE].
func expectedCounterpartyRender(level VisibilityLevel) string {
	switch level {
	case VisibilityFull:
		return privateCounterAddr
	case VisibilityPseudonymous:
		return GeneratePseudonym(privateCounterAddr, nil)
	case VisibilityRedacted:
		return "[PRIVATE]"
	default:
		return "[PRIVATE]"
	}
}

// engineForGrant builds a RedactionEngine where the granted address has
// the supplied grant level + ReasonDisclosureGrant, the counterparty is
// Hidden (no grant), and the viewer has no linked addresses. This is the
// canonical "grant viewer is not a participant" fixture.
func engineForGrant(t *testing.T, level VisibilityLevel) *RedactionEngine {
	t.Helper()
	return newEngineDetailed(
		VisibilityMap{
			grantedAddr:        level,
			privateCounterAddr: VisibilityHidden,
		},
		map[string]AddressVisibility{
			grantedAddr:        {Level: level, Reason: ReasonDisclosureGrant, Visible: true},
			privateCounterAddr: {Level: VisibilityHidden, Reason: ReasonNoAccess, Visible: false},
		},
		nil, // viewer has no linked addresses
	)
}

// ---------------------------------------------------------------------------
// RedactTransactions × {full, pseudonymous, redacted}
// ---------------------------------------------------------------------------

func TestRedactTransactions_FullGrant_RowSurvives_CounterpartyRevealed(t *testing.T) {
	engine := engineForGrant(t, VisibilityFull)
	txs := []Transaction{{Hash: "0x01", From: grantedAddr, To: strPtr(privateCounterAddr), Value: "1000", InputData: "0xaa"}}

	stats := &RedactStats{}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:auditor",
		RedactOpts{Stats: stats})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("Bug A — Full grant must keep the row, got %d (G10 still dropping?)", len(result))
	}
	if result[0].From != expectedGrantedRender(VisibilityFull) {
		t.Errorf("granted target From: expected real address %q, got %q", grantedAddr, result[0].From)
	}
	if result[0].To == nil || *result[0].To != expectedCounterpartyRender(VisibilityFull) {
		t.Errorf("Bug B — counterparty under Full grant must render as real address; got %v", result[0].To)
	}
	if result[0].Value != "1000" {
		t.Errorf("Full-grant row must preserve value, got %q", result[0].Value)
	}
	if stats.GrantFullReveals != 1 {
		t.Errorf("Full-grant counterparty reveal MUST increment audit counter; got %d", stats.GrantFullReveals)
	}
}

func TestRedactTransactions_PseudonymousGrant_RowSurvives_CounterpartyDemoted(t *testing.T) {
	// PR #282 regression check — pseudonymous behaviour MUST stay the
	// same after the Full/Redacted matrix extensions.
	engine := engineForGrant(t, VisibilityPseudonymous)
	txs := []Transaction{{Hash: "0x01", From: grantedAddr, To: strPtr(privateCounterAddr), Value: "1000"}}

	stats := &RedactStats{}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:auditor",
		RedactOpts{Stats: stats})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("Pseudonymous grant must keep the row, got %d", len(result))
	}
	if result[0].From != expectedGrantedRender(VisibilityPseudonymous) {
		t.Errorf("granted target From: expected %q, got %q", GeneratePseudonym(grantedAddr, nil), result[0].From)
	}
	if result[0].To == nil || *result[0].To != expectedCounterpartyRender(VisibilityPseudonymous) {
		t.Errorf("counterparty under pseudonymous lens must render as Address-XXXX; got %v (PR #282 regression?)", result[0].To)
	}
	if result[0].Value != "1000" {
		t.Errorf("Pseudonymous-grant row must preserve value, got %q", result[0].Value)
	}
	if stats.GrantFullReveals != 0 {
		t.Errorf("Pseudonymous grant must NOT count as a Full reveal; got %d", stats.GrantFullReveals)
	}
}

func TestRedactTransactions_RedactedGrant_RowSurvives_CounterpartyPrivate(t *testing.T) {
	engine := engineForGrant(t, VisibilityRedacted)
	txs := []Transaction{{Hash: "0x01", From: grantedAddr, To: strPtr(privateCounterAddr), Value: "1000", InputData: "0xaa"}}

	stats := &RedactStats{}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:auditor",
		RedactOpts{Stats: stats})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("Bug A — Redacted grant must keep the row (proof-of-activity); got %d", len(result))
	}
	if result[0].From != "[PRIVATE]" {
		t.Errorf("Redacted-grant granted target must render as [PRIVATE], got %q", result[0].From)
	}
	if result[0].To == nil || *result[0].To != "[PRIVATE]" {
		t.Errorf("Redacted-grant counterparty must render as [PRIVATE], got %v", result[0].To)
	}
	// Per matrix line 141: value is PRESERVED for redacted-grant rows
	// (timing-only audit explicitly preserves value).
	if result[0].Value != "1000" {
		t.Errorf("Redacted-grant row must preserve value (proof-of-activity audit lens); got %q", result[0].Value)
	}
	// InputData/Error/RevertReason stay stripped — calldata embeds
	// addresses and would defeat the redaction.
	if result[0].InputData != "" {
		t.Errorf("Redacted-grant row must strip InputData, got %q", result[0].InputData)
	}
	if stats.GrantFullReveals != 0 {
		t.Errorf("Redacted grant must NOT count as a Full reveal; got %d", stats.GrantFullReveals)
	}
}

// ---------------------------------------------------------------------------
// RedactTransfers × {full, pseudonymous, redacted}
// ---------------------------------------------------------------------------

func TestRedactTransfers_FullGrant_RowSurvives_CounterpartyRevealed(t *testing.T) {
	engine := engineForGrant(t, VisibilityFull)
	transfers := []TokenTransfer{{TxHash: "0x01", From: grantedAddr, To: privateCounterAddr, Value: "500"}}

	stats := &RedactStats{}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test:auditor",
		RedactOpts{Stats: stats})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("Bug A in RedactTransfers — Full grant must keep the row, got %d", len(result))
	}
	if result[0].From != grantedAddr {
		t.Errorf("granted target From: expected real address, got %q", result[0].From)
	}
	if result[0].To != privateCounterAddr {
		t.Errorf("Bug B in RedactTransfers — Full-grant counterparty must render as real address; got %q", result[0].To)
	}
	if result[0].Value != "500" {
		t.Errorf("Full-grant transfer must preserve value, got %q", result[0].Value)
	}
	if stats.GrantFullReveals != 1 {
		t.Errorf("Full-grant transfer reveal MUST increment audit counter; got %d", stats.GrantFullReveals)
	}
}

func TestRedactTransfers_PseudonymousGrant_RowSurvives_CounterpartyDemoted(t *testing.T) {
	engine := engineForGrant(t, VisibilityPseudonymous)
	transfers := []TokenTransfer{{TxHash: "0x01", From: grantedAddr, To: privateCounterAddr, Value: "500"}}

	stats := &RedactStats{}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test:auditor",
		RedactOpts{Stats: stats})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("Pseudonymous-grant transfer must keep the row, got %d", len(result))
	}
	if result[0].From != GeneratePseudonym(grantedAddr, nil) {
		t.Errorf("granted target: expected pseudonym, got %q", result[0].From)
	}
	if result[0].To != GeneratePseudonym(privateCounterAddr, nil) {
		t.Errorf("counterparty must render as Address-XXXX under pseudonymous lens (PR #282 regression?); got %q", result[0].To)
	}
}

func TestRedactTransfers_RedactedGrant_RowSurvives_CounterpartyPrivate(t *testing.T) {
	engine := engineForGrant(t, VisibilityRedacted)
	transfers := []TokenTransfer{{TxHash: "0x01", From: grantedAddr, To: privateCounterAddr, Value: "500"}}

	stats := &RedactStats{}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test:auditor",
		RedactOpts{Stats: stats})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("Bug A in RedactTransfers — Redacted grant must keep the row (proof-of-activity); got %d", len(result))
	}
	if result[0].From != "[PRIVATE]" {
		t.Errorf("Redacted-grant transfer From must be [PRIVATE], got %q", result[0].From)
	}
	if result[0].To != "[PRIVATE]" {
		t.Errorf("Redacted-grant transfer To must be [PRIVATE], got %q", result[0].To)
	}
	// Per matrix: value preserved for redacted-grant (timing-only audit)
	if result[0].Value != "500" {
		t.Errorf("Redacted-grant transfer must preserve value, got %q", result[0].Value)
	}
}

// ---------------------------------------------------------------------------
// RedactInternalTransactions × {full, pseudonymous, redacted}
// ---------------------------------------------------------------------------

func TestRedactInternalTransactions_FullGrant_RowSurvives_CounterpartyRevealed(t *testing.T) {
	engine := engineForGrant(t, VisibilityFull)
	itxs := []InternalTransaction{{TxHash: "0x01", From: grantedAddr, To: strPtr(privateCounterAddr), Value: "50"}}

	stats := &RedactStats{}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test:auditor",
		RedactOpts{Stats: stats})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("Bug A in RedactInternalTransactions — Full grant must keep the row, got %d", len(result))
	}
	if result[0].From != grantedAddr {
		t.Errorf("granted target From: expected real address, got %q", result[0].From)
	}
	if result[0].To == nil || *result[0].To != privateCounterAddr {
		t.Errorf("Bug B in RedactInternalTransactions — Full-grant counterparty must render as real address; got %v", result[0].To)
	}
	if stats.GrantFullReveals != 1 {
		t.Errorf("Full-grant internal-tx reveal MUST increment audit counter; got %d", stats.GrantFullReveals)
	}
}

func TestRedactInternalTransactions_PseudonymousGrant_RowSurvives_CounterpartyDemoted(t *testing.T) {
	engine := engineForGrant(t, VisibilityPseudonymous)
	itxs := []InternalTransaction{{TxHash: "0x01", From: grantedAddr, To: strPtr(privateCounterAddr), Value: "50"}}

	stats := &RedactStats{}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test:auditor",
		RedactOpts{Stats: stats})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("Pseudonymous-grant internal tx must keep the row, got %d", len(result))
	}
	if result[0].From != GeneratePseudonym(grantedAddr, nil) {
		t.Errorf("expected granted target pseudonym, got %q", result[0].From)
	}
	if result[0].To == nil || *result[0].To != GeneratePseudonym(privateCounterAddr, nil) {
		t.Errorf("internal-tx counterparty must render as Address-XXXX under pseudonymous lens (PR #282 regression?); got %v", result[0].To)
	}
}

func TestRedactInternalTransactions_RedactedGrant_RowSurvives_CounterpartyPrivate(t *testing.T) {
	engine := engineForGrant(t, VisibilityRedacted)
	itxs := []InternalTransaction{{TxHash: "0x01", From: grantedAddr, To: strPtr(privateCounterAddr), Value: "50"}}

	stats := &RedactStats{}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test:auditor",
		RedactOpts{Stats: stats})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("Bug A in RedactInternalTransactions — Redacted grant must keep the row; got %d", len(result))
	}
	if result[0].From != "[PRIVATE]" {
		t.Errorf("Redacted-grant internal-tx From must be [PRIVATE], got %q", result[0].From)
	}
	if result[0].To == nil || *result[0].To != "[PRIVATE]" {
		t.Errorf("Redacted-grant internal-tx To must be [PRIVATE], got %v", result[0].To)
	}
}

// ---------------------------------------------------------------------------
// Participant-override × grant interaction
// ---------------------------------------------------------------------------

// Participant override must win over the grant lens for ALL grant levels:
// when the viewer has their own linked address as a party in the tx, they
// already know the counterparty (their own wallet), so the grant's
// lens has no incremental privacy benefit. The granted party still
// renders at its own visibility level (e.g. pseudonym for a pseudonymous
// grant) but the counterparty is the viewer's own address (real).

func TestRedactTransactions_FullGrant_ParticipantOverrideWins(t *testing.T) {
	// Viewer is `from` (their own EOA), counterparty has Full grant.
	// The grant promotion is moot because participant override already
	// revealed the counterparty.
	engine := newEngineDetailed(
		VisibilityMap{
			viewerLinkedAddr: VisibilityFull,
			grantedAddr:      VisibilityFull,
		},
		map[string]AddressVisibility{
			viewerLinkedAddr: {Level: VisibilityFull, Reason: ReasonOwnAddress},
			grantedAddr:      {Level: VisibilityFull, Reason: ReasonDisclosureGrant},
		},
		[]string{viewerLinkedAddr},
	)
	stats := &RedactStats{}
	txs := []Transaction{{Hash: "0x01", From: viewerLinkedAddr, To: strPtr(grantedAddr), Value: "1"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:eve", RedactOpts{Stats: stats})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("participant must always see their own tx, got %d", len(result))
	}
	if result[0].From != viewerLinkedAddr {
		t.Errorf("viewer's own addr must render as real, got %q", result[0].From)
	}
	if result[0].To == nil || *result[0].To != grantedAddr {
		t.Errorf("granted counterparty must render as real, got %v", result[0].To)
	}
	if stats.GrantFullReveals != 0 {
		t.Errorf("participant-override path must NOT count as grant reveal (no new info disclosed); got %d", stats.GrantFullReveals)
	}
}

func TestRedactTransactions_PseudonymousGrant_ParticipantOverrideWins_NoDemotion(t *testing.T) {
	// Same shape as the Full-grant variant but with the counterparty at
	// Pseudonymous. The participant override means the viewer's own
	// address renders real; the counterparty still renders at its own
	// level (pseudonym). This pins that PR #282's pseudonymous demotion
	// doesn't leak through when participant override is in play (it
	// shouldn't — the gate is keyed on `!viewerIsParticipant`).
	engine := newEngineDetailed(
		VisibilityMap{
			viewerLinkedAddr: VisibilityFull,
			grantedAddr:      VisibilityPseudonymous,
		},
		map[string]AddressVisibility{
			viewerLinkedAddr: {Level: VisibilityFull, Reason: ReasonOwnAddress},
			grantedAddr:      {Level: VisibilityPseudonymous, Reason: ReasonDisclosureGrant},
		},
		[]string{viewerLinkedAddr},
	)
	txs := []Transaction{{Hash: "0x01", From: viewerLinkedAddr, To: strPtr(grantedAddr), Value: "1"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:eve")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("participant must see their own tx, got %d", len(result))
	}
	if result[0].From != viewerLinkedAddr {
		t.Errorf("viewer's own addr must render as real (participant override), got %q", result[0].From)
	}
	// Counterparty stays at its own pseudonym (grant lens doesn't apply
	// since viewer is a direct participant — they know who Bob is).
	if result[0].To == nil || *result[0].To != GeneratePseudonym(grantedAddr, nil) {
		t.Errorf("granted counterparty stays at its own pseudonym, got %v", result[0].To)
	}
}

// ---------------------------------------------------------------------------
// Audit-log assertion: the GrantFullReveals counter fires ONLY for the
// Full case (not for pseudonymous or redacted) and ONLY when the grant
// actually promoted a counterparty above its base. Below we also cover
// the "no reveal" case where both parties have Full grants — the
// counterparty doesn't need promotion, so no audit entry.
// ---------------------------------------------------------------------------

func TestRedactTransactions_FullGrant_NoCounterpartyPromotion_NoAuditFire(t *testing.T) {
	// Both parties are at Full (Bob via grant, public contract Full by
	// nature). Counterparty is already at Full — no promotion needed —
	// so GrantFullReveals must stay at 0.
	publicContract := "0xcccccccccccccccccccccccccccccccccccccccc"
	engine := newEngineDetailed(
		VisibilityMap{
			grantedAddr:    VisibilityFull,
			publicContract: VisibilityFull,
		},
		map[string]AddressVisibility{
			grantedAddr:    {Level: VisibilityFull, Reason: ReasonDisclosureGrant},
			publicContract: {Level: VisibilityFull, Reason: ReasonPublicAddress},
		},
		nil,
	)
	stats := &RedactStats{}
	txs := []Transaction{{Hash: "0x01", From: grantedAddr, To: strPtr(publicContract), Value: "1"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:auditor", RedactOpts{Stats: stats})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if stats.GrantFullReveals != 0 {
		t.Errorf("no counterparty promotion → no audit entry; got %d", stats.GrantFullReveals)
	}
}

// ---------------------------------------------------------------------------
// Matrix-conformance table-driven test — one row per non-trivial cell in
// the row-survival matrix at /docs/security/privacy-requirements
// §"Row-survival rules per surface" × {RedactTransactions, RedactTransfers,
// RedactInternalTransactions}. If someone edits the matrix doc, this test
// is the hand-maintained mirror — update the rows in lock-step.
// ---------------------------------------------------------------------------

type matrixCell struct {
	name        string
	grantLevel  VisibilityLevel
	wantSurvive bool
	wantFrom    string // expected From render for the granted target
	wantTo      string // expected To render for the counterparty
	wantReveals int    // expected GrantFullReveals delta for this row
}

func matrixCells() []matrixCell {
	return []matrixCell{
		{
			name:        "FullGrant_RowSurvives_CounterpartyRevealed",
			grantLevel:  VisibilityFull,
			wantSurvive: true,
			wantFrom:    grantedAddr,
			wantTo:      privateCounterAddr,
			wantReveals: 1,
		},
		{
			name:        "PseudonymousGrant_RowSurvives_CounterpartyDemoted",
			grantLevel:  VisibilityPseudonymous,
			wantSurvive: true,
			wantFrom:    GeneratePseudonym(grantedAddr, nil),
			wantTo:      GeneratePseudonym(privateCounterAddr, nil),
			wantReveals: 0,
		},
		{
			name:        "RedactedGrant_RowSurvives_CounterpartyPrivate",
			grantLevel:  VisibilityRedacted,
			wantSurvive: true,
			wantFrom:    "[PRIVATE]",
			wantTo:      "[PRIVATE]",
			wantReveals: 0,
		},
	}
}

func TestRedactor_DisclosureGrantMatrixConformance(t *testing.T) {
	for _, cell := range matrixCells() {
		cell := cell
		t.Run("Transactions/"+cell.name, func(t *testing.T) {
			engine := engineForGrant(t, cell.grantLevel)
			stats := &RedactStats{}
			txs := []Transaction{{Hash: "0xmatrix", From: grantedAddr, To: strPtr(privateCounterAddr), Value: "1"}}
			out, err := engine.RedactTransactions(context.Background(), txs, "did:test:auditor", RedactOpts{Stats: stats})
			if err != nil {
				t.Fatal(err)
			}
			if cell.wantSurvive && len(out) != 1 {
				t.Fatalf("matrix says row survives, got %d", len(out))
			}
			if !cell.wantSurvive && len(out) != 0 {
				t.Fatalf("matrix says row drops, got %d", len(out))
			}
			if cell.wantSurvive {
				if out[0].From != cell.wantFrom {
					t.Errorf("From: matrix says %q, got %q", cell.wantFrom, out[0].From)
				}
				if out[0].To == nil || *out[0].To != cell.wantTo {
					t.Errorf("To: matrix says %q, got %v", cell.wantTo, out[0].To)
				}
			}
			if stats.GrantFullReveals != cell.wantReveals {
				t.Errorf("GrantFullReveals: matrix says %d, got %d", cell.wantReveals, stats.GrantFullReveals)
			}
		})
		t.Run("Transfers/"+cell.name, func(t *testing.T) {
			engine := engineForGrant(t, cell.grantLevel)
			stats := &RedactStats{}
			transfers := []TokenTransfer{{TxHash: "0xmatrix", From: grantedAddr, To: privateCounterAddr, Value: "1"}}
			out, err := engine.RedactTransfers(context.Background(), transfers, "did:test:auditor", RedactOpts{Stats: stats})
			if err != nil {
				t.Fatal(err)
			}
			if cell.wantSurvive && len(out) != 1 {
				t.Fatalf("matrix says row survives, got %d", len(out))
			}
			if !cell.wantSurvive && len(out) != 0 {
				t.Fatalf("matrix says row drops, got %d", len(out))
			}
			if cell.wantSurvive {
				if out[0].From != cell.wantFrom {
					t.Errorf("transfer From: matrix says %q, got %q", cell.wantFrom, out[0].From)
				}
				if out[0].To != cell.wantTo {
					t.Errorf("transfer To: matrix says %q, got %q", cell.wantTo, out[0].To)
				}
			}
			if stats.GrantFullReveals != cell.wantReveals {
				t.Errorf("transfer GrantFullReveals: matrix says %d, got %d", cell.wantReveals, stats.GrantFullReveals)
			}
		})
		t.Run("InternalTransactions/"+cell.name, func(t *testing.T) {
			engine := engineForGrant(t, cell.grantLevel)
			stats := &RedactStats{}
			itxs := []InternalTransaction{{TxHash: "0xmatrix", From: grantedAddr, To: strPtr(privateCounterAddr), Value: "1"}}
			out, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test:auditor", RedactOpts{Stats: stats})
			if err != nil {
				t.Fatal(err)
			}
			if cell.wantSurvive && len(out) != 1 {
				t.Fatalf("matrix says row survives, got %d", len(out))
			}
			if cell.wantSurvive {
				if out[0].From != cell.wantFrom {
					t.Errorf("internal-tx From: matrix says %q, got %q", cell.wantFrom, out[0].From)
				}
				if out[0].To == nil || *out[0].To != cell.wantTo {
					t.Errorf("internal-tx To: matrix says %q, got %v", cell.wantTo, out[0].To)
				}
			}
			if stats.GrantFullReveals != cell.wantReveals {
				t.Errorf("internal-tx GrantFullReveals: matrix says %d, got %d", cell.wantReveals, stats.GrantFullReveals)
			}
		})
	}
}
