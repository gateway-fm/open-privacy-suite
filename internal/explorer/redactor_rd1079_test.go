package explorer

import (
	"context"
	"strings"
	"testing"

	"privacy-proxy/internal/rbac"
)

// rd1079DB is a redactor DB stub exposing a detailed visibility map and
// granting event access for every token contract, so RedactTransfers does not
// strip the row at the final per-contract event-access gate (orthogonal to
// the counterparty-lens behaviour under test).
type rd1079DB struct {
	visMap      VisibilityMap
	detailedMap map[string]AddressVisibility
	linkedAddrs []string
}

func (m *rd1079DB) GetBatchVisibility(_ context.Context, _ string, _ []string) (VisibilityMap, error) {
	return m.visMap, nil
}
func (m *rd1079DB) GetBatchVisibilityDetailed(_ context.Context, _ string, _ []string) (map[string]AddressVisibility, error) {
	return m.detailedMap, nil
}
func (m *rd1079DB) GetLinkedAddresses(_ context.Context, _ string) ([]string, error) {
	return m.linkedAddrs, nil
}
func (m *rd1079DB) GetBatchEventAccess(_ context.Context, _ string, addrs []string) (map[string]bool, error) {
	out := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		out[strings.ToLower(a)] = true
	}
	return out, nil
}

// Reproducer addresses from RD-1079.
const (
	rd1079Charlie = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc" // counterparty, NO grant
	rd1079Eve     = "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc" // grant subject (pseudonymous)
	rd1079Token   = "0xdadddddddddddddddddddddddddddddddddddddd" // private token contract
	rd1079TxHash  = "0x3a933c9aa94f41573fa96fb36a32d6b860f337366d23c4b0f8143b7237da7539"
)

func rd1079Engine() *RedactionEngine {
	return &RedactionEngine{readProfile: rbac.ReadProfileStandard, store: nil, db: &rd1079DB{
		visMap: VisibilityMap{
			rd1079Charlie: VisibilityHidden,
			rd1079Eve:     VisibilityPseudonymous,
			rd1079Token:   VisibilityHidden,
		},
		detailedMap: map[string]AddressVisibility{
			rd1079Charlie: {Level: VisibilityHidden},
			rd1079Eve:     {Level: VisibilityPseudonymous, Reason: ReasonNoAccess, Visible: true},
			rd1079Token:   {Level: VisibilityHidden},
		},
		linkedAddrs: nil, // viewer is NOT a transfer participant
	}}
}

// A pseudonymous recipient does not authorize a nonparticipant transfer.
func TestRedactTransfers_PseudonymousGrant_CounterpartyNotLeaked_RD1079(t *testing.T) {
	engine := rd1079Engine()
	transfers := []TokenTransfer{{
		TxHash:       rd1079TxHash,
		LogIndex:     0,
		TokenAddress: rd1079Token,
		From:         rd1079Charlie,
		To:           rd1079Eve,
		Value:        "100",
	}}

	got, err := engine.RedactTransfers(context.Background(), transfers, "did:test:dave", RedactOpts{})
	if err != nil {
		t.Fatalf("RedactTransfers: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a pseudonymous recipient does not admit an unrelated private sender: %+v", got)
	}

}

// Only a genuine visibleTo share, never the transfer union, reveals a private sender.
func TestRedactTransfers_VisibleToOverride_RevealsCounterparty_RD1079Repro(t *testing.T) {
	engine := rd1079Engine()
	transfers := []TokenTransfer{{
		TxHash:       rd1079TxHash,
		TokenAddress: rd1079Token,
		From:         rd1079Charlie,
		To:           rd1079Eve,
		Value:        "100",
	}}

	got, err := engine.RedactTransfers(context.Background(), transfers, "did:test:dave",
		RedactOpts{VisibleTxHashes: map[string]bool{rd1079TxHash: true}, ListedTxHashes: map[string]bool{rd1079TxHash: true}})
	if err != nil {
		t.Fatalf("RedactTransfers: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].From != rd1079Charlie {
		t.Errorf("a genuine visibleTo share reveals the counterparty in full hex; got %q", got[0].From)
	}

	got, err = engine.RedactTransfers(context.Background(), transfers, "did:test:dave",
		RedactOpts{VisibleTxHashes: map[string]bool{rd1079TxHash: true}})
	if err != nil {
		t.Fatalf("RedactTransfers (union): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a union-only hash must not admit an unrelated private transfer: %+v", got)
	}

}
