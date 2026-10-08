package explorer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// RD-1316 verifies parent-row inclusion at the viewer's ordinary address
// visibility. Genuine shares use ListedTxHashes; transfer participation
// uses VisibleTxHashes and retains the existing field-rendering policy.

const (
	rd1316EOA    = "0x1316000000000000000000000000000000000e01" // another org's user EOA (Hidden)
	rd1316Token  = "0x13160000000000000000000000000000000000b1" // another org's token (Redacted)
	rd1316Vault  = "0x13160000000000000000000000000000000000a1" // viewer's org contract (Full)
	rd1316Hash   = "0x1316000000000000000000000000000000000000000000000000000000000001"
	rd1316Input  = "0xa9059cbb00000000000000000000000013160000000000000000000000000000000000a100000000000000000000000000000000000000000000000000000000000003e8"
	rd1316Callee = "0x13160000000000000000000000000000000000c1" // another org's contract reached internally (Redacted)
)

// rd1316DB: detailed visibility map + event access on every token, so the
// final event-access strip of RedactTransfers does not interfere.
type rd1316DB struct {
	detailed    map[string]AddressVisibility
	linkedAddrs []string
}

func (m *rd1316DB) GetBatchVisibility(_ context.Context, _ string, _ []string) (VisibilityMap, error) {
	return visibilityMapFromDetailed(m.detailed), nil
}
func (m *rd1316DB) GetBatchVisibilityDetailed(_ context.Context, _ string, addrs []string) (map[string]AddressVisibility, error) {
	out := make(map[string]AddressVisibility, len(addrs))
	for _, a := range addrs {
		v, ok := m.detailed[strings.ToLower(a)]
		if !ok {
			v = AddressVisibility{Level: VisibilityHidden, Reason: ReasonNoAccess}
		}
		out[strings.ToLower(a)] = v
	}
	return out, nil
}
func (m *rd1316DB) GetLinkedAddresses(_ context.Context, _ string) ([]string, error) {
	return m.linkedAddrs, nil
}
func (m *rd1316DB) GetBatchEventAccess(_ context.Context, _ string, addrs []string) (map[string]bool, error) {
	out := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		out[strings.ToLower(a)] = true
	}
	return out, nil
}

func rd1316Engine(extra map[string]AddressVisibility) *RedactionEngine {
	detailed := map[string]AddressVisibility{
		rd1316EOA:    {Level: VisibilityHidden, Reason: ReasonNoAccess},
		rd1316Token:  {Level: VisibilityRedacted, Reason: ReasonNoAccess},
		rd1316Callee: {Level: VisibilityRedacted, Reason: ReasonNoAccess},
		rd1316Vault:  {Level: VisibilityFull, Reason: ReasonRBACGroupMember, Visible: true},
	}
	for k, v := range extra {
		detailed[k] = v
	}
	return &RedactionEngine{db: &rd1316DB{detailed: detailed}}
}

// unionOpts is what redactOptsFromFilter produces for a hash that is in the
// transfer-participant union only (no tx_visible_to listing).
func unionOpts(admin bool) RedactOpts {
	return RedactOpts{
		VisibleTxHashes:     map[string]bool{rd1316Hash: true},
		ParticipantTxHashes: map[string]bool{rd1316Hash: true},
		ViewerIsAdmin:       admin,
	}
}

func listedOpts() RedactOpts {
	return RedactOpts{
		VisibleTxHashes: map[string]bool{rd1316Hash: true},
		ListedTxHashes:  map[string]bool{rd1316Hash: true},
	}
}

func rd1316Tx() Transaction {
	nonce := uint64(7)
	return Transaction{
		Hash: rd1316Hash, From: rd1316EOA, To: strPtr(rd1316Token),
		Value: "1000", InputData: rd1316Input, Nonce: &nonce,
	}
}

// assertNoIdentity checks that none of the private addresses (default: the
// foreign EOA, token and callee) appears anywhere in v.
func assertNoIdentity(t *testing.T, v any, what string, private ...string) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.ToLower(string(b))
	if len(private) == 0 {
		private = []string{rd1316EOA, rd1316Token, rd1316Callee}
	}
	for _, addr := range private {
		if strings.Contains(body, strings.TrimPrefix(addr, "0x")) {
			t.Errorf("%s: %s revealed through the transfer-participant union (field or addressMetadata key): %s", what, addr, b)
		}
	}
}

func TestRedactTransactions_UnionKeepsRowWithoutRevealing_RD1316(t *testing.T) {
	for _, admin := range []bool{true, false} {
		name := "grant holder"
		if admin {
			name = "org admin"
		}
		t.Run(name, func(t *testing.T) {
			got, err := rd1316Engine(nil).RedactTransactions(context.Background(), []Transaction{rd1316Tx()}, "did:viewer", unionOpts(admin))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("the union must keep the row (RD-1009 coherence), got %d rows", len(got))
			}
			tx := got[0]
			if tx.From != "[PRIVATE]" {
				t.Errorf("From = %q, want [PRIVATE]", tx.From)
			}
			if tx.To == nil || *tx.To != "[PRIVATE]" {
				t.Errorf("To = %v, want [PRIVATE]", tx.To)
			}
			if tx.Nonce != nil {
				t.Errorf("nonce revealed: %d", *tx.Nonce)
			}
			if tx.InputData != "" {
				t.Errorf("calldata revealed: %s", tx.InputData)
			}
			if tx.Value != "" {
				t.Errorf("value revealed: %s", tx.Value)
			}
			assertNoIdentity(t, tx, "tx")
		})
	}
}

func TestRedactTransactions_GenuineListingStillReveals_RD1316(t *testing.T) {
	got, err := rd1316Engine(nil).RedactTransactions(context.Background(), []Transaction{rd1316Tx()}, "did:viewer", listedOpts())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].From != rd1316EOA || got[0].To == nil || *got[0].To != rd1316Token {
		t.Fatalf("a tx the sender shared with the viewer (tx_visible_to) reveals both parties, got %+v", got)
	}
	if got[0].AddressMetadata[rd1316EOA] != ReasonVisibleToGrant {
		t.Errorf("shared counterparty label = %q, want %q", got[0].AddressMetadata[rd1316EOA], ReasonVisibleToGrant)
	}
}

// VisibleTxHashes without ListedTxHashes (a caller that forgets the listings)
// keeps the row but reveals nothing: fail closed.
func TestRedactTransactions_VisibleHashWithoutListing_FailsClosed_RD1316(t *testing.T) {
	got, err := rd1316Engine(nil).RedactTransactions(context.Background(), []Transaction{rd1316Tx()}, "did:viewer",
		RedactOpts{VisibleTxHashes: map[string]bool{rd1316Hash: true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("row survival must hold, got %d", len(got))
	}
	assertNoIdentity(t, got[0], "tx")
}

// The union plays no part in RedactTransfers: the transfer that drove it
// survives on its own (here the admin's G10 exemption), with the sender
// [PRIVATE]. A non-admin whose union was driven by something else gets the
// ordinary G10 drop for this one-side-hidden transfer.
func TestRedactTransfers_UnionKeepsRowWithoutRevealing_RD1316(t *testing.T) {
	transfer := TokenTransfer{TxHash: rd1316Hash, TokenAddress: rd1316Token, From: rd1316EOA, To: rd1316Vault, Value: "1000"}
	got, err := rd1316Engine(nil).RedactTransfers(context.Background(), []TokenTransfer{transfer}, "did:viewer", unionOpts(true))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("the transfer to the admin's org contract must survive, got %d", len(got))
	}
	if got[0].From != "[PRIVATE]" || got[0].To != rd1316Vault {
		t.Errorf("from=%q to=%q, want [PRIVATE] and the admin's contract", got[0].From, got[0].To)
	}
	if got[0].Value != "" {
		t.Errorf("amount revealed next to a private sender: %s", got[0].Value)
	}
	// tokenAddress is public infrastructure on a transfer row (§3.3), so
	// only the sender's identity is checked here.
	assertNoIdentity(t, got[0], "transfer", rd1316EOA)

	got, err = rd1316Engine(nil).RedactTransfers(context.Background(), []TokenTransfer{transfer}, "did:viewer", unionOpts(false))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("the union must not keep a one-side-hidden transfer for a non-admin (G10), got %+v", got)
	}

	got, err = rd1316Engine(nil).RedactTransfers(context.Background(), []TokenTransfer{transfer}, "did:viewer", listedOpts())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].From != rd1316EOA {
		t.Fatalf("control: a genuine share reveals the transfer sender, got %+v", got)
	}
}

// The union is keyed on the parent tx hash, and a tx usually carries more than
// one transfer. Sibling transfers the union did not drive follow the ordinary
// drops: both-hidden for anyone, one-side-hidden (G10) for a non-admin.
func TestRedactTransfers_UnionDoesNotKeepSiblingTransfers_RD1316(t *testing.T) {
	const own = "0x13160000000000000000000000000000000000d1" // the non-admin viewer's wallet
	driverToVault := TokenTransfer{TxHash: rd1316Hash, LogIndex: 0, TokenAddress: rd1316Token, From: rd1316EOA, To: rd1316Vault, Value: "1000"}
	driverToOwn := TokenTransfer{TxHash: rd1316Hash, LogIndex: 1, TokenAddress: rd1316Token, From: rd1316EOA, To: own, Value: "7"}
	bothPrivate := TokenTransfer{TxHash: rd1316Hash, LogIndex: 2, TokenAddress: rd1316Token, From: rd1316EOA, To: rd1316Callee, Value: "5"}

	t.Run("org admin", func(t *testing.T) {
		got, err := rd1316Engine(nil).RedactTransfers(context.Background(), []TokenTransfer{driverToVault, bothPrivate}, "did:viewer", unionOpts(true))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].LogIndex != 0 {
			t.Fatalf("only the transfer into the org contract survives, got %+v", got)
		}
		assertNoIdentity(t, got, "transfers", rd1316EOA, rd1316Callee)
	})

	t.Run("own-address union viewer", func(t *testing.T) {
		engine := rd1316Engine(map[string]AddressVisibility{
			own: {Level: VisibilityFull, Reason: ReasonOwnAddress, Visible: true},
		})
		engine.db.(*rd1316DB).linkedAddrs = []string{own}
		got, err := engine.RedactTransfers(context.Background(), []TokenTransfer{driverToOwn, driverToVault, bothPrivate}, "did:viewer", unionOpts(false))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].LogIndex != 1 || got[0].To != own {
			t.Fatalf("only the viewer's own transfer survives, got %+v", got)
		}
	})
}

// Under ORG_ADMIN_VIEW_USER_TXS the audit view shows a union-kept row's value
// beside a private sender (or deployer), so the reveal is counted for the
// audit log like any other admin-view reveal. Without the flag nothing is
// counted and the value stays cleared.
func TestRedactTransactions_UnionRowUnderAdminView_CountsReveal_RD1316(t *testing.T) {
	deployed := rd1316Callee
	deploy := Transaction{Hash: rd1316Hash, From: rd1316EOA, ContractAddress: &deployed, Value: "42", InputData: "0x6080"}
	cases := []struct {
		name string
		tx   Transaction
		want JSONString
	}{
		{"both sides private", rd1316Tx(), "1000"},
		{"private deployer", deploy, "42"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, flag := range []bool{true, false} {
				stats := &RedactStats{}
				opts := unionOpts(true)
				opts.OrgAdminViewUserTxs = flag
				opts.Stats = stats
				got, err := rd1316Engine(nil).RedactTransactions(context.Background(), []Transaction{tc.tx}, "did:admin", opts)
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != 1 {
					t.Fatalf("flag=%v: the union keeps the row, got %d", flag, len(got))
				}
				assertNoIdentity(t, got[0], "tx")
				wantValue, wantCount := JSONString(""), 0
				if flag {
					wantValue, wantCount = tc.want, 1
				}
				if got[0].Value != wantValue {
					t.Errorf("flag=%v: value = %q, want %q", flag, got[0].Value, wantValue)
				}
				if stats.AdminUserTxsRevealed != wantCount {
					t.Errorf("flag=%v: AdminUserTxsRevealed = %d, want %d", flag, stats.AdminUserTxsRevealed, wantCount)
				}
			}
		})
	}
}

// Same audit rule on the internal frames of a union-kept parent: each frame
// with both sides private is counted when the audit view reveals its value.
func TestRedactInternalTransactions_UnionFramesUnderAdminView_CountsReveal_RD1316(t *testing.T) {
	itxs := []InternalTransaction{
		{TxHash: rd1316Hash, TraceAddress: "0", From: rd1316EOA, To: strPtr(rd1316Token), Value: "3"},
		{TxHash: rd1316Hash, TraceAddress: "0,0", From: rd1316Token, To: strPtr(rd1316Callee), Value: "2"},
		{TxHash: rd1316Hash, TraceAddress: "0,1", From: rd1316Token, To: strPtr(rd1316Vault), Value: "1000"},
	}
	stats := &RedactStats{}
	opts := unionOpts(true)
	opts.OrgAdminViewUserTxs = true
	opts.Stats = stats
	got, err := rd1316Engine(nil).RedactInternalTransactions(context.Background(), itxs, "did:admin", opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(itxs) {
		t.Fatalf("the kept parent's frames survive, got %d of %d", len(got), len(itxs))
	}
	for _, itx := range got {
		assertNoIdentity(t, itx, "internal tx")
	}
	if stats.AdminUserTxsRevealed != 2 {
		t.Errorf("AdminUserTxsRevealed = %d, want 2 (the two frames with both sides private)", stats.AdminUserTxsRevealed)
	}
}

func TestRedactInternalTransactions_UnionKeepsRowWithoutRevealing_RD1316(t *testing.T) {
	itxs := []InternalTransaction{
		{TxHash: rd1316Hash, TraceAddress: "0", From: rd1316EOA, To: strPtr(rd1316Token), Value: "0"},
		{TxHash: rd1316Hash, TraceAddress: "0,0", From: rd1316Token, To: strPtr(rd1316Callee), Value: "0"},
		{TxHash: rd1316Hash, TraceAddress: "0,1", From: rd1316Token, To: strPtr(rd1316Vault), Value: "1000"},
	}
	for _, admin := range []bool{true, false} {
		got, err := rd1316Engine(nil).RedactInternalTransactions(context.Background(), itxs, "did:viewer", unionOpts(admin))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(itxs) {
			t.Fatalf("admin=%v: internal frames of a kept parent tx must survive, got %d of %d", admin, len(got), len(itxs))
		}
		for _, itx := range got {
			assertNoIdentity(t, itx, "internal tx")
		}
		if got[2].To == nil || *got[2].To != rd1316Vault {
			t.Errorf("admin=%v: the viewer's own contract stays visible, got %v", admin, got[2].To)
		}
	}
}

// A Full disclosure grant on the transfer recipient still reveals the
// counterparty — on the transfer row, through the audited counterparty lens,
// not through the union.
func TestRedactTransfers_FullGrantCounterpartyViaLensNotUnion_RD1316(t *testing.T) {
	const grantee = "0x1316000000000000000000000000000000000e02"
	engine := rd1316Engine(map[string]AddressVisibility{
		grantee: {Level: VisibilityFull, Reason: ReasonDisclosureGrant, Visible: true},
	})
	stats := &RedactStats{}
	opts := unionOpts(false)
	opts.Stats = stats
	transfer := TokenTransfer{TxHash: rd1316Hash, TokenAddress: rd1316Token, From: rd1316EOA, To: grantee, Value: "1000"}
	got, err := engine.RedactTransfers(context.Background(), []TokenTransfer{transfer}, "did:auditor", opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].From != rd1316EOA {
		t.Fatalf("a Full grant on the recipient reveals the counterparty, got %+v", got)
	}
	if stats.GrantFullReveals != 1 {
		t.Errorf("the Full-grant reveal must be counted for the audit log, got %d", stats.GrantFullReveals)
	}
	// The lens reveal keeps the counterparty's own reason (§3.7.2): neither
	// "Shared" (no listing) nor "Counterparty" (the viewer took no part).
	if got[0].AddressMetadata[rd1316EOA] != ReasonNoAccess {
		t.Errorf("counterparty label = %q, want its own reason %q", got[0].AddressMetadata[rd1316EOA], ReasonNoAccess)
	}
}
