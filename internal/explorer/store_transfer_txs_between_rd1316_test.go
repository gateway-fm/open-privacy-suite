package explorer

import (
	"context"
	"database/sql"
	"testing"
)

// TestFindTransferTxsBetween_RD1316 covers the store query behind the third
// non-admin union driver class: tx hashes with a token transfer whose from and
// to are both in the given side set (the viewer's Full addresses plus the
// public zero address and precompiles), on a token the viewer has event
// access to.
func TestFindTransferTxsBetween_RD1316(t *testing.T) {
	dbURL, cleanup := setupTestContainer(t)
	defer cleanup()
	sqlDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()
	setupExplorerSchema(t, sqlDB)

	const (
		zero   = "0x0000000000000000000000000000000000000000"
		vault  = "0x00000000000000000000000000000000000000a1"
		hidden = "0x00000000000000000000000000000000000000e1"
		token  = "0x00000000000000000000000000000000000000b1"
		token2 = "0x00000000000000000000000000000000000000b2"
	)
	ctx := context.Background()
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count)
		VALUES (7, '0xblock7', '0xparent6', 7000, 21000, 30000000, 5)`); err != nil {
		t.Fatal(err)
	}
	rows := []struct{ hash, token, from, to string }{
		{"0xmint", token, zero, vault},
		{"0xburn", token, vault, zero},
		{"0xbetween", token, vault, "0x00000000000000000000000000000000000000A2"}, // stored mixed-case
		{"0xhiddenside", token, vault, hidden},
		{"0xnoaccess", token2, zero, vault},
	}
	for i, r := range rows {
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status)
			VALUES ($1, 7, $2, $3, $4, 0, 50000, 1000000000, 1)`, r.hash, i, hidden, r.token); err != nil {
			t.Fatal(err)
		}
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
			VALUES ($1, 0, $2, $3, $4, 1, 7)`, r.hash, r.token, r.from, r.to); err != nil {
			t.Fatal(err)
		}
	}

	store, err := NewStore(dbURL)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	got, err := store.FindTransferTxsBetween(ctx, []string{zero, vault, " 0X00000000000000000000000000000000000000A2 "}, []string{token}, nil, 100)
	if err != nil {
		t.Fatalf("FindTransferTxsBetween: %v", err)
	}
	for _, h := range []string{"0xmint", "0xburn", "0xbetween"} {
		if !got[h] {
			t.Errorf("%s: both sides in the set, accessible token — want it, got %v", h, got)
		}
	}
	for _, h := range []string{"0xhiddenside", "0xnoaccess"} {
		if got[h] {
			t.Errorf("%s: a side outside the set, or a token without access — must not match, got %v", h, got)
		}
	}

	for name, args := range map[string][2][]string{
		"no side addresses": {nil, {token}},
		"no tokens":         {{zero, vault}, nil},
	} {
		got, err := store.FindTransferTxsBetween(ctx, args[0], args[1], nil, 100)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != 0 {
			t.Errorf("%s: want empty, got %v", name, got)
		}
	}

	got, err = store.FindTransferTxsBetween(ctx, []string{zero, vault, "0x00000000000000000000000000000000000000a2"}, []string{token}, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("limit caps the result: want 2 of the 3 matches, got %v", got)
	}

	bb := uint64(7)
	got, err = store.FindTransferTxsBetween(ctx, []string{zero, vault}, []string{token}, &bb, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("beforeBlock bounds the scan, got %v", got)
	}
}
