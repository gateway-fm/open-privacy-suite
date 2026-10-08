package explorer

import (
	"context"
	"database/sql"
	"strconv"
	"testing"
)

// The SQL store answers the strict profile's batched lookups with the same rows
// its per-hash getters return, in one query each; unknown hashes are absent.
func TestStore_TxDataBatchResolver(t *testing.T) {
	var _ TxDataBatchResolver = (*Store)(nil)

	dbURL, cleanup := setupTestContainer(t)
	defer cleanup()
	sqlDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()
	setupExplorerSchema(t, sqlDB)
	insertTestFixtures(t, sqlDB)
	setupLogsTableForRD939(t, sqlDB)
	ctx := context.Background()
	for _, l := range []struct {
		tx  string
		idx int
	}{{"0xtx1", 1}, {"0xtx1", 0}, {"0xtx2", 0}, {"0xtx3", 0}} {
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO logs (tx_hash, log_index, address, topic0, data) VALUES ($1, $2, '0xemitter', '0xt0', '0x')`, l.tx, l.idx); err != nil {
			t.Fatalf("insert log: %v", err)
		}
	}

	store, err := NewStore(dbURL)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	logs, err := store.GetLogsByTransactions(ctx, []string{"0xtx1", "0xtx2", "0xunknown"})
	if err != nil {
		t.Fatalf("GetLogsByTransactions: %v", err)
	}
	var got []string
	for _, l := range logs {
		got = append(got, l.TxHash+":"+strconv.Itoa(l.LogIndex))
	}
	want := []string{"0xtx1:0", "0xtx1:1", "0xtx2:0"}
	if len(got) != len(want) {
		t.Fatalf("logs: want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("logs: want %v, got %v", want, got)
		}
	}

	txs, err := store.GetTransactionsByHashes(ctx, []string{"0xtx1", "0xtx3", "0xunknown"})
	if err != nil {
		t.Fatalf("GetTransactionsByHashes: %v", err)
	}
	byHash := make(map[string]Transaction)
	for _, tx := range txs {
		byHash[tx.Hash] = tx
	}
	if len(byHash) != 2 {
		t.Fatalf("transactions: want 0xtx1 and 0xtx3, got %d rows", len(txs))
	}
	for _, h := range []string{"0xtx1", "0xtx3"} {
		single, err := store.GetTransaction(ctx, h)
		if err != nil || single == nil {
			t.Fatalf("GetTransaction(%s): %v", h, err)
		}
		b := byHash[h]
		if b.From != single.From || b.HasRecipient() != single.HasRecipient() || (b.HasRecipient() && *b.To != *single.To) || string(b.Value) != string(single.Value) || (b.Nonce == nil) != (single.Nonce == nil) || (b.Nonce != nil && *b.Nonce != *single.Nonce) {
			t.Fatalf("%s: batched row %+v differs from GetTransaction %+v", h, b, *single)
		}
	}

	if logs, err := store.GetLogsByTransactions(ctx, nil); err != nil || logs != nil {
		t.Fatalf("empty input: want nil, nil; got %v, %v", logs, err)
	}
	if txs, err := store.GetTransactionsByHashes(ctx, nil); err != nil || txs != nil {
		t.Fatalf("empty input: want nil, nil; got %v, %v", txs, err)
	}
}
