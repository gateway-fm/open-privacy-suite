package explorer

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"privacy-proxy/internal/rbac"
)

// countingTxData is a TxDataResolver that counts per-hash lookups.
type countingTxData struct {
	mu     sync.Mutex
	txs    map[string]*Transaction
	logs   map[string][]Log
	perTx  int
	perLog int
}

func (c *countingTxData) GetTransaction(_ context.Context, hash string) (*Transaction, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.perTx++
	return c.txs[strings.ToLower(hash)], nil
}

func (c *countingTxData) GetLogsByTransaction(_ context.Context, hash string) ([]Log, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.perLog++
	return append([]Log(nil), c.logs[strings.ToLower(hash)]...), nil
}

// countingBatchTxData adds the TxDataBatchResolver extension.
type countingBatchTxData struct {
	countingTxData
	batchTxs  int
	batchLogs int
}

func (c *countingBatchTxData) GetTransactionsByHashes(_ context.Context, hashes []string) ([]Transaction, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.batchTxs++
	var out []Transaction
	for _, h := range hashes {
		if tx := c.txs[strings.ToLower(h)]; tx != nil {
			out = append(out, *tx)
		}
	}
	return out, nil
}

func (c *countingBatchTxData) GetLogsByTransactions(_ context.Context, hashes []string) ([]Log, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.batchLogs++
	var out []Log
	for _, h := range hashes {
		out = append(out, c.logs[strings.ToLower(h)]...)
	}
	return out, nil
}

const (
	sbViewer = "0x00000000000000000000000000000000000000a1"
	sbOther  = "0x00000000000000000000000000000000000000b2"
	sbToken  = "0x00000000000000000000000000000000000000c3"
)

func sbHash(i int) string { return fmt.Sprintf("0x%064x", i+1) }

func sbTopic(addr string) *string {
	t := "0x" + strings.Repeat("0", 24) + strings.TrimPrefix(addr, "0x")
	return &t
}

// sbData builds n transactions with one Transfer(other -> viewer) each: one
// transfer row, one log and one parent transaction per hash.
func sbData(n int) ([]TokenTransfer, []InternalTransaction, map[string]*Transaction, map[string][]Log) {
	t0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	var transfers []TokenTransfer
	var itxs []InternalTransaction
	txs := make(map[string]*Transaction)
	logs := make(map[string][]Log)
	for i := 0; i < n; i++ {
		h := sbHash(i)
		to := sbToken
		txs[h] = &Transaction{Hash: h, From: sbViewer, To: &to}
		logs[h] = []Log{{TxHash: h, LogIndex: 0, Address: sbToken, Topic0: &t0, Topic1: sbTopic(sbOther), Topic2: sbTopic(sbViewer), Data: "0x" + strings.Repeat("0", 63) + "1"}}
		transfers = append(transfers, TokenTransfer{TxHash: h, LogIndex: 0, TokenAddress: sbToken, From: sbOther, To: sbViewer, Value: "1"})
		// Two frames per parent: the parent lookup must still be one per hash.
		for f := 0; f < 2; f++ {
			itxs = append(itxs, InternalTransaction{TxHash: h, TraceAddress: fmt.Sprint(f), From: sbToken, To: &to, Value: "0"})
		}
	}
	return transfers, itxs, txs, logs
}

func sbEngine(resolver TxDataResolver) (*RedactionEngine, *countingDB) {
	db := newCountingDB(VisibilityMap{sbViewer: VisibilityFull, sbOther: VisibilityHidden, sbToken: VisibilityFull}, []string{sbViewer})
	engine := NewRedactionEngine(nil, db, rbac.ReadProfileStrict)
	engine.SetTxDataResolver(resolver)
	return engine, db
}

// Under strict, a transfers page costs one log lookup for the whole page (when
// the data source batches) and one log-redaction pass — not a lookup plus a
// full redaction per transaction.
func TestRedactTransfers_Strict_BatchesLogLookups(t *testing.T) {
	const n = 5
	transfers, _, txs, logs := sbData(n)

	batch := &countingBatchTxData{countingTxData: countingTxData{txs: txs, logs: logs}}
	engine, db := sbEngine(batch)
	if _, err := engine.RedactTransfers(context.Background(), transfers, "did:viewer"); err != nil {
		t.Fatal(err)
	}
	if batch.batchLogs != 1 || batch.perLog != 0 {
		t.Fatalf("batch source: want 1 batched log lookup and 0 per-tx lookups, got %d batched, %d per-tx", batch.batchLogs, batch.perLog)
	}
	if db.detailedCalls > 2 {
		t.Fatalf("want at most 2 visibility lookups per page (transfers + one log pass), got %d", db.detailedCalls)
	}

	plain := &countingTxData{txs: txs, logs: logs}
	engine, db = sbEngine(plain)
	if _, err := engine.RedactTransfers(context.Background(), transfers, "did:viewer"); err != nil {
		t.Fatal(err)
	}
	if plain.perLog != n {
		t.Fatalf("per-tx source: want %d log lookups, got %d", n, plain.perLog)
	}
	if db.detailedCalls > 2 {
		t.Fatalf("per-tx source: want one log-redaction pass, got %d visibility lookups", db.detailedCalls)
	}
}

// Under strict, an internal-calls page resolves each distinct parent once, in
// one batched lookup when the data source batches.
func TestRedactInternalTransactions_Strict_BatchesParentLookups(t *testing.T) {
	const n = 3
	_, itxs, txs, logs := sbData(n)

	batch := &countingBatchTxData{countingTxData: countingTxData{txs: txs, logs: logs}}
	engine, _ := sbEngine(batch)
	out, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:viewer")
	if err != nil {
		t.Fatal(err)
	}
	if batch.batchTxs != 1 || batch.perTx != 0 {
		t.Fatalf("batch source: want 1 batched parent lookup and 0 per-tx lookups, got %d batched, %d per-tx", batch.batchTxs, batch.perTx)
	}
	if len(out) != len(itxs) {
		t.Fatalf("viewer is the sender of every parent: want %d frames, got %d", len(itxs), len(out))
	}

	plain := &countingTxData{txs: txs, logs: logs}
	engine, _ = sbEngine(plain)
	if _, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:viewer"); err != nil {
		t.Fatal(err)
	}
	if plain.perTx != n {
		t.Fatalf("per-tx source: want %d parent lookups (one per distinct parent), got %d", n, plain.perTx)
	}
}

// Strict transaction rows omit token-transfer counts and categories.
// The transfers view lists events admitted for the current viewer.
func TestRedactTransactions_Strict_DropsTokenTransferCount(t *testing.T) {
	to := sbToken
	tx := Transaction{Hash: sbHash(0), From: sbViewer, To: &to, TokenTransferCount: 3, TxCategories: []string{"token_transfer"}}
	db := newCountingDB(VisibilityMap{sbViewer: VisibilityFull, sbToken: VisibilityFull}, []string{sbViewer})
	db.eventAccessMap = map[string]bool{sbToken: true}
	engine := NewRedactionEngine(nil, db, rbac.ReadProfileStrict)
	out, err := engine.RedactTransactions(context.Background(), []Transaction{tx}, "did:viewer")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("viewer is the sender: want the row, got %d rows", len(out))
	}
	if out[0].TokenTransferCount != 0 {
		t.Fatalf("strict: want tokenTransferCount 0, got %d", out[0].TokenTransferCount)
	}
	for _, c := range out[0].TxCategories {
		if c == "token_transfer" {
			t.Fatalf("strict: token_transfer category kept: %v", out[0].TxCategories)
		}
	}
}

func TestRedactTransactions_ParticipantFieldsByReadProfile(t *testing.T) {
	cases := []struct {
		name               string
		linked             string
		fromLevel, toLevel VisibilityLevel
		admitted           bool
		standardNonce      bool
	}{
		{"sender", sbOther, VisibilityFull, VisibilityHidden, true, true},
		{"recipient-hidden-sender", sbViewer, VisibilityHidden, VisibilityFull, true, false},
		{"recipient-redacted-sender", sbViewer, VisibilityRedacted, VisibilityFull, true, false},
		{"recipient-pseudonymous-sender", sbViewer, VisibilityPseudonymous, VisibilityFull, true, true},
		{"sender-pseudonymous-recipient", sbOther, VisibilityFull, VisibilityPseudonymous, true, true},
		{"nonparticipant", sbToken, VisibilityHidden, VisibilityFull, false, false},
	}
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		for _, tc := range cases {
			t.Run(profile.String()+"/"+tc.name, func(t *testing.T) {
				nonce := uint64(7)
				to := sbViewer
				tx := Transaction{Hash: sbHash(0), From: sbOther, To: &to, Nonce: &nonce, Value: "42", InputData: "0xabcd"}
				db := newCountingDB(VisibilityMap{sbOther: tc.fromLevel, sbViewer: tc.toLevel}, []string{tc.linked})
				engine := NewRedactionEngine(nil, db, profile)
				out, err := engine.RedactTransactions(context.Background(), []Transaction{tx}, "did:viewer")
				if err != nil {
					t.Fatal(err)
				}
				if !tc.admitted {
					if len(out) != 0 {
						t.Fatalf("nonparticipant must receive no hash, sender, recipient, value, calldata or nonce: got %+v", out)
					}
					return
				}
				if len(out) != 1 {
					t.Fatalf("participant must receive the transaction: got %d rows", len(out))
				}
				got := out[0]
				wantFrom, wantTo := tx.From, to
				if !profile.Strict() {
					if tc.fromLevel == VisibilityPseudonymous {
						wantFrom = engine.applyRedaction(tx.From, tc.fromLevel)
					}
					if tc.toLevel == VisibilityPseudonymous {
						wantTo = engine.applyRedaction(to, tc.toLevel)
					}
				}
				if got.Hash != tx.Hash || got.From != wantFrom || got.To == nil || *got.To != wantTo || got.Value != tx.Value || got.InputData != tx.InputData {
					t.Fatalf("participant fields differ: got %+v, want hash=%s from=%s to=%s value=%s calldata=%s", got, tx.Hash, wantFrom, wantTo, tx.Value, tx.InputData)
				}
				if profile.Strict() || tc.standardNonce {
					if got.Nonce == nil || *got.Nonce != nonce {
						t.Fatalf("participant must receive nonce %d, got %v", nonce, got.Nonce)
					}
				} else if got.Nonce != nil {
					t.Fatalf("standard recipient nonce policy must remain unchanged, got %d", *got.Nonce)
				}
			})
		}
	}
}

func TestRedactTransactions_DeploymentAddressByReadProfile(t *testing.T) {
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		t.Run(profile.String(), func(t *testing.T) {
			created := sbToken
			tx := Transaction{Hash: sbHash(0), From: sbOther, ContractAddress: &created}
			db := newCountingDB(VisibilityMap{sbOther: VisibilityFull, sbToken: VisibilityPseudonymous}, []string{sbOther})
			engine := NewRedactionEngine(nil, db, profile)
			out, err := engine.RedactTransactions(context.Background(), []Transaction{tx}, "did:viewer")
			if err != nil {
				t.Fatal(err)
			}
			if len(out) != 1 || out[0].ContractAddress == nil {
				t.Fatalf("deployer must receive the created contract field: %+v", out)
			}
			want := created
			if !profile.Strict() {
				want = engine.applyRedaction(created, VisibilityPseudonymous)
			}
			if *out[0].ContractAddress != want {
				t.Fatalf("created contract address = %s, want %s", *out[0].ContractAddress, want)
			}
		})
	}
}
