package server

import (
	"context"
	"testing"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// TestReconciler_CapturePromotion drives tickCaptures against a real Postgres
// with a fake receipt checker: a confirmed tx promotes, a reverted tx is
// dropped (no rows planted), an unmined tx is retried.
func TestReconciler_CapturePromotion(t *testing.T) {
	dbURL, cleanup := db.SetupTestContainer(t)
	defer cleanup()
	database, err := db.New(dbURL)
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	defer database.Close()
	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatalf("reset: %v", err)
	}
	ctx := context.Background()

	const org = "11111111-1111-1111-1111-111111111111"
	const contract = "0xcccccccccccccccccccccccccccccccccccccc10"
	writes := []rbac.CapturedWrite{{RecordType: "payment", RecordKey: "PAY-1", Field: "payer", Value: "did:test:alice", Merge: "set_once"}}

	mustEnqueue := func(tx string) {
		if err := database.EnqueuePendingRecordCaptures(ctx, tx, org, contract, "did:test:alice", writes); err != nil {
			t.Fatalf("enqueue %s: %v", tx, err)
		}
	}
	mustEnqueue("0xsuccess")
	mustEnqueue("0xrevert")
	mustEnqueue("0xunmined")

	r := NewVisibilityReconciler(database, DefaultVisibilityReconcilerConfig())
	r.SetReceiptStatus(func(_ context.Context, txHash string) (bool, bool, error) {
		switch txHash {
		case "0xsuccess":
			return true, true, nil
		case "0xrevert":
			return true, false, nil
		default: // 0xunmined
			return false, false, nil
		}
	})

	r.tickCaptures(ctx)

	// success → durable rows present
	caps, err := database.GetRecordCaptures(ctx, org, contract, "payment", "PAY-1")
	if err != nil {
		t.Fatalf("get captures: %v", err)
	}
	if len(caps) != 1 || caps[0].Value != "did:test:alice" {
		t.Fatalf("confirmed tx not promoted: %+v", caps)
	}

	// exactly the unmined row remains in the outbox (success promoted+deleted,
	// revert dropped)
	due, err := database.ListDuePendingRecordCaptures(ctx, 10)
	if err != nil {
		t.Fatalf("list due: %v", err)
	}
	if len(due) != 1 || due[0].TxHash != "0xunmined" {
		t.Fatalf("outbox after tick = %+v, want only 0xunmined", due)
	}
	// A not-yet-mined tx is a normal wait, NOT a failure: it must NOT increment
	// attempt_count, or a slow-to-mine tx would dead-letter at the cap before it
	// lands and permanently deny the record's stakeholders (RD-1206 fix). The row
	// stays due (retried next tick) with attempt_count untouched.
	if due[0].AttemptCount != 0 {
		t.Fatalf("unmined tx must not count toward the dead-letter cap, got attempt_count=%d", due[0].AttemptCount)
	}
}
