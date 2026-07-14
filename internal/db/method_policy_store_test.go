package db

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"privacy-proxy/internal/rbac"
)

const testPolicyJSON = `{"records":{"payment":{"capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},"remember":{"payer":{"source":"sender","merge":"set_once"}}}],"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},"allow":[{"callerIn":["payer"]}],"onNoRecord":"deny","else":"deny"}]}}}`

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		t.Fatalf("unmarshal a: %v", err)
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		t.Fatalf("unmarshal b: %v", err)
	}
	return reflect.DeepEqual(av, bv)
}

func seedOrgContract(t *testing.T, database *DB, addr string) (orgID, contractID string) {
	t.Helper()
	ctx := context.Background()
	org := &rbac.Organization{ID: uuid.New().String(), Slug: "mp-" + uuid.New().String()[:8], Name: "MP", Settings: map[string]any{}}
	if err := database.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("create org: %v", err)
	}
	c := &rbac.Contract{ID: uuid.New().String(), OrgID: org.ID, Address: addr, Name: "PaymentRegistry", Metadata: map[string]any{}}
	if err := database.CreateContract(ctx, c); err != nil {
		t.Fatalf("create contract: %v", err)
	}
	return org.ID, c.ID
}

// B2: method_policies column round-trips through the store (JSONB reformats, so
// compare semantically), and clears to nil.
func TestMethodPolicies_ColumnRoundTrip(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()
	ctx := context.Background()

	addr := "0xccccccccccccccccccccccccccccccccccccc001"
	orgID, contractID := seedOrgContract(t, database, addr)

	if err := database.UpdateContractMethodPolicies(ctx, contractID, []byte(testPolicyJSON)); err != nil {
		t.Fatalf("save policy: %v", err)
	}
	got, err := database.GetContractByAddress(ctx, orgID, addr)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.MethodPolicies == nil {
		t.Fatalf("policy not persisted")
	}
	if !jsonEqual(t, got.MethodPolicies, []byte(testPolicyJSON)) {
		t.Fatalf("policy mismatch:\n got %s", got.MethodPolicies)
	}

	// clear
	if err := database.UpdateContractMethodPolicies(ctx, contractID, nil); err != nil {
		t.Fatalf("clear policy: %v", err)
	}
	got, _ = database.GetContractByAddress(ctx, orgID, addr)
	if got.MethodPolicies != nil {
		t.Fatalf("policy not cleared: %s", got.MethodPolicies)
	}
}

// B3: outbox enqueue → list → promote → durable rows; org-scoped lookup;
// union idempotency; set-once conflict preserved (poison-detectable); revert
// delete; failure retry bookkeeping.
func TestMethodPolicies_CaptureOutbox(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()
	ctx := context.Background()

	addr := "0xcccccccccccccccccccccccccccccccccccccc02"
	orgID, _ := seedOrgContract(t, database, addr)

	writes := []rbac.CapturedWrite{
		{RecordType: "payment", RecordKey: "PAY-1", Field: "payer", Value: "did:test:alice", Merge: "set_once"},
		{RecordType: "payment", RecordKey: "PAY-1", Field: "payee", Value: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8", Merge: "set_once"},
		{RecordType: "payment", RecordKey: "PAY-1", Field: "audience", Value: "did:test:charlie", Merge: "union"},
	}
	if err := database.EnqueuePendingRecordCaptures(ctx, "0xtx1", orgID, addr, "did:test:alice", writes); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	due, err := database.ListDuePendingRecordCaptures(ctx, 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("list due: n=%d err=%v", len(due), err)
	}
	if err := database.PromoteRecordCapture(ctx, due[0]); err != nil {
		t.Fatalf("promote: %v", err)
	}
	// outbox drained
	due, _ = database.ListDuePendingRecordCaptures(ctx, 10)
	if len(due) != 0 {
		t.Fatalf("outbox not drained: %d", len(due))
	}
	// durable rows present
	caps, err := database.GetRecordCaptures(ctx, orgID, addr, "payment", "PAY-1")
	if err != nil || len(caps) != 3 {
		t.Fatalf("get captures: n=%d err=%v", len(caps), err)
	}

	// C1: cross-org lookup returns nothing
	otherCaps, _ := database.GetRecordCaptures(ctx, uuid.New().String(), addr, "payment", "PAY-1")
	if len(otherCaps) != 0 {
		t.Fatalf("cross-org lookup leaked %d rows", len(otherCaps))
	}

	// union idempotency: re-promote same audience → still one audience row
	if err := database.EnqueuePendingRecordCaptures(ctx, "0xtx1b", orgID, addr, "did:test:alice",
		[]rbac.CapturedWrite{{RecordType: "payment", RecordKey: "PAY-1", Field: "audience", Value: "did:test:charlie", Merge: "union"}}); err != nil {
		t.Fatalf("enqueue dup: %v", err)
	}
	due, _ = database.ListDuePendingRecordCaptures(ctx, 10)
	_ = database.PromoteRecordCapture(ctx, due[0])
	caps, _ = database.GetRecordCaptures(ctx, orgID, addr, "payment", "PAY-1")
	if len(caps) != 3 {
		t.Fatalf("union not idempotent: %d rows", len(caps))
	}

	// set-once conflict from a different sender → both values persist so the
	// evaluator can detect poison (H3).
	if err := database.EnqueuePendingRecordCaptures(ctx, "0xtx2", orgID, addr, "did:test:mallory",
		[]rbac.CapturedWrite{{RecordType: "payment", RecordKey: "PAY-1", Field: "payer", Value: "did:test:mallory", Merge: "set_once"}}); err != nil {
		t.Fatalf("enqueue poison: %v", err)
	}
	due, _ = database.ListDuePendingRecordCaptures(ctx, 10)
	_ = database.PromoteRecordCapture(ctx, due[0])
	caps, _ = database.GetRecordCaptures(ctx, orgID, addr, "payment", "PAY-1")
	payerVals := 0
	for _, c := range caps {
		if c.Field == "payer" {
			payerVals++
		}
	}
	if payerVals != 2 {
		t.Fatalf("expected 2 conflicting set-once payer rows (poison), got %d", payerVals)
	}

	// revert path: enqueue then delete without promoting
	if err := database.EnqueuePendingRecordCaptures(ctx, "0xtx3", orgID, addr, "did:test:alice", writes); err != nil {
		t.Fatalf("enqueue revert: %v", err)
	}
	due, _ = database.ListDuePendingRecordCaptures(ctx, 10)
	if err := database.DeletePendingRecordCapture(ctx, due[0].ID); err != nil {
		t.Fatalf("delete pending: %v", err)
	}
	due, _ = database.ListDuePendingRecordCaptures(ctx, 10)
	if len(due) != 0 {
		t.Fatalf("reverted pending not deleted: %d", len(due))
	}

	// failure bookkeeping: attempt increments, row stays due
	if err := database.EnqueuePendingRecordCaptures(ctx, "0xtx4", orgID, addr, "did:test:alice", writes); err != nil {
		t.Fatalf("enqueue fail: %v", err)
	}
	due, _ = database.ListDuePendingRecordCaptures(ctx, 10)
	if err := database.MarkPendingRecordCaptureFailure(ctx, due[0].ID, "node unreachable"); err != nil {
		t.Fatalf("mark failure: %v", err)
	}
	due, _ = database.ListDuePendingRecordCaptures(ctx, 10)
	if len(due) != 1 || due[0].AttemptCount != 1 {
		t.Fatalf("failure bookkeeping wrong: n=%d attempts=%d", len(due), func() int {
			if len(due) > 0 {
				return due[0].AttemptCount
			}
			return -1
		}())
	}
}
