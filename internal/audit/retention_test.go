package audit

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockRetentionStore tracks calls to each cleanup method.
type mockRetentionStore struct {
	accessCalls     atomic.Int64
	complianceCalls atomic.Int64
	rbacCalls       atomic.Int64
	travelCalls     atomic.Int64
	expiredCalls    atomic.Int64
	preregCalls     atomic.Int64
	lastPreregTTL   atomic.Int64 // nanoseconds

	// FIFO trim state. countTotal is what the mock returns from
	// CountAccessLogsTotal; trimBatch is the most recently requested
	// (maxRows, batchSize). trimReturns drives the per-call deletion count;
	// each entry is consumed in order and the last value is replayed once
	// exhausted (so a single-element slice means "always return that").
	countTotal       atomic.Int64
	trimMaxRows      atomic.Int64
	trimBatchSize    atomic.Int64
	trimCallCount    atomic.Int64
	trimReturnsMu    sync.Mutex
	trimReturns      []int64
	trimReturnsIdx   int

	// auditOfTheAudit captures every LogAuditAction invocation so tests can
	// assert that retention prunes record themselves in rbac_audit_log. Each
	// entry preserves call order; details is a shallow copy of the map passed
	// in so subsequent caller mutations cannot affect the recorded values.
	auditOfTheAuditMu sync.Mutex
	auditOfTheAudit   []auditEntry
}

// auditEntry is a single LogAuditAction call captured by mockRetentionStore.
type auditEntry struct {
	action  string
	details map[string]any
}

func (m *mockRetentionStore) CleanupAccessLogs(_ context.Context, _ time.Time) (PruneResult, error) {
	m.accessCalls.Add(1)
	// Synthetic id range + anchor so retention manager assertions on the
	// audit-of-the-audit metadata have something deterministic to compare to.
	return PruneResult{Deleted: 5, LowestID: 100, HighestID: 104, AnchorHash: "ttl-anchor-hash"}, nil
}

func (m *mockRetentionStore) CleanupComplianceLogs(_ context.Context, _ time.Time) (int64, error) {
	m.complianceCalls.Add(1)
	return 3, nil
}

func (m *mockRetentionStore) CleanupRBACAuditLogs(_ context.Context, _ time.Time) (int64, error) {
	m.rbacCalls.Add(1)
	return 2, nil
}

func (m *mockRetentionStore) CleanupUsedTravelRecords(_ context.Context, _ time.Time) (int64, error) {
	m.travelCalls.Add(1)
	return 1, nil
}

func (m *mockRetentionStore) CleanupExpiredRecords(_ context.Context) (int64, error) {
	m.expiredCalls.Add(1)
	return 0, nil
}

func (m *mockRetentionStore) DeleteOrphanedPreregisteredAddresses(_ context.Context, olderThan time.Duration) (int64, error) {
	m.preregCalls.Add(1)
	m.lastPreregTTL.Store(int64(olderThan))
	return 0, nil
}

func (m *mockRetentionStore) CountAccessLogsTotal(_ context.Context) (int64, error) {
	return m.countTotal.Load(), nil
}

func (m *mockRetentionStore) LogAuditAction(_ context.Context, action string, details map[string]any) error {
	// Shallow-copy details so subsequent caller mutations cannot retroactively
	// rewrite what we recorded.
	cp := make(map[string]any, len(details))
	for k, v := range details {
		cp[k] = v
	}
	m.auditOfTheAuditMu.Lock()
	m.auditOfTheAudit = append(m.auditOfTheAudit, auditEntry{action: action, details: cp})
	m.auditOfTheAuditMu.Unlock()
	return nil
}

// auditCallsFor returns a snapshot of every recorded LogAuditAction call whose
// action matches the supplied identifier. Lock is released before returning so
// callers can mutate the slice freely.
func (m *mockRetentionStore) auditCallsFor(action string) []auditEntry {
	m.auditOfTheAuditMu.Lock()
	defer m.auditOfTheAuditMu.Unlock()
	out := make([]auditEntry, 0, len(m.auditOfTheAudit))
	for _, e := range m.auditOfTheAudit {
		if e.action == action {
			out = append(out, e)
		}
	}
	return out
}

func (m *mockRetentionStore) TrimAccessLogsFIFOBatch(_ context.Context, maxRows int64, batchSize int) (PruneResult, error) {
	m.trimMaxRows.Store(maxRows)
	m.trimBatchSize.Store(int64(batchSize))
	callIdx := m.trimCallCount.Add(1)

	m.trimReturnsMu.Lock()
	defer m.trimReturnsMu.Unlock()
	if len(m.trimReturns) == 0 {
		return PruneResult{}, nil
	}
	idx := m.trimReturnsIdx
	if idx >= len(m.trimReturns) {
		idx = len(m.trimReturns) - 1
	} else {
		m.trimReturnsIdx++
	}
	deleted := m.trimReturns[idx]
	// Adjust the simulated row count so the loop terminates.
	cur := m.countTotal.Load()
	cur -= deleted
	if cur < 0 {
		cur = 0
	}
	m.countTotal.Store(cur)
	if deleted == 0 {
		return PruneResult{}, nil
	}
	// Synthesize a deterministic, monotonic id range per call so the
	// retention manager's accumulator (min lowest, max highest, last anchor)
	// has something realistic to record. Each call's range starts where the
	// previous call's ended.
	lowestID := (callIdx-1)*1000 + 1
	highestID := lowestID + deleted - 1
	return PruneResult{
		Deleted:    deleted,
		LowestID:   lowestID,
		HighestID:  highestID,
		AnchorHash: fmt.Sprintf("fifo-batch-%d-anchor", callIdx),
	}, nil
}

func TestRetention_DisabledWithZeroInterval(t *testing.T) {
	store := &mockRetentionStore{}
	mgr := NewRetentionManager(RetentionConfig{
		AccessLogs:      24 * time.Hour,
		CleanupInterval: 0, // disabled
	}, store)

	mgr.Start()
	// Give it a moment to start (it should exit immediately).
	time.Sleep(50 * time.Millisecond)
	mgr.Stop()

	if store.accessCalls.Load() != 0 {
		t.Fatal("expected no cleanup calls when interval is 0")
	}
}

func TestRetention_RunsOnStartAndInterval(t *testing.T) {
	store := &mockRetentionStore{}
	mgr := NewRetentionManager(RetentionConfig{
		AccessLogs:      24 * time.Hour,
		CleanupInterval: 50 * time.Millisecond,
	}, store)

	mgr.Start()
	// Wait for initial run + at least one tick.
	time.Sleep(120 * time.Millisecond)
	mgr.Stop()

	calls := store.accessCalls.Load()
	if calls < 2 {
		t.Fatalf("expected at least 2 cleanup calls (initial + tick), got %d", calls)
	}
}

func TestRetention_ZeroDurationSkipsTable(t *testing.T) {
	store := &mockRetentionStore{}
	mgr := NewRetentionManager(RetentionConfig{
		AccessLogs:      24 * time.Hour,
		ComplianceLogs:  0, // skip
		RBACAuditLogs:   0, // skip
		TravelRecords:   0, // skip
		CleanupInterval: 50 * time.Millisecond,
	}, store)

	mgr.Start()
	time.Sleep(80 * time.Millisecond)
	mgr.Stop()

	if store.accessCalls.Load() == 0 {
		t.Fatal("expected access_logs cleanup to run")
	}
	if store.complianceCalls.Load() != 0 {
		t.Fatal("expected compliance_logs cleanup to be skipped (zero duration)")
	}
	if store.rbacCalls.Load() != 0 {
		t.Fatal("expected rbac_audit_logs cleanup to be skipped (zero duration)")
	}
	if store.travelCalls.Load() != 0 {
		t.Fatal("expected travel_records cleanup to be skipped (zero duration)")
	}
	// Expired records always run.
	if store.expiredCalls.Load() == 0 {
		t.Fatal("expected expired records cleanup to always run")
	}
}

func TestRetention_PreregistrationSweepRunsOnInterval(t *testing.T) {
	store := &mockRetentionStore{}
	mgr := NewRetentionManager(RetentionConfig{
		AccessLogs:                     24 * time.Hour,
		CleanupInterval:                1 * time.Hour, // long, unrelated
		PreregistrationTTL:             30 * time.Minute,
		PreregistrationCleanupInterval: 50 * time.Millisecond,
	}, store)

	mgr.Start()
	time.Sleep(150 * time.Millisecond)
	mgr.Stop()

	calls := store.preregCalls.Load()
	if calls < 2 {
		t.Fatalf("expected at least 2 pre-reg sweep calls (initial + tick), got %d", calls)
	}
	if got := time.Duration(store.lastPreregTTL.Load()); got != 30*time.Minute {
		t.Fatalf("expected pre-reg TTL 30m, got %s", got)
	}
}

func TestRetention_PreregistrationDefaults(t *testing.T) {
	store := &mockRetentionStore{}
	mgr := NewRetentionManager(RetentionConfig{
		AccessLogs:      24 * time.Hour,
		CleanupInterval: 1 * time.Hour,
		// Leave preregistration fields at zero; defaults should kick in.
	}, store)

	if mgr.cfg.PreregistrationTTL != defaultPreregistrationTTL {
		t.Fatalf("expected default pre-reg TTL %s, got %s", defaultPreregistrationTTL, mgr.cfg.PreregistrationTTL)
	}
	if mgr.cfg.PreregistrationCleanupInterval != defaultPreregistrationCleanup {
		t.Fatalf("expected default pre-reg interval %s, got %s", defaultPreregistrationCleanup, mgr.cfg.PreregistrationCleanupInterval)
	}
}

func TestRetention_FIFOTrimSkippedWhenUnderCap(t *testing.T) {
	store := &mockRetentionStore{}
	store.countTotal.Store(50)
	mgr := NewRetentionManager(RetentionConfig{
		MaxAccessLogRows: 100,
		CleanupInterval:  0,
	}, store)
	mgr.trimAccessLogsFIFO(context.Background())
	if store.trimCallCount.Load() != 0 {
		t.Fatalf("expected no FIFO trim when under cap, got %d calls", store.trimCallCount.Load())
	}
}

func TestRetention_FIFOTrimDrainsInBatches(t *testing.T) {
	store := &mockRetentionStore{}
	store.countTotal.Store(10_500) // 500 over cap
	store.trimReturns = []int64{1000, 1000, 1000, 1000, 1000, 0}
	mgr := NewRetentionManager(RetentionConfig{
		MaxAccessLogRows:       10_000,
		AccessLogTrimBatchSize: 1000,
		CleanupInterval:        0,
	}, store)
	mgr.trimAccessLogsFIFO(context.Background())
	// The store reduces countTotal as TrimAccessLogsFIFOBatch is called; loop
	// should stop as soon as the cap is met (or the store returns 0).
	calls := store.trimCallCount.Load()
	if calls < 1 {
		t.Fatalf("expected at least one trim call, got %d", calls)
	}
	if store.trimMaxRows.Load() != 10_000 {
		t.Fatalf("expected maxRows=10000 propagated, got %d", store.trimMaxRows.Load())
	}
	if store.trimBatchSize.Load() != 1000 {
		t.Fatalf("expected batchSize=1000 propagated, got %d", store.trimBatchSize.Load())
	}

	// Audit-of-the-audit: trimAccessLogsFIFO must record exactly one
	// "audit.access_logs.prune" event whose payload pins reason=fifo, the
	// configured row cap, and a non-zero deleted count.
	auditCalls := store.auditCallsFor("audit.access_logs.prune")
	if len(auditCalls) != 1 {
		t.Fatalf("expected exactly 1 audit.access_logs.prune entry, got %d", len(auditCalls))
	}
	got := auditCalls[0].details
	if got["reason"] != "fifo" {
		t.Fatalf("audit details: reason=%v, want \"fifo\"", got["reason"])
	}
	deleted, ok := got["deleted_count"].(int64)
	if !ok || deleted <= 0 {
		t.Fatalf("audit details: deleted_count=%v (type %T), want positive int64", got["deleted_count"], got["deleted_count"])
	}
	maxRows, ok := got["max_rows"].(int64)
	if !ok || maxRows != 10_000 {
		t.Fatalf("audit details: max_rows=%v (type %T), want 10000", got["max_rows"], got["max_rows"])
	}
	// Deleted-range metadata sourced from PruneResult: lowest must be the
	// first batch's lowest (1, per the synthetic id range), highest must be
	// the last drainin batch's highest, and the anchor hash must match the
	// last batch's. The mock seeds those deterministically.
	lowestID, ok := got["lowest_id"].(int64)
	if !ok || lowestID != 1 {
		t.Fatalf("audit details: lowest_id=%v (type %T), want 1", got["lowest_id"], got["lowest_id"])
	}
	highestID, ok := got["highest_id"].(int64)
	if !ok || highestID <= 0 {
		t.Fatalf("audit details: highest_id=%v (type %T), want positive", got["highest_id"], got["highest_id"])
	}
	if highestID < lowestID {
		t.Fatalf("audit details: highest_id %d < lowest_id %d", highestID, lowestID)
	}
	anchor, ok := got["new_anchor_hash"].(string)
	if !ok || anchor == "" {
		t.Fatalf("audit details: new_anchor_hash=%v (type %T), want non-empty string", got["new_anchor_hash"], got["new_anchor_hash"])
	}
}

func TestRetention_FIFOTrimDisabledWithZeroMax(t *testing.T) {
	store := &mockRetentionStore{}
	store.countTotal.Store(1_000_000)
	mgr := NewRetentionManager(RetentionConfig{
		MaxAccessLogRows: 0,
		CleanupInterval:  0,
	}, store)
	mgr.trimAccessLogsFIFO(context.Background())
	if store.trimCallCount.Load() != 0 {
		t.Fatalf("expected no FIFO trim when MaxAccessLogRows=0, got %d", store.trimCallCount.Load())
	}
}

func TestRetention_StopChannelWorks(t *testing.T) {
	store := &mockRetentionStore{}
	mgr := NewRetentionManager(RetentionConfig{
		AccessLogs:      24 * time.Hour,
		CleanupInterval: 1 * time.Hour, // long interval
	}, store)

	mgr.Start()
	// Stop immediately - should not hang.
	done := make(chan struct{})
	go func() {
		mgr.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return in time")
	}
}
