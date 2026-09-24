package nodeapproval

import (
	"slices"
	"testing"
	"time"
)

// offlineLanes is a service whose lanes have no connection: enough for the retention store and
// the lanes' bookkeeping, which never touch the network.
func offlineLanes(retainMax int, targets ...string) (*Service, []*lane) {
	s := &Service{metrics: newDeliveryMetrics()}
	s.retain = newRetention(retainMax, s.metrics)
	for i, target := range targets {
		s.lanes = append(s.lanes, &lane{s: s, target: target, index: i, maxInFlight: 1, wake: make(chan struct{}, 1)})
	}
	s.retain.lanes = s.lanes
	return s, s.lanes
}

func seqs(entries ...*entry) []uint64 {
	var out []uint64
	for _, e := range entries {
		if e == nil {
			out = append(out, 0)
		} else {
			out = append(out, e.seq)
		}
	}
	return out
}

func TestRetentionEvictsOldestFirstAndCountsWhatALaneLost(t *testing.T) {
	s, lanes := offlineLanes(64, "sent", "behind")
	sent, behind := lanes[0], lanes[1]
	r, now := s.retain, time.Now()
	r.add(signedBatch(t, time.Minute, txHashes(1, 32)...), now)
	r.add(signedBatch(t, time.Minute, txHashes(101, 32)...), now)
	first, _ := r.takeFresh(sent, now)
	second, _ := r.takeFresh(sent, now)
	if got := seqs(first, second); !slices.Equal(got, []uint64{1, 2}) {
		t.Fatalf("fresh batches in the order %v", got)
	}
	r.add(signedBatch(t, time.Minute, txHashes(201, 32)...), now)
	if got := value(t, s.metrics.evicted); got != 32 {
		t.Fatalf("%v approvals evicted", got)
	}
	if got := value(t, s.metrics.retained); got != 64 {
		t.Fatalf("%v approvals retained", got)
	}
	// Evicting a batch the lane already took costs it nothing; one it never took is lost to it.
	if got := value(t, s.metrics.dropped.WithLabelValues("sent", dropEvicted)); got != 0 {
		t.Fatalf("the lane that sent the batch lost %v approvals", got)
	}
	if got := value(t, s.metrics.dropped.WithLabelValues("behind", dropEvicted)); got != 32 {
		t.Fatalf("the lane behind lost %v approvals, want 32", got)
	}
	next, _ := r.takeFresh(behind, now)
	if next == nil || next.seq != 2 {
		t.Fatalf("the lane behind resumes at %v, want the oldest batch still retained", seqs(next))
	}
}

func TestRetentionForgetsExpiredBatches(t *testing.T) {
	s, lanes := offlineLanes(defaultRetainMax, "producer")
	r, now := s.retain, time.Now()
	r.add(signedBatch(t, 100*time.Millisecond, txHashes(1, 1)...), now)
	r.add(signedBatch(t, time.Minute, txHashes(2, 1)...), now)
	e, _ := r.takeFresh(lanes[0], now.Add(200*time.Millisecond))
	if e == nil || e.seq != 2 {
		t.Fatalf("took %v; the expired batch must not be handed out", seqs(e))
	}
	if got := value(t, s.metrics.dropped.WithLabelValues("producer", dropExpired)); got != 1 {
		t.Fatalf("%v approvals counted expired", got)
	}
	if got := value(t, s.metrics.retained); got != 1 {
		t.Fatalf("%v approvals retained", got)
	}
}

// A redelivery covers what the lane had sent, newest first, and skips what is gone meanwhile.
func TestRedeliveryWalksNewestFirstOverWhatWasSent(t *testing.T) {
	s, lanes := offlineLanes(defaultRetainMax, "producer")
	l, r, now := lanes[0], s.retain, time.Now()
	for i := range 4 {
		r.add(signedBatch(t, time.Minute, txHashes(i*10, 1)...), now)
	}
	for range 3 {
		r.takeFresh(l, now)
	}
	d := r.redelivery(l, now)
	if !d.active || d.next != 3 || d.low != 1 {
		t.Fatalf("redelivery %+v; want batches 3 down to 1", d)
	}
	var got []uint64
	for e := r.redeliver(&d, now); e != nil; e = r.redeliver(&d, now) {
		got = append(got, e.seq)
	}
	if !slices.Equal(got, []uint64{3, 2, 1}) || d.active {
		t.Fatalf("redelivered %v, active %v", got, d.active)
	}
}

func TestLanePicksFreshBatchesBeforeRetriesAndRedelivery(t *testing.T) {
	s, lanes := offlineLanes(defaultRetainMax, "producer")
	l, r, now := lanes[0], s.retain, time.Now()
	for i := range 3 {
		r.add(signedBatch(t, time.Minute, txHashes(i*10, 1)...), now)
	}
	var taken []*entry
	for range 3 {
		e, _ := r.takeFresh(l, now)
		taken = append(taken, e)
	}
	l.retries = []*job{{e: taken[1]}}
	l.redo = r.redelivery(l, now)
	r.add(signedBatch(t, time.Minute, txHashes(99, 1)...), now) // a fresh batch arrives last
	var order []uint64
	for {
		j, _ := l.pickLocked(now)
		if j == nil {
			break
		}
		order = append(order, j.e.seq)
	}
	// Fresh (4), then the retry (2), then the redelivery newest first (3, 2, 1).
	if !slices.Equal(order, []uint64{4, 2, 3, 2, 1}) {
		t.Fatalf("picked %v", order)
	}
}

// A boot id acts only when it is new for the current connection; an answer from an earlier
// connection is ignored, and a second restart restarts the one redelivery instead of adding one.
func TestBootIDsActOncePerConnection(t *testing.T) {
	s, lanes := offlineLanes(defaultRetainMax, "producer")
	l, r, now := lanes[0], s.retain, time.Now()
	for i := range 3 {
		r.add(signedBatch(t, time.Minute, txHashes(i*10, 1)...), now)
		r.takeFresh(l, now)
	}
	l.gen = 2
	l.observeBoot(2, "boot-a")
	if l.boot != "boot-a" || l.redo.active {
		t.Fatalf("the first boot id seen must be learned, not redelivered to: boot %q, redelivery %v", l.boot, l.redo.active)
	}
	l.observeBoot(1, "boot-old") // a late answer from the previous connection
	if l.boot != "boot-a" || l.redo.active {
		t.Fatalf("a stale boot id acted: boot %q, redelivery %v", l.boot, l.redo.active)
	}
	l.observeBoot(2, "boot-b")
	if !l.redo.active || l.redo.next != 3 {
		t.Fatalf("a new boot id did not start the redelivery: %+v", l.redo)
	}
	r.redeliver(&l.redo, now) // batch 3 is on its way
	l.observeBoot(2, "boot-c")
	if !l.redo.active || l.redo.next != 3 {
		t.Fatalf("a second restart must restart the one redelivery from the newest: %+v", l.redo)
	}
	if got := value(t, s.metrics.redeliveries.WithLabelValues("producer")); got != 2 {
		t.Fatalf("%v redeliveries counted", got)
	}
}
