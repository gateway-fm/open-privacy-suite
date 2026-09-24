package nodeapproval

import (
	"log/slog"
	"sync"
	"time"
)

// retention keeps every signed batch until it expires, so a producer that restarts gets back what
// it had confirmed (wire contract §4, §5). It is also each lane's queue of fresh batches: a lane
// walks it oldest first with its own cursor, so a slow or unreachable producer holds back neither
// the signer nor another producer, and the cap bounds how far a lane can fall behind.
type retention struct {
	mu        sync.Mutex
	entries   []*entry // oldest first; entries[head:] are retained, with consecutive seq
	head      int
	next      uint64 // seq of the next batch; the first is 1
	approvals int
	max       int
	finished  bool // the signer has stopped: nothing more is added
	lanes     []*lane
	m         *deliveryMetrics
	log       logGate
}

// entry is one retained batch.
type entry struct {
	seq     uint64
	batch   Batch
	expires time.Time // expires_at: producers refuse the batch from then on
	signed  time.Time // when it was retained; delivery latency counts from here
}

func newRetention(max int, m *deliveryMetrics) *retention {
	return &retention{max: max, next: 1, m: m}
}

// add retains a signed batch, evicts the oldest beyond the cap and wakes every lane.
func (r *retention) add(b Batch, now time.Time) {
	r.mu.Lock()
	r.pruneLocked(now)
	r.entries = append(r.entries, &entry{seq: r.next, batch: b, expires: time.UnixMilli(int64(b.ExpiresAt)), signed: now})
	r.next++
	r.approvals += len(b.Approvals)
	for r.approvals > r.max && len(r.entries)-r.head > 1 {
		r.removeLocked(dropEvicted, now)
	}
	r.m.retained.Set(float64(r.approvals))
	lanes := r.lanes
	r.mu.Unlock()
	for _, l := range lanes {
		l.notify()
	}
}

// prune forgets the batches that expired, while nothing new arrives to do it.
func (r *retention) prune(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now)
}

func (r *retention) pruneLocked(now time.Time) {
	for r.head < len(r.entries) && !now.Before(r.entries[r.head].expires) {
		r.removeLocked(dropExpired, now)
	}
	r.m.retained.Set(float64(r.approvals))
}

// removeLocked forgets the oldest retained batch. A lane that has not taken it yet never will:
// that is the lane's loss, counted under reason.
func (r *retention) removeLocked(reason string, now time.Time) {
	e := r.entries[r.head]
	r.entries[r.head] = nil
	r.head++
	n := len(e.batch.Approvals)
	r.approvals -= n
	if reason == dropEvicted {
		r.m.evicted.Add(float64(n))
		if held, ok := r.log.allow(dropEvicted, now); ok {
			slog.Warn("approval retention is full: evicting the oldest approvals; a producer restart cannot get them back",
				"retain_max", r.max, "approvals", n, "suppressed", held)
		}
	}
	for _, l := range r.lanes {
		if e.seq > l.cursor {
			l.lost(reason, n, now, nil)
		}
	}
	if r.head*2 >= len(r.entries) {
		kept := copy(r.entries, r.entries[r.head:])
		clear(r.entries[kept:])
		r.entries, r.head = r.entries[:kept], 0
	}
}

// takeFresh hands the lane the oldest batch it has not taken yet; finished reports that the
// signer has stopped and nothing is left for the lane.
func (r *retention) takeFresh(l *lane, now time.Time) (*entry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now)
	for e := r.afterLocked(l.cursor); e != nil; e = r.afterLocked(l.cursor) {
		l.cursor = e.seq
		if now.Before(e.expires) {
			return e, false
		}
		// Expired behind a batch that lives longer, because the TTL was shortened meanwhile.
		l.lost(dropExpired, len(e.batch.Approvals), now, nil)
	}
	return nil, r.finished
}

// redelivery is the pass a lane runs when its producer restarted: every retained batch the lane
// had taken, newest first (wire contract §4).
func (r *retention) redelivery(l *lane, now time.Time) redelivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now)
	if r.head == len(r.entries) {
		return redelivery{}
	}
	low := r.entries[r.head].seq
	high := min(l.cursor, r.entries[len(r.entries)-1].seq)
	if high < low {
		return redelivery{}
	}
	return redelivery{active: true, next: high, low: low}
}

// redeliver is the pass's next batch, newest first, skipping what expired or was evicted since
// the pass began; the pass ends when nothing older is left.
func (r *retention) redeliver(d *redelivery, now time.Time) *entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	for d.active {
		if d.next == 0 || d.next < d.low {
			d.active = false
			break
		}
		e := r.atLocked(d.next)
		d.next--
		if e != nil && now.Before(e.expires) {
			return e
		}
	}
	return nil
}

// finish records that the signer has stopped, so a lane that has taken everything ends its drain.
func (r *retention) finish() {
	r.mu.Lock()
	r.finished = true
	lanes := r.lanes
	r.mu.Unlock()
	for _, l := range lanes {
		l.notify()
	}
}

// unsent counts the retained batches the lane never took, for the shutdown report.
func (r *retention) unsent(l *lane) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.afterLocked(l.cursor)
	if e == nil {
		return 0
	}
	return len(r.entries) - r.head - int(e.seq-r.entries[r.head].seq)
}

// afterLocked is the oldest retained batch newer than seq.
func (r *retention) afterLocked(seq uint64) *entry {
	if r.head == len(r.entries) {
		return nil
	}
	i := 0
	if front := r.entries[r.head].seq; seq >= front {
		i = int(seq - front + 1)
	}
	if r.head+i >= len(r.entries) {
		return nil
	}
	return r.entries[r.head+i]
}

// atLocked is the retained batch with this seq, or nil once it is gone.
func (r *retention) atLocked(seq uint64) *entry {
	if r.head == len(r.entries) {
		return nil
	}
	front := r.entries[r.head].seq
	if seq < front || seq-front >= uint64(len(r.entries)-r.head) {
		return nil
	}
	return r.entries[r.head+int(seq-front)]
}
