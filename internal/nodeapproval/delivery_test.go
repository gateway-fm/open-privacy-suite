package nodeapproval

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/codes"
)

func TestConfirmedApprovalsCountMembersAfterSuccessIncludingRedelivery(t *testing.T) {
	p := newProducer(t, "producer:1", "boot-a")
	p.set(func(p *producer) { p.always = codes.Unavailable })
	s := startDelivery(t, time.Minute, testDelivery(p))
	waitReady(t, s)
	registry := prometheus.NewRegistry()
	registry.MustRegister(s)
	confirmed := func() float64 {
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, family := range families {
			if family.GetName() == "privacyproxy_approval_confirmed_total" {
				return family.GetMetric()[0].GetCounter().GetValue()
			}
		}
		return 0
	}
	hashes := txHashes(1, 3)
	s.publish(signedBatch(t, time.Minute, hashes...))
	waitUntil(t, 2*time.Second, "a retryable refusal", func() bool {
		return value(t, s.metrics.retries.WithLabelValues(p.name)) >= 1
	})
	if got := confirmed(); got != 0 {
		t.Fatalf("refused approvals counted as confirmed: %v", got)
	}
	p.set(func(p *producer) { p.always = codes.OK })
	waitUntil(t, 2*time.Second, "three approvals confirmed in one batch", func() bool { return confirmed() == 3 })
	p.restart("boot-b")
	waitUntil(t, 3*time.Second, "the redelivery confirmed three more approvals", func() bool { return confirmed() == 6 })
	if !p.holds("boot-b", hashes...) {
		t.Fatal("confirmation preceded storage on the restarted producer")
	}
}

func TestDeliveryConfirmsEachBatchOnOneConnection(t *testing.T) {
	p := newProducer(t, "producer-a:1", "boot-a")
	s := startDelivery(t, time.Minute, testDelivery(p))
	waitReady(t, s)
	first, second := txHashes(1, 1)[0], txHashes(2, 1)[0]
	prepared := approvalFor(first)
	prepared.Approval.Principal = common.HexToHash("0x03") // whatever a caller left there
	if err := s.Enqueue(prepared); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 2*time.Second, "the first approval is stored", func() bool { return p.holds("boot-a", first) })
	enqueue(t, s, second)
	waitUntil(t, 2*time.Second, "the second approval is stored", func() bool { return p.holds("boot-a", second) })
	for _, call := range p.received() {
		if call.envelope.keyID != "default" {
			t.Fatalf("signed under key id %q", call.envelope.keyID)
		}
		for _, reserved := range call.envelope.reserved {
			if reserved != (common.Hash{}) {
				t.Fatalf("the reserved field carries %s; senders write zeros", reserved)
			}
		}
	}
	// OPS counts a batch when the confirmation arrives, which is after the producer stored it.
	waitCounted(t, s, p.name, "OK", 2)
	waitUntil(t, 2*time.Second, "both delivery latencies are observed", func() bool {
		return value(t, s.metrics.latency.WithLabelValues(p.name)) == 2
	})
	if got := value(t, s.metrics.connected.WithLabelValues(p.name)); got != 1 {
		t.Fatalf("connected gauge %v", got)
	}
	p.mu.Lock()
	dials := p.dials
	p.mu.Unlock()
	if dials != 1 {
		t.Fatalf("%d connections for two batches; calls share one", dials)
	}
}

// A full store refuses with UNAVAILABLE and the store-full trailer: OPS keeps the batch and
// retries, and the producer ends up holding it once.
func TestFullStoreIsRetriedAndStoredOnce(t *testing.T) {
	p := newProducer(t, "producer-a:1", "boot-a")
	p.set(func(p *producer) { p.script = []codes.Code{answerStoreFull} })
	s := startDelivery(t, time.Minute, testDelivery(p))
	waitReady(t, s)
	h := txHashes(1, 1)[0]
	enqueue(t, s, h)
	waitUntil(t, 3*time.Second, "the refused approval is stored", func() bool { return p.holds("boot-a", h) })
	if got := p.storedIn("boot-a"); len(got) != 1 {
		t.Fatalf("stored %d times", len(got))
	}
	if calls := len(p.received()); calls != 2 {
		t.Fatalf("%d calls, want the refused one and one retry", calls)
	}
	waitCounted(t, s, p.name, "OK", 1)
	for code, want := range map[string]float64{"StoreFull": 1, "OK": 1, "Unavailable": 0} {
		if got := value(t, s.metrics.batches.WithLabelValues(p.name, code)); got != want {
			t.Fatalf("batches{code=%s} = %v, want %v", code, got, want)
		}
	}
	if got := value(t, s.metrics.retries.WithLabelValues(p.name)); got != 1 {
		t.Fatalf("%v retries", got)
	}
}

// The statuses a producer answers for a batch it will never accept are final: dropped, counted,
// never sent again — and the lane carries on with the next batch.
func TestPermanentRefusalsAreDroppedNotRetried(t *testing.T) {
	for _, code := range []codes.Code{codes.InvalidArgument, codes.PermissionDenied, codes.Unauthenticated,
		codes.FailedPrecondition, codes.ResourceExhausted, codes.OutOfRange, codes.Unimplemented} {
		t.Run(code.String(), func(t *testing.T) {
			p := newProducer(t, "producer-a:1", "boot-a")
			p.set(func(p *producer) { p.script = []codes.Code{code} })
			s := startDelivery(t, time.Minute, testDelivery(p))
			waitReady(t, s)
			refused, next := txHashes(1, 1)[0], txHashes(2, 1)[0]
			enqueue(t, s, refused)
			waitUntil(t, 2*time.Second, "the refusal is counted", func() bool {
				return value(t, s.metrics.dropped.WithLabelValues(p.name, dropPermanent)) == 1
			})
			enqueue(t, s, next)
			waitUntil(t, 2*time.Second, "the next approval is stored", func() bool { return p.holds("boot-a", next) })
			time.Sleep(150 * time.Millisecond) // longer than any retry would wait
			calls := 0
			for _, call := range p.received() {
				if slices.Contains(call.envelope.hashes, refused) {
					calls++
				}
			}
			if calls != 1 {
				t.Fatalf("the refused batch was sent %d times", calls)
			}
			if got := value(t, s.metrics.retries.WithLabelValues(p.name)); got != 0 {
				t.Fatalf("%v retries after a permanent refusal", got)
			}
			// The next batch can be stored before the refusal's answer is counted.
			waitCounted(t, s, p.name, code.String(), 1)
		})
	}
}

// Everything else is retried: the receiver starting or stopping, the call's own deadline,
// internal errors and codes the contract does not name.
func TestRetryableFailuresAreRetried(t *testing.T) {
	for name, answer := range map[string]codes.Code{"DeadlineExceeded": answerStall, "Unavailable": codes.Unavailable,
		"Internal": codes.Internal, "Unknown": codes.Unknown, "Aborted": codes.Aborted} {
		t.Run(name, func(t *testing.T) {
			p := newProducer(t, "producer-a:1", "boot-a")
			p.set(func(p *producer) { p.script = []codes.Code{answer} })
			cfg := testDelivery(p)
			cfg.timeout = 100 * time.Millisecond
			s := startDelivery(t, time.Minute, cfg)
			waitReady(t, s)
			h := txHashes(1, 1)[0]
			enqueue(t, s, h)
			waitUntil(t, 3*time.Second, "the approval is stored after a retry", func() bool { return p.holds("boot-a", h) })
			if got := value(t, s.metrics.batches.WithLabelValues(p.name, name)); got != 1 {
				t.Fatalf("batches{code=%s} = %v", name, got)
			}
			if got := value(t, s.metrics.retries.WithLabelValues(p.name)); got != 1 {
				t.Fatalf("%v retries", got)
			}
			if got := p.storedIn("boot-a"); len(got) != 1 {
				t.Fatalf("stored %d times", len(got))
			}
		})
	}
}

func TestRetriesStopAtExpiry(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		p := newProducer(t, "producer-a:1", "boot-a")
		p.set(func(p *producer) { p.always = codes.Unavailable })
		s := startDelivery(t, time.Minute, testDelivery(p))
		waitReady(t, s)
		b := signedBatch(t, 400*time.Millisecond, txHashes(1, 1)...)
		s.publish(b)
		expires := time.UnixMilli(int64(b.ExpiresAt))
		waitUntil(t, 3*time.Second, "the expired batch is counted", func() bool {
			return value(t, s.metrics.dropped.WithLabelValues(p.name, dropExpired)) == 1
		})
		time.Sleep(200 * time.Millisecond)
		calls := p.received()
		if len(calls) < 2 {
			t.Fatalf("%d calls: the batch was not retried", len(calls))
		}
		for _, call := range calls {
			if call.at.After(expires.Add(20 * time.Millisecond)) {
				t.Fatalf("a call at %v, after expires_at %v", call.at.Format(time.StampMicro), expires.Format(time.StampMicro))
			}
		}
	})
	// A call to a producer that hangs ends at expires_at, not at the (longer) delivery timeout.
	t.Run("stalled", func(t *testing.T) {
		p := newProducer(t, "producer-a:1", "boot-a")
		p.set(func(p *producer) { p.always = answerStall })
		cfg := testDelivery(p)
		cfg.timeout = 5 * time.Second
		s := startDelivery(t, time.Minute, cfg)
		waitReady(t, s)
		s.publish(signedBatch(t, 300*time.Millisecond, txHashes(1, 1)...))
		waitUntil(t, 1500*time.Millisecond, "the expired batch is counted", func() bool {
			return value(t, s.metrics.dropped.WithLabelValues(p.name, dropExpired)) == 1
		})
	})
}

// While a lane refuses, it probes with one call at a time; the batches waiting to be retried
// hold no call slot. Once the producer takes batches again, all of them arrive.
func TestARefusingLaneProbesWithOneCall(t *testing.T) {
	p := newProducer(t, "producer-a:1", "boot-a")
	p.set(func(p *producer) { p.always = answerStoreFull })
	s := startDelivery(t, time.Minute, testDelivery(p))
	waitReady(t, s)
	hashes := txHashes(1, 20)
	for _, h := range hashes {
		s.publish(signedBatch(t, time.Minute, h))
	}
	// The calls sent before the first refusal come back; from then on only probes are in flight.
	l := s.lanes[0]
	waitUntil(t, 2*time.Second, "the lane backs off with only its probe out", func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		probes := 0
		if l.backoff.probing {
			probes = 1
		}
		return l.backoff.active && l.calls == probes
	})
	p.set(func(p *producer) { p.peak = p.active })
	before := len(p.received())
	time.Sleep(600 * time.Millisecond)
	p.mu.Lock()
	peak := p.peak
	p.mu.Unlock()
	if peak > 1 {
		t.Fatalf("%d calls in flight on a refusing lane; it may have one probe", peak)
	}
	if len(p.received()) == before {
		t.Fatal("the refusing lane stopped probing")
	}
	p.set(func(p *producer) { p.always = codes.OK })
	waitUntil(t, 3*time.Second, "every batch is stored", func() bool { return p.holds("boot-a", hashes...) })
}

// A restarted producer has lost its store. Status on the new connection reveals the new boot
// id, and OPS resends what it retains and has not expired, newest first — without waiting for a
// new batch.
func TestProducerRestartRedeliversRetainedBatchesNewestFirst(t *testing.T) {
	p := newProducer(t, "producer-a:1", "boot-a")
	cfg := testDelivery(p)
	cfg.maxInFlight = 1 // one call at a time, so the producer sees the order OPS sends in
	s := startDelivery(t, time.Minute, cfg)
	waitReady(t, s)
	short, older, newer := txHashes(1, 1)[0], txHashes(2, 1)[0], txHashes(3, 1)[0]
	s.publish(signedBatch(t, 300*time.Millisecond, short))
	s.publish(signedBatch(t, time.Minute, older))
	s.publish(signedBatch(t, time.Minute, newer))
	waitUntil(t, 2*time.Second, "boot-a holds all three", func() bool { return p.holds("boot-a", short, older, newer) })
	time.Sleep(400 * time.Millisecond) // the short-lived batch expires
	statuses := p.statusCalls()
	p.restart("boot-b")
	waitUntil(t, 3*time.Second, "boot-b gets the retained batches back", func() bool { return p.holds("boot-b", older, newer) })
	if got := p.storedIn("boot-b"); !slices.Equal(got, []common.Hash{newer, older}) {
		t.Fatalf("redelivered %v; want the unexpired batches newest first", got)
	}
	if p.statusCalls() <= statuses {
		t.Fatal("no Status call on the new connection")
	}
	if got := value(t, s.metrics.redeliveries.WithLabelValues(p.name)); got != 1 {
		t.Fatalf("%v redeliveries", got)
	}
}

// The boot id travels in every response: a Deliver answer from a new process triggers the
// redelivery even when no Status call has seen it yet.
func TestNewBootIDInADeliverResponseTriggersRedelivery(t *testing.T) {
	p := newProducer(t, "producer-a:1", "boot-a")
	cfg := testDelivery(p)
	cfg.statusEvery = time.Hour // only the first Status, on connect
	s := startDelivery(t, time.Minute, cfg)
	waitUntil(t, 2*time.Second, "the first Status", func() bool { return p.statusCalls() == 1 })
	earlier, later := txHashes(1, 1)[0], txHashes(2, 1)[0]
	s.publish(signedBatch(t, time.Minute, earlier))
	waitUntil(t, 2*time.Second, "boot-a holds the earlier batch", func() bool { return p.holds("boot-a", earlier) })
	p.set(func(p *producer) { p.boot = "boot-b" })
	s.publish(signedBatch(t, time.Minute, later))
	waitUntil(t, 2*time.Second, "boot-b gets the earlier batch again", func() bool { return p.holds("boot-b", earlier, later) })
}

// Every batch goes to every producer independently: one that is down or stalled holds back
// neither the signer nor the other producer, and catches up when it is back.
func TestTargetsAreIndependent(t *testing.T) {
	for name, trouble := range map[string]func(b *producer){
		"down":    func(b *producer) { b.stop() },
		"stalled": func(b *producer) { b.set(func(b *producer) { b.always = answerStall }) },
	} {
		t.Run(name, func(t *testing.T) {
			a := newProducer(t, "producer-a:1", "boot-a")
			b := newProducer(t, "producer-b:1", "boot-b")
			trouble(b)
			cfg := testDelivery(a, b)
			cfg.timeout = 200 * time.Millisecond
			cfg.maxInFlight = 2
			s := startDelivery(t, time.Minute, cfg)
			waitReady(t, s)
			hashes := txHashes(1, 50)
			enqueue(t, s, hashes...)
			waitUntil(t, 2*time.Second, "a stores everything while b is in trouble", func() bool { return a.holds("boot-a", hashes...) })
			if name == "down" {
				b.start()
			} else {
				b.set(func(b *producer) { b.always = codes.OK })
			}
			waitUntil(t, 5*time.Second, "b catches up", func() bool { return b.holds("boot-b", hashes...) })
		})
	}
}

func TestCallsInFlightAreBounded(t *testing.T) {
	p := newProducer(t, "producer-a:1", "boot-a")
	gate := make(chan struct{})
	p.set(func(p *producer) { p.gate = gate })
	cfg := testDelivery(p)
	cfg.maxInFlight = 3
	cfg.timeout = 5 * time.Second
	s := startDelivery(t, time.Minute, cfg)
	waitReady(t, s)
	hashes := txHashes(1, 10)
	for _, h := range hashes {
		s.publish(signedBatch(t, time.Minute, h))
	}
	waitUntil(t, 2*time.Second, "three calls are in flight", func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.active == 3
	})
	time.Sleep(100 * time.Millisecond)
	if got := value(t, s.metrics.inFlight.WithLabelValues(p.name)); got != 3 {
		t.Fatalf("in-flight gauge %v", got)
	}
	close(gate)
	waitUntil(t, 3*time.Second, "every batch is stored", func() bool { return p.holds("boot-a", hashes...) })
	p.mu.Lock()
	peak := p.peak
	p.mu.Unlock()
	if peak != 3 {
		t.Fatalf("%d calls in flight at once, the bound is 3", peak)
	}
}

// Beyond OPS_APPROVAL_RETAIN_MAX the oldest batches go first, and a restarted producer gets
// back only what is still retained.
func TestRetentionCapEvictsTheOldestBatches(t *testing.T) {
	p := newProducer(t, "producer-a:1", "boot-a")
	cfg := testDelivery(p)
	cfg.retainMax = 64
	s := startDelivery(t, time.Minute, cfg)
	waitReady(t, s)
	oldest, middle, newest := txHashes(1, 32), txHashes(101, 32), txHashes(201, 32)
	for _, batch := range [][]common.Hash{oldest, middle, newest} {
		s.publish(signedBatch(t, time.Minute, batch...))
		waitUntil(t, 2*time.Second, "the batch is stored", func() bool { return p.holds("boot-a", batch...) })
	}
	if got := value(t, s.metrics.evicted); got != 32 {
		t.Fatalf("%v approvals evicted, want the oldest batch's 32", got)
	}
	if got := value(t, s.metrics.retained); got != 64 {
		t.Fatalf("%v approvals retained", got)
	}
	if got := value(t, s.metrics.dropped.WithLabelValues(p.name, dropEvicted)); got != 0 {
		t.Fatalf("%v approvals counted lost, but the producer had them all", got)
	}
	p.restart("boot-b")
	waitUntil(t, 3*time.Second, "boot-b gets the retained batches", func() bool { return p.holds("boot-b", append(middle, newest...)...) })
	time.Sleep(100 * time.Millisecond)
	for _, h := range p.storedIn("boot-b") {
		if slices.Contains(oldest, h) {
			t.Fatalf("evicted approval %s was redelivered", h)
		}
	}
}

// Enqueue refuses unless some producer is connected and has answered Status on this connection
// within the ready window, for this chain, trusting the key OPS signs with.
func TestEnqueueRequiresAReadyProducer(t *testing.T) {
	h := txHashes(1, 1)[0]
	t.Run("none connected", func(t *testing.T) {
		p := newProducer(t, "producer-a:1", "boot-a")
		p.stop()
		s := startDelivery(t, time.Minute, testDelivery(p))
		if err := s.Enqueue(approvalFor(h)); !errors.Is(err, errNoProducerReady) {
			t.Fatalf("Enqueue with no producer: %v", err)
		}
		if got := value(t, s.metrics.refused.WithLabelValues(refusedNotReady)); got != 1 {
			t.Fatalf("%v refusals counted", got)
		}
		p.start()
		waitReady(t, s)
		enqueue(t, s, h)
		waitUntil(t, 2*time.Second, "the approval is stored", func() bool { return p.holds("boot-a", h) })
	})
	// A mismatching answer ends readiness at once, without waiting out the ready window.
	for name, mismatch := range map[string]func(p *producer){
		"another chain":    func(p *producer) { p.chain = 1 },
		"untrusted key id": func(p *producer) { p.keys = []string{"rotated"} },
	} {
		t.Run(name, func(t *testing.T) {
			p := newProducer(t, "producer-a:1", "boot-a")
			s := startDelivery(t, time.Minute, testDelivery(p))
			waitReady(t, s)
			var before int
			p.set(func(p *producer) { mismatch(p); before = p.statuses })
			// Status calls are sequential: once the second one after the change arrives, OPS has
			// taken in the first.
			waitUntil(t, 2*time.Second, "a Status answered after the change", func() bool { return p.statusCalls() >= before+2 })
			if err := s.Enqueue(approvalFor(h)); !errors.Is(err, errNoProducerReady) {
				t.Fatalf("Enqueue after a mismatching Status: %v", err)
			}
		})
	}
	t.Run("Status unanswered", func(t *testing.T) {
		p := newProducer(t, "producer-a:1", "boot-a")
		s := startDelivery(t, time.Minute, testDelivery(p))
		waitReady(t, s)
		p.set(func(p *producer) { p.statusErr = codes.Unavailable })
		waitUntil(t, 2*time.Second, "the ready window lapses", func() bool { return !s.ready(31337, time.Now()) })
		if err := s.Enqueue(approvalFor(h)); !errors.Is(err, errNoProducerReady) {
			t.Fatalf("Enqueue: %v", err)
		}
	})
}

// A producer whose chain or trusted keys do not match is reported, and its lane keeps running.
func TestStatusMismatchesAreReportedAndTheLaneKeepsRunning(t *testing.T) {
	p := newProducer(t, "producer-a:1", "boot-a")
	p.set(func(p *producer) { p.keys, p.chain = []string{"rotated"}, 1 })
	s := startDelivery(t, time.Minute, testDelivery(p))
	waitUntil(t, 2*time.Second, "the key id mismatch is reported", func() bool {
		return value(t, s.metrics.mismatches.WithLabelValues(p.name, "key_id")) >= 1
	})
	// OPS learns its chain from what it approves; until then there is nothing to compare.
	if got := value(t, s.metrics.mismatches.WithLabelValues(p.name, "chain_id")); got != 0 {
		t.Fatalf("chain mismatch reported before OPS knew its chain: %v", got)
	}
	h := txHashes(1, 1)[0]
	if err := s.Enqueue(approvalFor(h)); !errors.Is(err, errNoProducerReady) {
		t.Fatalf("Enqueue to a mismatched producer: %v", err)
	}
	waitUntil(t, 2*time.Second, "the chain mismatch is reported", func() bool {
		return value(t, s.metrics.mismatches.WithLabelValues(p.name, "chain_id")) >= 1
	})
	s.publish(signedBatch(t, time.Minute, h))
	waitUntil(t, 2*time.Second, "the lane still delivers", func() bool { return p.holds("boot-a", h) })
}

// OPS signs with the shorter of OPS_APPROVAL_TTL and the smallest maximum TTL a producer reports.
func TestSigningTTLFollowsTheProducersMaximum(t *testing.T) {
	for name, c := range map[string]struct {
		producerMax time.Duration
		want        time.Duration
	}{
		"producer allows less": {30 * time.Second, 30 * time.Second},
		"producer allows more": {time.Hour, 10 * time.Minute},
	} {
		t.Run(name, func(t *testing.T) {
			p := newProducer(t, "producer-a:1", "boot-a")
			p.set(func(p *producer) { p.maxTTLms = uint64(c.producerMax.Milliseconds()) })
			s := startDelivery(t, 10*time.Minute, testDelivery(p))
			waitReady(t, s)
			h := txHashes(1, 1)[0]
			enqueue(t, s, h)
			waitUntil(t, 2*time.Second, "the approval is stored", func() bool { return p.holds("boot-a", h) })
			env := p.received()[0].envelope
			if got := env.expires.Sub(env.issued); got != c.want {
				t.Fatalf("signed for %v, want %v", got, c.want)
			}
		})
	}
}

// The opt-in hop recorder marks the first Deliver call and its confirmation.
func TestHopsRecordTheDeliveryCall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hops.json")
	t.Setenv("OPS_APPROVAL_HOPS_FILE", path)
	p := newProducer(t, "producer-a:1", "boot-a")
	s := startDelivery(t, time.Minute, testDelivery(p))
	waitReady(t, s)
	h := txHashes(1, 1)[0]
	prepared := approvalFor(h)
	if err := s.Enqueue(prepared); err != nil {
		t.Fatal(err)
	}
	s.TraceForward(prepared)
	waitUntil(t, 2*time.Second, "the approval is stored", func() bool { return p.holds("boot-a", h) })
	s.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []Hop
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d hop rows", len(rows))
	}
	r := rows[0]
	marks := []int64{r.Queued, r.SignStart, r.SignEnd, r.CallStart, r.Stored}
	for i, m := range marks {
		if m == 0 || i > 0 && m < marks[i-1] {
			t.Fatalf("hop marks out of order or missing: %+v", r)
		}
	}
	if r.ForwardStart == 0 {
		t.Fatalf("forward mark missing: %+v", r)
	}
}

// A producer that reports a maximum TTL below MinApprovalTTL would have OPS sign approvals that
// expire inside the wait window: it is reported, is not ready, and does not shorten the TTL OPS
// signs with for the other producers.
func TestAProducerBelowTheMinimumTTLIsNotReadyAndDoesNotShortenTheTTL(t *testing.T) {
	short := newProducer(t, "producer-short:1", "boot-short")
	short.set(func(p *producer) { p.maxTTLms = 1000 })
	normal := newProducer(t, "producer-normal:1", "boot-normal")
	s := startDelivery(t, 10*time.Minute, testDelivery(short, normal))
	waitUntil(t, 2*time.Second, "the short maximum TTL is reported", func() bool {
		return value(t, s.metrics.mismatches.WithLabelValues(short.name, "max_ttl")) >= 1
	})
	if got := s.signingTTL(); got != 10*time.Minute {
		t.Fatalf("signing TTL %v, want the configured 10m", got)
	}
	short.stop()
	waitUntil(t, 2*time.Second, "the normal producer is ready", func() bool { return s.Accepting() })
	h := txHashes(1, 1)[0]
	enqueue(t, s, h)
	waitUntil(t, 2*time.Second, "the approval is stored", func() bool { return normal.holds("boot-normal", h) })
	env := normal.received()[0].envelope
	if got := env.expires.Sub(env.issued); got != 10*time.Minute {
		t.Fatalf("signed for %v, want 10m", got)
	}
}

// A lane forgets its producer's maximum TTL when it stops being ready, so a standby that went
// away no longer shortens what OPS signs for the others.
func TestALaneThatStopsBeingReadyNoLongerShortensTheTTL(t *testing.T) {
	standby := newProducer(t, "producer-standby:1", "boot-standby")
	standby.set(func(p *producer) { p.maxTTLms = uint64((30 * time.Second).Milliseconds()) })
	primary := newProducer(t, "producer-primary:1", "boot-primary")
	s := startDelivery(t, 10*time.Minute, testDelivery(standby, primary))
	waitUntil(t, 2*time.Second, "the standby's maximum applies", func() bool { return s.signingTTL() == 30*time.Second })
	standby.stop()
	waitUntil(t, 5*time.Second, "the standby's maximum is forgotten", func() bool { return s.signingTTL() == 10*time.Minute })
}

// A misconfigured producer cannot keep accepting preflights or shorten every other producer's
// approvals after OPS has learned the chain of the transactions it approves.
func TestAProducerForAnotherChainIsNotReadyAndDoesNotShortenTheTTL(t *testing.T) {
	p := newProducer(t, "producer:1", "boot")
	s := startDelivery(t, 10*time.Minute, testDelivery(p))
	waitReady(t, s)
	enqueue(t, s, txHashes(1, 1)...)
	p.set(func(p *producer) {
		p.chain = 1
		p.maxTTLms = uint64(MinApprovalTTL.Milliseconds())
	})
	waitUntil(t, 2*time.Second, "the wrong chain is not ready", func() bool {
		return value(t, s.metrics.mismatches.WithLabelValues(p.name, "chain_id")) >= 1 && !s.Accepting()
	})
	if got := s.signingTTL(); got != 10*time.Minute {
		t.Fatalf("wrong-chain producer shortened the signing TTL to %v", got)
	}
	p.set(func(p *producer) { p.chain = 31337 })
	waitReady(t, s)
	if got := s.signingTTL(); got != MinApprovalTTL {
		t.Fatalf("recovered producer's maximum TTL was not applied: %v", got)
	}
}

// waitCounted waits until OPS has counted want batches with code for target. OPS counts a batch
// when the producer's answer arrives, which can be after a producer-side check already succeeded.
func waitCounted(t *testing.T, s *Service, target, code string, want float64) {
	t.Helper()
	waitUntil(t, 2*time.Second, fmt.Sprintf("batches{code=%s} reaches %v", code, want), func() bool {
		return value(t, s.metrics.batches.WithLabelValues(target, code)) == want
	})
}
