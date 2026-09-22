package nodepolicy

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeLease is a Lease whose outcome the test controls step by step.
type fakeLease struct {
	mu       sync.Mutex
	acquire  bool
	held     bool
	heldErr  error
	acquires int
	releases int
}

func (l *fakeLease) set(acquire, held bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.acquire, l.held = acquire, held
}
func (l *fakeLease) Acquire(context.Context) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.acquires++
	if l.acquire {
		l.held = true
	}
	return l.acquire, nil
}
func (l *fakeLease) Held(context.Context) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.held, l.heldErr
}
func (l *fakeLease) Release(context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.releases++
	l.held = false
	return nil
}
func (l *fakeLease) counts() (int, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.acquires, l.releases
}

// worker records whether the elected work is running and observes its context.
type worker struct {
	running atomic.Int32
	starts  atomic.Int32
	stops   atomic.Int32
}

func (w *worker) run(ctx context.Context) {
	w.starts.Add(1)
	w.running.Store(1)
	<-ctx.Done()
	w.running.Store(0)
	w.stops.Add(1)
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition never met: %s", what)
}

func TestRunElectedStartsWorkOnlyWhileHoldingTheLease(t *testing.T) {
	lease := &fakeLease{}
	w := &worker{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunElected(ctx, lease, 10*time.Millisecond, w.run, nil) }()

	// Not elected: the work must never start, however many attempts are made.
	eventually(t, "acquisition attempts", func() bool { a, _ := lease.counts(); return a >= 3 })
	if w.starts.Load() != 0 {
		t.Fatal("work started without the lease")
	}

	// Elected: the work starts.
	lease.set(true, true)
	eventually(t, "work started after election", func() bool { return w.running.Load() == 1 })

	// The lease is lost (connection dropped, lock gone): the work is stopped and
	// the lease released, and the loop returns to campaigning.
	lease.set(false, false)
	eventually(t, "work stopped after losing the lease", func() bool { return w.stops.Load() == 1 })
	eventually(t, "lease released after loss", func() bool { _, r := lease.counts(); return r >= 1 })
	if w.running.Load() != 0 {
		t.Fatal("work still running without the lease")
	}

	// Re-elected: the work starts again, as a fresh term.
	lease.set(true, true)
	eventually(t, "work restarted after re-election", func() bool { return w.starts.Load() == 2 && w.running.Load() == 1 })

	// Shutdown stops the work and releases the lease exactly once more.
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected exit: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunElected did not return on cancellation")
	}
	if w.running.Load() != 0 || w.stops.Load() != 2 {
		t.Fatalf("work not stopped on shutdown: running=%d stops=%d", w.running.Load(), w.stops.Load())
	}
	if _, r := lease.counts(); r != 2 {
		t.Fatalf("expected two releases (loss + shutdown), got %d", r)
	}
}

func TestRunElectedTreatsAHeldCheckErrorAsLoss(t *testing.T) {
	lease := &fakeLease{acquire: true}
	w := &worker{}
	var reported atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = RunElected(ctx, lease, 10*time.Millisecond, w.run, func(error) { reported.Add(1) })
	}()
	eventually(t, "work started", func() bool { return w.running.Load() == 1 })

	// The liveness probe fails: the lease cannot be trusted, so the work stops.
	lease.mu.Lock()
	lease.heldErr = errors.New("connection reset")
	lease.acquire = false
	lease.mu.Unlock()
	eventually(t, "work stopped on probe error", func() bool { return w.stops.Load() == 1 })
	eventually(t, "loss reported", func() bool { return reported.Load() >= 1 })
}

func TestRunElectedRejectsAnUnusableInterval(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		if err := RunElected(context.Background(), &fakeLease{}, interval, func(context.Context) {}, nil); err == nil {
			t.Fatalf("interval %v accepted", interval)
		}
	}
}
