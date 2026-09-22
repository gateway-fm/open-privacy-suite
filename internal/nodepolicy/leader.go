package nodepolicy

import (
	"context"
	"errors"
	"time"
)

// Lease is the mutual exclusion between OPS instances for work that must have
// exactly one writer at a time: the fact publisher and the submission
// reconciler. Several instances share one database and one node; without a
// lease every instance publishes, deltas collapse into full snapshots, and the
// shared acknowledgement cursor stops describing the node.
//
// Acquire never blocks. Held is a live probe of the same lease, not a cached
// answer, so a lost connection reads as a lost lease. Release is idempotent.
type Lease interface {
	Acquire(ctx context.Context) (bool, error)
	Held(ctx context.Context) (bool, error)
	Release(ctx context.Context) error
}

// ErrLeaseLost reports that the elected work was stopped because the lease
// could no longer be confirmed.
var ErrLeaseLost = errors.New("node policy lease lost")

// errWorkReturned reports a term that ended because the work itself returned
// while the lease was still held. The lease is released so another instance
// can try, and the next campaign starts a fresh term.
var errWorkReturned = errors.New("elected work returned before the lease was lost")

// leaseReleaseTimeout bounds the unlock at the end of a term. Shutdown must
// not hang on an unreachable database: the session dying frees the lock anyway.
const leaseReleaseTimeout = 5 * time.Second

// RunElected campaigns for the lease every interval and runs work only while
// holding it. The work receives a context that is cancelled when the lease is
// lost or when ctx ends; after the work returns the lease is released and the
// loop campaigns again. Failover between instances therefore takes about one
// interval plus the work's own shutdown. Errors are reported, never hidden.
func RunElected(ctx context.Context, lease Lease, interval time.Duration, work func(context.Context), report func(error)) error {
	if lease == nil || work == nil || interval <= 0 {
		return errors.New("elected work needs a lease, work and a positive interval")
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		held, err := lease.Acquire(ctx)
		switch {
		case err != nil:
			if report != nil && ctx.Err() == nil {
				report(err)
			}
		case held:
			if err := serveTerm(ctx, lease, tick, work); err != nil && report != nil && ctx.Err() == nil {
				report(err)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// serveTerm runs one term of leadership: the work runs until the lease is no
// longer confirmed or ctx ends, then the lease is released. It returns why the
// term ended, or nil for an ordinary shutdown.
func serveTerm(ctx context.Context, lease Lease, tick *time.Ticker, work func(context.Context)) error {
	term, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		work(term)
	}()
	var cause error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-done:
			cause = errWorkReturned
			break loop
		case <-tick.C:
			held, err := lease.Held(ctx)
			if err != nil {
				cause = errors.Join(ErrLeaseLost, err)
				break loop
			}
			if !held {
				cause = ErrLeaseLost
				break loop
			}
		}
	}
	cancel()
	<-done
	// Release must not be skipped because the parent is already cancelled, and
	// must not block shutdown on a database that has stopped answering.
	release, stop := context.WithTimeout(context.WithoutCancel(ctx), leaseReleaseTimeout)
	defer stop()
	_ = lease.Release(release)
	return cause
}
