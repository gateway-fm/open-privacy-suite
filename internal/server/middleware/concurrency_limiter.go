package middleware

import (
	"sync"
)

// ConcurrencyLimiter caps the number of in-flight requests per user.
// This protects the proxy's own resources (DB connections, CPU) from
// being exhausted by a single user sending many concurrent requests.
// It is NOT rate limiting -- it's a concurrency cap.
//
// Anonymous requests (userID == "") have no identity to key a per-user bucket
// on, so they share a single global semaphore (anonSem). Before RD-1164 #3
// anonymous traffic bypassed the limiter entirely (returned true), so an
// unauthenticated flood could exhaust the DB pool / CPU while still running
// JWT/RBAC/compliance work per request. A shared bucket bounds the total
// in-flight anonymous work without letting one client (spoofable, shared IP
// behind the ingress) starve the others.
type ConcurrencyLimiter struct {
	mu      sync.Mutex
	sems    map[string]chan struct{}
	maxConc int
	anonSem chan struct{} // shared bucket for anonymous (userID == "") traffic; nil = disabled
}

// NewConcurrencyLimiter creates a limiter with the given max concurrent
// requests per user and a shared max for anonymous traffic. A per-user value
// of 0 disables the per-user cap; an anonymous value of 0 disables the
// anonymous cap.
func NewConcurrencyLimiter(maxConcurrent, maxAnonymous int) *ConcurrencyLimiter {
	cl := &ConcurrencyLimiter{
		sems:    make(map[string]chan struct{}),
		maxConc: maxConcurrent,
	}
	if maxAnonymous > 0 {
		cl.anonSem = make(chan struct{}, maxAnonymous)
	}
	return cl
}

// TryAcquire attempts to acquire a slot for the given user.
// Returns true if acquired, false if the user (or the shared anonymous bucket)
// is at the concurrency limit.
func (cl *ConcurrencyLimiter) TryAcquire(userID string) bool {
	if userID == "" {
		// Anonymous: bounded by the shared semaphore, not a per-user bucket.
		if cl.anonSem == nil {
			return true // anonymous cap disabled
		}
		select {
		case cl.anonSem <- struct{}{}:
			return true
		default:
			return false
		}
	}

	if cl.maxConc <= 0 {
		return true // per-user cap disabled
	}

	cl.mu.Lock()
	sem, ok := cl.sems[userID]
	if !ok {
		sem = make(chan struct{}, cl.maxConc)
		cl.sems[userID] = sem
	}
	cl.mu.Unlock()

	select {
	case sem <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release releases a slot for the given user. Must be called after TryAcquire
// returns true, typically via defer.
func (cl *ConcurrencyLimiter) Release(userID string) {
	if userID == "" {
		if cl.anonSem != nil {
			select {
			case <-cl.anonSem:
			default:
				// Should not happen -- Release called without Acquire
			}
		}
		return
	}

	if cl.maxConc <= 0 {
		return
	}

	cl.mu.Lock()
	sem, ok := cl.sems[userID]
	cl.mu.Unlock()

	if ok {
		select {
		case <-sem:
		default:
			// Should not happen -- Release called without Acquire
		}
	}
}
