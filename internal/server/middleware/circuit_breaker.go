package middleware

import (
	"sync"
	"time"
)

// CircuitBreaker tracks upstream 429 responses per API key.
// When tripped, subsequent requests are rejected immediately for the
// cooldown period (1 second, matching the RPC proxy's rate limit window).
type CircuitBreaker struct {
	mu       sync.RWMutex
	tripped  map[string]time.Time // apiKey -> last 429 timestamp
	cooldown time.Duration
}

// NewCircuitBreaker creates a circuit breaker with a 1-second cooldown.
func NewCircuitBreaker() *CircuitBreaker {
	return NewCircuitBreakerWithCooldown(time.Second)
}

// NewCircuitBreakerWithCooldown creates a circuit breaker with an explicit
// cooldown. Callers outside this package need it to build a breaker that trips
// for less than the production second — before the package split, tests reached
// into the unexported fields directly, which is no longer possible.
func NewCircuitBreakerWithCooldown(cooldown time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		tripped:  make(map[string]time.Time),
		cooldown: cooldown,
	}
}

// IsOpen returns true if the circuit is open (should reject requests).
func (cb *CircuitBreaker) IsOpen(apiKey string) bool {
	if apiKey == "" {
		return false // no API key = no circuit to trip
	}
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	t, ok := cb.tripped[apiKey]
	if !ok {
		return false
	}
	return time.Since(t) < cb.cooldown
}

// Trip records a 429 for the given API key.
func (cb *CircuitBreaker) Trip(apiKey string) {
	if apiKey == "" {
		return
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.tripped[apiKey] = time.Now()
}

// Reset clears the trip state for an API key (on successful response).
func (cb *CircuitBreaker) Reset(apiKey string) {
	if apiKey == "" {
		return
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()
	delete(cb.tripped, apiKey)
}
