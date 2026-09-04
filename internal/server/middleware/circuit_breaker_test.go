package middleware

import (
	"testing"
	"time"
)

func TestCircuitBreaker_NotTripped(t *testing.T) {
	cb := NewCircuitBreaker()
	if cb.IsOpen("key1") {
		t.Error("expected circuit to be closed for untripped key")
	}
}

func TestCircuitBreaker_TripAndRecover(t *testing.T) {
	cb := &CircuitBreaker{
		tripped:  make(map[string]time.Time),
		cooldown: 50 * time.Millisecond, // short for testing
	}

	cb.Trip("key1")
	if !cb.IsOpen("key1") {
		t.Error("expected circuit to be open after trip")
	}

	// Different key should not be affected
	if cb.IsOpen("key2") {
		t.Error("expected circuit to be closed for different key")
	}

	// Wait for cooldown
	time.Sleep(60 * time.Millisecond)
	if cb.IsOpen("key1") {
		t.Error("expected circuit to be closed after cooldown")
	}
}

func TestCircuitBreaker_Reset(t *testing.T) {
	cb := NewCircuitBreaker()
	cb.Trip("key1")
	if !cb.IsOpen("key1") {
		t.Error("expected circuit to be open after trip")
	}

	cb.Reset("key1")
	if cb.IsOpen("key1") {
		t.Error("expected circuit to be closed after reset")
	}
}

func TestCircuitBreaker_EmptyKey(t *testing.T) {
	cb := NewCircuitBreaker()
	cb.Trip("")
	if cb.IsOpen("") {
		t.Error("empty key should never trip")
	}
}
