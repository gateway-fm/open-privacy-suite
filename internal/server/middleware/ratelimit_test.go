package middleware

import (
	"sync"
	"testing"
	"time"
)

func TestRateLimiterRPS(t *testing.T) {
	rl := NewRateLimiter(1 * time.Minute)
	defer rl.Stop()

	userID := "user1"
	rpsLimit := 5

	// Should allow up to rpsLimit requests
	for i := 0; i < rpsLimit; i++ {
		allowed, reason := rl.CheckAndIncrement(userID, &rpsLimit, nil)
		if !allowed {
			t.Errorf("Request %d should be allowed, but was denied: %s", i+1, reason)
		}
	}

	// 6th request should be denied
	allowed, reason := rl.CheckAndIncrement(userID, &rpsLimit, nil)
	if allowed {
		t.Error("6th request should be denied (RPS limit exceeded)")
	}
	if reason == "" {
		t.Error("Expected non-empty reason for denied request")
	}
}

func TestRateLimiterDaily(t *testing.T) {
	rl := NewRateLimiter(1 * time.Minute)
	defer rl.Stop()

	userID := "user2"
	dailyLimit := 3

	// Should allow up to dailyLimit requests
	for i := 0; i < dailyLimit; i++ {
		allowed, reason := rl.CheckAndIncrement(userID, nil, &dailyLimit)
		if !allowed {
			t.Errorf("Request %d should be allowed, but was denied: %s", i+1, reason)
		}
	}

	// 4th request should be denied
	allowed, reason := rl.CheckAndIncrement(userID, nil, &dailyLimit)
	if allowed {
		t.Error("4th request should be denied (daily limit exceeded)")
	}
	if reason == "" {
		t.Error("Expected non-empty reason for denied request")
	}
}

func TestRateLimiterNoLimits(t *testing.T) {
	rl := NewRateLimiter(1 * time.Minute)
	defer rl.Stop()

	userID := "user3"

	// Should allow unlimited requests when limits are nil
	for i := 0; i < 100; i++ {
		allowed, _ := rl.CheckAndIncrement(userID, nil, nil)
		if !allowed {
			t.Errorf("Request %d should be allowed (no limits set)", i+1)
		}
	}
}

func TestRateLimiterZeroLimits(t *testing.T) {
	rl := NewRateLimiter(1 * time.Minute)
	defer rl.Stop()

	userID := "user4"
	zeroLimit := 0

	// Zero limits should be treated as unlimited (0 means no limit set)
	for i := 0; i < 10; i++ {
		allowed, _ := rl.CheckAndIncrement(userID, &zeroLimit, &zeroLimit)
		if !allowed {
			t.Errorf("Request %d should be allowed (zero limits mean unlimited)", i+1)
		}
	}
}

func TestRateLimiterDifferentUsers(t *testing.T) {
	rl := NewRateLimiter(1 * time.Minute)
	defer rl.Stop()

	rpsLimit := 2

	// User1 uses their limit
	for i := 0; i < 2; i++ {
		allowed, _ := rl.CheckAndIncrement("user1", &rpsLimit, nil)
		if !allowed {
			t.Error("User1 should be allowed")
		}
	}

	// User1 is now blocked
	allowed, _ := rl.CheckAndIncrement("user1", &rpsLimit, nil)
	if allowed {
		t.Error("User1 should be blocked (limit exceeded)")
	}

	// User2 should still have their full limit
	for i := 0; i < 2; i++ {
		allowed, _ := rl.CheckAndIncrement("user2", &rpsLimit, nil)
		if !allowed {
			t.Error("User2 should be allowed (different user)")
		}
	}
}

func TestRateLimiterConcurrent(t *testing.T) {
	rl := NewRateLimiter(1 * time.Minute)
	defer rl.Stop()

	userID := "concurrent_user"
	rpsLimit := 100

	var wg sync.WaitGroup
	allowedCount := 0
	var mu sync.Mutex

	// Launch 150 concurrent requests (limit is 100)
	for i := 0; i < 150; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed, _ := rl.CheckAndIncrement(userID, &rpsLimit, nil)
			if allowed {
				mu.Lock()
				allowedCount++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Should allow exactly rpsLimit requests
	if allowedCount != rpsLimit {
		t.Errorf("Expected %d allowed requests, got %d", rpsLimit, allowedCount)
	}
}

func TestRateLimiterStats(t *testing.T) {
	rl := NewRateLimiter(1 * time.Minute)
	defer rl.Stop()

	// Initially empty
	stats := rl.Stats()
	if stats.TrackedUsers != 0 {
		t.Errorf("Expected 0 tracked users, got %d", stats.TrackedUsers)
	}

	// Add some users
	rpsLimit := 10
	rl.CheckAndIncrement("user1", &rpsLimit, nil)
	rl.CheckAndIncrement("user2", &rpsLimit, nil)
	rl.CheckAndIncrement("user3", &rpsLimit, nil)

	stats = rl.Stats()
	if stats.TrackedUsers != 3 {
		t.Errorf("Expected 3 tracked users, got %d", stats.TrackedUsers)
	}
}

func TestRateLimiterBothLimits(t *testing.T) {
	rl := NewRateLimiter(1 * time.Minute)
	defer rl.Stop()

	userID := "both_limits_user"
	rpsLimit := 10
	dailyLimit := 5

	// Daily limit is more restrictive
	for i := 0; i < dailyLimit; i++ {
		allowed, _ := rl.CheckAndIncrement(userID, &rpsLimit, &dailyLimit)
		if !allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 6th request should be denied by daily limit
	allowed, reason := rl.CheckAndIncrement(userID, &rpsLimit, &dailyLimit)
	if allowed {
		t.Error("6th request should be denied by daily limit")
	}
	if reason != "rate limit exceeded (daily limit)" {
		t.Errorf("Expected daily limit reason, got: %s", reason)
	}
}

func TestStartOfDay(t *testing.T) {
	// Test that startOfDay returns midnight UTC
	now := time.Date(2024, 3, 15, 14, 30, 45, 123456789, time.UTC)
	sod := startOfDay(now)

	expected := time.Date(2024, 3, 15, 0, 0, 0, 0, time.UTC)
	if !sod.Equal(expected) {
		t.Errorf("startOfDay(%v) = %v, expected %v", now, sod, expected)
	}
}
