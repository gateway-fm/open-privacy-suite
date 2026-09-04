package middleware

import (
	"sync"
	"time"
)

// RateLimiterCleanupInterval is how often the rate limiter prunes stale
// per-user windows and daily counters. It is the limiter's own housekeeping
// cadence — it has no meaning outside NewRateLimiter — so it lives here rather
// than with the server's request-handling policy constants.
const RateLimiterCleanupInterval = 10 * time.Second

// RateLimiter provides rate limiting based on user-specific limits.
// It uses a sliding window for per-second limits and a daily counter for daily limits.
type RateLimiter struct {
	mu           sync.RWMutex
	wg           sync.WaitGroup
	rpsWindows   map[string]*slidingWindow // userID -> sliding window for RPS
	dailyCounts  map[string]*dailyCounter  // userID -> daily counter
	windowSize   time.Duration             // Size of the sliding window (typically 1 second)
	cleanupEvery time.Duration
	stopCleanup  chan struct{}
}

// slidingWindow tracks requests in a sliding time window.
type slidingWindow struct {
	timestamps []time.Time
}

// dailyCounter tracks requests per day.
type dailyCounter struct {
	count int
	day   time.Time // Start of the day (UTC)
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(cleanupEvery time.Duration) *RateLimiter {
	rl := &RateLimiter{
		rpsWindows:   make(map[string]*slidingWindow),
		dailyCounts:  make(map[string]*dailyCounter),
		windowSize:   time.Second,
		cleanupEvery: cleanupEvery,
		stopCleanup:  make(chan struct{}),
	}

	// Start cleanup goroutine
	rl.wg.Add(1)
	go rl.cleanup()

	return rl
}

// CheckAndIncrement checks if a request is allowed and increments counters atomically.
// Returns (allowed, reason) where reason explains why the request was denied.
func (rl *RateLimiter) CheckAndIncrement(userID string, rpsLimit, dailyLimit *int) (bool, string) {
	now := time.Now().UTC()

	// Lock for the entire check-and-increment operation to ensure atomicity
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check RPS limit
	if rpsLimit != nil && *rpsLimit > 0 {
		if !rl.checkRPSLocked(userID, *rpsLimit, now) {
			return false, "rate limit exceeded (requests per second)"
		}
	}

	// Check daily limit
	if dailyLimit != nil && *dailyLimit > 0 {
		if !rl.checkDailyLocked(userID, *dailyLimit, now) {
			return false, "rate limit exceeded (daily limit)"
		}
	}

	// Increment counters after all checks pass (already holding lock)
	rl.incrementCountersLocked(userID, now)

	return true, ""
}

// checkRPSLocked checks if the request would exceed the RPS limit.
// Caller must hold rl.mu.
func (rl *RateLimiter) checkRPSLocked(userID string, limit int, now time.Time) bool {
	window, exists := rl.rpsWindows[userID]

	if !exists {
		return true // No existing window, will be created on increment
	}

	// Count requests in the last window
	cutoff := now.Add(-rl.windowSize)
	count := 0
	for _, ts := range window.timestamps {
		if ts.After(cutoff) {
			count++
		}
	}

	return count < limit
}

// checkDailyLocked checks if the request would exceed the daily limit.
// Caller must hold rl.mu.
func (rl *RateLimiter) checkDailyLocked(userID string, limit int, now time.Time) bool {
	counter, exists := rl.dailyCounts[userID]

	if !exists {
		return true // No existing counter, will be created on increment
	}

	// Reset if day changed
	today := startOfDay(now)
	if !counter.day.Equal(today) {
		return true // New day, counter will be reset on increment
	}

	return counter.count < limit
}

// incrementCountersLocked increments both RPS and daily counters.
// Caller must hold rl.mu.
func (rl *RateLimiter) incrementCountersLocked(userID string, now time.Time) {
	// Increment RPS window
	window, exists := rl.rpsWindows[userID]
	if !exists {
		window = &slidingWindow{timestamps: make([]time.Time, 0, 100)}
		rl.rpsWindows[userID] = window
	}
	window.timestamps = append(window.timestamps, now)

	// Increment daily counter
	counter, exists := rl.dailyCounts[userID]
	today := startOfDay(now)
	if !exists {
		counter = &dailyCounter{day: today}
		rl.dailyCounts[userID] = counter
	}
	if !counter.day.Equal(today) {
		counter.count = 0
		counter.day = today
	}
	counter.count++
}

// cleanup periodically cleans up old entries.
func (rl *RateLimiter) cleanup() {
	defer rl.wg.Done()
	ticker := time.NewTicker(rl.cleanupEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.doCleanup()
		case <-rl.stopCleanup:
			return
		}
	}
}

// doCleanup removes old entries from the rate limiter.
func (rl *RateLimiter) doCleanup() {
	now := time.Now().UTC()
	cutoff := now.Add(-rl.windowSize * 2) // Keep 2 windows of history
	today := startOfDay(now)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Clean up RPS windows
	for userID, window := range rl.rpsWindows {
		// Filter out old timestamps
		newTimestamps := make([]time.Time, 0, len(window.timestamps))
		for _, ts := range window.timestamps {
			if ts.After(cutoff) {
				newTimestamps = append(newTimestamps, ts)
			}
		}
		window.timestamps = newTimestamps

		// Remove empty windows
		if len(window.timestamps) == 0 {
			delete(rl.rpsWindows, userID)
		}
	}

	// Clean up old daily counters (keep today and yesterday)
	yesterday := today.AddDate(0, 0, -1)
	for userID, counter := range rl.dailyCounts {
		if counter.day.Before(yesterday) {
			delete(rl.dailyCounts, userID)
		}
	}
}

// Stop stops the cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stopCleanup)
	rl.wg.Wait()
}

// Stats returns statistics about the rate limiter.
type RateLimiterStats struct {
	TrackedUsers      int `json:"tracked_users"`
	RPSWindowEntries  int `json:"rps_window_entries"`
	DailyCountEntries int `json:"daily_count_entries"`
}

// Stats returns current statistics.
func (rl *RateLimiter) Stats() RateLimiterStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	// Count total timestamp entries across all RPS windows
	totalTimestamps := 0
	for _, window := range rl.rpsWindows {
		totalTimestamps += len(window.timestamps)
	}

	return RateLimiterStats{
		TrackedUsers:      len(rl.rpsWindows),
		RPSWindowEntries:  totalTimestamps,
		DailyCountEntries: len(rl.dailyCounts),
	}
}

// startOfDay returns the start of the day (00:00:00 UTC) for the given time.
func startOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}
