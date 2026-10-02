//go:build mockauth

package e2e

import (
	"sync"
	"time"
)

// The cross-org oracle middleware enforces the same 1 RPS trace budget as live
// debug_traceCall, keyed per caller IP. E2E suites issue many verdict requests
// from 127.0.0.1 in quick succession; pace them so the contract tests exercise
// policy outcomes rather than rate limiting.
var (
	oracleE2ERateMu   sync.Mutex
	oracleE2ELastCall time.Time
)

func waitOracleE2ERateLimit() {
	oracleE2ERateMu.Lock()
	defer oracleE2ERateMu.Unlock()
	const minSpacing = 1100 * time.Millisecond
	if wait := minSpacing - time.Since(oracleE2ELastCall); wait > 0 {
		time.Sleep(wait)
	}
	oracleE2ELastCall = time.Now()
}
