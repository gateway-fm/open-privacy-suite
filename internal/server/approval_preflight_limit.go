package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	goredis "github.com/redis/go-redis/v9"

	privacyredis "privacy-proxy/internal/redis"
)

// Approval preflight rate limit.
//
// With signed approvals on, every eth_sendRawTransaction that passes RBAC is
// simulated on the node before OPS signs an approval for it. That simulation
// is node compute any authorised caller could otherwise demand as fast as it
// can submit, and every admitted approval occupies the producer's approval
// store until it is released or expires. The limit is a token bucket per
// principal: Rate preflights a second sustained, up to Burst back to back.
//
// With REDIS_URL set the bucket lives in Redis, so every OPS instance draws on
// one budget per principal. Without Redis — like every other state store — it
// is held per instance. If Redis stops answering at run time, each instance
// keeps enforcing the same rate and burst on its own until Redis is back, the
// way the server's other limiters (all in-process) behave regardless of Redis:
// the limit loosens to one budget per instance, but it never disappears and it
// never refuses every caller because Redis is down.

const (
	preflightRateEnv  = "OPS_APPROVAL_PREFLIGHT_RATE"
	preflightBurstEnv = "OPS_APPROVAL_PREFLIGHT_BURST"

	// defaultPreflightRate and defaultPreflightBurst leave interactive users and
	// moderate service accounts untouched while keeping any one principal to a
	// small share of the node: about 3% of the ~650 preflights a second measured
	// end to end with the gate on. Rate × approval TTL bounds what one principal
	// can hold in the producer's approval store (100k): about 12k at the default
	// 10-minute TTL, 72k at the 1-hour maximum. The burst is two seconds of the
	// rate, which absorbs a client that batches its submissions.
	defaultPreflightRate  = 20
	defaultPreflightBurst = 40

	// The bounds keep a misconfiguration from silently disabling the limit and
	// keep every bucket value an exact integer in Redis's Lua (a double).
	minPreflightRate  = 0.001
	maxPreflightRate  = 100_000
	maxPreflightBurst = 100_000

	preflightKeyPrefix = "pp:rl:preflight:"

	// preflightSweepInterval is how often the in-memory limiter drops principals
	// whose bucket is full again; holding them would change nothing.
	preflightSweepInterval = time.Minute
)

// preflightLimit is a per-principal preflight budget.
type preflightLimit struct {
	Rate  float64 // preflights per second, sustained
	Burst int     // preflights back to back after an idle period
}

// interval is the time one preflight uses up, 1/Rate, in whole microseconds so
// the Redis and in-memory buckets agree exactly.
func (l preflightLimit) interval() time.Duration {
	return time.Duration(math.Round(1e6/l.Rate)) * time.Microsecond
}

// tolerance is how far a principal's bucket may run ahead of now.
func (l preflightLimit) tolerance() time.Duration {
	return time.Duration(l.Burst-1) * l.interval()
}

// preflightLimitFromEnv reads OPS_APPROVAL_PREFLIGHT_RATE (preflights per second
// per principal, decimals allowed) and OPS_APPROVAL_PREFLIGHT_BURST. Unset means
// the default; anything else outside the bounds is a start-up error.
func preflightLimitFromEnv() (preflightLimit, error) {
	limit := preflightLimit{Rate: defaultPreflightRate, Burst: defaultPreflightBurst}
	if value := os.Getenv(preflightRateEnv); value != "" {
		rate, err := strconv.ParseFloat(value, 64)
		if err != nil || !(rate >= minPreflightRate && rate <= maxPreflightRate) {
			return preflightLimit{}, fmt.Errorf("%s must be a number of preflights per second between %g and %d", preflightRateEnv, minPreflightRate, maxPreflightRate)
		}
		limit.Rate = rate
	}
	if value := os.Getenv(preflightBurstEnv); value != "" {
		burst, err := strconv.Atoi(value)
		if err != nil || burst < 1 || burst > maxPreflightBurst {
			return preflightLimit{}, fmt.Errorf("%s must be a whole number between 1 and %d", preflightBurstEnv, maxPreflightBurst)
		}
		limit.Burst = burst
	}
	return limit, nil
}

// preflightLimiter decides whether a principal may run one more preflight now,
// and counts it if so.
type preflightLimiter interface {
	Allow(ctx context.Context, principal string) bool
}

var (
	_ preflightLimiter = (*localPreflightLimiter)(nil)
	_ preflightLimiter = (*redisPreflightLimiter)(nil)
)

// configurePreflightLimit installs the preflight limit when signed approvals are
// on; it runs right after configureNodeApprovals. The settings are read and
// validated only then, like the other OPS_APPROVAL_* settings. A processor with
// approvals but no limit refuses every preflight (limitPreflight).
func (p *JSONRPCProcessor) configurePreflightLimit(client *privacyredis.Client) error {
	if p.nodeApprovals == nil {
		return nil
	}
	limit, err := preflightLimitFromEnv()
	if err != nil {
		return err
	}
	if client != nil {
		p.preflightLimiter = newRedisPreflightLimiter(client, limit)
	} else {
		p.preflightLimiter = newLocalPreflightLimiter(limit)
	}
	slog.Info("approval preflight rate limit", "rate_per_second", limit.Rate, "burst", limit.Burst, "shared_through_redis", client != nil)
	return nil
}

// limitPreflight refuses a call whose principal is over its preflight budget,
// before anything is simulated. nil means the preflight may run. Callers
// without an identity, should any group ever let them send, share one budget.
// The budget is spent even when Prepare then rejects the transaction without
// asking the node (an unsupported transaction type): that costs only the
// caller.
func (p *JSONRPCProcessor) limitPreflight(ctx context.Context, req *ProcessRequest, start time.Time) *ProcessResult {
	if p.preflightLimiter == nil {
		// Signed approvals are on but the limit was never installed: a wiring
		// fault. Refuse, as for a preflight that cannot run, rather than
		// simulate without a bound.
		slog.Error("signed preflight refused: approval preflight rate limit not configured")
		p.recordRPCOutcome(req.Method, "preflight_unavailable", start)
		req.denialReason = ReasonTracingUnavailable
		p.logAccess(ctx, req, http.StatusForbidden)
		return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusForbidden, Message: "signed preflight unavailable or unsupported transaction", Reason: ReasonTracingUnavailable}}
	}
	if p.preflightLimiter.Allow(ctx, req.UserID) {
		return nil
	}
	p.recordRPCOutcome(req.Method, "preflight_rate_limited", start)
	req.denialReason = ReasonRateLimited
	p.logAccess(ctx, req, http.StatusTooManyRequests)
	return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusTooManyRequests, Message: rateLimitExceededPerSecond, Reason: ReasonRateLimited}}
}

// localPreflightLimiter holds the buckets in process memory: the limit when
// REDIS_URL is unset, and each instance's stand-in while Redis is unreachable.
// A bucket is its theoretical arrival time (GCRA): a preflight is admitted
// while that time is at most tolerance ahead of now, and pushes it one
// interval further.
type localPreflightLimiter struct {
	interval  time.Duration
	tolerance time.Duration
	now       func() time.Time

	mu        sync.Mutex
	tat       map[string]time.Time
	lastSweep time.Time
}

func newLocalPreflightLimiter(limit preflightLimit) *localPreflightLimiter {
	return &localPreflightLimiter{
		interval:  limit.interval(),
		tolerance: limit.tolerance(),
		now:       time.Now,
		tat:       make(map[string]time.Time),
	}
}

func (l *localPreflightLimiter) Allow(_ context.Context, principal string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastSweep) >= preflightSweepInterval {
		for key, tat := range l.tat {
			if !tat.After(now) {
				delete(l.tat, key)
			}
		}
		l.lastSweep = now
	}
	tat, ok := l.tat[principal]
	if !ok || tat.Before(now) {
		tat = now
	}
	if tat.Sub(now) > l.tolerance {
		return false
	}
	l.tat[principal] = tat.Add(l.interval)
	return true
}

// preflightBucketScript is localPreflightLimiter.Allow on a bucket kept in
// Redis, atomically, so every OPS instance draws on one budget per principal.
// Time is the Redis server's, so instances whose clocks drift still agree. The
// key expires when the bucket is full again, which is when it stops mattering.
// A call never resets a bucket it finds further ahead than its own settings
// allow: while a settings change rolls out, each instance enforces its own
// limit on the one shared budget. (A Redis clock that steps back delays
// refills by the step instead.)
//
// The script must never answer with an error: the Redis client's circuit
// breaker, shared with sessions and OAuth, counts every error reply as a
// failure, and this runs once per transaction. So a missing or unreadable value
// is a full bucket, the expiry is at least 1 ms, the script is sent with EVAL
// rather than EVALSHA (no NOSCRIPT replies after a Redis restart), and it asks
// for effect replication, without which a Redis older than 5 refuses a write
// after TIME (from 7 on it is the only mode and the call a no-op).
//
// KEYS[1] = bucket key; value = theoretical arrival time, microseconds
// ARGV[1] = interval, microseconds
// ARGV[2] = tolerance, microseconds
//
// Returns 1 when the preflight may run, 0 when the principal is over its limit.
var preflightBucketScript = goredis.NewScript(`
if redis.replicate_commands then redis.replicate_commands() end
local now = redis.call('TIME')
now = tonumber(now[1]) * 1000000 + tonumber(now[2])
local interval = tonumber(ARGV[1])
local tolerance = tonumber(ARGV[2])
local tat = tonumber(redis.call('GET', KEYS[1])) or 0
if tat < now then tat = now end
if tat - now > tolerance then return 0 end
tat = tat + interval
local ttl = math.max(1, math.ceil((tat - now) / 1000))
redis.call('SET', KEYS[1], string.format('%d', tat), 'PX', string.format('%d', ttl))
return 1
`)

// redisPreflightLimiter keeps the buckets in Redis and falls back to its own
// in-memory buckets for any call Redis does not answer.
type redisPreflightLimiter struct {
	client          *privacyredis.Client
	intervalMicros  int64
	toleranceMicros int64
	local           *localPreflightLimiter
	degraded        atomic.Bool
}

func newRedisPreflightLimiter(client *privacyredis.Client, limit preflightLimit) *redisPreflightLimiter {
	return &redisPreflightLimiter{
		client:          client,
		intervalMicros:  limit.interval().Microseconds(),
		toleranceMicros: limit.tolerance().Microseconds(),
		local:           newLocalPreflightLimiter(limit),
	}
}

func (l *redisPreflightLimiter) Allow(ctx context.Context, principal string) bool {
	admitted, err := preflightBucketScript.Eval(ctx, l.client, []string{preflightLimitKey(principal)}, l.intervalMicros, l.toleranceMicros).Int()
	if err != nil {
		// A caller that gave up says nothing about Redis.
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && l.degraded.CompareAndSwap(false, true) {
			slog.Warn("approval preflight rate limit: Redis unavailable; enforcing the limit per instance until it answers again", "error", err)
		}
		return l.local.Allow(ctx, principal)
	}
	if l.degraded.CompareAndSwap(true, false) {
		slog.Info("approval preflight rate limit: Redis answering again; limit shared across instances")
	}
	return admitted == 1
}

// preflightLimitKey names a principal's bucket by a digest of the principal, so
// the shared keyspace does not list who is submitting transactions.
func preflightLimitKey(principal string) string {
	sum := sha256.Sum256([]byte(principal))
	return preflightKeyPrefix + hex.EncodeToString(sum[:])
}
