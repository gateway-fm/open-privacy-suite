package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/nodeapproval"
	privacyredis "privacy-proxy/internal/redis"
)

func TestPreflightLimitFromEnv(t *testing.T) {
	tests := []struct {
		name    string
		rate    string
		burst   string
		want    preflightLimit
		wantErr string
	}{
		{name: "defaults", want: preflightLimit{Rate: 20, Burst: 40}},
		{name: "whole rate and burst", rate: "5", burst: "10", want: preflightLimit{Rate: 5, Burst: 10}},
		{name: "fractional rate", rate: "0.5", want: preflightLimit{Rate: 0.5, Burst: 40}},
		{name: "burst of one", burst: "1", want: preflightLimit{Rate: 20, Burst: 1}},
		{name: "largest values", rate: "100000", burst: "100000", want: preflightLimit{Rate: 100000, Burst: 100000}},
		{name: "smallest rate", rate: "0.001", want: preflightLimit{Rate: 0.001, Burst: 40}},
		{name: "rate not a number", rate: "fast", wantErr: preflightRateEnv},
		{name: "rate zero", rate: "0", wantErr: preflightRateEnv},
		{name: "rate below the floor", rate: "0.0005", wantErr: preflightRateEnv},
		{name: "rate negative", rate: "-1", wantErr: preflightRateEnv},
		{name: "rate NaN", rate: "NaN", wantErr: preflightRateEnv},
		{name: "rate infinite", rate: "Inf", wantErr: preflightRateEnv},
		{name: "rate above the ceiling", rate: "100000.5", wantErr: preflightRateEnv},
		{name: "rate with a unit", rate: "20/s", wantErr: preflightRateEnv},
		{name: "burst not a number", burst: "lots", wantErr: preflightBurstEnv},
		{name: "burst zero", burst: "0", wantErr: preflightBurstEnv},
		{name: "burst negative", burst: "-3", wantErr: preflightBurstEnv},
		{name: "burst fractional", burst: "2.5", wantErr: preflightBurstEnv},
		{name: "burst above the ceiling", burst: "100001", wantErr: preflightBurstEnv},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(preflightRateEnv, tt.rate)
			t.Setenv(preflightBurstEnv, tt.burst)
			got, err := preflightLimitFromEnv()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestConfigurePreflightLimit(t *testing.T) {
	approvals := func(t *testing.T) *nodeapproval.Service {
		t.Helper()
		isolateApprovalEnv(t)
		// Opens no connection: the RPC client dials on first use.
		service, err := nodeapproval.NewPreflight("http://127.0.0.1:1")
		require.NoError(t, err)
		t.Cleanup(service.Close)
		return service
	}
	redisClient := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = redisClient.Close() })

	t.Run("signed approvals off: no limit and the settings are not read", func(t *testing.T) {
		t.Setenv(preflightRateEnv, "fast")
		p := &JSONRPCProcessor{}
		require.NoError(t, p.configurePreflightLimit(redisClient))
		require.Nil(t, p.preflightLimiter)
	})
	t.Run("signed approvals on: invalid settings stop start-up", func(t *testing.T) {
		p := &JSONRPCProcessor{nodeApprovals: approvals(t)}
		t.Setenv(preflightBurstEnv, "0")
		require.ErrorContains(t, p.configurePreflightLimit(redisClient), preflightBurstEnv)
	})
	t.Run("signed approvals on without Redis: per-instance limit", func(t *testing.T) {
		p := &JSONRPCProcessor{nodeApprovals: approvals(t)}
		require.NoError(t, p.configurePreflightLimit(nil))
		require.IsType(t, &localPreflightLimiter{}, p.preflightLimiter)
	})
	t.Run("signed approvals on with Redis: limit shared through Redis", func(t *testing.T) {
		p := &JSONRPCProcessor{nodeApprovals: approvals(t)}
		require.NoError(t, p.configurePreflightLimit(redisClient))
		require.IsType(t, &redisPreflightLimiter{}, p.preflightLimiter)
	})
}

func TestLocalPreflightLimiter_BurstThenRate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newLocalPreflightLimiter(preflightLimit{Rate: 10, Burst: 3})
	l.now = func() time.Time { return now }
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		require.True(t, l.Allow(ctx, "alice"), "burst preflight %d", i+1)
	}
	require.False(t, l.Allow(ctx, "alice"), "over the burst")
	require.True(t, l.Allow(ctx, "bob"), "another principal has its own budget")

	now = now.Add(99 * time.Millisecond)
	require.False(t, l.Allow(ctx, "alice"), "a tenth of a second has not passed")
	now = now.Add(time.Millisecond)
	require.True(t, l.Allow(ctx, "alice"), "one preflight back after 1/rate")
	require.False(t, l.Allow(ctx, "alice"))

	now = now.Add(time.Hour)
	for i := 0; i < 3; i++ {
		require.True(t, l.Allow(ctx, "alice"), "an idle principal gets its burst back, preflight %d", i+1)
	}
	require.False(t, l.Allow(ctx, "alice"), "idle time never adds more than the burst")
}

func TestLocalPreflightLimiter_CallersWithoutIdentityShareOneBudget(t *testing.T) {
	l := newLocalPreflightLimiter(preflightLimit{Rate: 0.001, Burst: 1})
	ctx := context.Background()
	require.True(t, l.Allow(ctx, ""))
	require.False(t, l.Allow(ctx, ""), "no identity is one principal, never an exemption")
}

func TestLocalPreflightLimiter_ForgetsIdlePrincipals(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newLocalPreflightLimiter(preflightLimit{Rate: 1, Burst: 1})
	l.now = func() time.Time { return now }
	ctx := context.Background()
	require.True(t, l.Allow(ctx, "alice"))
	require.True(t, l.Allow(ctx, "bob"))
	now = now.Add(2 * preflightSweepInterval)
	require.True(t, l.Allow(ctx, "carol"))
	l.mu.Lock()
	defer l.mu.Unlock()
	require.Len(t, l.tat, 1, "principals whose budget is full again are dropped")
}

func TestLocalPreflightLimiter_ConcurrentCallersShareOneBudget(t *testing.T) {
	l := newLocalPreflightLimiter(preflightLimit{Rate: 0.001, Burst: 10})
	var admitted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow(context.Background(), "alice") {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 10, admitted.Load())
}

func TestRedisPreflightLimiter(t *testing.T) {
	redisURL := startPreflightTestRedis(t)
	ctx := context.Background()

	t.Run("refills at the configured rate and the key expires once full", func(t *testing.T) {
		client := connectPreflightRedis(t, redisURL)
		l := newRedisPreflightLimiter(client, preflightLimit{Rate: 1, Burst: 1})
		principal := "did:test:refill"
		require.True(t, l.Allow(ctx, principal))
		require.False(t, l.Allow(ctx, principal), "one per second")
		stored, err := client.Get(ctx, preflightLimitKey(principal)).Result()
		require.NoError(t, err)
		_, err = strconv.ParseInt(stored, 10, 64)
		require.NoError(t, err, "the bucket holds whole microseconds: %q", stored)
		ttl, err := client.PTTL(ctx, preflightLimitKey(principal)).Result()
		require.NoError(t, err)
		require.Positive(t, ttl, "the bucket key must expire")
		require.LessOrEqual(t, ttl, time.Second, "no longer than it takes to refill")
		time.Sleep(1100 * time.Millisecond)
		require.True(t, l.Allow(ctx, principal), "back after 1/rate")
		require.False(t, l.degraded.Load(), "every call was answered by Redis")
	})

	// The script shares the client's circuit breaker with sessions and OAuth,
	// so it must answer without an error at every setting the bounds allow.
	t.Run("answers without an error at the extremes of the settings", func(t *testing.T) {
		client := connectPreflightRedis(t, redisURL)
		for _, limit := range []preflightLimit{
			{Rate: maxPreflightRate, Burst: 1},
			{Rate: maxPreflightRate, Burst: maxPreflightBurst},
			{Rate: minPreflightRate, Burst: 1},
			{Rate: minPreflightRate, Burst: maxPreflightBurst},
		} {
			key := preflightLimitKey(fmt.Sprintf("did:test:extreme-%g-%d", limit.Rate, limit.Burst))
			for i := 0; i < 3; i++ {
				_, err := preflightBucketScript.Eval(ctx, client, []string{key},
					limit.interval().Microseconds(), limit.tolerance().Microseconds()).Int()
				require.NoError(t, err, "%+v, call %d", limit, i+1)
			}
		}
	})

	// While a settings change rolls out, instances with old and new settings
	// share the bucket; neither may hand back budget the other spent.
	t.Run("an instance with a smaller burst leaves the spent budget spent", func(t *testing.T) {
		principal := "did:test:rolling-change"
		larger := newRedisPreflightLimiter(connectPreflightRedis(t, redisURL), preflightLimit{Rate: 0.001, Burst: 10})
		smaller := newRedisPreflightLimiter(connectPreflightRedis(t, redisURL), preflightLimit{Rate: 0.001, Burst: 2})
		for i := 0; i < 10; i++ {
			require.True(t, larger.Allow(ctx, principal), "preflight %d", i+1)
		}
		require.False(t, smaller.Allow(ctx, principal), "over the smaller burst as well")
		require.False(t, larger.Allow(ctx, principal), "the larger budget is still spent")
	})

	t.Run("instances admit exactly one burst between them", func(t *testing.T) {
		instances := []*redisPreflightLimiter{
			newRedisPreflightLimiter(connectPreflightRedis(t, redisURL), preflightLimit{Rate: 0.001, Burst: 10}),
			newRedisPreflightLimiter(connectPreflightRedis(t, redisURL), preflightLimit{Rate: 0.001, Burst: 10}),
		}
		var admitted atomic.Int64
		var wg sync.WaitGroup
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func(l *redisPreflightLimiter) {
				defer wg.Done()
				if l.Allow(ctx, "did:test:concurrent") {
					admitted.Add(1)
				}
			}(instances[i%2])
		}
		wg.Wait()
		require.EqualValues(t, 10, admitted.Load())
	})

	t.Run("the principal is not written into Redis", func(t *testing.T) {
		client := connectPreflightRedis(t, redisURL)
		principal := "did:test:private-principal"
		require.True(t, newRedisPreflightLimiter(client, preflightLimit{Rate: 1, Burst: 5}).Allow(ctx, principal))
		keys, err := client.Keys(ctx, "*private-principal*").Result()
		require.NoError(t, err)
		require.Empty(t, keys)
		require.Equal(t, int64(1), client.Exists(ctx, preflightLimitKey(principal)).Val())
	})
}

// switchableRedis dials Redis until it is switched off. While off, new dials
// fail and open connections fail on their next read or write, as they do when
// Redis goes away.
type switchableRedis struct{ down atomic.Bool }

var errRedisSwitchedOff = errors.New("redis switched off by the test")

func (s *switchableRedis) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if s.down.Load() {
		return nil, errRedisSwitchedOff
	}
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &switchableConn{Conn: conn, redis: s}, nil
}

type switchableConn struct {
	net.Conn
	redis *switchableRedis
}

func (c *switchableConn) Read(b []byte) (int, error) {
	if c.redis.down.Load() {
		return 0, errRedisSwitchedOff
	}
	return c.Conn.Read(b)
}

func (c *switchableConn) Write(b []byte) (int, error) {
	if c.redis.down.Load() {
		return 0, errRedisSwitchedOff
	}
	return c.Conn.Write(b)
}

// cutOffRedisClient connects to redisURL through a switch the test can turn
// off, with no retries so each failure is one call.
func cutOffRedisClient(t *testing.T, redisURL string, breaker goredis.Limiter) (*privacyredis.Client, *switchableRedis) {
	t.Helper()
	outage := &switchableRedis{}
	options, err := goredis.ParseURL(redisURL)
	require.NoError(t, err)
	options.Dialer = outage.dial
	options.MaxRetries = -1
	options.Limiter = breaker
	client := goredis.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })
	return client, outage
}

// While one instance cannot reach Redis it keeps enforcing the same rate and
// burst on its own — also once the server's circuit breaker has opened and
// every call fails fast — so the limit loosens to one budget per instance but
// never disappears and never refuses everyone.
func TestRedisPreflightLimiter_RedisOutage(t *testing.T) {
	redisURL := startPreflightTestRedis(t)
	limit := preflightLimit{Rate: 0.001, Burst: 2}
	ctx := context.Background()
	healthy := newRedisPreflightLimiter(connectPreflightRedis(t, redisURL), limit)
	client, outage := cutOffRedisClient(t, redisURL, privacyredis.NewCircuitBreaker(5, time.Minute))
	cutOff := newRedisPreflightLimiter(client, limit)

	require.True(t, healthy.Allow(ctx, "alice"))
	require.True(t, cutOff.Allow(ctx, "alice"))
	require.False(t, cutOff.Allow(ctx, "alice"), "one budget across instances while Redis answers")

	outage.down.Store(true)
	require.True(t, cutOff.Allow(ctx, "alice"))
	require.True(t, cutOff.Allow(ctx, "alice"))
	require.False(t, cutOff.Allow(ctx, "alice"), "the burst still applies without Redis")
	require.True(t, cutOff.degraded.Load())
	for i := 0; i < 5; i++ {
		cutOff.Allow(ctx, fmt.Sprintf("did:test:outage-%d", i))
	}
	require.ErrorIs(t, client.Ping(ctx).Err(), privacyredis.ErrCircuitOpen, "the failures have opened the breaker")
	require.True(t, cutOff.Allow(ctx, "bob"))
	require.True(t, cutOff.Allow(ctx, "bob"))
	require.False(t, cutOff.Allow(ctx, "bob"), "the burst still applies with the breaker open")
	require.False(t, healthy.Allow(ctx, "alice"), "instances that reach Redis keep the shared budget")
}

// The instance never latches onto its own budget: the first call Redis answers
// puts it back on the shared one.
func TestRedisPreflightLimiter_BackOnSharedBudgetOnceRedisAnswers(t *testing.T) {
	redisURL := startPreflightTestRedis(t)
	limit := preflightLimit{Rate: 0.001, Burst: 2}
	ctx := context.Background()
	healthy := newRedisPreflightLimiter(connectPreflightRedis(t, redisURL), limit)
	client, outage := cutOffRedisClient(t, redisURL, nil)
	cutOff := newRedisPreflightLimiter(client, limit)

	require.True(t, healthy.Allow(ctx, "alice"))
	require.True(t, healthy.Allow(ctx, "alice"))
	outage.down.Store(true)
	require.True(t, cutOff.Allow(ctx, "alice"), "alone, the instance has its own budget")
	require.True(t, cutOff.Allow(ctx, "bob"))
	require.True(t, cutOff.degraded.Load())

	outage.down.Store(false)
	require.False(t, cutOff.Allow(ctx, "alice"), "the shared budget applies again")
	require.False(t, cutOff.degraded.Load())
	require.True(t, cutOff.Allow(ctx, "bob"))
	require.True(t, cutOff.Allow(ctx, "bob"), "what bob spent alone stayed with that instance")
	require.False(t, cutOff.Allow(ctx, "bob"))
}
