package nodeapproval

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"privacy-proxy/internal/nodeapproval/approvalpb"
)

// Delivery defaults (wire contract §7) and the fixed intervals around them.
const (
	defaultDeliveryTimeout = 2 * time.Second
	defaultMaxInFlight     = 8
	defaultRetainMax       = 100_000
	maxDeliveryTimeout     = time.Minute
	maxInFlightLimit       = 1024

	// statusEvery is how often a lane asks its producer for Status while connected; readyWindow
	// is how recent a matching answer must be for Enqueue to accept (wire contract §4, §5).
	statusEvery = time.Second
	readyWindow = 5 * time.Second
	// drainTimeout bounds how long a graceful stop keeps delivering what Enqueue had already
	// accepted. Every accepted approval belongs to a transaction that is being forwarded;
	// dropping it at shutdown means a timeout for that transaction.
	drainTimeout = 2 * time.Second
	// pruneEvery is how often the signer forgets expired batches while nothing new arrives.
	pruneEvery = time.Second
)

// Pacing. Reconnects back off from 100 ms to at most 1 s and resolve the target name on every
// attempt, so a producer restarting on a new address is reached within about a second (wire
// contract §1). A lane that is refused backs off as a whole, from 50 ms to 1 s, probing with a
// single call meanwhile (§5).
const (
	connectBaseDelay = 100 * time.Millisecond
	connectMaxDelay  = time.Second
	connectTimeout   = time.Second
	keepaliveTime    = 20 * time.Second
	keepaliveTimeout = 5 * time.Second
	retryBaseDelay   = 50 * time.Millisecond
	retryMaxDelay    = time.Second
	reconnectPause   = 100 * time.Millisecond
	logEvery         = 10 * time.Second
)

// A full store answers UNAVAILABLE with this trailer (wire contract §3, check 8).
const (
	reasonTrailer   = "ops-approval-reason"
	storeFullReason = "store-full"
)

// errNoProducerReady is Enqueue's refusal when no producer could take the approval.
var errNoProducerReady = errors.New("no approval producer is ready")

// deliveryConfig is where and how signed batches are delivered.
type deliveryConfig struct {
	targets     []string
	timeout     time.Duration
	maxInFlight int
	retainMax   int
	// Fixed in production; tests shorten them.
	statusEvery time.Duration
	readyWindow time.Duration
	drain       time.Duration
	// dialer replaces gRPC's own TCP dialer; tests use in-memory listeners.
	dialer func(ctx context.Context, addr string) (net.Conn, error)
}

// configuredDelivery reads the delivery settings (wire contract §7); targets is the value of
// OPS_APPROVAL_TARGETS. An invalid value fails start-up rather than being clamped.
func configuredDelivery(targets string) (deliveryConfig, error) {
	list, err := parseTargets(targets)
	if err != nil {
		return deliveryConfig{}, err
	}
	cfg := deliveryConfig{targets: list, timeout: defaultDeliveryTimeout, maxInFlight: defaultMaxInFlight,
		retainMax: defaultRetainMax, statusEvery: statusEvery, readyWindow: readyWindow, drain: drainTimeout}
	if value := os.Getenv("OPS_APPROVAL_DELIVERY_TIMEOUT"); value != "" {
		d, err := time.ParseDuration(value)
		if err != nil || d < time.Millisecond || d > maxDeliveryTimeout {
			return deliveryConfig{}, errors.New("OPS_APPROVAL_DELIVERY_TIMEOUT must be a duration between 1ms and 1m")
		}
		cfg.timeout = d
	}
	if value := os.Getenv("OPS_APPROVAL_MAX_IN_FLIGHT"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > maxInFlightLimit {
			return deliveryConfig{}, fmt.Errorf("OPS_APPROVAL_MAX_IN_FLIGHT must be an integer between 1 and %d", maxInFlightLimit)
		}
		cfg.maxInFlight = n
	}
	if value := os.Getenv("OPS_APPROVAL_RETAIN_MAX"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < MaxBatchApprovals {
			return deliveryConfig{}, fmt.Errorf("OPS_APPROVAL_RETAIN_MAX must be an integer of at least %d approvals", MaxBatchApprovals)
		}
		cfg.retainMax = n
	}
	return cfg, nil
}

// parseTargets reads OPS_APPROVAL_TARGETS: a comma-separated list of distinct host:port.
func parseTargets(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errors.New("OPS_APPROVAL_TARGETS must list at least one producer as host:port")
	}
	var targets []string
	for _, part := range strings.Split(value, ",") {
		target := strings.TrimSpace(part)
		host, port, err := net.SplitHostPort(target)
		if err == nil && host == "" {
			err = errors.New("no host")
		}
		if err == nil {
			var n uint64
			if n, err = strconv.ParseUint(port, 10, 16); err == nil && n == 0 {
				err = errors.New("port 0")
			}
		}
		if err != nil {
			return nil, fmt.Errorf("OPS_APPROVAL_TARGETS must be a comma-separated list of host:port; %q is not one", target)
		}
		if slices.Contains(targets, target) {
			return nil, fmt.Errorf("OPS_APPROVAL_TARGETS lists %s twice", target)
		}
		targets = append(targets, target)
	}
	return targets, nil
}

// startDelivery opens a lane per target and starts the signer. Lanes connect in the background:
// a producer that is down at start-up does not stop OPS, it only is not ready.
func (s *Service) startDelivery(cfg deliveryConfig) error {
	s.metrics = newDeliveryMetrics()
	s.retain = newRetention(cfg.retainMax, s.metrics)
	s.queue = make(chan Approval, 4096)
	s.drain = cfg.drain
	for i, target := range cfg.targets {
		l, err := newLane(s, i, target, cfg)
		if err != nil {
			for _, open := range s.lanes {
				_ = open.conn.Close()
			}
			s.lanes = nil
			return err
		}
		s.lanes = append(s.lanes, l)
	}
	s.retain.lanes = s.lanes
	run, cancel := context.WithCancel(context.Background())
	stop, halt := context.WithCancel(context.Background())
	s.cancel, s.stop = cancel, halt
	s.signDone = make(chan struct{})
	go s.signLoop(run)
	for _, l := range s.lanes {
		go l.run(stop)
		go l.watch(stop)
	}
	return nil
}

// stopDelivery lets every lane deliver what was signed, for at most the drain timeout, then
// stops them and closes their connections. The signer has already stopped.
func (s *Service) stopDelivery() {
	if len(s.lanes) == 0 {
		return
	}
	deadline := time.NewTimer(s.drain)
	defer deadline.Stop()
drain:
	for _, l := range s.lanes {
		select {
		case <-l.done:
		case <-deadline.C:
			break drain
		}
	}
	s.stop()
	for _, l := range s.lanes {
		<-l.done
		<-l.watched
		if err := l.conn.Close(); err != nil {
			slog.Warn("approval connection close failed", "target", l.target, "error", err)
		}
		l.report()
	}
}

// ready reports whether some producer can take an approval for chain now.
func (s *Service) ready(chain uint64, now time.Time) bool {
	for _, l := range s.lanes {
		if l.readyFor(chain, now) {
			return true
		}
	}
	return false
}

// Accepting reports whether some producer is ready to take approvals, whatever its chain. The
// request path asks before it spends a preflight on the node; Enqueue then checks the chain.
func (s *Service) Accepting() bool {
	now := time.Now().UnixNano()
	for _, l := range s.lanes {
		if now < l.readyUntil.Load() {
			return true
		}
	}
	return false
}

// signingTTL is OPS_APPROVAL_TTL shortened to the smallest maximum TTL a producer reported, so
// no producer refuses a batch for its lifetime (wire contract §5).
func (s *Service) signingTTL() time.Duration {
	ttl := s.ttl
	for _, l := range s.lanes {
		if ms := l.maxTTL.Load(); ms > 0 && time.Duration(ms)*time.Millisecond < ttl {
			ttl = time.Duration(ms) * time.Millisecond
		}
	}
	return ttl
}

// lane delivers every signed batch to one producer over one gRPC connection. It bounds the calls
// in flight, backs off as a whole while the producer refuses, redelivers after a restart, and
// knows whether the producer is ready (wire contract §4, §5).
type lane struct {
	s           *Service
	target      string
	index       int
	conn        *grpc.ClientConn
	client      approvalpb.ApprovalDeliveryClient
	timeout     time.Duration
	maxInFlight int
	statusEvery time.Duration
	readyWindow time.Duration
	wake        chan struct{} // capacity 1: the dispatcher may have something to do

	// cursor is the newest batch this lane took as fresh; guarded by s.retain.mu.
	cursor uint64

	mu      sync.Mutex
	calls   int    // Deliver calls in flight
	retries []*job // refused for now; they wait without holding a call slot, oldest first
	redo    redelivery
	backoff laneBackoff
	gen     uint64 // connection generation: one per READY
	boot    string // the producer process that confirmed what this lane sent

	// Read by Enqueue and the signer without a lock.
	readyChain atomic.Uint64
	readyUntil atomic.Int64 // Unix nanoseconds; 0 while not ready
	maxTTL     atomic.Int64 // milliseconds, from the last Status; 0 until one arrives

	connections atomic.Int64 // READY transitions, for the shutdown report
	abandoned   atomic.Int64 // calls cut short by the end of the drain
	log         logGate
	done        chan struct{} // the dispatcher and its calls have ended
	watched     chan struct{} // the connection watcher has ended
}

// job is one batch on its way to one producer; it survives retries.
type job struct {
	e       *entry
	fresh   bool // sent to this producer for the first time, not redelivered
	probe   bool // the single call a backing-off lane allows
	started bool // its first call is marked in the hop recorder
}

// redelivery is a lane's pass over the retained batches after its producer restarted, from next
// down to low. A lane runs at most one; a later restart starts it over from the newest.
type redelivery struct {
	active    bool
	next, low uint64
}

// laneBackoff is a lane's refusal state: while active, one probe call at a time, once until has
// passed. The probe's answer ends the backoff or extends it.
type laneBackoff struct {
	active  bool
	probing bool
	attempt int
	until   time.Time
}

// outcome is how a call ends for its job.
type outcome int

const (
	outcomeDone      outcome = iota // stored, or refused for good: the job is over
	outcomeRetry                    // refused for now: the job waits for another call
	outcomeExpired                  // expires_at passed before the call: over, counted
	outcomeAbandoned                // cut short by the end of the drain
)

func newLane(s *Service, index int, target string, cfg deliveryConfig) (*lane, error) {
	options := []grpc.DialOption{
		// Plaintext by decision (production plan §0.3): the Ed25519 signature protects every batch,
		// and a network rule lets only OPS reach the producer's port.
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: keepaliveTime, Timeout: keepaliveTimeout, PermitWithoutStream: true}),
		grpc.WithConnectParams(grpc.ConnectParams{MinConnectTimeout: connectTimeout,
			Backoff: backoff.Config{BaseDelay: connectBaseDelay, Multiplier: 1.6, Jitter: 0.2, MaxDelay: connectMaxDelay}}),
		// Retries are OPS's own (wire contract §1, §5): no gRPC retry policy, no service config.
		grpc.WithDisableRetry(),
		grpc.WithDisableServiceConfig(),
		// An idle channel closes its connection and would notice a producer restart only at the
		// next batch; a lane keeps its connection open for the life of OPS.
		grpc.WithIdleTimeout(0),
	}
	if cfg.dialer != nil {
		options = append(options, grpc.WithContextDialer(cfg.dialer))
	}
	// passthrough hands the name to the dialer, which resolves it on every attempt; gRPC's DNS
	// resolver would re-resolve at most every 30 s.
	conn, err := grpc.NewClient("passthrough:///"+target, options...)
	if err != nil {
		return nil, fmt.Errorf("approval target %s: %w", target, err)
	}
	l := &lane{s: s, target: target, index: index, conn: conn, client: approvalpb.NewApprovalDeliveryClient(conn),
		timeout: cfg.timeout, maxInFlight: cfg.maxInFlight, statusEvery: cfg.statusEvery, readyWindow: cfg.readyWindow,
		wake: make(chan struct{}, 1), done: make(chan struct{}), watched: make(chan struct{})}
	// Every series exists from the start, so rates and alerts see zero rather than nothing.
	m := s.metrics
	m.connected.WithLabelValues(target).Set(0)
	m.inFlight.WithLabelValues(target).Set(0)
	m.retries.WithLabelValues(target)
	m.redeliveries.WithLabelValues(target)
	m.latency.WithLabelValues(target)
	for _, reason := range []string{dropPermanent, dropExpired, dropEvicted} {
		m.dropped.WithLabelValues(target, reason)
	}
	return l, nil
}

func (l *lane) notify() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

// readyFor reports whether this producer can take an approval for chain: connected, and it
// answered Status on this connection within the ready window, for that chain, trusting the key
// OPS signs with.
func (l *lane) readyFor(chain uint64, now time.Time) bool {
	return now.UnixNano() < l.readyUntil.Load() && l.readyChain.Load() == chain
}

// run hands batches to calls: fresh ones first, then retries, then the redelivery; never more
// calls than maxInFlight, and one at a time while the producer refuses. It returns once the drain
// is complete or stop ends, after its calls have.
func (l *lane) run(stop context.Context) {
	defer close(l.done)
	var calls sync.WaitGroup
	defer calls.Wait()
	for {
		j, wait, finished := l.next(time.Now())
		if j != nil {
			calls.Add(1)
			go func() {
				defer calls.Done()
				l.send(stop, j)
			}()
			continue
		}
		if finished || !l.idle(stop, wait) {
			return
		}
	}
}

// idle waits for a wake-up, for wait when it is positive, or for stop; false means stop.
func (l *lane) idle(stop context.Context, wait time.Duration) bool {
	var timeout <-chan time.Time
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-l.wake:
	case <-timeout:
	case <-stop.Done():
		return false
	}
	return true
}

// next is the job to send now; otherwise how long a backing-off lane waits before its probe, and
// whether the drain is complete.
func (l *lane) next(now time.Time) (*job, time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.calls >= l.maxInFlight {
		return nil, 0, false
	}
	probe := l.backoff.active
	if probe {
		if l.backoff.probing {
			return nil, 0, false
		}
		if wait := l.backoff.until.Sub(now); wait > 0 {
			return nil, wait, false
		}
	}
	j, finished := l.pickLocked(now)
	if j == nil {
		return nil, 0, finished && l.calls == 0
	}
	j.probe = probe
	l.backoff.probing = probe
	l.calls++
	return j, 0, false
}

// pickLocked chooses among what waits: fresh batches first, then retries (oldest first), then the
// redelivery (newest first). finished reports that nothing is left and the signer has stopped.
func (l *lane) pickLocked(now time.Time) (*job, bool) {
	e, finished := l.s.retain.takeFresh(l, now)
	if e != nil {
		return &job{e: e, fresh: true}, false
	}
	for len(l.retries) > 0 {
		j := l.retries[0]
		l.retries[0] = nil
		l.retries = l.retries[1:]
		if now.Before(j.e.expires) {
			return j, false
		}
		l.lost(dropExpired, len(j.e.batch.Approvals), now, nil)
	}
	if e := l.s.retain.redeliver(&l.redo, now); e != nil {
		return &job{e: e}, false
	}
	return nil, finished
}

// send makes one Deliver call for the job and settles what follows from its status.
func (l *lane) send(stop context.Context, j *job) {
	e := j.e
	now := time.Now()
	if !now.Before(e.expires) {
		l.settle(j, outcomeExpired, now)
		return
	}
	hop := j.fresh && l.index == 0 // the hop recorder follows the first delivery to the first target
	if hop && !j.started {
		j.started = true
		mark(e.batch.Approvals, func(h *Hop, n int64) { h.CallStart = n })
	}
	gen := l.generation()
	deadline := now.Add(l.timeout)
	if e.expires.Before(deadline) {
		deadline = e.expires
	}
	ctx, cancel := context.WithDeadline(stop, deadline)
	var trailer metadata.MD
	inFlight := l.s.metrics.inFlight.WithLabelValues(l.target)
	inFlight.Inc()
	resp, err := l.client.Deliver(ctx, &approvalpb.DeliverRequest{Batch: e.batch.Encoded()}, grpc.Trailer(&trailer))
	inFlight.Dec()
	cancel()
	if err != nil && stop.Err() != nil {
		l.abandoned.Add(1)
		l.settle(j, outcomeAbandoned, time.Now())
		return
	}
	now = time.Now()
	code := status.Code(err)
	label := code.String()
	if code == codes.Unavailable && slices.Contains(trailer.Get(reasonTrailer), storeFullReason) {
		label = "StoreFull"
	}
	l.s.metrics.batches.WithLabelValues(l.target, label).Inc()
	switch {
	case err == nil:
		if hop {
			mark(e.batch.Approvals, func(h *Hop, n int64) { h.Stored = n })
		}
		if j.fresh {
			l.s.metrics.latency.WithLabelValues(l.target).Observe(now.Sub(e.signed).Seconds())
		}
		if int(resp.GetStored()) != len(e.batch.Approvals) {
			if held, ok := l.log.allow("stored", now); ok {
				slog.Warn("approval producer confirmed a batch with a different count", "target", l.target,
					"approvals", len(e.batch.Approvals), "stored", resp.GetStored(), "suppressed", held)
			}
		}
		l.observeBoot(gen, resp.GetBootId())
		l.settle(j, outcomeDone, now)
	case permanent(code):
		l.lost(dropPermanent, len(e.batch.Approvals), now, err)
		l.settle(j, outcomeDone, now)
	default:
		l.s.metrics.retries.WithLabelValues(l.target).Inc()
		if held, ok := l.log.allow("retry:"+label, now); ok {
			slog.Warn("approval producer refused a batch for now; retrying", "target", l.target, "code", label,
				"error", status.Convert(err).Message(), "suppressed", held)
		}
		l.settle(j, outcomeRetry, now)
	}
}

// settle records the end of a call. A probe's answer decides the lane's backoff: a retryable
// refusal extends it, any other answer ends it. Another retryable refusal starts a backoff if none
// is running; answers to calls sent before the backoff began do not change it.
func (l *lane) settle(j *job, o outcome, now time.Time) {
	if o == outcomeExpired {
		l.lost(dropExpired, len(j.e.batch.Approvals), now, nil)
	}
	l.mu.Lock()
	l.calls--
	probe := j.probe
	j.probe = false
	if probe {
		l.backoff.probing = false
	}
	switch o {
	case outcomeRetry:
		l.retries = append(l.retries, j)
		if probe || !l.backoff.active {
			l.backoff.active = true
			l.backoff.until = now.Add(retryDelay(l.backoff.attempt))
			l.backoff.attempt++
		}
	case outcomeDone:
		if probe {
			l.backoff = laneBackoff{}
		}
	}
	l.mu.Unlock()
	l.notify()
}

// retryDelay is how long a refused lane waits before its next probe: exponential from
// retryBaseDelay, capped at retryMaxDelay, with jitter so OPS instances do not probe in step.
func retryDelay(attempt int) time.Duration {
	d := retryMaxDelay
	if attempt < 8 {
		d = min(retryBaseDelay<<attempt, retryMaxDelay)
	}
	return d/2 + rand.N(d/2+1)
}

// permanent reports a refusal retrying cannot change (wire contract §3): a malformed or wrongly
// signed batch, an untrusted key, the wrong chain, a lifetime the producer does not accept, a batch
// expired or issued in the future, and the gRPC libraries' own limits and wrong-service answers.
// Everything else is retried until the batch expires.
func permanent(code codes.Code) bool {
	switch code {
	case codes.InvalidArgument, codes.PermissionDenied, codes.Unauthenticated, codes.FailedPrecondition,
		codes.ResourceExhausted, codes.OutOfRange, codes.Unimplemented:
		return true
	}
	return false
}

// lost counts approvals this lane gave up on, and says so at most once per logEvery per reason.
func (l *lane) lost(reason string, approvals int, now time.Time, err error) {
	l.s.metrics.dropped.WithLabelValues(l.target, reason).Add(float64(approvals))
	key := reason
	attrs := []any{"target", l.target, "reason", reason, "approvals", approvals}
	if err != nil {
		code := status.Code(err).String()
		key += ":" + code
		attrs = append(attrs, "code", code, "error", status.Convert(err).Message())
	}
	if held, ok := l.log.allow(key, now); ok {
		slog.Error("approval batch dropped: its transactions wait for an approval that does not come",
			append(attrs, "suppressed", held)...)
	}
}

func (l *lane) generation() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.gen
}

// observeBoot acts on the boot id in an answer to a call made in connection generation gen. A
// boot id new for the current connection means the producer restarted and lost its store; answers
// that belong to an earlier connection are ignored.
func (l *lane) observeBoot(gen uint64, boot string) {
	if boot == "" {
		return
	}
	l.mu.Lock()
	if gen != l.gen || boot == l.boot {
		l.mu.Unlock()
		return
	}
	previous := l.boot
	l.boot = boot
	l.mu.Unlock()
	if previous != "" {
		l.startRedelivery(boot, previous)
	}
}

// startRedelivery starts the lane's one redelivery over, from the newest retained batch.
func (l *lane) startRedelivery(boot, previous string) {
	d := l.s.retain.redelivery(l, time.Now())
	l.mu.Lock()
	l.redo = d
	l.mu.Unlock()
	l.s.metrics.redeliveries.WithLabelValues(l.target).Inc()
	batches := 0
	if d.active {
		batches = int(d.next - d.low + 1)
	}
	slog.Warn("approval producer restarted; redelivering the retained approvals, newest first", "target", l.target,
		"boot_id", boot, "previous_boot_id", previous, "batches", batches)
	l.notify()
}

// watch follows the connection. It reconnects a lost one without waiting for a batch, asks the
// producer for Status on every new connection and then every statusEvery, and keeps readiness and
// the connected gauge current.
func (l *lane) watch(stop context.Context) {
	defer close(l.watched)
	defer l.notReady()
	redial := false // the first connection is immediate; a redial after a loss is paced
	l.conn.Connect()
	for {
		state := l.conn.GetState()
		switch state {
		case connectivity.Ready:
			if !l.pollStatus(stop, l.becameReady(time.Now())) {
				return
			}
			continue
		case connectivity.Idle:
			l.notReady()
			// A lost connection leaves the channel idle until a call needs it. Reconnect now,
			// after one jittered pause, so a restarted producer gets its Status call and its
			// redelivery promptly, and a peer that accepts and resets cannot cause a dial storm.
			if redial && !sleep(stop, reconnectPause+rand.N(reconnectPause)) {
				return
			}
			redial = true
			l.conn.Connect()
		default:
			l.notReady()
		}
		if !l.conn.WaitForStateChange(stop, state) {
			return
		}
	}
}

// becameReady starts a new connection generation: answers to calls made before it belong to the
// previous connection. A lane waiting out a backoff probes at once, since what refused it may
// have been the connection itself.
func (l *lane) becameReady(now time.Time) uint64 {
	l.mu.Lock()
	l.gen++
	gen := l.gen
	if l.backoff.active && !l.backoff.probing {
		l.backoff.until = now
	}
	l.mu.Unlock()
	l.connections.Add(1)
	l.s.metrics.connected.WithLabelValues(l.target).Set(1)
	l.notify()
	return gen
}

func (l *lane) notReady() {
	l.readyUntil.Store(0)
	l.s.metrics.connected.WithLabelValues(l.target).Set(0)
}

// pollStatus asks for Status now and every statusEvery while the connection stays ready. It
// returns false once stop ends.
func (l *lane) pollStatus(stop context.Context, gen uint64) bool {
	for {
		l.status(stop, gen)
		wait, cancel := context.WithTimeout(stop, l.statusEvery)
		changed := l.conn.WaitForStateChange(wait, connectivity.Ready)
		cancel()
		if stop.Err() != nil {
			return false
		}
		if changed {
			return true
		}
	}
}

// status asks the producer who it is. The answer counts only for the connection it was asked on:
// it refreshes readiness, the maximum TTL OPS signs with and the boot id, and reports a chain or
// key id that does not match — the lane keeps running either way.
func (l *lane) status(stop context.Context, gen uint64) {
	ctx, cancel := context.WithTimeout(stop, l.timeout)
	st, err := l.client.Status(ctx, &approvalpb.StatusRequest{})
	cancel()
	now := time.Now()
	if err != nil {
		if stop.Err() == nil {
			if held, ok := l.log.allow("status", now); ok {
				slog.Warn("approval producer did not answer Status", "target", l.target, "code", status.Code(err).String(),
					"error", status.Convert(err).Message(), "suppressed", held)
			}
		}
		return
	}
	if gen != l.generation() {
		return
	}
	keyID := l.s.signer.KeyID()
	trusted := slices.Contains(st.GetTrustedKeyIds(), keyID)
	if !trusted {
		l.mismatch("key_id", now, "key_id", keyID, "trusted_key_ids", st.GetTrustedKeyIds())
	}
	if chain := l.s.chainID.Load(); chain != 0 && st.GetChainId() != chain {
		l.mismatch("chain_id", now, "chain_id", chain, "producer_chain_id", st.GetChainId())
	}
	l.maxTTL.Store(int64(min(st.GetMaxTtlMs(), uint64(MaxApprovalTTL.Milliseconds()))))
	if trusted {
		l.readyChain.Store(st.GetChainId())
		l.readyUntil.Store(now.Add(l.readyWindow).UnixNano())
	} else {
		l.readyUntil.Store(0)
	}
	l.observeBoot(gen, st.GetBootId())
}

func (l *lane) mismatch(setting string, now time.Time, attrs ...any) {
	l.s.metrics.mismatches.WithLabelValues(l.target, setting).Inc()
	if held, ok := l.log.allow("mismatch:"+setting, now); ok {
		slog.Error("approval producer does not match OPS and refuses what OPS signs",
			append([]any{"target", l.target, "setting", setting, "suppressed", held}, attrs...)...)
	}
}

// report is the lane's shutdown line: connections used, and what it could not deliver in time.
func (l *lane) report() {
	slog.Info("approval connections used", "count", l.connections.Load(), "target", l.target)
	l.mu.Lock()
	waiting, redelivering := len(l.retries), l.redo.active
	l.mu.Unlock()
	if n := l.s.retain.unsent(l) + waiting + int(l.abandoned.Load()); n > 0 || redelivering {
		slog.Warn("approval delivery stopped before the producer confirmed every batch", "target", l.target,
			"batches", n, "redelivery_unfinished", redelivering)
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// logGate lets one line per key through every logEvery and says how many it held back, so a
// producer refusing every batch costs one line per interval, not one per batch.
type logGate struct {
	mu   sync.Mutex
	next map[string]time.Time
	held map[string]int
}

func (g *logGate) allow(key string, now time.Time) (int, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Before(g.next[key]) {
		g.held[key]++
		return 0, false
	}
	if g.next == nil {
		g.next, g.held = map[string]time.Time{}, map[string]int{}
	}
	g.next[key] = now.Add(logEvery)
	held := g.held[key]
	g.held[key] = 0
	return held, true
}
