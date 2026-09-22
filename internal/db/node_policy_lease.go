package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"sync"
	"time"
)

// nodePolicyPublisherLock is the advisory-lock key for the one OPS instance
// that publishes node policy. It sits beside the configuration scope lock
// (730074) so the two cannot be confused in pg_locks.
const nodePolicyPublisherLock int64 = 730075

// leaseUnlockTimeout bounds the unlock that precedes returning a connection to
// the pool; a hung database must not hang the caller.
const leaseUnlockTimeout = 2 * time.Second

// NodePolicyLease is a session-level Postgres advisory lock held on a
// connection pinned for as long as the lease is held. Postgres releases the
// lock when the session ends, so a crashed or partitioned holder loses the
// lease without any cleanup — the next instance's Acquire simply succeeds.
//
// The pinned connection is returned to the pool as soon as the lease is not
// held, so campaigning instances do not each keep an idle connection.
type NodePolicyLease struct {
	pool *sql.DB
	mu   sync.Mutex
	conn *sql.Conn
	// tuned records that this session carries the holder's keepalive settings,
	// so they are reset before the connection goes back to the shared pool.
	tuned bool
}

// NodePolicyLease returns a lease bound to this database. Each caller that
// wants to campaign holds its own lease value.
func (d *DB) NodePolicyLease() *NodePolicyLease {
	return &NodePolicyLease{pool: d.conn}
}

// Acquire tries to take the lease without waiting. A holder calling Acquire
// again keeps the lease; Release undoes every acquisition at once.
func (l *NodePolicyLease) Acquire(ctx context.Context) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		conn, err := l.pool.Conn(ctx)
		if err != nil {
			return false, err
		}
		l.conn = conn
	}
	var got bool
	if err := l.conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, nodePolicyPublisherLock).Scan(&got); err != nil {
		l.discard()
		return false, err
	}
	if !got {
		l.drop()
		return false, nil
	}
	// Holder only. A holder that vanishes mid-session keeps the lock until the
	// server notices the dead socket. Postgres inherits the OS defaults (about
	// two hours of idle keepalive on Linux, about fifteen minutes of
	// retransmits when a response was in flight) while facts expire after the
	// configured lifetime (thirty seconds by default), so the holder's session
	// asks for its own: about ten seconds either way — five idle, then three
	// probes two seconds apart, and the same bound on unacknowledged data.
	// Campaigners never carry these settings and Release resets them before
	// the pool sees the session again. Over a Unix socket they are accepted
	// and have no effect.
	if _, err := l.conn.ExecContext(ctx, `SELECT set_config('tcp_keepalives_idle', '5', false), set_config('tcp_keepalives_interval', '2', false), set_config('tcp_keepalives_count', '3', false), set_config('tcp_user_timeout', '11000', false)`); err != nil {
		l.discard()
		return false, err
	}
	l.tuned = true
	return true, nil
}

// Held asks the database, not memory, whether this session still holds the
// lease. A failed probe means the session cannot be trusted and is reported as
// an error after the connection is discarded.
func (l *NodePolicyLease) Held(ctx context.Context) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return false, nil
	}
	var held bool
	err := l.conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=$1 AND objsubid=1 AND pid=pg_backend_pid() AND granted)`, nodePolicyPublisherLock).Scan(&held)
	if err != nil {
		l.discard()
		return false, err
	}
	if !held {
		l.drop()
	}
	return held, nil
}

// Release gives the lease up and returns the connection to the pool. A lease
// that is not held, or whose session has already died, releases to nothing.
func (l *NodePolicyLease) Release(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dropWithContext(ctx)
	return nil
}

// drop returns the connection to the pool after unlocking everything the
// session holds. Unlocking is done even when the probe said nothing is held:
// a pooled connection that still carried the advisory lock would block every
// campaigner for good, with no owner left to release it.
func (l *NodePolicyLease) drop() {
	ctx, cancel := context.WithTimeout(context.Background(), leaseUnlockTimeout)
	defer cancel()
	l.dropWithContext(ctx)
}

func (l *NodePolicyLease) dropWithContext(ctx context.Context) {
	if l.conn == nil {
		return
	}
	if _, err := l.conn.ExecContext(ctx, `SELECT pg_advisory_unlock_all()`); err != nil {
		// The session is gone, and so is every lock it held; make sure the
		// pool does not reuse it.
		l.discard()
		return
	}
	if l.tuned {
		// Do not hand the holder's socket settings to the next pool user.
		if _, err := l.conn.ExecContext(ctx, `RESET tcp_keepalives_idle; RESET tcp_keepalives_interval; RESET tcp_keepalives_count; RESET tcp_user_timeout`); err != nil {
			l.discard()
			return
		}
	}
	_ = l.conn.Close()
	l.conn = nil
	l.tuned = false
}

// discard makes sure a connection in an unknown state is never reused: it is
// marked bad so the pool closes it instead of handing it to the next caller
// with an advisory lock possibly still attached.
func (l *NodePolicyLease) discard() {
	if l.conn == nil {
		return
	}
	_ = l.conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = l.conn.Close()
	l.conn = nil
	l.tuned = false
}
