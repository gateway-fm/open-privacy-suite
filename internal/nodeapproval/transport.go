package nodeapproval

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"time"
)

func dialApproval(ctx context.Context, address string) (net.Conn, error) {
	c, err := (&net.Dialer{Timeout: time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if err = c.(*net.TCPConn).SetNoDelay(true); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// No application replies are expected. This read only detects EOF/socket errors
// so a broken idle connection reconnects without waiting for another approval.
func watchConnection(c net.Conn) <-chan struct{} {
	broken := make(chan struct{})
	go func() { var b [1]byte; _, _ = c.Read(b[:]); close(broken) }()
	return broken
}

func writeAll(c net.Conn, frame []byte) error {
	if err := c.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	for len(frame) > 0 {
		n, err := c.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

// Reconnect pacing. A connection can be lost by a failed dial, a failed write or
// a peer close; each is followed by one pause before the next attempt, so a peer
// that accepts and immediately resets (a plugin at its connection limit, a proxy,
// a half-started node) cannot turn OPS into a dial storm. Jitter keeps several
// OPS instances from retrying in step.
const reconnectPause = 100 * time.Millisecond

// drainTimeout bounds how long a graceful stop keeps delivering what Enqueue had
// already accepted. Every accepted approval belongs to a transaction that is being
// forwarded; dropping it at shutdown means a timeout for that transaction.
const drainTimeout = 2 * time.Second

func pause(ctx context.Context) bool {
	timer := time.NewTimer(reconnectPause + time.Duration(rand.Int64N(int64(reconnectPause))))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (s *Service) deliver(ctx context.Context, conn net.Conn) {
	defer close(s.done)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	broken := watchConnection(conn)
	// A batch whose write failed is kept and sent first on the next connection.
	// The frame is already signed, so it is resent byte for byte; the producer's
	// store is keyed by transaction hash, so a duplicate is harmless. Without
	// this, a reset socket silently lost every approval in flight.
	var retry *Batch
	// Once ctx ends, delivery continues for what is already signed, until the
	// signer closes s.signed or drainTimeout passes. dialCtx bounds that phase.
	dialCtx := ctx
	var draining <-chan struct{}
	for {
		if conn == nil {
			var err error
			conn, err = dialApproval(dialCtx, s.address)
			if err != nil {
				if !pause(dialCtx) {
					return
				}
				continue
			}
			s.connections.Add(1)
			broken = watchConnection(conn)
		}
		var batch Batch
		if retry != nil {
			batch, retry = *retry, nil
		} else {
			select {
			case <-ctx.Done():
				if draining == nil {
					var cancel context.CancelFunc
					dialCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), drainTimeout)
					defer cancel()
					draining = dialCtx.Done()
					ctx = dialCtx // the loop now ends when the drain deadline passes
					continue
				}
				return
			case <-broken:
				conn.Close()
				conn = nil
				if !pause(dialCtx) {
					return
				}
				continue
			case b, ok := <-s.signed:
				if !ok {
					return // the signer has drained the queue and closed the channel
				}
				batch = b
			}
		}
		mark(batch.Approvals, func(h *Hop, n int64) { h.DeliveryStart = n })
		frame := batch.frame
		if len(frame) < 4 || len(frame) > MaxBatchFrame+4 {
			slog.Error("invalid approval frame", "error", errors.New("frame size"))
			continue
		}
		mark(batch.Approvals, func(h *Hop, n int64) { h.Encoded = n; h.Connected = n; h.WriteStart = n })
		if err := writeAll(conn, frame); err != nil {
			slog.Warn("approval delivery failed; resending after reconnect", "error", err, "approvals", len(batch.Approvals))
			conn.Close()
			conn = nil
			retry = &batch
			if !pause(dialCtx) {
				return
			}
			continue
		}
		mark(batch.Approvals, func(h *Hop, n int64) { h.Written = n })
	}
}
