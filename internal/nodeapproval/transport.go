package nodeapproval

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
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

func (s *Service) deliver(ctx context.Context, conn net.Conn) {
	defer close(s.done)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	broken := watchConnection(conn)
	jsonMode := os.Getenv("OPS_APPROVAL_ENCODING") == "json" // comparison only
	for {
		if conn == nil {
			var err error
			conn, err = dialApproval(ctx, s.address)
			if err != nil {
				// Backoff only while disconnected. Connected delivery has no polling/timer.
				timer := time.NewTimer(100 * time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
					continue
				}
			}
			s.connections.Add(1)
			broken = watchConnection(conn)
		}
		select {
		case <-ctx.Done():
			return
		case <-broken:
			conn.Close()
			conn = nil
		case batch := <-s.signed:
			mark(batch.Approvals, func(h *Hop, n int64) { h.DeliveryStart = n })
			frame := batch.frame
			if jsonMode {
				data, err := json.Marshal(batch)
				if err != nil {
					continue
				}
				frame = binary.BigEndian.AppendUint32(nil, uint32(len(data)))
				frame = append(frame, data...)
			}
			if len(frame) < 4 || len(frame) > MaxBatchFrame+4 {
				slog.Error("invalid approval frame", "error", errors.New("frame size"))
				continue
			}
			mark(batch.Approvals, func(h *Hop, n int64) { h.Encoded = n; h.Connected = n; h.WriteStart = n })
			if err := writeAll(conn, frame); err != nil {
				slog.Warn("approval delivery failed", "error", err)
				conn.Close()
				conn = nil
			}
			mark(batch.Approvals, func(h *Hop, n int64) { h.Written = n })
		}
	}
}
