package nodeapproval

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"
)

func acceptSoon(t *testing.T, l *net.TCPListener) *net.TCPConn {
	t.Helper()
	if err := l.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	c, err := l.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestConnectionEstablishedAtStartupAndReconnectsWithoutAnApproval(t *testing.T) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	s, err := New("http://127.0.0.1:1", l.Addr().String(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	first := acceptSoon(t, l) // no Enqueue has happened
	first.Close()
	second := acceptSoon(t, l)
	defer second.Close() // idle EOF triggers background reconnect
	if len(s.queue) != 0 {
		t.Fatal("unexpected approval")
	}
}

func TestTCPNoDelayIsActuallyEnabled(t *testing.T) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := dialApproval(context.Background(), l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	socket, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value int
	var sockErr error
	if err := socket.Control(func(fd uintptr) {
		value, sockErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY)
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil || value == 0 {
		t.Fatalf("TCP_NODELAY = %d, error %v", value, sockErr)
	}
	// Darwin returns a nonzero flag mask; Linux commonly returns 1. Verify
	// the boolean semantics against an explicit disabled setting too.
	if err := c.(*net.TCPConn).SetNoDelay(false); err != nil {
		t.Fatal(err)
	}
	if err := socket.Control(func(fd uintptr) {
		value, sockErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY)
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil || value != 0 {
		t.Fatalf("disabled TCP_NODELAY = %d, error %v", value, sockErr)
	}

}
