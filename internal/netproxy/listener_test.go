package netproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// echoDriver is a test driver: dials an in-memory echo server and does nothing
// local-side. Used to exercise listener/splice without a real protocol.
type echoDriver struct {
	upstream net.Addr
}

func (e *echoDriver) Name() string { return "echo" }
func (e *echoDriver) DialAndAuthenticate(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: 2 * time.Second}
	return d.DialContext(ctx, e.upstream.Network(), e.upstream.String())
}
func (e *echoDriver) ServeLocal(_, _ net.Conn) error { return nil }

// startEchoServer accepts N connections and echoes bytes back.
func startEchoServer(t *testing.T) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr()
}

func TestListener_OneAcceptAndSplice(t *testing.T) {
	upstream := startEchoServer(t)
	reg := NewRegistry()
	sess, err := reg.Start(&echoDriver{upstream: upstream}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.DialTimeout("tcp", sess.Addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial session: %v", err)
	}
	defer conn.Close()

	msg := "hello vault\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo mismatch: %q", buf)
	}

	// Second dial must fail — listener is gone after one accept.
	if _, err := net.DialTimeout("tcp", sess.Addr, 500*time.Millisecond); err == nil {
		t.Fatalf("expected dial-after-accept to fail")
	}
}

func TestListener_TimeoutIfNoAccept(t *testing.T) {
	upstream := startEchoServer(t)
	reg := NewRegistry()
	sess, err := reg.Start(&echoDriver{upstream: upstream}, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-sess.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("session did not close after timeout")
	}

	if _, err := net.DialTimeout("tcp", sess.Addr, 200*time.Millisecond); err == nil {
		t.Fatal("expected connection refused after timeout")
	}
}

func TestListener_CloseAllOnLock(t *testing.T) {
	upstream := startEchoServer(t)
	reg := NewRegistry()
	var addrs []string
	for i := 0; i < 3; i++ {
		sess, err := reg.Start(&echoDriver{upstream: upstream}, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		addrs = append(addrs, sess.Addr)
	}
	reg.CloseAll()
	for _, a := range addrs {
		if _, err := net.DialTimeout("tcp", a, 200*time.Millisecond); err == nil {
			t.Fatalf("listener %s still up after CloseAll", a)
		}
	}
}

func TestListener_BindsLoopbackOnly(t *testing.T) {
	upstream := startEchoServer(t)
	reg := NewRegistry()
	sess, err := reg.Start(&echoDriver{upstream: upstream}, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if !strings.HasPrefix(sess.Addr, "127.0.0.1:") {
		t.Fatalf("expected 127.0.0.1 bind, got %s", sess.Addr)
	}
}

// Ensure the Hoster optional interface reports host for logging.
func TestSessionHostFor(t *testing.T) {
	if sessionHostFor(&echoDriver{}) != "-" {
		t.Fatal("expected '-' for driver without Hoster")
	}
	h := &hosterDriver{host: "imap.example.com:993"}
	if got := sessionHostFor(h); got != "imap.example.com:993" {
		t.Fatalf("host = %q", got)
	}
}

type hosterDriver struct {
	echoDriver
	host string
}

func (h *hosterDriver) UpstreamHost() string { return h.host }

// Smoke: the unused fmt import check — keeps vet happy when tests shrink.
var _ = fmt.Sprintf
