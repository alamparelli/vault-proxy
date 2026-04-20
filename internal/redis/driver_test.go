package redis

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// stubRedis parses RESP2 AUTH with a fixed password and then echoes.
type stubRedis struct {
	wantPass string
	ln       net.Listener
}

func newStubRedis(t *testing.T, pass string) *stubRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &stubRedis{wantPass: pass, ln: ln}
	go s.accept()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *stubRedis) accept() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *stubRedis) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)

	// Read array header for AUTH.
	hdr, _ := r.ReadString('\n')
	if !strings.HasPrefix(hdr, "*") {
		return
	}
	// Drain the next 2 or 3 args ($len\r\n<bytes>\r\n).
	args := []string{}
	for i := 0; i < 3; i++ {
		lenLine, err := r.ReadString('\n')
		if err != nil {
			break
		}
		if !strings.HasPrefix(lenLine, "$") {
			break
		}
		// Skip parsing length — read until CRLF on the content line.
		content, _ := r.ReadString('\n')
		args = append(args, strings.TrimRight(content, "\r\n"))
		if strings.TrimSpace(hdr[1:]) == "2" && len(args) == 2 {
			break
		}
	}
	if len(args) < 2 || strings.ToUpper(args[0]) != "AUTH" {
		conn.Write([]byte("-ERR expected AUTH\r\n"))
		return
	}
	pass := args[len(args)-1]
	if pass != s.wantPass {
		conn.Write([]byte("-WRONGPASS\r\n"))
		return
	}
	conn.Write([]byte("+OK\r\n"))
	conn.SetDeadline(time.Time{})
	io.Copy(conn, r)
}

func TestRedisDriver_AUTHSucceeds(t *testing.T) {
	srv := newStubRedis(t, "s3cret")
	host, portStr, _ := net.SplitHostPort(srv.ln.Addr().String())
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	d := New(&Config{
		Host:     host,
		Port:     port,
		Password: []byte("s3cret"),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := d.DialAndAuthenticate(ctx)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	// Post-auth: canary message echoes back.
	conn.Write([]byte("PING\r\n"))
	buf := make([]byte, 16)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "PING\r\n" {
		t.Fatalf("post-auth splice mismatch: %q", buf[:n])
	}
}

func TestRedisDriver_AUTHFails(t *testing.T) {
	srv := newStubRedis(t, "right")
	host, portStr, _ := net.SplitHostPort(srv.ln.Addr().String())
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	d := New(&Config{Host: host, Port: port, Password: []byte("wrong")})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := d.DialAndAuthenticate(ctx); err == nil {
		t.Fatal("expected AUTH failure")
	}
}
