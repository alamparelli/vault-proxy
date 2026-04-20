package smtp

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// stubSMTPServer walks through EHLO + AUTH LOGIN validating the expected
// base64-encoded user and password, then echoes bytes.
type stubSMTPServer struct {
	wantUser string
	wantPass string
	ln       net.Listener
}

func newStubSMTP(t *testing.T, user, pass string) *stubSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &stubSMTPServer{wantUser: user, wantPass: pass, ln: ln}
	go s.accept(t)
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *stubSMTPServer) addr() string { return s.ln.Addr().String() }

func (s *stubSMTPServer) accept(t *testing.T) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(t, conn)
	}
}

func (s *stubSMTPServer) handle(t *testing.T, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte("220 stub.example ESMTP\r\n"))
	r := bufio.NewReader(conn)

	var step int
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			conn.Write([]byte("250-stub.example\r\n250 AUTH LOGIN\r\n"))
		case strings.HasPrefix(up, "AUTH LOGIN"):
			conn.Write([]byte("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")) + "\r\n"))
			step = 1
		case step == 1:
			decoded, _ := base64.StdEncoding.DecodeString(line)
			if string(decoded) != s.wantUser {
				conn.Write([]byte("535 bad user\r\n"))
				return
			}
			conn.Write([]byte("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")) + "\r\n"))
			step = 2
		case step == 2:
			decoded, _ := base64.StdEncoding.DecodeString(line)
			if string(decoded) != s.wantPass {
				conn.Write([]byte("535 bad pass\r\n"))
				return
			}
			conn.Write([]byte("235 auth ok\r\n"))
			conn.SetDeadline(time.Time{})
			io.Copy(conn, r)
			return
		default:
			conn.Write([]byte("500 unexpected\r\n"))
			return
		}
	}
}

func TestSMTPDriver_Handshake_PlaintextUpstream(t *testing.T) {
	srv := newStubSMTP(t, "me@example", "secret")
	host, portStr, _ := net.SplitHostPort(srv.addr())
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	d := New(&Config{
		Host:     host,
		Port:     port,
		User:     "me@example",
		Password: []byte("secret"),
		TLSMode:  "none",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := d.DialAndAuthenticate(ctx)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("MAIL FROM:<me@example>\r\n"))
	buf := make([]byte, 32)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := conn.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "MAIL FROM") {
		t.Fatalf("post-auth splice did not echo: %q", buf[:n])
	}
}

func TestSMTPDriver_ServeLocal_EHLOThenAUTHLOGIN(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	d := New(&Config{})
	done := make(chan error, 1)
	go func() { done <- d.ServeLocal(a, nil) }()

	r := bufio.NewReader(b)
	greeting, _ := r.ReadString('\n')
	if !strings.HasPrefix(greeting, "220") {
		t.Fatalf("greeting: %q", greeting)
	}

	b.Write([]byte("EHLO test\r\n"))
	// Drain multi-line 250 response.
	for {
		line, _ := r.ReadString('\n')
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	b.Write([]byte("AUTH LOGIN\r\n"))
	r.ReadString('\n') // 334 Username
	b.Write([]byte(base64.StdEncoding.EncodeToString([]byte("anyuser")) + "\r\n"))
	r.ReadString('\n') // 334 Password
	b.Write([]byte(base64.StdEncoding.EncodeToString([]byte("anypass")) + "\r\n"))
	final, _ := r.ReadString('\n')
	if !strings.HasPrefix(final, "235") {
		t.Fatalf("expected 235, got %q", final)
	}
	// ServeLocal returns after 235 so caller can splice.
	if err := <-done; err != nil {
		t.Fatalf("ServeLocal err: %v", err)
	}
}
