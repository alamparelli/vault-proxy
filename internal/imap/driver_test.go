package imap

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// stubIMAPServer speaks just enough of IMAP to validate the driver's upstream
// handshake: sends the greeting, expects LOGIN with a specific user/password,
// replies OK, then echoes bytes back (so the test can verify the splice).
type stubIMAPServer struct {
	wantUser string
	wantPass string
	ln       net.Listener
}

func newStubIMAP(t *testing.T, user, pass string) *stubIMAPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &stubIMAPServer{wantUser: user, wantPass: pass, ln: ln}
	go s.accept(t)
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *stubIMAPServer) addr() string { return s.ln.Addr().String() }

func (s *stubIMAPServer) accept(t *testing.T) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(t, conn)
	}
}

func (s *stubIMAPServer) handle(t *testing.T, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte("* OK [CAPABILITY IMAP4rev1] test server ready\r\n"))
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			return
		}
		tag, cmd := parts[0], strings.ToUpper(parts[1])
		switch cmd {
		case "LOGIN":
			// parts[2] is `"user" "pass"`
			args := parts[2]
			if args != `"`+s.wantUser+`" "`+s.wantPass+`"` {
				conn.Write([]byte(tag + " NO bad creds\r\n"))
				return
			}
			conn.Write([]byte(tag + " OK LOGIN completed\r\n"))
			// Echo the rest.
			conn.SetDeadline(time.Time{})
			io.Copy(conn, r)
			return
		default:
			conn.Write([]byte(tag + " BAD only LOGIN supported\r\n"))
		}
	}
}

func TestIMAPDriver_Handshake_PlaintextUpstream(t *testing.T) {
	srv := newStubIMAP(t, "agent@example.com", "hunter2")
	host, portStr, _ := net.SplitHostPort(srv.addr())
	var port int
	if _, err := parsePort(portStr, &port); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Host:     host,
		Port:     port,
		User:     "agent@example.com",
		Password: []byte("hunter2"),
		TLSMode:  "none",
	}
	d := New(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := d.DialAndAuthenticate(ctx)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	// Now a client would send IMAP commands. Send a canary and expect echo.
	if _, err := conn.Write([]byte("hello post auth\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello post auth\n" {
		t.Fatalf("post-auth splice mismatch: %q", buf[:n])
	}
}

// Verify ServeLocal greets and accepts a dummy LOGIN, returning nil so the
// caller can splice.
func TestIMAPDriver_ServeLocal_AcceptsDummyLogin(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	d := New(&Config{})
	go func() {
		d.ServeLocal(a, nil)
	}()

	r := bufio.NewReader(b)
	greeting, _ := r.ReadString('\n')
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("greeting: %q", greeting)
	}

	b.Write([]byte("x1 LOGIN anything whatever\r\n"))
	resp, _ := r.ReadString('\n')
	if !strings.HasPrefix(resp, "x1 OK LOGIN") {
		t.Fatalf("expected x1 OK, got %q", resp)
	}
}

// parsePort is a tiny fmt.Sscanf replacement without importing strconv twice.
func parsePort(s string, out *int) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	*out = n
	return 1, nil
}
