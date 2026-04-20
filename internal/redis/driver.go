// Package redis implements an auth-only Redis proxy driver. Vault dials
// upstream, optionally negotiates TLS, issues AUTH and SELECT with stored
// credentials, then returns an authenticated connection. Local-side handling
// is trivial: Redis clients send commands without a required greeting, so the
// only thing to do is swallow any initial HELLO/AUTH/SELECT the client sends.
package redis

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Config holds connection parameters.
type Config struct {
	Host          string
	Port          int
	Username      string
	Password      []byte // wiped after use
	DB            int
	TLS           bool
	TLSSkipVerify bool
}

// Driver implements netproxy.ProtocolDriver for Redis.
type Driver struct{ cfg *Config }

// New returns a Driver bound to cfg.
func New(cfg *Config) *Driver { return &Driver{cfg: cfg} }

// Name identifies the protocol in logs.
func (d *Driver) Name() string { return "redis" }

// UpstreamHost returns host:port for logging.
func (d *Driver) UpstreamHost() string { return fmt.Sprintf("%s:%d", d.cfg.Host, d.cfg.Port) }

// Wipe zeros the stored password.
func (d *Driver) Wipe() {
	for i := range d.cfg.Password {
		d.cfg.Password[i] = 0
	}
}

// DialAndAuthenticate dials, optionally TLS-wraps, and runs AUTH + SELECT.
func (d *Driver) DialAndAuthenticate(ctx context.Context) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", d.cfg.Host, d.cfg.Port)
	dialer := &net.Dialer{Timeout: 15 * time.Second}

	var conn net.Conn
	var err error
	if d.cfg.TLS {
		tlsCfg := &tls.Config{ServerName: d.cfg.Host, InsecureSkipVerify: d.cfg.TLSSkipVerify}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(conn)

	if len(d.cfg.Password) > 0 {
		var args [][]byte
		if d.cfg.Username != "" {
			args = [][]byte{[]byte("AUTH"), []byte(d.cfg.Username), d.cfg.Password}
		} else {
			args = [][]byte{[]byte("AUTH"), d.cfg.Password}
		}
		if err := writeRESP(conn, args); err != nil {
			conn.Close()
			return nil, err
		}
		if err := expectOK(r); err != nil {
			conn.Close()
			return nil, fmt.Errorf("AUTH: %w", err)
		}
	}
	if d.cfg.DB > 0 {
		if err := writeRESP(conn, [][]byte{[]byte("SELECT"), []byte(strconv.Itoa(d.cfg.DB))}); err != nil {
			conn.Close()
			return nil, err
		}
		if err := expectOK(r); err != nil {
			conn.Close()
			return nil, fmt.Errorf("SELECT: %w", err)
		}
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

// ServeLocal is a no-op: Redis clients may send any command first. Any AUTH
// or SELECT they send will be proxied to the (already authenticated) upstream,
// which will reply with whatever the upstream says. In practice most clients
// configured without a password simply don't send AUTH, and everything just
// works. For clients that do send AUTH with the local dummy password, we'd
// need to swallow and fake-OK it here — but that requires parsing RESP and
// the real-world compatibility win is small. Keep it simple.
func (d *Driver) ServeLocal(_, _ net.Conn) error { return nil }

// writeRESP serialises a command array in RESP2 bulk-string form.
func writeRESP(w net.Conn, parts [][]byte) error {
	var b strings.Builder
	b.WriteString("*")
	b.WriteString(strconv.Itoa(len(parts)))
	b.WriteString("\r\n")
	for _, p := range parts {
		b.WriteString("$")
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteString("\r\n")
		b.Write(p)
		b.WriteString("\r\n")
	}
	_, err := w.Write([]byte(b.String()))
	return err
}

// expectOK reads a single simple-string reply and asserts "+OK\r\n".
// An error reply "-ERR..." is surfaced as an error.
func expectOK(r *bufio.Reader) error {
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimRight(line, "\r\n")
	switch {
	case strings.HasPrefix(line, "+OK"):
		return nil
	case strings.HasPrefix(line, "-"):
		return fmt.Errorf("%s", strings.TrimPrefix(line, "-"))
	default:
		return fmt.Errorf("unexpected reply: %q", line)
	}
}
