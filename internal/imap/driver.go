// Package imap implements an auth-only IMAP proxy driver. Vault authenticates
// the upstream connection with stored credentials, synthesises the client-side
// greeting and LOGIN exchange with a dummy credential from the local client,
// then hands off a transparent byte pipe for all post-auth IMAP traffic.
package imap

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// Config holds the runtime parameters copied out of the vault so the stored
// password can be wiped after DialAndAuthenticate returns.
type Config struct {
	Host     string
	Port     int
	User     string
	Password []byte // wiped after use
	TLSMode  string // "implicit" | "starttls" | "none"

	// TLSSkipVerify mirrors the Service.TLSSkipVerify flag for self-signed
	// upstreams; default is false (verify).
	TLSSkipVerify bool
}

// Driver implements netproxy.ProtocolDriver for IMAP.
type Driver struct {
	cfg *Config
}

// New returns a Driver bound to cfg. The caller retains ownership of cfg and
// is responsible for zeroing the password after Close.
func New(cfg *Config) *Driver { return &Driver{cfg: cfg} }

// Name identifies the protocol in logs.
func (d *Driver) Name() string { return "imap" }

// UpstreamHost returns host:port for logging.
func (d *Driver) UpstreamHost() string {
	return fmt.Sprintf("%s:%d", d.cfg.Host, d.cfg.Port)
}

// Wipe zeros the stored password.
func (d *Driver) Wipe() {
	for i := range d.cfg.Password {
		d.cfg.Password[i] = 0
	}
}

// DialAndAuthenticate opens a TCP connection, runs TLS + LOGIN handshake, and
// returns the authenticated connection ready for post-auth IMAP commands.
func (d *Driver) DialAndAuthenticate(ctx context.Context) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", d.cfg.Host, d.cfg.Port)

	dialer := &net.Dialer{Timeout: 15 * time.Second}
	var rawConn net.Conn
	var err error

	switch d.cfg.TLSMode {
	case "implicit":
		tlsCfg := &tls.Config{ServerName: d.cfg.Host, InsecureSkipVerify: d.cfg.TLSSkipVerify}
		rawConn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	default:
		rawConn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	conn := rawConn
	conn.SetDeadline(time.Now().Add(20 * time.Second))

	r := bufio.NewReader(conn)

	// Read server greeting — expect "* OK ...".
	if line, err := r.ReadString('\n'); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read greeting: %w", err)
	} else if !strings.HasPrefix(line, "* OK") && !strings.HasPrefix(line, "* PREAUTH") {
		conn.Close()
		return nil, fmt.Errorf("unexpected greeting: %s", strings.TrimSpace(line))
	}

	if d.cfg.TLSMode == "starttls" {
		if err := writeLine(conn, "A001 STARTTLS"); err != nil {
			conn.Close()
			return nil, err
		}
		if err := expectTaggedOK(r, "A001"); err != nil {
			conn.Close()
			return nil, fmt.Errorf("STARTTLS: %w", err)
		}
		tlsCfg := &tls.Config{ServerName: d.cfg.Host, InsecureSkipVerify: d.cfg.TLSSkipVerify}
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("STARTTLS handshake: %w", err)
		}
		conn = tlsConn
		r = bufio.NewReader(conn)
	}

	// Send LOGIN. Quote user and password per RFC 3501 using literal form
	// when needed; for simplicity we use quoted-string after basic escaping.
	cmd := fmt.Sprintf("A002 LOGIN %s %s", quoteIMAP(d.cfg.User), quoteIMAP(string(d.cfg.Password)))
	if err := writeLine(conn, cmd); err != nil {
		conn.Close()
		return nil, err
	}
	if err := expectTaggedOK(r, "A002"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("LOGIN: %w", err)
	}

	conn.SetDeadline(time.Time{}) // clear handshake deadline
	return conn, nil
}

// ServeLocal synthesises an IMAP server greeting to the local client and
// accepts exactly one tagged LOGIN command (contents ignored), replying OK,
// then returns so the caller can splice bytes post-auth.
func (d *Driver) ServeLocal(local, _ net.Conn) error {
	local.SetDeadline(time.Now().Add(30 * time.Second))
	defer local.SetDeadline(time.Time{})

	if err := writeLine(local, "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN LOGINDISABLED=NO] vault-proxy ready"); err != nil {
		return err
	}

	r := bufio.NewReader(local)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read local command: %w", err)
		}
		trimmed := strings.TrimRight(line, "\r\n")
		tag, cmd, rest := splitIMAP(trimmed)
		if tag == "" {
			return fmt.Errorf("malformed local command: %q", trimmed)
		}

		switch strings.ToUpper(cmd) {
		case "CAPABILITY":
			if err := writeLine(local, "* CAPABILITY IMAP4rev1 AUTH=PLAIN"); err != nil {
				return err
			}
			if err := writeLine(local, tag+" OK CAPABILITY completed"); err != nil {
				return err
			}
		case "NOOP":
			if err := writeLine(local, tag+" OK NOOP completed"); err != nil {
				return err
			}
		case "LOGIN":
			_ = rest // intentionally ignore local credentials
			if err := writeLine(local, tag+" OK LOGIN completed"); err != nil {
				return err
			}
			return nil
		case "AUTHENTICATE":
			// We do not advertise SASL methods; reject gracefully to force LOGIN.
			if err := writeLine(local, tag+" NO AUTHENTICATE not supported by vault-proxy; use LOGIN"); err != nil {
				return err
			}
		case "LOGOUT":
			writeLine(local, "* BYE vault-proxy signing off")
			writeLine(local, tag+" OK LOGOUT completed")
			return fmt.Errorf("client logged out before auth")
		default:
			if err := writeLine(local, tag+" BAD command not available before LOGIN"); err != nil {
				return err
			}
		}
	}
}

// writeLine sends a line terminated by CRLF.
func writeLine(w net.Conn, line string) error {
	_, err := w.Write([]byte(line + "\r\n"))
	return err
}

// expectTaggedOK reads response lines until one with the given tag appears.
// Untagged responses (starting with "*") are skipped.
func expectTaggedOK(r *bufio.Reader, tag string) error {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "* ") {
			continue
		}
		if strings.HasPrefix(line, tag+" OK") {
			return nil
		}
		if strings.HasPrefix(line, tag+" ") {
			return fmt.Errorf("server rejected: %s", line)
		}
		// Stray output, keep reading.
	}
}

// splitIMAP splits "TAG CMD rest" preserving rest verbatim.
func splitIMAP(line string) (tag, cmd, rest string) {
	i := strings.IndexByte(line, ' ')
	if i < 0 {
		return line, "", ""
	}
	tag = line[:i]
	rem := line[i+1:]
	j := strings.IndexByte(rem, ' ')
	if j < 0 {
		return tag, rem, ""
	}
	return tag, rem[:j], rem[j+1:]
}

// quoteIMAP wraps s in IMAP quoted-string form with basic escaping.
// Callers should avoid passing user/pass containing CR or LF (validated
// upstream at service-add time via host checks; RFC 3501 allows quoted
// strings to contain any 7-bit char except CR/LF).
func quoteIMAP(s string) string {
	// Backslash-escape \ and " per RFC 3501.
	replaced := strings.ReplaceAll(s, `\`, `\\`)
	replaced = strings.ReplaceAll(replaced, `"`, `\"`)
	return `"` + replaced + `"`
}
