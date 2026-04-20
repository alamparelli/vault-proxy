// Package smtp implements an auth-only SMTP proxy driver. Vault authenticates
// the upstream connection with stored credentials via AUTH LOGIN, synthesises
// the client-side greeting and AUTH exchange with any dummy credential from
// the local client, then hands off a transparent byte pipe.
package smtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Config holds the runtime parameters copied out of the vault.
type Config struct {
	Host          string
	Port          int
	User          string
	Password      []byte // wiped after use
	TLSMode       string // "implicit" | "starttls" | "none"
	TLSSkipVerify bool
}

// Driver implements netproxy.ProtocolDriver for SMTP.
type Driver struct{ cfg *Config }

// New returns a Driver bound to cfg.
func New(cfg *Config) *Driver { return &Driver{cfg: cfg} }

// Name identifies the protocol in logs.
func (d *Driver) Name() string { return "smtp" }

// UpstreamHost returns host:port for logging.
func (d *Driver) UpstreamHost() string { return fmt.Sprintf("%s:%d", d.cfg.Host, d.cfg.Port) }

// Wipe zeros the stored password.
func (d *Driver) Wipe() {
	for i := range d.cfg.Password {
		d.cfg.Password[i] = 0
	}
}

// DialAndAuthenticate dials, negotiates TLS + STARTTLS as configured, and
// completes AUTH LOGIN with stored credentials.
func (d *Driver) DialAndAuthenticate(ctx context.Context) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", d.cfg.Host, d.cfg.Port)
	dialer := &net.Dialer{Timeout: 15 * time.Second}

	var conn net.Conn
	var err error
	switch d.cfg.TLSMode {
	case "implicit":
		tlsCfg := &tls.Config{ServerName: d.cfg.Host, InsecureSkipVerify: d.cfg.TLSSkipVerify}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	default:
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	r := bufio.NewReader(conn)

	// Expect 220 greeting.
	if code, _, err := readSMTP(r); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read greeting: %w", err)
	} else if code != 220 {
		conn.Close()
		return nil, fmt.Errorf("greeting code %d, want 220", code)
	}

	// EHLO.
	if err := writeLine(conn, "EHLO vault-proxy"); err != nil {
		conn.Close()
		return nil, err
	}
	if code, _, err := readSMTP(r); err != nil || code != 250 {
		conn.Close()
		return nil, fmt.Errorf("EHLO: code=%d err=%v", code, err)
	}

	if d.cfg.TLSMode == "starttls" {
		if err := writeLine(conn, "STARTTLS"); err != nil {
			conn.Close()
			return nil, err
		}
		if code, _, err := readSMTP(r); err != nil || code != 220 {
			conn.Close()
			return nil, fmt.Errorf("STARTTLS: code=%d err=%v", code, err)
		}
		tlsCfg := &tls.Config{ServerName: d.cfg.Host, InsecureSkipVerify: d.cfg.TLSSkipVerify}
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("STARTTLS handshake: %w", err)
		}
		conn = tlsConn
		r = bufio.NewReader(conn)
		// Re-send EHLO after STARTTLS per RFC 3207.
		if err := writeLine(conn, "EHLO vault-proxy"); err != nil {
			conn.Close()
			return nil, err
		}
		if code, _, err := readSMTP(r); err != nil || code != 250 {
			conn.Close()
			return nil, fmt.Errorf("EHLO after STARTTLS: code=%d err=%v", code, err)
		}
	}

	// AUTH LOGIN.
	if err := writeLine(conn, "AUTH LOGIN"); err != nil {
		conn.Close()
		return nil, err
	}
	if code, _, err := readSMTP(r); err != nil || code != 334 {
		conn.Close()
		return nil, fmt.Errorf("AUTH LOGIN: code=%d err=%v", code, err)
	}
	if err := writeLine(conn, base64.StdEncoding.EncodeToString([]byte(d.cfg.User))); err != nil {
		conn.Close()
		return nil, err
	}
	if code, _, err := readSMTP(r); err != nil || code != 334 {
		conn.Close()
		return nil, fmt.Errorf("AUTH LOGIN user: code=%d err=%v", code, err)
	}
	if err := writeLine(conn, base64.StdEncoding.EncodeToString(d.cfg.Password)); err != nil {
		conn.Close()
		return nil, err
	}
	if code, _, err := readSMTP(r); err != nil || code != 235 {
		conn.Close()
		return nil, fmt.Errorf("AUTH LOGIN pass: code=%d err=%v", code, err)
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

// ServeLocal greets the local client as 220 and walks through EHLO + AUTH
// LOGIN with canned responses (credentials ignored), then returns so the
// caller can splice bytes for the MAIL/RCPT/DATA phase.
func (d *Driver) ServeLocal(local, _ net.Conn) error {
	local.SetDeadline(time.Now().Add(30 * time.Second))
	defer local.SetDeadline(time.Time{})

	if err := writeLine(local, "220 vault-proxy ESMTP ready"); err != nil {
		return err
	}
	r := bufio.NewReader(local)

	// Accept HELO/EHLO loop; respond to RSET/NOOP; drive AUTH LOGIN then return.
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read local: %w", err)
		}
		cmd := strings.ToUpper(strings.TrimRight(line, "\r\n"))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			// Advertise AUTH but not STARTTLS (local leg is already loopback).
			for _, r := range []string{
				"250-vault-proxy",
				"250-8BITMIME",
				"250-SIZE 52428800",
				"250 AUTH LOGIN PLAIN",
			} {
				if err := writeLine(local, r); err != nil {
					return err
				}
			}
		case strings.HasPrefix(cmd, "HELO"):
			if err := writeLine(local, "250 vault-proxy"); err != nil {
				return err
			}
		case strings.HasPrefix(cmd, "NOOP"):
			if err := writeLine(local, "250 OK"); err != nil {
				return err
			}
		case strings.HasPrefix(cmd, "RSET"):
			if err := writeLine(local, "250 OK"); err != nil {
				return err
			}
		case strings.HasPrefix(cmd, "QUIT"):
			writeLine(local, "221 bye")
			return fmt.Errorf("client quit before auth")
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			// Either inline credential on same line or challenge round.
			if strings.HasPrefix(cmd, "AUTH PLAIN ") {
				// credential was supplied inline; ignore content.
				if err := writeLine(local, "235 authentication successful"); err != nil {
					return err
				}
				return nil
			}
			if err := writeLine(local, "334 "); err != nil {
				return err
			}
			if _, err := r.ReadString('\n'); err != nil {
				return err
			}
			if err := writeLine(local, "235 authentication successful"); err != nil {
				return err
			}
			return nil
		case strings.HasPrefix(cmd, "AUTH LOGIN"):
			if err := writeLine(local, "334 "+base64.StdEncoding.EncodeToString([]byte("Username:"))); err != nil {
				return err
			}
			if _, err := r.ReadString('\n'); err != nil {
				return err
			}
			if err := writeLine(local, "334 "+base64.StdEncoding.EncodeToString([]byte("Password:"))); err != nil {
				return err
			}
			if _, err := r.ReadString('\n'); err != nil {
				return err
			}
			if err := writeLine(local, "235 authentication successful"); err != nil {
				return err
			}
			return nil
		default:
			if err := writeLine(local, "530 authentication required"); err != nil {
				return err
			}
		}
	}
}

func writeLine(w net.Conn, line string) error {
	_, err := w.Write([]byte(line + "\r\n"))
	return err
}

// readSMTP reads a multi-line SMTP response and returns the final status code
// and the concatenated text.
func readSMTP(r *bufio.Reader) (int, string, error) {
	var text strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return 0, "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 4 {
			return 0, "", fmt.Errorf("short response: %q", line)
		}
		code, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, "", fmt.Errorf("bad code in %q", line)
		}
		text.WriteString(line[4:])
		text.WriteByte('\n')
		// Continuation marker is '-' in column 4; final line uses ' '.
		if line[3] == ' ' {
			return code, text.String(), nil
		}
	}
}
