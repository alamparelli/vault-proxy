package postgres

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// Config holds connection parameters copied out of the vault.
type Config struct {
	Host          string
	Port          int
	User          string
	Password      []byte // wiped after use
	Database      string
	TLSMode       string // "require" (default) | "prefer" | "disable"
	TLSSkipVerify bool
}

// Driver implements netproxy.ProtocolDriver for Postgres.
type Driver struct{ cfg *Config }

// New returns a Driver bound to cfg.
func New(cfg *Config) *Driver { return &Driver{cfg: cfg} }

// Name identifies the protocol in logs.
func (d *Driver) Name() string { return "postgres" }

// UpstreamHost returns host:port for logging.
func (d *Driver) UpstreamHost() string { return fmt.Sprintf("%s:%d", d.cfg.Host, d.cfg.Port) }

// Wipe zeros the stored password.
func (d *Driver) Wipe() {
	for i := range d.cfg.Password {
		d.cfg.Password[i] = 0
	}
}

// DialAndAuthenticate dials, optionally negotiates TLS, sends a StartupMessage
// using the stored credentials, and completes SCRAM-SHA-256 or cleartext
// password authentication as requested by the server. Returns the
// authenticated connection positioned just after ReadyForQuery.
func (d *Driver) DialAndAuthenticate(ctx context.Context) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", d.cfg.Host, d.cfg.Port)
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))

	// SSLRequest negotiation.
	if d.cfg.TLSMode != "disable" {
		if err := writeSSLRequest(conn); err != nil {
			conn.Close()
			return nil, err
		}
		var resp [1]byte
		if _, err := conn.Read(resp[:]); err != nil {
			conn.Close()
			return nil, fmt.Errorf("read ssl response: %w", err)
		}
		switch resp[0] {
		case 'S':
			tlsCfg := &tls.Config{ServerName: d.cfg.Host, InsecureSkipVerify: d.cfg.TLSSkipVerify}
			tlsConn := tls.Client(conn, tlsCfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, fmt.Errorf("tls handshake: %w", err)
			}
			conn = tlsConn
		case 'N':
			if d.cfg.TLSMode == "require" {
				conn.Close()
				return nil, fmt.Errorf("server refused TLS but tls=require")
			}
		default:
			conn.Close()
			return nil, fmt.Errorf("unexpected SSL response: %c", resp[0])
		}
	}

	// Send StartupMessage.
	params := map[string]string{
		"user":     d.cfg.User,
		"database": d.cfg.Database,
	}
	if err := writeStartupMessage(conn, params); err != nil {
		conn.Close()
		return nil, err
	}

	r := bufio.NewReader(conn)

	// Auth loop.
	for {
		typ, body, err := readMessage(r)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("read auth response: %w", err)
		}
		switch typ {
		case msgErrorResponse:
			conn.Close()
			return nil, fmt.Errorf("server error: %s", parseErrorBody(body))
		case msgAuthentication:
			if len(body) < 4 {
				conn.Close()
				return nil, fmt.Errorf("short authentication body")
			}
			sub := int32FromBytes(body[:4])
			switch sub {
			case authOK:
				goto postAuth
			case authCleartextPass:
				pw := append([]byte(nil), d.cfg.Password...)
				pw = append(pw, 0)
				if err := writeMessage(conn, msgPasswordMsg, pw); err != nil {
					conn.Close()
					return nil, err
				}
			case authSASL:
				// body[4:] is null-terminated list of mechanism names.
				if !containsMechanism(body[4:], "SCRAM-SHA-256") {
					conn.Close()
					return nil, fmt.Errorf("server does not offer SCRAM-SHA-256")
				}
				if err := scramSHA256(conn, r, d.cfg.User, d.cfg.Password); err != nil {
					conn.Close()
					return nil, fmt.Errorf("scram: %w", err)
				}
				goto postAuth
			default:
				conn.Close()
				return nil, fmt.Errorf("unsupported auth method sub=%d (server requires a mechanism vault-proxy does not implement)", sub)
			}
		default:
			conn.Close()
			return nil, fmt.Errorf("unexpected message type %c during auth", typ)
		}
	}

postAuth:
	// Drain ParameterStatus / BackendKeyData / NoticeResponse until the first
	// ReadyForQuery. The local server will synthesise its own set, so we do
	// not relay these.
	for {
		typ, body, err := readMessage(r)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("drain post-auth: %w", err)
		}
		switch typ {
		case msgParameterStat, msgBackendKeyData, 'N': // N = NoticeResponse
			continue
		case msgReadyForQuery:
			conn.SetDeadline(time.Time{})
			return conn, nil
		case msgErrorResponse:
			conn.Close()
			return nil, fmt.Errorf("post-auth error: %s", parseErrorBody(body))
		default:
			// Unknown frame — ignore and keep draining.
		}
	}
}

// ServeLocal acts as a minimal Postgres server to the local client: declines
// SSL, reads the StartupMessage (ignored), answers AuthenticationCleartextPassword
// (password discarded), and sends AuthenticationOk + synthetic ParameterStatus
// + BackendKeyData + ReadyForQuery. After this returns the caller splices.
func (d *Driver) ServeLocal(local, _ net.Conn) error {
	local.SetDeadline(time.Now().Add(30 * time.Second))
	defer local.SetDeadline(time.Time{})
	r := bufio.NewReader(local)

	// First frame may be SSLRequest (length=8 body=magic). Handle repeatedly
	// until a regular StartupMessage arrives.
	for {
		body, err := readStartup(r)
		if err != nil {
			return fmt.Errorf("read startup: %w", err)
		}
		if len(body) == 4 {
			// SSLRequest (length=8 total, body=4 bytes of magic) or CancelRequest.
			code := int32FromBytes(body[:4])
			if uint32(code) == sslRequestCode {
				if _, err := local.Write([]byte{'N'}); err != nil {
					return err
				}
				continue
			}
			// GSSAPIRequest or CancelRequest — decline and close.
			return fmt.Errorf("unsupported startup code %d", code)
		}
		// Regular StartupMessage.
		if len(body) < 4 {
			return fmt.Errorf("startup too short")
		}
		// body[0:4] = protocol version; body[4:] = params.
		break
	}

	// Ask the client for a cleartext password; we discard it.
	var req [4]byte
	putInt32(req[:], authCleartextPass)
	if err := writeMessage(local, msgAuthentication, req[:]); err != nil {
		return err
	}
	typ, _, err := readMessage(r)
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	if typ != msgPasswordMsg {
		return fmt.Errorf("expected PasswordMessage, got %c", typ)
	}

	// AuthenticationOk.
	var ok [4]byte
	putInt32(ok[:], authOK)
	if err := writeMessage(local, msgAuthentication, ok[:]); err != nil {
		return err
	}

	// Minimal ParameterStatus entries so clients that check server_version etc.
	// do not bail. Values are best-effort placeholders; the real values come
	// from the upstream once we splice.
	for _, kv := range [][2]string{
		{"server_version", "14.0 (vault-proxy)"},
		{"server_encoding", "UTF8"},
		{"client_encoding", "UTF8"},
		{"DateStyle", "ISO, MDY"},
		{"TimeZone", "UTC"},
		{"integer_datetimes", "on"},
		{"standard_conforming_strings", "on"},
	} {
		body := make([]byte, 0, 64)
		body = append(body, []byte(kv[0])...)
		body = append(body, 0)
		body = append(body, []byte(kv[1])...)
		body = append(body, 0)
		if err := writeMessage(local, msgParameterStat, body); err != nil {
			return err
		}
	}

	// BackendKeyData with placeholder pid/secret (cancellation will not work
	// through the pipe, which is acceptable for a one-shot session).
	var bkd [8]byte
	putInt32(bkd[:4], 0)
	putInt32(bkd[4:], 0)
	if err := writeMessage(local, msgBackendKeyData, bkd[:]); err != nil {
		return err
	}

	// ReadyForQuery with transaction-idle status.
	if err := writeMessage(local, msgReadyForQuery, []byte{'I'}); err != nil {
		return err
	}

	return nil
}

// containsMechanism scans a null-terminated list of SASL mechanism names for
// the given mechanism.
func containsMechanism(list []byte, mech string) bool {
	for _, name := range bytes.Split(list, []byte{0}) {
		if len(name) == 0 {
			continue
		}
		if strings.EqualFold(string(name), mech) {
			return true
		}
	}
	return false
}
