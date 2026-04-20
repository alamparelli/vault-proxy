// Package postgres implements an auth-only Postgres proxy driver.
//
// Upstream: speaks the real client side of the Postgres v3 startup, optional
// TLS via SSLRequest, and SCRAM-SHA-256 authentication with stored credentials.
//
// Local: acts as a Postgres server for a single client, declines SSL, ignores
// the client's startup parameters (they're overridden by the stored user/db),
// and completes a minimal AuthenticationCleartextPassword exchange (password
// discarded). Then the caller splices bytes between local and upstream.
package postgres

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// Message types (sent from server) and tags (sent from client) in the v3
// Postgres frontend/backend protocol. Only the ones we need are defined.
const (
	msgAuthentication byte = 'R'
	msgBackendKeyData byte = 'K'
	msgErrorResponse  byte = 'E'
	msgParameterStat  byte = 'S'
	msgReadyForQuery  byte = 'Z'
	msgPasswordMsg    byte = 'p' // also SASLInitialResponse / SASLResponse
	msgTerminate      byte = 'X'
)

// Authentication sub-codes (in the 'R' message body).
const (
	authOK            int32 = 0
	authCleartextPass int32 = 3
	authSASL          int32 = 10
	authSASLContinue  int32 = 11
	authSASLFinal     int32 = 12
)

// sslRequestCode is the magic value sent in place of a protocol version to
// request SSL negotiation.
const sslRequestCode uint32 = 80877103

// protocolVersion3 is the StartupMessage protocol version (3.0).
const protocolVersion3 uint32 = 196608

// writeStartupMessage sends a StartupMessage with the given key/value
// parameters. The message has no type byte; it starts directly with length.
func writeStartupMessage(w io.Writer, params map[string]string) error {
	body := make([]byte, 0, 256)
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], protocolVersion3)
	body = append(body, ver[:]...)
	for k, v := range params {
		body = append(body, []byte(k)...)
		body = append(body, 0)
		body = append(body, []byte(v)...)
		body = append(body, 0)
	}
	body = append(body, 0) // trailing zero terminates the parameter list
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(body)+4))
	if _, err := w.Write(length[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// writeSSLRequest sends an SSLRequest (length=8, body=magic).
func writeSSLRequest(w io.Writer) error {
	var buf [8]byte
	binary.BigEndian.PutUint32(buf[:4], 8)
	binary.BigEndian.PutUint32(buf[4:], sslRequestCode)
	_, err := w.Write(buf[:])
	return err
}

// writeMessage sends a typed message: [type][length(int32)][body].
// length includes the length field itself but not the type byte.
func writeMessage(w io.Writer, typ byte, body []byte) error {
	var hdr [5]byte
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(body)+4))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(body) > 0 {
		_, err := w.Write(body)
		return err
	}
	return nil
}

// readMessage reads a typed message: type byte, length, body.
func readMessage(r *bufio.Reader) (byte, []byte, error) {
	typ, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length < 4 {
		return 0, nil, fmt.Errorf("invalid message length: %d", length)
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return typ, body, nil
}

// readStartup reads an untyped startup-phase message: length, body.
// Used for StartupMessage and SSLRequest coming from a local client.
func readStartup(r *bufio.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length < 4 || length > 10000 {
		return nil, fmt.Errorf("invalid startup length: %d", length)
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// errorBody formats a minimal ErrorResponse body: S (severity), C (code),
// M (message), terminated by a final null.
func errorBody(severity, code, message string) []byte {
	buf := make([]byte, 0, 64+len(message))
	buf = append(buf, 'S')
	buf = append(buf, []byte(severity)...)
	buf = append(buf, 0)
	buf = append(buf, 'C')
	buf = append(buf, []byte(code)...)
	buf = append(buf, 0)
	buf = append(buf, 'M')
	buf = append(buf, []byte(message)...)
	buf = append(buf, 0)
	buf = append(buf, 0)
	return buf
}

// parseErrorBody extracts the M (message) field for logging.
func parseErrorBody(body []byte) string {
	i := 0
	for i < len(body) {
		if body[i] == 0 {
			return ""
		}
		field := body[i]
		i++
		end := i
		for end < len(body) && body[end] != 0 {
			end++
		}
		val := string(body[i:end])
		i = end + 1
		if field == 'M' {
			return val
		}
	}
	return ""
}
