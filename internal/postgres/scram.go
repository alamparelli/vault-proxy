package postgres

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// scramSHA256 runs the client half of a SCRAM-SHA-256 exchange over an
// already-open Postgres connection that is in the middle of authentication
// (an AuthenticationSASL message has just been received listing SCRAM-SHA-256
// as a mechanism). On success the upstream moves through AuthenticationOk.
func scramSHA256(w io.Writer, r *bufio.Reader, user string, password []byte) error {
	// 1. Client-first-message
	clientNonce, err := randomNonce(18)
	if err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	// Postgres ignores the user field in SCRAM client-first — it already
	// knows it from StartupMessage. We still send an empty one per spec.
	clientFirstBare := fmt.Sprintf("n=,r=%s", clientNonce)
	clientFirst := "n,," + clientFirstBare

	// SASLInitialResponse body = mechanism\0int32(len)msg
	mechanism := "SCRAM-SHA-256"
	body := make([]byte, 0, len(mechanism)+1+4+len(clientFirst))
	body = append(body, []byte(mechanism)...)
	body = append(body, 0)
	var lenBuf [4]byte
	putInt32(lenBuf[:], int32(len(clientFirst)))
	body = append(body, lenBuf[:]...)
	body = append(body, []byte(clientFirst)...)
	if err := writeMessage(w, msgPasswordMsg, body); err != nil {
		return err
	}

	// 2. Expect AuthenticationSASLContinue with server-first-message.
	typ, rb, err := readMessage(r)
	if err != nil {
		return fmt.Errorf("read SASL continue: %w", err)
	}
	if typ == msgErrorResponse {
		return fmt.Errorf("server error: %s", parseErrorBody(rb))
	}
	if typ != msgAuthentication {
		return fmt.Errorf("unexpected msg %c during SASL", typ)
	}
	if len(rb) < 4 {
		return fmt.Errorf("short auth body")
	}
	sub := int32FromBytes(rb[:4])
	if sub != authSASLContinue {
		return fmt.Errorf("expected SASLContinue, got auth sub=%d", sub)
	}
	serverFirst := string(rb[4:])

	// Parse server-first: r=<nonce>,s=<base64 salt>,i=<iter>
	parts := parseSCRAM(serverFirst)
	serverNonce, saltB64, iterStr := parts["r"], parts["s"], parts["i"]
	if serverNonce == "" || saltB64 == "" || iterStr == "" {
		return fmt.Errorf("malformed server-first: %q", serverFirst)
	}
	if !strings.HasPrefix(serverNonce, clientNonce) {
		return fmt.Errorf("server nonce does not begin with client nonce")
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return fmt.Errorf("decode salt: %w", err)
	}
	iterations, err := strconv.Atoi(iterStr)
	if err != nil || iterations < 1 {
		return fmt.Errorf("bad iteration count %q", iterStr)
	}

	// 3. Compute proof.
	saltedPassword := pbkdf2.Key(password, salt, iterations, sha256.Size, sha256.New)
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)

	clientFinalWithoutProof := fmt.Sprintf("c=biws,r=%s", serverNonce)
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof
	clientSig := hmacSHA256(storedKey[:], []byte(authMessage))
	proof := xorSlice(clientKey, clientSig)
	clientFinal := clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof)

	if err := writeMessage(w, msgPasswordMsg, []byte(clientFinal)); err != nil {
		return err
	}

	// 4. Expect AuthenticationSASLFinal with server-final-message.
	typ, rb, err = readMessage(r)
	if err != nil {
		return fmt.Errorf("read SASL final: %w", err)
	}
	if typ == msgErrorResponse {
		return fmt.Errorf("server error: %s", parseErrorBody(rb))
	}
	if typ != msgAuthentication {
		return fmt.Errorf("unexpected msg %c during SASL final", typ)
	}
	sub = int32FromBytes(rb[:4])
	if sub != authSASLFinal {
		return fmt.Errorf("expected SASLFinal, got auth sub=%d", sub)
	}
	serverFinal := string(rb[4:])

	// Verify server signature.
	serverFinalParts := parseSCRAM(serverFinal)
	vB64 := serverFinalParts["v"]
	if vB64 == "" {
		return fmt.Errorf("missing server signature")
	}
	expectedSig, err := base64.StdEncoding.DecodeString(vB64)
	if err != nil {
		return fmt.Errorf("decode server sig: %w", err)
	}
	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))
	serverSig := hmacSHA256(serverKey, []byte(authMessage))
	if !hmac.Equal(expectedSig, serverSig) {
		return fmt.Errorf("server signature mismatch")
	}

	// 5. Expect AuthenticationOk.
	typ, rb, err = readMessage(r)
	if err != nil {
		return fmt.Errorf("read authOk: %w", err)
	}
	if typ != msgAuthentication {
		return fmt.Errorf("unexpected msg %c awaiting AuthOk", typ)
	}
	if int32FromBytes(rb[:4]) != authOK {
		return fmt.Errorf("expected AuthenticationOk after SASL final")
	}

	// user is referenced for future extensibility (channel-binding, etc.).
	_ = user
	return nil
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func xorSlice(a, b []byte) []byte {
	if len(a) != len(b) {
		return nil
	}
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func parseSCRAM(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		if i := strings.IndexByte(part, '='); i > 0 {
			out[part[:i]] = part[i+1:]
		}
	}
	return out
}

func randomNonce(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(buf), nil
}

func int32FromBytes(b []byte) int32 {
	return int32(uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]))
}

func putInt32(b []byte, v int32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}
