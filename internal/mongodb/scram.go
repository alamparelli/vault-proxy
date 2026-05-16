package mongodb

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// SCRAM-SHA-256 client implementation operating on raw byte payloads. We do
// NOT do channel binding (tls-server-end-point) — MongoDB does not negotiate
// it and Apple/most clusters do not require it.

// scramClient tracks an in-progress SCRAM-SHA-256 exchange.
type scramClient struct {
	user            string
	password        []byte
	nonce           string
	clientFirstBare string
	authMessage     string
	saltedPassword  []byte
}

func newScramClient(user string, password []byte) (*scramClient, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("scram nonce: %w", err)
	}
	return &scramClient{
		user:     user,
		password: password,
		nonce:    base64.RawStdEncoding.EncodeToString(buf),
	}, nil
}

// clientFirst returns the SASL client-first-message payload (no GS2 channel
// binding flag prefix). MongoDB expects the entire client-first message
// including the "n,," GS2 header in the saslStart payload.
func (s *scramClient) clientFirst() []byte {
	s.clientFirstBare = "n=" + saslEscape(s.user) + ",r=" + s.nonce
	return []byte("n,," + s.clientFirstBare)
}

// clientFinal consumes the server-first message and returns the
// client-final-message payload that should be sent in saslContinue.
func (s *scramClient) clientFinal(serverFirst []byte) ([]byte, error) {
	parts := parseSaslMessage(string(serverFirst))
	serverNonce := parts["r"]
	saltB64 := parts["s"]
	iterStr := parts["i"]
	if serverNonce == "" || saltB64 == "" || iterStr == "" {
		return nil, fmt.Errorf("server-first missing fields: %q", serverFirst)
	}
	if !strings.HasPrefix(serverNonce, s.nonce) {
		return nil, fmt.Errorf("server nonce does not begin with client nonce")
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	iterations, err := strconv.Atoi(iterStr)
	if err != nil || iterations < 1 {
		return nil, fmt.Errorf("bad iteration count %q", iterStr)
	}

	s.saltedPassword = pbkdf2.Key(s.password, salt, iterations, sha256.Size, sha256.New)
	clientKey := hmacSHA256(s.saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)

	clientFinalWithoutProof := "c=biws,r=" + serverNonce // biws = base64("n,,")
	s.authMessage = s.clientFirstBare + "," + string(serverFirst) + "," + clientFinalWithoutProof

	clientSig := hmacSHA256(storedKey[:], []byte(s.authMessage))
	proof := xorSlice(clientKey, clientSig)

	return []byte(clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof)), nil
}

// verifyServerFinal checks the server's v= signature.
func (s *scramClient) verifyServerFinal(serverFinal []byte) error {
	parts := parseSaslMessage(string(serverFinal))
	if e := parts["e"]; e != "" {
		return fmt.Errorf("scram server error: %s", e)
	}
	vB64 := parts["v"]
	if vB64 == "" {
		return fmt.Errorf("server-final missing v=")
	}
	expected, err := base64.StdEncoding.DecodeString(vB64)
	if err != nil {
		return fmt.Errorf("decode server sig: %w", err)
	}
	serverKey := hmacSHA256(s.saltedPassword, []byte("Server Key"))
	serverSig := hmacSHA256(serverKey, []byte(s.authMessage))
	if !hmac.Equal(expected, serverSig) {
		return fmt.Errorf("server signature mismatch")
	}
	return nil
}

func parseSaslMessage(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		if i := strings.IndexByte(part, '='); i > 0 {
			out[part[:i]] = part[i+1:]
		}
	}
	return out
}

// saslEscape encodes the SASLname per RFC 5802: , becomes =2C and = becomes =3D.
func saslEscape(s string) string {
	if !strings.ContainsAny(s, "=,") {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch r {
		case ',':
			b.WriteString("=2C")
		case '=':
			b.WriteString("=3D")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
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
