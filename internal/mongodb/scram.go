package mongodb

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // MongoDB SCRAM-SHA-1 prehashes the password with MD5 — required by protocol, not security-sensitive
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // legacy SCRAM-SHA-1 support required by MongoDB users created before Atlas migrated defaults to SHA-256
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// SCRAM client supporting both SCRAM-SHA-256 (default, preferred) and
// SCRAM-SHA-1 (legacy — required by MongoDB users created before the cluster
// was migrated to SHA-256, and by some self-hosted older deployments).
//
// MongoDB does NOT negotiate channel binding (tls-server-end-point), so we
// always send the GS2 header "n,," and never include the c=biws extension's
// channel binding token.

// scramHash is one of the two supported families.
type scramHash struct {
	name string // "SCRAM-SHA-256" | "SCRAM-SHA-1"
	new  func() hash.Hash
	size int
}

var (
	scramSHA256 = scramHash{name: "SCRAM-SHA-256", new: sha256.New, size: sha256.Size}
	scramSHA1   = scramHash{name: "SCRAM-SHA-1", new: sha1.New, size: sha1.Size}
)

// scramHashFor returns the hash spec for the named mechanism. An empty string
// defaults to SCRAM-SHA-256 (modern, preferred).
func scramHashFor(mech string) (scramHash, error) {
	switch mech {
	case "", "SCRAM-SHA-256":
		return scramSHA256, nil
	case "SCRAM-SHA-1":
		return scramSHA1, nil
	default:
		return scramHash{}, fmt.Errorf("unsupported SCRAM mechanism %q", mech)
	}
}

// scramClient tracks an in-progress SCRAM-SHA-{1,256} exchange.
type scramClient struct {
	hashSpec        scramHash
	user            string
	password        []byte
	nonce           string
	clientFirstBare string
	authMessage     string
	saltedPassword  []byte
}

func newScramClient(user string, password []byte, h scramHash) (*scramClient, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("scram nonce: %w", err)
	}
	return &scramClient{
		hashSpec: h,
		user:     user,
		password: password,
		nonce:    base64.RawStdEncoding.EncodeToString(buf),
	}, nil
}

// clientFirst returns the SASL client-first-message payload (with the "n,,"
// GS2 header — MongoDB expects the entire client-first message in saslStart).
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

	// SCRAM-SHA-1 against MongoDB uses MongoDB's legacy password digest
	// (hex(MD5(user + ":mongo:" + password))) as the input to PBKDF2 instead
	// of the raw password. SCRAM-SHA-256 (post-MongoDB-4.0) uses the SASLprep
	// password directly. Without this, SHA-1 auth fails with "bad auth" against
	// any MongoDB server — see SERVER-2479 / SCRAM-SHA-1 mongoPasswordDigest.
	pwdInput := s.password
	if s.hashSpec.name == "SCRAM-SHA-1" {
		sum := md5.Sum([]byte(s.user + ":mongo:" + string(s.password)))
		pwdInput = []byte(hex.EncodeToString(sum[:]))
	}
	s.saltedPassword = pbkdf2.Key(pwdInput, salt, iterations, s.hashSpec.size, s.hashSpec.new)
	clientKey := s.hmac(s.saltedPassword, []byte("Client Key"))
	storedKey := s.hashOf(clientKey)

	clientFinalWithoutProof := "c=biws,r=" + serverNonce // biws = base64("n,,")
	s.authMessage = s.clientFirstBare + "," + string(serverFirst) + "," + clientFinalWithoutProof

	clientSig := s.hmac(storedKey, []byte(s.authMessage))
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
	serverKey := s.hmac(s.saltedPassword, []byte("Server Key"))
	serverSig := s.hmac(serverKey, []byte(s.authMessage))
	if !hmac.Equal(expected, serverSig) {
		return fmt.Errorf("server signature mismatch")
	}
	return nil
}

func (s *scramClient) hmac(key, data []byte) []byte {
	h := hmac.New(s.hashSpec.new, key)
	h.Write(data)
	return h.Sum(nil)
}

func (s *scramClient) hashOf(data []byte) []byte {
	h := s.hashSpec.new()
	h.Write(data)
	return h.Sum(nil)
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
