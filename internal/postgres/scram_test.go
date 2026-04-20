package postgres

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// TestSCRAM_ClientHalf drives scramSHA256 against a minimal server that
// follows RFC 5802. It verifies the client computes a correct proof.
func TestSCRAM_ClientHalf(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	br := bufio.NewReader(b)
	ar := bufio.NewReader(a)

	password := []byte("hunter2")
	salt := []byte("randomsalt123456")
	iter := 4096

	errCh := make(chan error, 1)
	go func() {
		errCh <- scramSHA256(a, ar, "user", password)
	}()

	// Read SASLInitialResponse (message type 'p').
	typ, body, err := readMessage(br)
	if err != nil {
		t.Fatal(err)
	}
	if typ != msgPasswordMsg {
		t.Fatalf("expected 'p', got %c", typ)
	}
	// body: mechanism\0 int32(len) msg
	idx := bytes.IndexByte(body, 0)
	if idx < 0 {
		t.Fatal("no mechanism terminator")
	}
	mech := string(body[:idx])
	if mech != "SCRAM-SHA-256" {
		t.Fatalf("mech = %q", mech)
	}
	msgLen := int(int32FromBytes(body[idx+1 : idx+5]))
	clientFirst := string(body[idx+5 : idx+5+msgLen])
	cfb := strings.TrimPrefix(clientFirst, "n,,")
	parts := parseSCRAM(cfb)
	clientNonce := parts["r"]
	if clientNonce == "" {
		t.Fatalf("no client nonce in %q", clientFirst)
	}

	// Send SASLContinue.
	serverNonce := clientNonce + "SERVER"
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	serverFirst := fmt.Sprintf("r=%s,s=%s,i=%d", serverNonce, saltB64, iter)
	sc := make([]byte, 0, 4+len(serverFirst))
	var sub [4]byte
	putInt32(sub[:], authSASLContinue)
	sc = append(sc, sub[:]...)
	sc = append(sc, []byte(serverFirst)...)
	if err := writeMessage(b, msgAuthentication, sc); err != nil {
		t.Fatal(err)
	}

	// Read SASLResponse (message 'p' containing client-final).
	typ, body, err = readMessage(br)
	if err != nil {
		t.Fatal(err)
	}
	if typ != msgPasswordMsg {
		t.Fatalf("expected 'p' for client-final, got %c", typ)
	}
	clientFinal := string(body)
	cfParts := parseSCRAM(clientFinal)
	proof, err := base64.StdEncoding.DecodeString(cfParts["p"])
	if err != nil {
		t.Fatalf("decode proof: %v", err)
	}

	// Recompute expected proof server-side.
	saltedPassword := pbkdf2.Key(password, salt, iter, sha256.Size, sha256.New)
	clientKey := hmacSum(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	clientFinalWithoutProof := "c=biws,r=" + serverNonce
	authMsg := cfb + "," + serverFirst + "," + clientFinalWithoutProof
	clientSig := hmacSum(storedKey[:], []byte(authMsg))
	want := make([]byte, len(clientKey))
	for i := range clientKey {
		want[i] = clientKey[i] ^ clientSig[i]
	}
	if !bytes.Equal(proof, want) {
		t.Fatal("client proof mismatch")
	}

	// Send SASLFinal.
	serverKey := hmacSum(saltedPassword, []byte("Server Key"))
	serverSig := hmacSum(serverKey, []byte(authMsg))
	sf := make([]byte, 0, 4+len(serverSig)+2)
	putInt32(sub[:], authSASLFinal)
	sf = append(sf, sub[:]...)
	sf = append(sf, []byte("v="+base64.StdEncoding.EncodeToString(serverSig))...)
	if err := writeMessage(b, msgAuthentication, sf); err != nil {
		t.Fatal(err)
	}

	// Send AuthenticationOk.
	putInt32(sub[:], authOK)
	if err := writeMessage(b, msgAuthentication, sub[:]); err != nil {
		t.Fatal(err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("scramSHA256: %v", err)
	}
}

func hmacSum(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// sanity: reader is used
var _ = io.EOF
