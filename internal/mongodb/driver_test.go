package mongodb

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// TestDialAndAuthenticate_Success spins up a fake upstream MongoDB server that
// performs a real SCRAM-SHA-256 exchange with the configured user/password,
// verifies the client proof, sends a valid server-final, and reports done=true.
//
// This exercises the wire protocol, BSON, OP_MSG framing, and SCRAM crypto end
// to end. We deliberately use a fresh tcp listener with no TLS — that path is
// exercised separately at integration level against real MongoDB.
func TestDialAndAuthenticate_Success(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	const (
		user = "alice"
		pass = "wonderland"
	)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer conn.Close()
		if err := serveFakeUpstream(conn, user, pass); err != nil {
			t.Errorf("fake upstream: %v", err)
		}
	}()

	host, port := splitHostPort(t, ln.Addr().String())
	drv := New(&Config{
		Host:     host,
		Port:     port,
		User:     user,
		Password: []byte(pass),
		AuthDB:   "admin",
		TLSMode:  "disable",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := drv.DialAndAuthenticate(ctx)
	if err != nil {
		t.Fatalf("DialAndAuthenticate: %v", err)
	}
	conn.Close()
	wg.Wait()
}

// TestDialAndAuthenticate_BadPassword ensures the client rejects a tampered
// server signature (which is what a wrong password would manifest as on either
// side of the conversation).
func TestDialAndAuthenticate_BadPassword(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Server expects "wonderland" but client will send proof computed
		// against "wrong-password" — server-final verification will pass
		// because the server uses its own expectation, but the SCRAM client
		// proof will fail at the server. We simulate by replying with an
		// error doc on saslContinue.
		_ = serveFakeUpstreamWithBadFinal(conn)
	}()

	host, port := splitHostPort(t, ln.Addr().String())
	drv := New(&Config{
		Host: host, Port: port,
		User: "alice", Password: []byte("wrong-password"),
		AuthDB: "admin", TLSMode: "disable",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := drv.DialAndAuthenticate(ctx); err == nil {
		t.Fatal("expected error from DialAndAuthenticate")
	}
}

// TestServeLocal_Hello reads a client hello and verifies the synthesised reply
// is parseable and looks like a standalone-server hello with no auth required.
func TestServeLocal_Hello(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	drv := New(&Config{User: "u", Password: []byte("p")})

	done := make(chan error, 1)
	go func() {
		done <- drv.ServeLocal(serverSide, nil)
	}()

	if _, err := WriteOpMsg(clientSide, Doc{{Key: "hello", Value: int32(1)}}, 0); err != nil {
		t.Fatalf("write client hello: %v", err)
	}
	hdr, body, err := ReadMessage(clientSide)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if hdr.OpCode != opMsgCode {
		t.Errorf("opCode = %d", hdr.OpCode)
	}
	reply, _, err := ParseOpMsgBody(body)
	if err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if reply.Lookup("ok") != 1.0 {
		t.Errorf("ok = %v", reply.Lookup("ok"))
	}
	if reply.Lookup("isWritablePrimary") != true {
		t.Errorf("isWritablePrimary not true")
	}
	if reply.Lookup("saslSupportedMechs") != nil {
		t.Errorf("synthesised reply must NOT advertise auth mechanisms")
	}

	if err := <-done; err != nil {
		t.Errorf("ServeLocal returned %v", err)
	}
}

// serveFakeUpstream runs the smallest credible MongoDB server impersonation
// our driver needs: reply to hello, then run SCRAM-SHA-256 verifying the
// client's proof, then reply with done=true.
func serveFakeUpstream(conn net.Conn, user, password string) error {
	// 1. hello
	hdr, body, err := ReadMessage(conn)
	if err != nil {
		return err
	}
	if hdr.OpCode != opMsgCode {
		return errf("upstream: expected OP_MSG, got %d", hdr.OpCode)
	}
	doc, _, err := ParseOpMsgBody(body)
	if err != nil {
		return err
	}
	if doc.Lookup("hello") == nil {
		return errf("expected hello command")
	}
	if err := WriteOpMsgReply(conn, Doc{
		{Key: "ok", Value: float64(1)},
		{Key: "maxWireVersion", Value: int32(17)},
		{Key: "saslSupportedMechs", Value: []string{"SCRAM-SHA-256"}},
	}, 0, hdr.RequestID); err != nil {
		return err
	}

	// 2. saslStart with SCRAM client-first
	hdr, body, err = ReadMessage(conn)
	if err != nil {
		return err
	}
	doc, _, _ = ParseOpMsgBody(body)
	if doc.Lookup("saslStart") == nil {
		return errf("expected saslStart")
	}
	clientFirst, _ := doc.Lookup("payload").(Binary)
	cf := string(clientFirst.Data)
	// Strip "n,," GS2 prefix.
	if !strings.HasPrefix(cf, "n,,") {
		return errf("bad client-first prefix: %q", cf)
	}
	bare := strings.TrimPrefix(cf, "n,,")
	parts := parseSaslMessage(bare)
	clientNonce := parts["r"]
	if clientNonce == "" {
		return errf("missing client nonce")
	}

	// Build server-first: append our own nonce, fixed salt+iterations.
	serverNonceRaw := make([]byte, 18)
	_, _ = rand.Read(serverNonceRaw)
	serverNonce := clientNonce + base64.RawStdEncoding.EncodeToString(serverNonceRaw)
	saltRaw := make([]byte, 16)
	_, _ = rand.Read(saltRaw)
	saltB64 := base64.StdEncoding.EncodeToString(saltRaw)
	iters := 4096
	serverFirst := "r=" + serverNonce + ",s=" + saltB64 + ",i=4096"

	if err := WriteOpMsgReply(conn, Doc{
		{Key: "ok", Value: float64(1)},
		{Key: "conversationId", Value: int32(1)},
		{Key: "done", Value: false},
		{Key: "payload", Value: Binary{Subtype: 0, Data: []byte(serverFirst)}},
	}, 0, hdr.RequestID); err != nil {
		return err
	}

	// 3. saslContinue with client-final → verify proof, send server-final.
	hdr, body, err = ReadMessage(conn)
	if err != nil {
		return err
	}
	doc, _, _ = ParseOpMsgBody(body)
	if doc.Lookup("saslContinue") == nil {
		return errf("expected saslContinue")
	}
	cfPayload, _ := doc.Lookup("payload").(Binary)
	cfStr := string(cfPayload.Data)
	cfParts := parseSaslMessage(cfStr)
	if cfParts["r"] != serverNonce {
		return errf("client final has wrong nonce")
	}
	clientProofB64 := cfParts["p"]
	if clientProofB64 == "" {
		return errf("missing client proof")
	}

	saltedPassword := pbkdf2.Key([]byte(password), saltRaw, iters, sha256.Size, sha256.New)
	clientKey := hmac.New(sha256.New, saltedPassword)
	clientKey.Write([]byte("Client Key"))
	ck := clientKey.Sum(nil)
	storedKey := sha256.Sum256(ck)

	authMessage := bare + "," + serverFirst + "," + "c=biws,r=" + serverNonce
	clientSig := hmac.New(sha256.New, storedKey[:])
	clientSig.Write([]byte(authMessage))
	cs := clientSig.Sum(nil)

	expectedProof := make([]byte, len(ck))
	for i := range ck {
		expectedProof[i] = ck[i] ^ cs[i]
	}
	expectedProofB64 := base64.StdEncoding.EncodeToString(expectedProof)
	if expectedProofB64 != clientProofB64 {
		return errf("client proof mismatch")
	}

	serverKey := hmac.New(sha256.New, saltedPassword)
	serverKey.Write([]byte("Server Key"))
	sk := serverKey.Sum(nil)
	serverSig := hmac.New(sha256.New, sk)
	serverSig.Write([]byte(authMessage))
	ss := serverSig.Sum(nil)

	serverFinal := "v=" + base64.StdEncoding.EncodeToString(ss)
	return WriteOpMsgReply(conn, Doc{
		{Key: "ok", Value: float64(1)},
		{Key: "conversationId", Value: int32(1)},
		{Key: "done", Value: true},
		{Key: "payload", Value: Binary{Subtype: 0, Data: []byte(serverFinal)}},
	}, 0, hdr.RequestID)
}

// serveFakeUpstreamWithBadFinal replies with an error doc on saslContinue.
func serveFakeUpstreamWithBadFinal(conn net.Conn) error {
	// hello
	hdr, _, err := ReadMessage(conn)
	if err != nil {
		return err
	}
	_ = WriteOpMsgReply(conn, Doc{
		{Key: "ok", Value: float64(1)},
		{Key: "maxWireVersion", Value: int32(17)},
	}, 0, hdr.RequestID)

	// saslStart → reply with arbitrary server-first (signature won't match)
	hdr, _, err = ReadMessage(conn)
	if err != nil {
		return err
	}
	_ = WriteOpMsgReply(conn, Doc{
		{Key: "ok", Value: float64(1)},
		{Key: "conversationId", Value: int32(1)},
		{Key: "done", Value: false},
		{Key: "payload", Value: Binary{Subtype: 0, Data: []byte("r=DEADBEEF,s=YWFh,i=4096")}},
	}, 0, hdr.RequestID)

	// saslContinue → reject
	hdr, _, _ = ReadMessage(conn)
	return WriteOpMsgReply(conn, Doc{
		{Key: "ok", Value: float64(0)},
		{Key: "code", Value: int32(18)},
		{Key: "errmsg", Value: "Authentication failed."},
	}, 0, hdr.RequestID)
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host: %v", err)
	}
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port
}

type fmtErr struct{ msg string }

func (e *fmtErr) Error() string { return e.msg }

func errf(format string, args ...any) error {
	// Keep the test self-contained; we don't pull in fmt to avoid double import here.
	// Builders use this for terse error labels.
	msg := format
	for _, a := range args {
		msg += " " + asString(a)
	}
	return &fmtErr{msg: msg}
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case int:
		return itoa(t)
	case int32:
		return itoa(int(t))
	default:
		return "?"
	}
}

var _ = io.EOF // keep io import in case future tests want it
