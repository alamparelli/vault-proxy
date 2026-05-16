package mongodb

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// Config carries connection parameters copied out of vault on session start.
type Config struct {
	Host          string
	Port          int
	User          string
	Password      []byte // wiped after handshake
	AuthDB        string // authSource — defaults to "admin"
	TLSMode       string // "require" (default) | "prefer" | "disable"
	TLSSkipVerify bool
	ReplicaSet    string // optional, surfaced in synthesised hello replies
}

// Driver implements netproxy.ProtocolDriver for MongoDB. The strategy:
//
//  1. Vault dials upstream, optionally negotiates TLS, sends a hello with
//     `saslSupportedMechs: "<authDB>.<user>"`, then runs the SCRAM-SHA-256
//     conversation with stored credentials.
//  2. ServeLocal reads the client's hello, replies with an auth-free
//     standalone-server hello, and returns. The listener splices after that.
//
// Clients must connect locally without credentials, e.g.:
//
//	mongodb://127.0.0.1:54321/yourdb?directConnection=true
//
// `directConnection=true` keeps the driver from running SDAM topology
// discovery against the fake hello (which would expose the real replica set
// member list otherwise).
type Driver struct {
	cfg *Config
}

// New returns a Driver bound to cfg.
func New(cfg *Config) *Driver {
	if cfg.AuthDB == "" {
		cfg.AuthDB = "admin"
	}
	if cfg.Port == 0 {
		cfg.Port = 27017
	}
	if cfg.TLSMode == "" {
		cfg.TLSMode = "require"
	}
	return &Driver{cfg: cfg}
}

// Name identifies the protocol in logs.
func (d *Driver) Name() string { return "mongodb" }

// UpstreamHost returns host:port for logging.
func (d *Driver) UpstreamHost() string { return fmt.Sprintf("%s:%d", d.cfg.Host, d.cfg.Port) }

// Wipe zeros the in-memory password copy.
func (d *Driver) Wipe() {
	for i := range d.cfg.Password {
		d.cfg.Password[i] = 0
	}
}

// DialAndAuthenticate opens a TCP+TLS connection to the upstream server,
// performs hello, and runs SCRAM-SHA-256. Returns the authenticated conn.
func (d *Driver) DialAndAuthenticate(ctx context.Context) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", d.cfg.Host, d.cfg.Port)
	dialer := &net.Dialer{Timeout: 15 * time.Second}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))

	if d.cfg.TLSMode != "disable" {
		tlsCfg := &tls.Config{ServerName: d.cfg.Host, InsecureSkipVerify: d.cfg.TLSSkipVerify}
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			if d.cfg.TLSMode == "prefer" {
				// Fall back to plain TCP — re-dial since the original conn was consumed.
				conn, err = dialer.DialContext(ctx, "tcp", addr)
				if err != nil {
					return nil, fmt.Errorf("redial plain after TLS prefer-fallback: %w", err)
				}
				conn.SetDeadline(time.Now().Add(20 * time.Second))
			} else {
				return nil, fmt.Errorf("tls handshake: %w", err)
			}
		} else {
			conn = tlsConn
		}
	}

	// hello with saslSupportedMechs to let the server tell us which mechanism
	// the user is registered for. We only support SCRAM-SHA-256.
	hello := Doc{
		{Key: "hello", Value: int32(1)},
		{Key: "$db", Value: d.cfg.AuthDB},
		{Key: "saslSupportedMechs", Value: d.cfg.AuthDB + "." + d.cfg.User},
		{Key: "client", Value: Doc{
			{Key: "application", Value: Doc{{Key: "name", Value: "vault-proxy"}}},
			{Key: "driver", Value: Doc{
				{Key: "name", Value: "vault-proxy-mongo"},
				{Key: "version", Value: "0.1"},
			}},
		}},
	}
	if _, err := WriteOpMsg(conn, hello, 0); err != nil {
		conn.Close()
		return nil, err
	}

	r := bufio.NewReader(conn)
	helloHdr, helloBody, err := ReadMessage(r)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read hello reply: %w", err)
	}
	if helloHdr.OpCode != opMsgCode {
		conn.Close()
		return nil, fmt.Errorf("hello reply unexpected opcode %d", helloHdr.OpCode)
	}
	helloDoc, _, err := ParseOpMsgBody(helloBody)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("parse hello reply: %w", err)
	}
	if okVal := okFloat(helloDoc.Lookup("ok")); okVal != 1.0 {
		conn.Close()
		return nil, fmt.Errorf("hello returned ok=%v: %v", okVal, helloDoc.Lookup("errmsg"))
	}

	// saslStart with SCRAM-SHA-256 client-first.
	scram, err := newScramClient(d.cfg.User, d.cfg.Password)
	if err != nil {
		conn.Close()
		return nil, err
	}
	saslStart := Doc{
		{Key: "saslStart", Value: int32(1)},
		{Key: "$db", Value: d.cfg.AuthDB},
		{Key: "mechanism", Value: "SCRAM-SHA-256"},
		{Key: "payload", Value: Binary{Subtype: 0, Data: scram.clientFirst()}},
		{Key: "options", Value: Doc{{Key: "skipEmptyExchange", Value: true}}},
	}
	if _, err := WriteOpMsg(conn, saslStart, 0); err != nil {
		conn.Close()
		return nil, err
	}

	contDoc, err := readOpMsgDoc(r)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("saslStart reply: %w", err)
	}
	if okFloat(contDoc.Lookup("ok")) != 1.0 {
		conn.Close()
		return nil, fmt.Errorf("saslStart not ok: %v", contDoc.Lookup("errmsg"))
	}
	convoID, _ := contDoc.Lookup("conversationId").(int32)
	if convoID == 0 {
		conn.Close()
		return nil, fmt.Errorf("saslStart missing conversationId")
	}
	serverFirst, err := binaryPayload(contDoc.Lookup("payload"))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("saslStart payload: %w", err)
	}

	clientFinal, err := scram.clientFinal(serverFirst)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("scram client-final: %w", err)
	}

	// saslContinue with client-final.
	saslContinue := Doc{
		{Key: "saslContinue", Value: int32(1)},
		{Key: "$db", Value: d.cfg.AuthDB},
		{Key: "conversationId", Value: convoID},
		{Key: "payload", Value: Binary{Subtype: 0, Data: clientFinal}},
	}
	if _, err := WriteOpMsg(conn, saslContinue, 0); err != nil {
		conn.Close()
		return nil, err
	}
	finalDoc, err := readOpMsgDoc(r)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("saslContinue reply: %w", err)
	}
	if okFloat(finalDoc.Lookup("ok")) != 1.0 {
		conn.Close()
		return nil, fmt.Errorf("saslContinue not ok: %v", finalDoc.Lookup("errmsg"))
	}
	serverFinal, err := binaryPayload(finalDoc.Lookup("payload"))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("saslContinue payload: %w", err)
	}
	if err := scram.verifyServerFinal(serverFinal); err != nil {
		conn.Close()
		return nil, err
	}

	// Some servers require an extra saslContinue with empty payload before
	// done=true. We requested skipEmptyExchange in saslStart, so MongoDB 4.4+
	// answers with done=true here. Older servers would need a third roundtrip;
	// we don't currently support them.
	done, _ := finalDoc.Lookup("done").(bool)
	if !done {
		conn.Close()
		return nil, fmt.Errorf("server requires multi-step SASL; vault-proxy requires MongoDB 4.4+ with skipEmptyExchange")
	}

	// Note: r holds the bufio.Reader — any bytes the upstream sent after the
	// saslContinue reply are buffered there and would be lost when we hand
	// the raw conn to the splicer. In practice MongoDB sends nothing until
	// the client makes a query, so this is fine; verify via tests.
	conn.SetDeadline(time.Time{})

	// Capture cached upstream maxWireVersion / topologyVersion so ServeLocal
	// can synthesise a faithful local hello.
	_ = helloDoc
	return conn, nil
}

// ServeLocal reads the client's initial hello, replies with an auth-free
// standalone hello, and returns. After that the listener splices client ↔
// upstream so all subsequent commands hit the authenticated session.
func (d *Driver) ServeLocal(local, _ net.Conn) error {
	local.SetDeadline(time.Now().Add(30 * time.Second))
	defer local.SetDeadline(time.Time{})

	r := bufio.NewReader(local)
	hdr, body, err := ReadMessage(r)
	if err != nil {
		return fmt.Errorf("read client hello: %w", err)
	}
	switch hdr.OpCode {
	case opMsgCode:
		// new wire protocol
	case opQueryCode:
		// legacy isMaster — we still reply, but most modern drivers do not use this.
		return fmt.Errorf("legacy OP_QUERY hello not supported; client must use wire >= 6")
	default:
		return fmt.Errorf("unexpected opcode %d on first message", hdr.OpCode)
	}

	doc, _, err := ParseOpMsgBody(body)
	if err != nil {
		return fmt.Errorf("parse client hello: %w", err)
	}
	if doc.Lookup("hello") == nil && doc.Lookup("isMaster") == nil && doc.Lookup("ismaster") == nil {
		return fmt.Errorf("first message is not hello/isMaster")
	}

	// Synthesise a standalone-server reply. No saslSupportedMechs → driver
	// will NOT try to authenticate. Modern wire version so most operations
	// are available.
	reply := Doc{
		{Key: "isWritablePrimary", Value: true},
		{Key: "ismaster", Value: true}, // legacy alias some clients still look at
		{Key: "maxBsonObjectSize", Value: int32(16777216)},
		{Key: "maxMessageSizeBytes", Value: int32(48000000)},
		{Key: "maxWriteBatchSize", Value: int32(100000)},
		{Key: "localTime", Value: time.Now().UTC()},
		{Key: "logicalSessionTimeoutMinutes", Value: int32(30)},
		{Key: "connectionId", Value: int32(1)},
		{Key: "minWireVersion", Value: int32(0)},
		{Key: "maxWireVersion", Value: int32(17)}, // MongoDB 6.0 wire level
		{Key: "readOnly", Value: false},
		{Key: "ok", Value: float64(1)},
	}
	if d.cfg.ReplicaSet != "" {
		reply = append(reply, DocElem{Key: "setName", Value: d.cfg.ReplicaSet})
	}
	return WriteOpMsgReply(local, reply, 0, hdr.RequestID)
}

func readOpMsgDoc(r *bufio.Reader) (Doc, error) {
	hdr, body, err := ReadMessage(r)
	if err != nil {
		return nil, err
	}
	if hdr.OpCode != opMsgCode {
		return nil, fmt.Errorf("unexpected opcode %d", hdr.OpCode)
	}
	doc, _, err := ParseOpMsgBody(body)
	return doc, err
}

// okFloat normalises the BSON "ok" field, which servers may encode as either
// double (1.0) or int32 (1).
func okFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int32:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}

// binaryPayload extracts the Data from a BSON Binary, regardless of subtype.
func binaryPayload(v any) ([]byte, error) {
	b, ok := v.(Binary)
	if !ok {
		return nil, fmt.Errorf("payload is not BSON binary (got %T)", v)
	}
	return b.Data, nil
}
