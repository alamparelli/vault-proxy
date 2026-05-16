package mongodb

import (
	"reflect"
	"testing"
)

func TestBSONRoundTrip(t *testing.T) {
	in := Doc{
		{Key: "hello", Value: int32(1)},
		{Key: "$db", Value: "admin"},
		{Key: "ok", Value: float64(1)},
		{Key: "isWritablePrimary", Value: true},
		{Key: "maxWireVersion", Value: int32(17)},
		{Key: "saslSupportedMechs", Value: "admin.alice"},
		{Key: "payload", Value: Binary{Subtype: 0, Data: []byte("n,,n=alice,r=abc123")}},
		{Key: "client", Value: Doc{
			{Key: "application", Value: Doc{{Key: "name", Value: "vault-proxy"}}},
		}},
		{Key: "tags", Value: []string{"a", "b", "c"}},
	}

	encoded, err := EncodeDoc(in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(encoded) < 5 {
		t.Fatalf("encoded too short: %d", len(encoded))
	}

	decoded, n, err := DecodeDoc(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n != len(encoded) {
		t.Errorf("decoded n=%d, expected %d", n, len(encoded))
	}

	if v := decoded.Lookup("hello"); v != int32(1) {
		t.Errorf("hello = %v", v)
	}
	if v := decoded.Lookup("$db"); v != "admin" {
		t.Errorf("$db = %v", v)
	}
	if v := decoded.Lookup("ok"); v != 1.0 {
		t.Errorf("ok = %v", v)
	}
	if v := decoded.Lookup("isWritablePrimary"); v != true {
		t.Errorf("isWritablePrimary = %v", v)
	}
	if v := decoded.Lookup("maxWireVersion"); v != int32(17) {
		t.Errorf("maxWireVersion = %v", v)
	}

	bin, ok := decoded.Lookup("payload").(Binary)
	if !ok || bin.Subtype != 0 || string(bin.Data) != "n,,n=alice,r=abc123" {
		t.Errorf("payload = %#v", bin)
	}

	client, ok := decoded.Lookup("client").(Doc)
	if !ok {
		t.Fatalf("client missing or wrong type: %T", decoded.Lookup("client"))
	}
	app, _ := client.Lookup("application").(Doc)
	if v := app.Lookup("name"); v != "vault-proxy" {
		t.Errorf("client.application.name = %v", v)
	}

	tags, _ := decoded.Lookup("tags").(Doc)
	got := []string{}
	for _, e := range tags {
		s, _ := e.Value.(string)
		got = append(got, s)
	}
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("tags = %v", got)
	}
}

func TestBSONDecodeShortInput(t *testing.T) {
	if _, _, err := DecodeDoc([]byte{0x05, 0, 0, 0, 0}); err == nil {
		// 5-byte empty doc is valid
	} else {
		t.Errorf("empty-doc decode failed: %v", err)
	}
	if _, _, err := DecodeDoc([]byte{0x01}); err == nil {
		t.Error("expected error on 1-byte input")
	}
}

func TestOpMsgRoundTrip(t *testing.T) {
	doc := Doc{
		{Key: "ok", Value: float64(1)},
		{Key: "conversationId", Value: int32(7)},
	}
	buf := &writeBuf{}
	if _, err := WriteOpMsg(buf, doc, 0); err != nil {
		t.Fatalf("write: %v", err)
	}
	hdr, body, err := ReadMessage(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if hdr.OpCode != opMsgCode {
		t.Errorf("opCode = %d, want %d", hdr.OpCode, opMsgCode)
	}
	parsed, _, err := ParseOpMsgBody(body)
	if err != nil {
		t.Fatalf("parse body: %v", err)
	}
	if v := parsed.Lookup("ok"); v != 1.0 {
		t.Errorf("ok = %v", v)
	}
	if v := parsed.Lookup("conversationId"); v != int32(7) {
		t.Errorf("conversationId = %v", v)
	}
}

// writeBuf is a tiny in-memory pipe: Write appends, Read pops from the front.
// Plays the role of a net.Conn for round-trip tests of the framing layer.
type writeBuf struct {
	data []byte
	off  int
}

func (w *writeBuf) Write(p []byte) (int, error) { w.data = append(w.data, p...); return len(p), nil }
func (w *writeBuf) Read(p []byte) (int, error) {
	if w.off >= len(w.data) {
		return 0, errEOF
	}
	n := copy(p, w.data[w.off:])
	w.off += n
	return n, nil
}

var errEOF = &eofErr{}

type eofErr struct{}

func (*eofErr) Error() string { return "EOF" }
