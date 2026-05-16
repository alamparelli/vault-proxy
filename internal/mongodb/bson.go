// Package mongodb implements an auth-only MongoDB proxy driver. The strategy
// mirrors postgres/imap/smtp: vault dials upstream, completes hello + SCRAM-SHA-256
// using stored credentials, then accepts one local connection, advertises an
// auth-free standalone server in its hello reply, and splices.
//
// Clients should connect locally with `mongodb://127.0.0.1:PORT/dbname` —
// no credentials in the URI. Their queries are forwarded to the already-
// authenticated upstream session, so they execute under the stored user's
// role grants.
package mongodb

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// BSON document encoder/decoder, scoped to the handful of element types this
// package actually needs: int32, int64, double, string, boolean, binary, and
// embedded document. Arrays are encoded as documents with string-integer keys.
//
// We deliberately do NOT depend on go.mongodb.org/mongo-driver here — bringing
// in the official driver just to handshake would balloon vault-proxy's binary
// size for a small, well-specified protocol slice.

// bsonElem types we emit.
const (
	bsonTypeDouble   byte = 0x01
	bsonTypeString   byte = 0x02
	bsonTypeDocument byte = 0x03
	bsonTypeArray    byte = 0x04
	bsonTypeBinary   byte = 0x05
	bsonTypeBoolean  byte = 0x08
	bsonTypeDateTime byte = 0x09
	bsonTypeNull     byte = 0x0A
	bsonTypeInt32    byte = 0x10
	bsonTypeInt64    byte = 0x12
)

// Binary represents a BSON binary value with subtype.
type Binary struct {
	Subtype byte
	Data    []byte
}

// Doc is an ordered key/value pair list. Order matters for MongoDB commands —
// the first field is the command name and MongoDB rejects out-of-order docs
// in some contexts.
type Doc []DocElem

// DocElem is one element of a Doc.
type DocElem struct {
	Key   string
	Value any
}

// Lookup returns the value for the first element whose Key matches, or nil.
func (d Doc) Lookup(key string) any {
	for _, e := range d {
		if e.Key == key {
			return e.Value
		}
	}
	return nil
}

// EncodeDoc serialises an ordered Doc to BSON.
func EncodeDoc(d Doc) ([]byte, error) {
	// First pass: serialise elements into a body buffer, then prepend length
	// and append the trailing null.
	body := make([]byte, 0, 64)
	for _, elem := range d {
		eb, err := encodeElement(elem.Key, elem.Value)
		if err != nil {
			return nil, fmt.Errorf("encode %q: %w", elem.Key, err)
		}
		body = append(body, eb...)
	}
	totalLen := 4 + len(body) + 1
	out := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(out[:4], uint32(totalLen))
	copy(out[4:], body)
	out[totalLen-1] = 0
	return out, nil
}

func encodeElement(key string, v any) ([]byte, error) {
	switch val := v.(type) {
	case int32:
		buf := make([]byte, 1+len(key)+1+4)
		buf[0] = bsonTypeInt32
		copy(buf[1:], key)
		buf[1+len(key)] = 0
		binary.LittleEndian.PutUint32(buf[1+len(key)+1:], uint32(val))
		return buf, nil
	case int:
		// Width-determinate: prefer int32 if it fits, else int64.
		if val >= math.MinInt32 && val <= math.MaxInt32 {
			return encodeElement(key, int32(val))
		}
		return encodeElement(key, int64(val))
	case int64:
		buf := make([]byte, 1+len(key)+1+8)
		buf[0] = bsonTypeInt64
		copy(buf[1:], key)
		buf[1+len(key)] = 0
		binary.LittleEndian.PutUint64(buf[1+len(key)+1:], uint64(val))
		return buf, nil
	case float64:
		buf := make([]byte, 1+len(key)+1+8)
		buf[0] = bsonTypeDouble
		copy(buf[1:], key)
		buf[1+len(key)] = 0
		binary.LittleEndian.PutUint64(buf[1+len(key)+1:], math.Float64bits(val))
		return buf, nil
	case string:
		// BSON string is: int32 length-including-null || bytes || 0x00
		strBytes := []byte(val)
		buf := make([]byte, 1+len(key)+1+4+len(strBytes)+1)
		buf[0] = bsonTypeString
		copy(buf[1:], key)
		buf[1+len(key)] = 0
		off := 1 + len(key) + 1
		binary.LittleEndian.PutUint32(buf[off:], uint32(len(strBytes)+1))
		copy(buf[off+4:], strBytes)
		// trailing null already zero-filled
		return buf, nil
	case bool:
		buf := make([]byte, 1+len(key)+1+1)
		buf[0] = bsonTypeBoolean
		copy(buf[1:], key)
		buf[1+len(key)] = 0
		if val {
			buf[1+len(key)+1] = 1
		}
		return buf, nil
	case nil:
		buf := make([]byte, 1+len(key)+1)
		buf[0] = bsonTypeNull
		copy(buf[1:], key)
		return buf, nil
	case Binary:
		buf := make([]byte, 1+len(key)+1+4+1+len(val.Data))
		buf[0] = bsonTypeBinary
		copy(buf[1:], key)
		buf[1+len(key)] = 0
		off := 1 + len(key) + 1
		binary.LittleEndian.PutUint32(buf[off:], uint32(len(val.Data)))
		buf[off+4] = val.Subtype
		copy(buf[off+5:], val.Data)
		return buf, nil
	case Doc:
		sub, err := EncodeDoc(val)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 1+len(key)+1+len(sub))
		buf[0] = bsonTypeDocument
		copy(buf[1:], key)
		buf[1+len(key)] = 0
		copy(buf[1+len(key)+1:], sub)
		return buf, nil
	case []string:
		// Encode as a BSON array (= document with "0","1",... keys).
		arr := make(Doc, len(val))
		for i, s := range val {
			arr[i] = DocElem{Key: itoa(i), Value: s}
		}
		sub, err := EncodeDoc(arr)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 1+len(key)+1+len(sub))
		buf[0] = bsonTypeArray
		copy(buf[1:], key)
		buf[1+len(key)] = 0
		copy(buf[1+len(key)+1:], sub)
		return buf, nil
	case time.Time:
		buf := make([]byte, 1+len(key)+1+8)
		buf[0] = bsonTypeDateTime
		copy(buf[1:], key)
		buf[1+len(key)] = 0
		binary.LittleEndian.PutUint64(buf[1+len(key)+1:], uint64(val.UnixMilli()))
		return buf, nil
	default:
		return nil, fmt.Errorf("unsupported BSON type %T", v)
	}
}

// DecodeDoc parses a top-level BSON document from b, returning the ordered
// list of elements and the number of bytes consumed.
func DecodeDoc(b []byte) (Doc, int, error) {
	if len(b) < 5 {
		return nil, 0, fmt.Errorf("doc too short")
	}
	total := int(binary.LittleEndian.Uint32(b[:4]))
	if total < 5 || total > len(b) {
		return nil, 0, fmt.Errorf("bad doc length %d (have %d)", total, len(b))
	}
	if b[total-1] != 0 {
		return nil, 0, fmt.Errorf("doc not null-terminated")
	}

	out := Doc{}
	off := 4
	for off < total-1 {
		typ := b[off]
		off++
		nameEnd := indexByte(b[off:], 0)
		if nameEnd < 0 {
			return nil, 0, fmt.Errorf("unterminated element name")
		}
		key := string(b[off : off+nameEnd])
		off += nameEnd + 1
		val, n, err := decodeValue(typ, b[off:])
		if err != nil {
			return nil, 0, fmt.Errorf("decode %q: %w", key, err)
		}
		off += n
		out = append(out, DocElem{Key: key, Value: val})
	}
	return out, total, nil
}

func decodeValue(typ byte, b []byte) (any, int, error) {
	switch typ {
	case bsonTypeDouble:
		if len(b) < 8 {
			return nil, 0, fmt.Errorf("short double")
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(b[:8])), 8, nil
	case bsonTypeString:
		if len(b) < 4 {
			return nil, 0, fmt.Errorf("short string len")
		}
		l := int(binary.LittleEndian.Uint32(b[:4]))
		if l < 1 || 4+l > len(b) {
			return nil, 0, fmt.Errorf("bad string len %d", l)
		}
		return string(b[4 : 4+l-1]), 4 + l, nil
	case bsonTypeDocument, bsonTypeArray:
		sub, n, err := DecodeDoc(b)
		if err != nil {
			return nil, 0, err
		}
		return sub, n, nil
	case bsonTypeBinary:
		if len(b) < 5 {
			return nil, 0, fmt.Errorf("short binary")
		}
		l := int(binary.LittleEndian.Uint32(b[:4]))
		if l < 0 || 5+l > len(b) {
			return nil, 0, fmt.Errorf("bad binary len %d", l)
		}
		return Binary{Subtype: b[4], Data: append([]byte{}, b[5:5+l]...)}, 5 + l, nil
	case bsonTypeBoolean:
		if len(b) < 1 {
			return nil, 0, fmt.Errorf("short bool")
		}
		return b[0] != 0, 1, nil
	case bsonTypeDateTime:
		if len(b) < 8 {
			return nil, 0, fmt.Errorf("short datetime")
		}
		return time.UnixMilli(int64(binary.LittleEndian.Uint64(b[:8]))), 8, nil
	case bsonTypeNull:
		return nil, 0, nil
	case bsonTypeInt32:
		if len(b) < 4 {
			return nil, 0, fmt.Errorf("short int32")
		}
		return int32(binary.LittleEndian.Uint32(b[:4])), 4, nil
	case bsonTypeInt64:
		if len(b) < 8 {
			return nil, 0, fmt.Errorf("short int64")
		}
		return int64(binary.LittleEndian.Uint64(b[:8])), 8, nil
	default:
		return nil, 0, fmt.Errorf("unsupported BSON type 0x%02x", typ)
	}
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// itoa is a tiny replacement for strconv.Itoa to avoid importing strconv just
// for array key encoding (which we do for SCRAM payload sequences etc.).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
