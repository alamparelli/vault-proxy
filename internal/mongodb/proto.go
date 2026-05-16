package mongodb

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"
)

// MongoDB wire protocol — minimal OP_MSG support.
//
// Header (16 bytes, little-endian):
//
//	int32 messageLength    // total length including this header
//	int32 requestID
//	int32 responseTo
//	int32 opCode           // 2013 = OP_MSG
//
// OP_MSG body:
//
//	uint32 flagBits
//	sections...
//
// Section type 0: { byte 0x00 || BSON document }
//
// We only emit section type 0. We only decode section type 0; the upstream may
// occasionally pad with type-1 sequences but the responses we care about
// (hello, saslStart, saslContinue) all use type 0.

const (
	opMsgCode    int32 = 2013
	opReplyCode  int32 = 1     // legacy, used in OP_QUERY reply
	opQueryCode  int32 = 2004  // legacy hello (rare nowadays)
	maxMsgLength       = 48_000_000
)

var requestIDCounter uint32

func nextRequestID() int32 {
	return int32(atomic.AddUint32(&requestIDCounter, 1))
}

// WriteOpMsg serialises an OP_MSG with one type-0 section containing doc.
// Returns the requestID used so callers can correlate replies.
func WriteOpMsg(w io.Writer, doc Doc, flagBits uint32) (int32, error) {
	body, err := EncodeDoc(doc)
	if err != nil {
		return 0, err
	}
	reqID := nextRequestID()

	// header (16) + flagBits (4) + section-kind (1) + body
	msg := make([]byte, 16+4+1+len(body))
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.LittleEndian.PutUint32(msg[4:8], uint32(reqID))
	binary.LittleEndian.PutUint32(msg[8:12], 0) // responseTo = 0 for fresh request
	binary.LittleEndian.PutUint32(msg[12:16], uint32(opMsgCode))
	binary.LittleEndian.PutUint32(msg[16:20], flagBits)
	msg[20] = 0 // section kind: body
	copy(msg[21:], body)

	if _, err := w.Write(msg); err != nil {
		return 0, fmt.Errorf("write OP_MSG: %w", err)
	}
	return reqID, nil
}

// WriteOpMsgReply emits an OP_MSG with responseTo set to a previously received
// requestID. Used by the local listener when replying to a client request.
func WriteOpMsgReply(w io.Writer, doc Doc, flagBits uint32, responseTo int32) error {
	body, err := EncodeDoc(doc)
	if err != nil {
		return err
	}
	msg := make([]byte, 16+4+1+len(body))
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.LittleEndian.PutUint32(msg[4:8], uint32(nextRequestID()))
	binary.LittleEndian.PutUint32(msg[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(msg[12:16], uint32(opMsgCode))
	binary.LittleEndian.PutUint32(msg[16:20], flagBits)
	msg[20] = 0
	copy(msg[21:], body)
	_, err = w.Write(msg)
	return err
}

// MsgHeader carries the four header ints we care about.
type MsgHeader struct {
	Length    int32
	RequestID int32
	ResponseTo int32
	OpCode    int32
}

// ReadMessage reads a single MongoDB wire message from r. It returns the
// header plus the *body* bytes (everything after the 16-byte header). The
// caller is responsible for deciding how to interpret the body based on
// OpCode.
func ReadMessage(r io.Reader) (MsgHeader, []byte, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return MsgHeader{}, nil, fmt.Errorf("read header: %w", err)
	}
	h := MsgHeader{
		Length:     int32(binary.LittleEndian.Uint32(hdr[0:4])),
		RequestID:  int32(binary.LittleEndian.Uint32(hdr[4:8])),
		ResponseTo: int32(binary.LittleEndian.Uint32(hdr[8:12])),
		OpCode:     int32(binary.LittleEndian.Uint32(hdr[12:16])),
	}
	if h.Length < 16 || h.Length > maxMsgLength {
		return h, nil, fmt.Errorf("absurd message length %d", h.Length)
	}
	body := make([]byte, h.Length-16)
	if _, err := io.ReadFull(r, body); err != nil {
		return h, nil, fmt.Errorf("read body: %w", err)
	}
	return h, body, nil
}

// ParseOpQueryBody extracts the query document from an OP_QUERY body. The
// legacy isMaster/hello handshake — sent by every conformant driver on the
// very first packet of a fresh connection, before it knows the server's wire
// version — uses this opcode. After parsing one such message and replying
// with an OP_REPLY, drivers upgrade to OP_MSG for everything else.
//
// OP_QUERY body layout (little-endian):
//
//	int32 flags
//	cstring fullCollectionName  // e.g. "admin.$cmd"
//	int32 numberToSkip
//	int32 numberToReturn
//	document query
//	(optional) document returnFieldsSelector — ignored
func ParseOpQueryBody(body []byte) (Doc, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("OP_QUERY body too short")
	}
	off := 4 // skip flags
	end := indexByte(body[off:], 0)
	if end < 0 {
		return nil, fmt.Errorf("OP_QUERY missing collection name terminator")
	}
	off += end + 1
	if len(body)-off < 8 {
		return nil, fmt.Errorf("OP_QUERY missing skip/return")
	}
	off += 8 // skip numberToSkip + numberToReturn
	doc, _, err := DecodeDoc(body[off:])
	if err != nil {
		return nil, fmt.Errorf("OP_QUERY decode query: %w", err)
	}
	return doc, nil
}

// WriteOpReply emits a legacy OP_REPLY containing a single document. Used to
// answer the initial OP_QUERY hello so drivers can negotiate up to OP_MSG.
//
// OP_REPLY body layout:
//
//	int32 responseFlags
//	int64 cursorID
//	int32 startingFrom
//	int32 numberReturned
//	document(s)
func WriteOpReply(w io.Writer, doc Doc, responseTo int32) error {
	body, err := EncodeDoc(doc)
	if err != nil {
		return err
	}
	// header (16) + responseFlags(4) + cursorID(8) + startingFrom(4) + numberReturned(4) + body
	msg := make([]byte, 16+4+8+4+4+len(body))
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.LittleEndian.PutUint32(msg[4:8], uint32(nextRequestID()))
	binary.LittleEndian.PutUint32(msg[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(msg[12:16], uint32(opReplyCode))
	binary.LittleEndian.PutUint32(msg[16:20], 0)            // responseFlags
	binary.LittleEndian.PutUint64(msg[20:28], 0)            // cursorID
	binary.LittleEndian.PutUint32(msg[28:32], 0)            // startingFrom
	binary.LittleEndian.PutUint32(msg[32:36], 1)            // numberReturned
	copy(msg[36:], body)
	_, err = w.Write(msg)
	return err
}

// ParseOpMsgBody extracts the first type-0 document from an OP_MSG body.
// Returns the document plus the flagBits. Type-1 sections (sequences) are
// skipped — we never need them for the handshake.
func ParseOpMsgBody(body []byte) (Doc, uint32, error) {
	if len(body) < 5 {
		return nil, 0, fmt.Errorf("OP_MSG body too short")
	}
	flagBits := binary.LittleEndian.Uint32(body[:4])
	off := 4
	for off < len(body) {
		kind := body[off]
		off++
		switch kind {
		case 0:
			doc, _, err := DecodeDoc(body[off:])
			if err != nil {
				return nil, 0, err
			}
			return doc, flagBits, nil
		case 1:
			// Type-1 section: int32 size including itself, cstring identifier,
			// then concatenated BSON docs. We don't care about its contents.
			if len(body)-off < 4 {
				return nil, 0, fmt.Errorf("short type-1 section")
			}
			size := int(binary.LittleEndian.Uint32(body[off : off+4]))
			if size < 4 || off+size > len(body) {
				return nil, 0, fmt.Errorf("bad type-1 size %d", size)
			}
			off += size
		default:
			return nil, 0, fmt.Errorf("unknown section kind %d", kind)
		}
	}
	return nil, 0, fmt.Errorf("OP_MSG has no type-0 section")
}
