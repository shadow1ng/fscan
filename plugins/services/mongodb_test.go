//go:build plugin_mongodb || !plugin_selective

package services

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func TestReadMongoMsgRejectsTooLargeResponse(t *testing.T) {
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[:4], uint32(16+maxMongoMessageBody+1))

	_, err := readMongoMsg(bytes.NewReader(header), time.Second)
	if err == nil {
		t.Fatal("readMongoMsg() error = nil, want too-large response error")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("readMongoMsg() error = %v, want too large", err)
	}
}

func TestReadMongoMsgHandlesEmptyBody(t *testing.T) {
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[:4], 16)

	got, err := readMongoMsg(bytes.NewReader(header), time.Second)
	if err != nil {
		t.Fatalf("readMongoMsg() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("readMongoMsg() len = %d, want 0", len(got))
	}
}

func TestBuildBSONEncodesFullStringAndBinaryLengths(t *testing.T) {
	longString := strings.Repeat("a", 300)
	longBinary := bytes.Repeat([]byte{0x42}, 300)

	doc := buildBSON(mongoDoc{"s": longString})
	pos := 4
	if doc[pos] != 0x02 {
		t.Fatalf("first bson type = 0x%02x, want string", doc[pos])
	}
	pos += 1 + len("s") + 1
	if got := binary.LittleEndian.Uint32(doc[pos : pos+4]); got != uint32(len(longString)+1) {
		t.Fatalf("string length = %d, want %d", got, len(longString)+1)
	}

	doc = buildBSON(mongoDoc{"b": longBinary})
	pos = 4
	if doc[pos] != 0x05 {
		t.Fatalf("first bson type = 0x%02x, want binary", doc[pos])
	}
	pos += 1 + len("b") + 1
	if got := binary.LittleEndian.Uint32(doc[pos : pos+4]); got != uint32(len(longBinary)) {
		t.Fatalf("binary length = %d, want %d", got, len(longBinary))
	}
}

func TestBuildBSONEncodesFloat64Bits(t *testing.T) {
	doc := buildBSON(mongoDoc{"ok": 1.5})
	pos := 4
	if doc[pos] != 0x01 {
		t.Fatalf("bson type = 0x%02x, want double", doc[pos])
	}
	pos += 1 + len("ok") + 1
	if got := binary.LittleEndian.Uint64(doc[pos : pos+8]); got != 0x3ff8000000000000 {
		t.Fatalf("double bits = 0x%x, want 1.5 bits", got)
	}
}

func TestParseMongoCommandReplyReadsSCRAMFields(t *testing.T) {
	payload := []byte("r=clientserver,s=" + base64.StdEncoding.EncodeToString([]byte("salt")) + ",i=4096")
	doc := buildBSON(mongoDoc{
		"ok":             1,
		"conversationId": 7,
		"payload":        payload,
		"done":           false,
	})

	reply, err := parseMongoCommandReply(doc)
	if err != nil {
		t.Fatalf("parseMongoCommandReply() error = %v", err)
	}
	if !reply.ok || !reply.conversationSet || reply.conversationID != 7 || string(reply.payload) != string(payload) {
		t.Fatalf("unexpected reply: %+v", reply)
	}
}

func TestParseMongoCommandReplySkipsExtraBSONFields(t *testing.T) {
	payload := []byte("r=clientserver,s=" + base64.StdEncoding.EncodeToString([]byte("salt")) + ",i=4096")
	doc := buildBSON(mongoDoc{
		"$clusterTime":   mongoDoc{"clusterTime": 1},
		"operationTime":  int64(123),
		"ok":             1,
		"conversationId": 9,
		"payload":        payload,
	})

	reply, err := parseMongoCommandReply(doc)
	if err != nil {
		t.Fatalf("parseMongoCommandReply() error = %v", err)
	}
	if !reply.ok || reply.conversationID != 9 || string(reply.payload) != string(payload) {
		t.Fatalf("unexpected reply: %+v", reply)
	}
}

func TestBuildMongoSCRAMClientFinalRejectsBadNonce(t *testing.T) {
	serverFirst := "r=othernonce,s=" + base64.StdEncoding.EncodeToString([]byte("salt")) + ",i=4096"
	if _, err := buildMongoSCRAMClientFinal("user", "pass", "n=user,r=client", serverFirst); err == nil {
		t.Fatal("buildMongoSCRAMClientFinal() error = nil, want nonce error")
	}
}

func TestBuildMongoSCRAMClientFinalBuildsProof(t *testing.T) {
	serverFirst := "r=clientserver,s=" + base64.StdEncoding.EncodeToString([]byte("salt")) + ",i=4096"
	got, err := buildMongoSCRAMClientFinal("user", "pass", "n=user,r=client", serverFirst)
	if err != nil {
		t.Fatalf("buildMongoSCRAMClientFinal() error = %v", err)
	}
	if !strings.HasPrefix(got, "c=biws,r=clientserver,p=") {
		t.Fatalf("client final = %q", got)
	}
}
