//go:build plugin_cassandra || !plugin_selective

package services

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestCQLRecvRejectsTooLargeFrame(t *testing.T) {
	header := make([]byte, 9)
	header[4] = cqlOpReady
	binary.BigEndian.PutUint32(header[5:9], maxCQLFrameBody+1)

	_, _, err := cqlRecv(bytes.NewReader(header))
	if err == nil {
		t.Fatal("cqlRecv() error = nil, want too-large frame error")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("cqlRecv() error = %v, want too large", err)
	}
}

func TestCQLRecvAllowsEmptyBody(t *testing.T) {
	header := make([]byte, 9)
	header[4] = cqlOpReady

	opcode, body, err := cqlRecv(bytes.NewReader(header))
	if err != nil {
		t.Fatalf("cqlRecv() error = %v", err)
	}
	if opcode != cqlOpReady || len(body) != 0 {
		t.Fatalf("cqlRecv() opcode=%d body=%q, want ready empty body", opcode, body)
	}
}

func TestValidateCQLQueryResponseRejectsErrors(t *testing.T) {
	if err := validateCQLQueryResponse(cqlOpResult, []byte("rows")); err != nil {
		t.Fatalf("validateCQLQueryResponse() error = %v", err)
	}
	if err := validateCQLQueryResponse(cqlOpError, []byte("permission denied")); err == nil {
		t.Fatal("validateCQLQueryResponse() error = nil, want query error")
	}
	if err := validateCQLQueryResponse(cqlOpReady, nil); err == nil {
		t.Fatal("validateCQLQueryResponse() error = nil, want unexpected opcode error")
	}
}
