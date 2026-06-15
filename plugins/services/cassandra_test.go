//go:build plugin_cassandra || !plugin_selective

package services

import (
	"bytes"
	"encoding/binary"
	"errors"
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

func TestClassifyCassandraErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil", nil, ErrorTypeUnknown},
		{"auth error", errors.New("authentication failed"), ErrorTypeAuth},
		{"bad credentials", errors.New("bad credentials"), ErrorTypeAuth},
		{"network error", errors.New("connection refused"), ErrorTypeNetwork},
		{"unknown", errors.New("random cassandra error"), ErrorTypeUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyCassandraErrorType(tt.err); got != tt.want {
				t.Errorf("classifyCassandraErrorType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCqlShortString(t *testing.T) {
	got := cqlShortString("AB")
	if len(got) != 4 || binary.BigEndian.Uint16(got[:2]) != 2 || string(got[2:]) != "AB" {
		t.Errorf("cqlShortString(AB) = %v", got)
	}
	empty := cqlShortString("")
	if len(empty) != 2 || binary.BigEndian.Uint16(empty) != 0 {
		t.Errorf("cqlShortString empty = %v", empty)
	}
}

func TestCqlLongString(t *testing.T) {
	got := cqlLongString("XYZ")
	if len(got) != 7 || binary.BigEndian.Uint32(got[:4]) != 3 || string(got[4:]) != "XYZ" {
		t.Errorf("cqlLongString(XYZ) = %v", got)
	}
}

func TestCqlStringMap(t *testing.T) {
	m := map[string]string{"k": "v"}
	got := cqlStringMap(m)
	if got[0] != 0x00 || got[1] != 0x01 {
		t.Errorf("count bytes wrong: %v", got[:2])
	}
	if !bytes.Contains(got, []byte("k")) || !bytes.Contains(got, []byte("v")) {
		t.Errorf("missing key/value in %v", got)
	}
}

func TestExtractClusterName(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"empty", nil, "unknown"},
		{"short", []byte{0x01, 0x02}, "unknown"},
		{"printable", append([]byte{0x00, 0x00, 0x00, 0x01}, []byte("TestCluster")...), "TestCluster"},
		{"binary prefix", append([]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02}, []byte("MyCluster")...), "MyCluster"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractClusterName(tt.data)
			if !strings.Contains(got, tt.want) && got != tt.want {
				t.Errorf("extractClusterName() = %q, want %q", got, tt.want)
			}
		})
	}
}
