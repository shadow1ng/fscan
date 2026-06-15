//go:build plugin_kafka || !plugin_selective

package services

import (
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type chunkedKafkaReader struct {
	data      []byte
	chunkSize int
}

func (r *chunkedKafkaReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := len(r.data)
	if r.chunkSize > 0 && n > r.chunkSize {
		n = r.chunkSize
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

func TestKafkaRecvHandlesChunkedResponse(t *testing.T) {
	packet := make([]byte, 4+6)
	binary.BigEndian.PutUint32(packet[:4], 6)
	binary.BigEndian.PutUint32(packet[4:8], 123)
	copy(packet[8:], []byte("ok"))

	got, err := kafkaRecv(&chunkedKafkaReader{data: packet, chunkSize: 1})
	if err != nil {
		t.Fatalf("kafkaRecv() error = %v", err)
	}
	if string(got) != "ok" {
		t.Fatalf("kafkaRecv() = %q, want ok", got)
	}
}

func TestKafkaRecvRejectsTooLargeResponse(t *testing.T) {
	packet := make([]byte, 4)
	binary.BigEndian.PutUint32(packet, maxKafkaResponseSize+1)

	if _, err := kafkaRecv(&chunkedKafkaReader{data: packet}); err == nil {
		t.Fatal("kafkaRecv() error = nil, want too-large response error")
	}
}

func TestKafkaRecvRejectsShortResponse(t *testing.T) {
	packet := make([]byte, 4)
	binary.BigEndian.PutUint32(packet, 3)

	if _, err := kafkaRecv(&chunkedKafkaReader{data: packet}); err == nil {
		t.Fatal("kafkaRecv() error = nil, want invalid length error")
	}
}

func TestClassifyKafkaErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil", nil, ErrorTypeUnknown},
		{"sasl auth failed", errors.New("sasl authentication failed"), ErrorTypeAuth},
		{"unauthorized", errors.New("unauthorized"), ErrorTypeAuth},
		{"broker not available", errors.New("broker not available"), ErrorTypeNetwork},
		{"connection refused", errors.New("connection refused"), ErrorTypeNetwork},
		{"unknown", errors.New("random kafka error"), ErrorTypeUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyKafkaErrorType(tt.err); got != tt.want {
				t.Errorf("classifyKafkaErrorType() = %v, want %v", got, tt.want)
			}
		})
	}
}
