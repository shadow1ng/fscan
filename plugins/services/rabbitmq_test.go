//go:build plugin_rabbitmq || !plugin_selective

package services

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRabbitMQManagementRejectsGenericHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("plain http service"))
	}))
	defer server.Close()

	result := NewRabbitMQPlugin().testManagementInterface(context.Background(), hostInfoFromServer(t, server), testSession())
	if result.Success {
		t.Fatalf("testManagementInterface reported generic HTTP as RabbitMQ: %#v", result)
	}
}

func TestReadRabbitMQAMQPResponseHandlesChunkedReads(t *testing.T) {
	ok, err := readRabbitMQAMQPResponse(&chunkedByteReader{data: []byte("AMQP"), chunkSize: 1})
	if err != nil || !ok {
		t.Fatalf("readRabbitMQAMQPResponse(AMQP) = %v, %v", ok, err)
	}

	ok, err = readRabbitMQAMQPResponse(&chunkedByteReader{data: []byte{0x01, 0, 0, 0, 0, 0, 0, 0}, chunkSize: 2})
	if err != nil || !ok {
		t.Fatalf("readRabbitMQAMQPResponse(frame) = %v, %v", ok, err)
	}

	ok, err = readRabbitMQAMQPResponse(bytes.NewReader([]byte{0x01, 0, 0}))
	if err == nil || ok {
		t.Fatalf("readRabbitMQAMQPResponse(short) = %v, %v; want short read error", ok, err)
	}
}

type chunkedByteReader struct {
	data      []byte
	chunkSize int
}

func (r *chunkedByteReader) Read(p []byte) (int, error) {
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
