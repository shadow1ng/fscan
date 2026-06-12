//go:build plugin_rmi || !plugin_selective

package services

import (
	"io"
	"testing"
)

type chunkedRMIReader struct {
	data      []byte
	chunkSize int
}

func (r *chunkedRMIReader) Read(p []byte) (int, error) {
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

func TestReadRMIEndpointHandlesChunkedReads(t *testing.T) {
	data := []byte{0x00, 0x09}
	data = append(data, "localhost"...)
	data = append(data, 0x00, 0x00, 0x04, 0x4b)

	got := readRMIEndpoint(&chunkedRMIReader{data: data, chunkSize: 1})
	if got != "Java RMI endpoint=localhost:1099" {
		t.Fatalf("readRMIEndpoint() = %q", got)
	}
}
