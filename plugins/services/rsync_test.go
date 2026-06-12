//go:build (plugin_rsync || !plugin_selective) && go1.21

package services

import (
	"io"
	"testing"
)

type chunkedRsyncReader struct {
	data      []byte
	chunkSize int
}

func (r *chunkedRsyncReader) Read(p []byte) (int, error) {
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

func TestReadRsyncLineHandlesChunkedReads(t *testing.T) {
	got, err := readRsyncLine(&chunkedRsyncReader{data: []byte("@RSYNCD: 31.0\nrest"), chunkSize: 1}, 256)
	if err != nil {
		t.Fatalf("readRsyncLine() error = %v", err)
	}
	if got != "@RSYNCD: 31.0\n" {
		t.Fatalf("readRsyncLine() = %q", got)
	}
}
