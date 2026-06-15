//go:build (plugin_rsync || !plugin_selective) && go1.21

package services

import (
	"errors"
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

func TestClassifyRsyncErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil", nil, ErrorTypeUnknown},
		{"authentication failed", errors.New("authentication failed"), ErrorTypeAuth},
		{"access denied", errors.New("access denied"), ErrorTypeAuth},
		{"connection refused", errors.New("connection refused"), ErrorTypeNetwork},
		{"unknown", errors.New("random rsync error"), ErrorTypeUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyRsyncErrorType(tt.err); got != tt.want {
				t.Errorf("classifyRsyncErrorType() = %v, want %v", got, tt.want)
			}
		})
	}
}
