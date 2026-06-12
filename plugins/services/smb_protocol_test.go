//go:build plugin_smb || !plugin_selective

package services

import (
	"io"
	"net"
	"testing"
	"time"
)

type chunkedSMBConn struct {
	data      []byte
	chunkSize int
}

func (c *chunkedSMBConn) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := len(c.data)
	if c.chunkSize > 0 && n > c.chunkSize {
		n = c.chunkSize
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

func (c *chunkedSMBConn) Write([]byte) (int, error)       { return 0, nil }
func (c *chunkedSMBConn) Close() error                    { return nil }
func (c *chunkedSMBConn) LocalAddr() net.Addr             { return nil }
func (c *chunkedSMBConn) RemoteAddr() net.Addr            { return nil }
func (c *chunkedSMBConn) SetDeadline(time.Time) error     { return nil }
func (c *chunkedSMBConn) SetReadDeadline(time.Time) error { return nil }
func (c *chunkedSMBConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestReadSMBMessageHandlesChunkedReads(t *testing.T) {
	got, err := readSMBMessage(&chunkedSMBConn{data: []byte{0, 0, 0, 3, 'S', 'M', 'B'}, chunkSize: 1})
	if err != nil {
		t.Fatalf("readSMBMessage() error = %v", err)
	}
	if string(got) != "\x00\x00\x00\x03SMB" {
		t.Fatalf("readSMBMessage() = %q", got)
	}
}
