//go:build plugin_jdwp || !plugin_selective

package services

import (
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

type chunkedJDWPConn struct {
	data      []byte
	chunkSize int
}

func (c *chunkedJDWPConn) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := c.chunkSize
	if n <= 0 || n > len(c.data) {
		n = len(c.data)
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

func (c *chunkedJDWPConn) Write([]byte) (int, error) { return 0, nil }
func (c *chunkedJDWPConn) SetDeadline(time.Time) error {
	return nil
}

func TestJDWPGetVersionHandlesChunkedReads(t *testing.T) {
	const version = "Java Debug Wire Protocol"
	body := make([]byte, 4+len(version))
	binary.BigEndian.PutUint32(body[:4], uint32(len(version)))
	copy(body[4:], version)

	reply := make([]byte, 11+len(body))
	binary.BigEndian.PutUint32(reply[:4], uint32(len(reply)))
	copy(reply[11:], body)

	p := NewJDWPPlugin()
	got := p.getVersion(&chunkedJDWPConn{data: reply, chunkSize: 3}, time.Second)
	if got != version {
		t.Fatalf("getVersion() = %q, want %q", got, version)
	}
}

func TestParseJDWPVersionStringTruncatesByRune(t *testing.T) {
	version := strings.Repeat("界", 205)
	body := make([]byte, 4+len(version))
	binary.BigEndian.PutUint32(body[:4], uint32(len(version)))
	copy(body[4:], version)

	got := parseJDWPVersionString(body)
	if !utf8.ValidString(got) || len([]rune(got)) != 203 || !strings.HasSuffix(got, "...") {
		t.Fatalf("parseJDWPVersionString() = %q", got)
	}
}
