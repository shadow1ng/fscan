//go:build (plugin_socks5proxy || !plugin_selective) && !no_local

package local

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

type socksTestConn struct {
	r bytes.Reader
	w bytes.Buffer
}

func newSocksTestConn(data []byte) *socksTestConn {
	return &socksTestConn{r: *bytes.NewReader(data)}
}

func (c *socksTestConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err == io.EOF && n > 0 {
		return n, nil
	}
	return n, err
}

func (c *socksTestConn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *socksTestConn) Close() error                { return nil }
func (c *socksTestConn) LocalAddr() net.Addr         { return nil }
func (c *socksTestConn) RemoteAddr() net.Addr        { return nil }
func (c *socksTestConn) SetDeadline(time.Time) error { return nil }
func (c *socksTestConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *socksTestConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestSocks5HandshakeValidation(t *testing.T) {
	p := NewSocks5ProxyPlugin()

	t.Run("truncated methods", func(t *testing.T) {
		conn := newSocksTestConn([]byte{0x05, 0x02, 0x00})
		if err := p.handleSocks5Handshake(conn); err == nil {
			t.Fatal("handleSocks5Handshake() error = nil, want truncated method list error")
		}
	})

	t.Run("no no-auth method", func(t *testing.T) {
		conn := newSocksTestConn([]byte{0x05, 0x01, 0x02})
		if err := p.handleSocks5Handshake(conn); err == nil {
			t.Fatal("handleSocks5Handshake() error = nil, want unsupported method error")
		}
		if got := conn.w.Bytes(); !bytes.Equal(got, []byte{0x05, 0xff}) {
			t.Fatalf("handshake response = % x, want 05 ff", got)
		}
	})

	t.Run("accepts no-auth", func(t *testing.T) {
		conn := newSocksTestConn([]byte{0x05, 0x02, 0x02, 0x00})
		if err := p.handleSocks5Handshake(conn); err != nil {
			t.Fatalf("handleSocks5Handshake() error = %v", err)
		}
		if got := conn.w.Bytes(); !bytes.Equal(got, []byte{0x05, 0x00}) {
			t.Fatalf("handshake response = % x, want 05 00", got)
		}
	})
}

func TestSocks5RequestRejectsMalformedInputBeforeDial(t *testing.T) {
	p := NewSocks5ProxyPlugin()

	tests := []struct {
		name string
		req  []byte
	}{
		{name: "bad reserved byte", req: []byte{0x05, 0x01, 0x01, 0x01}},
		{name: "empty domain", req: []byte{0x05, 0x01, 0x00, 0x03, 0x00}},
		{name: "truncated domain", req: []byte{0x05, 0x01, 0x00, 0x03, 0x04, 't', 'e'}},
		{name: "zero ipv4 port", req: []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0}},
		{name: "truncated ipv6", req: []byte{0x05, 0x01, 0x00, 0x04, 0x20, 0x01}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := p.handleSocks5Request(newSocksTestConn(tt.req), nil); err == nil {
				t.Fatal("handleSocks5Request() error = nil, want malformed request error")
			}
		})
	}
}
