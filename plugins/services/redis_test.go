//go:build plugin_redis || !plugin_selective

package services

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestRedisReadReplyIsBounded(t *testing.T) {
	conn := &redisReplyTestConn{Reader: strings.NewReader(strings.Repeat("a", maxRedisReplyBytes+1024))}

	got, err := NewRedisPlugin().readReply(conn)
	if err != nil {
		t.Fatalf("readReply() error = %v", err)
	}
	if len(got) != maxRedisReplyBytes {
		t.Fatalf("readReply() len = %d, want %d", len(got), maxRedisReplyBytes)
	}
}

type redisReplyTestConn struct {
	*strings.Reader
}

func (c *redisReplyTestConn) Write([]byte) (int, error)        { return 0, nil }
func (c *redisReplyTestConn) Close() error                     { return nil }
func (c *redisReplyTestConn) LocalAddr() net.Addr              { return nil }
func (c *redisReplyTestConn) RemoteAddr() net.Addr             { return nil }
func (c *redisReplyTestConn) SetDeadline(time.Time) error      { return nil }
func (c *redisReplyTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *redisReplyTestConn) SetWriteDeadline(time.Time) error { return nil }
