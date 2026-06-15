//go:build plugin_redis || !plugin_selective

package services

import (
	"errors"
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

func TestClassifyRedisErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil", nil, ErrorTypeUnknown},
		{"wrongpass", errors.New("wrongpass invalid password"), ErrorTypeAuth},
		{"noauth", errors.New("noauth authentication required"), ErrorTypeAuth},
		{"connection refused", errors.New("connection refused"), ErrorTypeNetwork},
		{"unknown", errors.New("random redis error"), ErrorTypeUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyRedisErrorType(tt.err); got != tt.want {
				t.Errorf("classifyRedisErrorType() = %v, want %v", got, tt.want)
			}
		})
	}
}
