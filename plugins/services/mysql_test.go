//go:build plugin_mysql || !plugin_selective

package services

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/shadow1ng/fscan/common"
)

type chunkedMySQLConn struct {
	data      []byte
	chunkSize int
}

func (c *chunkedMySQLConn) Read(p []byte) (int, error) {
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

func (c *chunkedMySQLConn) Write([]byte) (int, error)       { return 0, nil }
func (c *chunkedMySQLConn) Close() error                    { return nil }
func (c *chunkedMySQLConn) LocalAddr() net.Addr             { return nil }
func (c *chunkedMySQLConn) RemoteAddr() net.Addr            { return nil }
func (c *chunkedMySQLConn) SetDeadline(time.Time) error     { return nil }
func (c *chunkedMySQLConn) SetReadDeadline(time.Time) error { return nil }
func (c *chunkedMySQLConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestReadMySQLBannerHandlesChunkedHandshake(t *testing.T) {
	data := []byte{0x2a, 0x00, 0x00, 0x00, 0x0a}
	data = append(data, []byte("8.0.36\x00")...)
	got := NewMySQLPlugin().readMySQLBanner(&chunkedMySQLConn{data: data, chunkSize: 1}, &common.Config{Timeout: time.Second})
	if got != "MySQL 8.0.36" {
		t.Fatalf("readMySQLBanner() = %q, want MySQL 8.0.36", got)
	}
}

func TestMySQLConnStringEscapesCredentialsAndIPv6(t *testing.T) {
	info := &common.HostInfo{Host: "2001:db8::1", Port: 3306}
	got, err := mySQLConnString("user", "pa:ss@/word", info, 3*time.Second)
	if err != nil {
		t.Fatalf("mySQLConnString() error = %v", err)
	}

	for _, want := range []string{
		"user:pa:ss@/word@tcp([2001:db8::1]:3306)/information_schema",
		"charset=utf8",
		"timeout=3s",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("mySQLConnString() = %q, missing %q", got, want)
		}
	}

	cfg, err := mysql.ParseDSN(got)
	if err != nil {
		t.Fatalf("mysql.ParseDSN() error = %v", err)
	}
	if cfg.User != "user" || cfg.Passwd != "pa:ss@/word" || cfg.Addr != "[2001:db8::1]:3306" {
		t.Fatalf("parsed DSN user/pass/addr = %q/%q/%q", cfg.User, cfg.Passwd, cfg.Addr)
	}
}

func TestMySQLConnStringRejectsUnsupportedUsernameDelimiters(t *testing.T) {
	info := &common.HostInfo{Host: "127.0.0.1", Port: 3306}
	if _, err := mySQLConnString("user:name", "pass", info, time.Second); err == nil {
		t.Fatal("mySQLConnString() error = nil, want unsupported delimiter error")
	}
}

func TestMySQLConnStringRejectsAtSign(t *testing.T) {
	info := &common.HostInfo{Host: "127.0.0.1", Port: 3306}
	if _, err := mySQLConnString("user@host", "pass", info, time.Second); err == nil {
		t.Fatal("mySQLConnString() error = nil, want unsupported delimiter error for @")
	}
}

func TestMySQLConnStringRejectsSlash(t *testing.T) {
	info := &common.HostInfo{Host: "127.0.0.1", Port: 3306}
	if _, err := mySQLConnString("user/name", "pass", info, time.Second); err == nil {
		t.Fatal("mySQLConnString() error = nil, want unsupported delimiter error for /")
	}
}

func TestMySQLConnStringValidUser(t *testing.T) {
	info := &common.HostInfo{Host: "127.0.0.1", Port: 3306}
	dsn, err := mySQLConnString("root", "password", info, 3*time.Second)
	if err != nil {
		t.Fatalf("mySQLConnString() error = %v", err)
	}
	if dsn == "" {
		t.Fatal("mySQLConnString() returned empty DSN")
	}
}

func TestClassifyMySQLErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil error", nil, ErrorTypeUnknown},
		{"access denied for user", errors.New("access denied for user"), ErrorTypeAuth},
		{"host is not allowed", errors.New("host is not allowed"), ErrorTypeAuth},
		{"too many connections", errors.New("too many connections"), ErrorTypeNetwork},
		{"can't connect to mysql server", errors.New("can't connect to mysql server"), ErrorTypeNetwork},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyMySQLErrorType(tt.err)
			if got != tt.want {
				t.Errorf("classifyMySQLErrorType(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
