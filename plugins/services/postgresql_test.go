//go:build plugin_postgresql || !plugin_selective

package services

import (
	"errors"
	"strings"
	"testing"

	"github.com/shadow1ng/fscan/common"
)

func TestPostgreSQLConnStringEscapesIPv6AndCredentials(t *testing.T) {
	info := &common.HostInfo{Host: "2001:db8::1", Port: 5432}
	got := postgreSQLConnString("user:name", "pa:ss word", info, 3)

	for _, want := range []string{
		"postgres://user%3Aname:pa%3Ass%20word@[2001:db8::1]:5432/postgres",
		"connect_timeout=3",
		"sslmode=disable",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("postgreSQLConnString() = %q, missing %q", got, want)
		}
	}
}

func TestPostgreSQLVulnInfoTruncatesByRune(t *testing.T) {
	got := truncateRunes(strings.Repeat("界", 105), 100)
	if len([]rune(got)) != 103 || !strings.HasSuffix(got, "...") {
		t.Fatalf("postgresql truncation helper = %q", got)
	}
}

func TestClassifyPostgreSQLErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil", nil, ErrorTypeUnknown},
		{"password authentication failed", errors.New("password authentication failed"), ErrorTypeAuth},
		{"pq role", errors.New("pq: role \"foo\" does not exist"), ErrorTypeAuth},
		{"dial tcp", errors.New("dial tcp connection refused"), ErrorTypeNetwork},
		{"eof", errors.New("eof"), ErrorTypeNetwork},
		{"unknown", errors.New("random pg error"), ErrorTypeUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyPostgreSQLErrorType(tt.err); got != tt.want {
				t.Errorf("classifyPostgreSQLErrorType() = %v, want %v", got, tt.want)
			}
		})
	}
}
