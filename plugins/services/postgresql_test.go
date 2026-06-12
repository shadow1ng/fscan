//go:build plugin_postgresql || !plugin_selective

package services

import (
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
