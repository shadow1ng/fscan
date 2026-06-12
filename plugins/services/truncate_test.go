//go:build plugin_redis || !plugin_selective

package services

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateRunesKeepsUTF8Valid(t *testing.T) {
	got := truncateRunes(strings.Repeat("界", 205), 200)
	if !utf8.ValidString(got) {
		t.Fatalf("truncateRunes returned invalid utf8: %q", got)
	}
	if len([]rune(got)) != 203 || !strings.HasSuffix(got, "...") {
		t.Fatalf("truncateRunes() = rune len %d value %q", len([]rune(got)), got)
	}

	got = truncateRunes(strings.Repeat("界", 55), 50)
	if !utf8.ValidString(got) || len([]rune(got)) != 53 || !strings.HasSuffix(got, "...") {
		t.Fatalf("truncateRunes(50) = rune len %d value %q", len([]rune(got)), got)
	}
}

func TestRedisTruncateTextTruncatesByRune(t *testing.T) {
	got := NewRedisPlugin().truncateText(strings.Repeat("界", 55))
	if !utf8.ValidString(got) || len([]rune(got)) != 53 {
		t.Fatalf("truncateText() = %q", got)
	}
}
