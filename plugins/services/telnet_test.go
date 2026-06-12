//go:build plugin_telnet || !plugin_selective

package services

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTelnetExtractEvidenceTruncatesByRune(t *testing.T) {
	p := NewTelnetPlugin()
	got := p.extractEvidence("CMD_START\n" + strings.Repeat("界", 105) + "\nCMD_END")
	if !utf8.ValidString(got) || len([]rune(got)) != 103 || !strings.HasSuffix(got, "...") {
		t.Fatalf("extractEvidence() = %q", got)
	}
}
