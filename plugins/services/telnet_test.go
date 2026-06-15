//go:build plugin_telnet || !plugin_selective

package services

import (
	"errors"
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

func TestClassifyTelnetErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil", nil, ErrorTypeUnknown},
		{"login failed", errors.New("login failed"), ErrorTypeAuth},
		{"credentials rejected", errors.New("credentials rejected"), ErrorTypeAuth},
		{"connection refused", errors.New("connection refused"), ErrorTypeNetwork},
		{"unknown", errors.New("random telnet error"), ErrorTypeUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyTelnetErrorType(tt.err); got != tt.want {
				t.Errorf("classifyTelnetErrorType() = %v, want %v", got, tt.want)
			}
		})
	}
}
