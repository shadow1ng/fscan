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

func TestIsShellPrompt(t *testing.T) {
	p := NewTelnetPlugin()

	positive := []struct {
		name, data string
	}{
		{"linux root", "root@host:~#"},
		{"linux user", "user@host:~$"},
		{"cisco", "Router>"},
		{"cisco enable", "Router#"},
		{"bracket prompt", "[admin@host ~]$"},
		{"paren prompt", "host(config)#"},
		{"bash keyword", "bash-4.2$"},
		{"trailing space", "root@host:~# "},
		{"multiline last", "Welcome\nroot@host:~#"},
	}

	negative := []struct {
		name, data string
	}{
		{"empty", ""},
		{"decoration hashes", "################"},
		{"decoration arrows", ">>>>>>>>"},
		{"decoration dollars", "$$$$$$$$"},
		{"cisco motd border", "###################################################"},
		{"motd with hash mid", "# Welcome to Cisco IOS"},
		{"plain text", "Cisco IOS Software, Version 12.2"},
		{"login prompt", "Login:"},
		{"password prompt", "Password:"},
		{"motd multiline", "##########\nWelcome to Router\n##########"},
	}

	for _, tt := range positive {
		if !p.isShellPrompt(tt.data) {
			t.Errorf("isShellPrompt(%q) = false, want true [%s]", tt.data, tt.name)
		}
	}

	for _, tt := range negative {
		if p.isShellPrompt(tt.data) {
			t.Errorf("isShellPrompt(%q) = true, want false [%s]", tt.data, tt.name)
		}
	}
}
