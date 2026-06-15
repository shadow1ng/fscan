//go:build plugin_ssh || !plugin_selective

package services

import (
	"errors"
	"testing"
)

func TestClassifySSHErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil error", nil, ErrorTypeUnknown},
		{"unable to authenticate", errors.New("unable to authenticate"), ErrorTypeAuth},
		{"no supported methods remain", errors.New("no supported methods remain"), ErrorTypeAuth},
		{"handshake failed", errors.New("handshake failed"), ErrorTypeThrottle},
		{"ssh disconnect", errors.New("ssh: disconnect"), ErrorTypeThrottle},
		{"max startups", errors.New("max startups"), ErrorTypeThrottle},
		{"connection refused", errors.New("connection refused"), ErrorTypeNetwork},
		{"random error", errors.New("random error"), ErrorTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifySSHErrorType(tt.err)
			if got != tt.want {
				t.Errorf("classifySSHErrorType(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestClassifySSHError(t *testing.T) {
	authKeywords := []string{"bad password", "invalid key"}
	throttleKeywords := []string{"rate limited", "too fast"}

	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil error", nil, ErrorTypeUnknown},
		{"custom auth keyword", errors.New("bad password provided"), ErrorTypeAuth},
		{"custom throttle keyword", errors.New("rate limited by server"), ErrorTypeThrottle},
		{"network error", errors.New("connection refused"), ErrorTypeNetwork},
		{"no match", errors.New("something else"), ErrorTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifySSHError(tt.err, authKeywords, throttleKeywords)
			if got != tt.want {
				t.Errorf("classifySSHError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
