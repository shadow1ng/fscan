//go:build plugin_smtp || !plugin_selective

package services

import (
	"errors"
	"testing"
)

func TestClassifySMTPErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil error", nil, ErrorTypeUnknown},
		{"535 authentication failed", errors.New("535 authentication failed"), ErrorTypeAuth},
		{"relay access denied", errors.New("relay access denied"), ErrorTypeAuth},
		{"connection refused", errors.New("connection refused"), ErrorTypeNetwork},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifySMTPErrorType(tt.err)
			if got != tt.want {
				t.Errorf("classifySMTPErrorType(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
