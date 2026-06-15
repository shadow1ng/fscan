//go:build plugin_ftp || !plugin_selective

package services

import (
	"errors"
	"testing"
)

func TestClassifyFTPErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil error", nil, ErrorTypeUnknown},
		{"530 login incorrect", errors.New("530 login incorrect"), ErrorTypeAuth},
		{"530 not logged in", errors.New("530 not logged in"), ErrorTypeAuth},
		{"authentication failed", errors.New("authentication failed"), ErrorTypeAuth},
		{"too many connections", errors.New("421 there are too many connections"), ErrorTypeNetwork},
		{"connection refused", errors.New("connection refused"), ErrorTypeNetwork},
		{"random error", errors.New("random error"), ErrorTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyFTPErrorType(tt.err)
			if got != tt.want {
				t.Errorf("classifyFTPErrorType(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
