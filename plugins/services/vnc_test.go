//go:build plugin_vnc || !plugin_selective

package services

import (
	"errors"
	"testing"
)

func TestClassifyVNCErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil error", nil, ErrorTypeUnknown},
		{"authentication failed", errors.New("authentication failed"), ErrorTypeAuth},
		{"too many authentication failures", errors.New("too many authentication failures"), ErrorTypeNetwork},
		{"connection refused", errors.New("connection refused"), ErrorTypeNetwork},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyVNCErrorType(tt.err)
			if got != tt.want {
				t.Errorf("classifyVNCErrorType(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
