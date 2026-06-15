//go:build plugin_activemq || !plugin_selective

package services

import (
	"errors"
	"testing"
)

func TestClassifyActiveMQErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil error", nil, ErrorTypeUnknown},
		{"authentication failed", errors.New("authentication failed"), ErrorTypeAuth},
		{"connection refused", errors.New("connection refused"), ErrorTypeNetwork},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyActiveMQErrorType(tt.err)
			if got != tt.want {
				t.Errorf("classifyActiveMQErrorType(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
