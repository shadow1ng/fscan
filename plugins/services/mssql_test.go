//go:build plugin_mssql || !plugin_selective

package services

import (
	"errors"
	"testing"
)

func TestClassifyMSSQLErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil error", nil, ErrorTypeUnknown},
		{"login failed", errors.New("login failed"), ErrorTypeAuth},
		{"account locked", errors.New("account locked"), ErrorTypeAuth},
		{"context deadline exceeded", errors.New("context deadline exceeded"), ErrorTypeNetwork},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyMSSQLErrorType(tt.err)
			if got != tt.want {
				t.Errorf("classifyMSSQLErrorType(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
