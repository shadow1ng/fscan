//go:build plugin_oracle || !plugin_selective

package services

import (
	"errors"
	"testing"
)

func TestClassifyOracleErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorType
	}{
		{"nil error", nil, ErrorTypeUnknown},
		{"ORA-01017 invalid username/password", errors.New("ORA-01017: invalid username/password"), ErrorTypeAuth},
		{"TNS-12541 no listener", errors.New("TNS-12541 no listener"), ErrorTypeNetwork},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyOracleErrorType(tt.err)
			if got != tt.want {
				t.Errorf("classifyOracleErrorType(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
