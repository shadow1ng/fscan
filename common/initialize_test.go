package common

import (
	"strings"
	"testing"
)

func TestValidateExclusiveParams(t *testing.T) {
	previous := GetFlagVars()
	t.Cleanup(func() { flagVars = previous })

	tests := []struct {
		name    string
		info    *HostInfo
		flags   *FlagVars
		wantErr string
	}{
		{name: "host only", info: &HostInfo{Host: "127.0.0.1"}, flags: &FlagVars{}},
		{name: "url only", info: &HostInfo{}, flags: &FlagVars{TargetURL: "http://example.com"}},
		{name: "local only", info: &HostInfo{}, flags: &FlagVars{LocalPlugin: "sshkey"}},
		{name: "host and url conflict", info: &HostInfo{Host: "127.0.0.1"}, flags: &FlagVars{TargetURL: "http://example.com"}, wantErr: "-h"},
		{name: "host url local conflict", info: &HostInfo{Host: "127.0.0.1"}, flags: &FlagVars{TargetURL: "http://example.com", LocalPlugin: "sshkey"}, wantErr: "-local"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flagVars = tt.flags
			err := ValidateExclusiveParams(tt.info)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateExclusiveParams error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateExclusiveParams error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestCleanupWithoutOutput(t *testing.T) {
	oldResultOutput := ResultOutput
	oldStdoutWriter := StdoutWriter
	t.Cleanup(func() {
		ResultOutput = oldResultOutput
		StdoutWriter = oldStdoutWriter
	})

	ResultOutput = nil
	StdoutWriter = nil
	if err := Cleanup(); err != nil {
		t.Fatalf("Cleanup error = %v", err)
	}
}
