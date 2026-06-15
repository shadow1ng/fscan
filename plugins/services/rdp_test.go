//go:build plugin_rdp || !plugin_selective

package services

import (
	"testing"

	"github.com/shadow1ng/fscan/common/i18n"
)

func TestBuildBanner(t *testing.T) {
	p := &RDPPlugin{}
	fallback := i18n.GetText("rdp_remote_desktop_service")

	tests := []struct {
		name   string
		osInfo map[string]any
		want   string
	}{
		{
			name:   "nil map",
			osInfo: nil,
			want:   fallback,
		},
		{
			name:   "empty map",
			osInfo: map[string]any{},
			want:   fallback,
		},
		{
			name:   "OsVerion and NetBIOSComputerName",
			osInfo: map[string]any{"OsVerion": "Windows 10", "NetBIOSComputerName": "DESKTOP-01"},
			want:   "RDP (Windows 10, DESKTOP-01)",
		},
		{
			name:   "only OsVerion",
			osInfo: map[string]any{"OsVerion": "Windows Server 2019"},
			want:   "RDP (Windows Server 2019)",
		},
		{
			name:   "only NetBIOSComputerName",
			osInfo: map[string]any{"NetBIOSComputerName": "MY-HOST"},
			want:   "RDP (Hostname:MY-HOST)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.buildBanner(tt.osInfo)
			if got != tt.want {
				t.Errorf("buildBanner() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractStringField(t *testing.T) {
	p := &RDPPlugin{}

	tests := []struct {
		name   string
		osInfo map[string]any
		key    string
		want   string
	}{
		{
			name:   "key exists and is string",
			osInfo: map[string]any{"foo": "bar"},
			key:    "foo",
			want:   "bar",
		},
		{
			name:   "key exists but not string",
			osInfo: map[string]any{"foo": 42},
			key:    "foo",
			want:   "",
		},
		{
			name:   "key does not exist",
			osInfo: map[string]any{"foo": "bar"},
			key:    "missing",
			want:   "",
		},
		{
			name:   "nil map",
			osInfo: nil,
			key:    "foo",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.extractStringField(tt.osInfo, tt.key)
			if got != tt.want {
				t.Errorf("extractStringField(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}
