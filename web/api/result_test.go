//go:build web

package api

import (
	"testing"
	"unicode/utf8"
)

func TestExtractHostPortIPv6(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantHost string
		wantPort string
	}{
		{name: "ipv4", target: "192.168.1.1:80", wantHost: "192.168.1.1", wantPort: "80"},
		{name: "hostname", target: "example.com:443", wantHost: "example.com", wantPort: "443"},
		{name: "bracketed ipv6", target: "[2001:db8::1]:8443", wantHost: "2001:db8::1", wantPort: "8443"},
		{name: "bare ipv6 without port", target: "2001:db8::1", wantHost: "2001:db8::1", wantPort: ""},
		{name: "invalid port", target: "example.com:abc", wantHost: "example.com:abc", wantPort: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractHost(tt.target); got != tt.wantHost {
				t.Fatalf("extractHost(%q) = %q, want %q", tt.target, got, tt.wantHost)
			}
			if got := extractPort(tt.target); got != tt.wantPort {
				t.Fatalf("extractPort(%q) = %q, want %q", tt.target, got, tt.wantPort)
			}
		})
	}
}

func TestTargetWithDetailsPort(t *testing.T) {
	tests := []struct {
		name   string
		target string
		port   interface{}
		want   string
	}{
		{name: "hostname", target: "example.com", port: 443, want: "example.com:443"},
		{name: "ipv4", target: "192.168.1.1", port: "80", want: "192.168.1.1:80"},
		{name: "bare ipv6", target: "2001:db8::1", port: 8443, want: "[2001:db8::1]:8443"},
		{name: "bracketed ipv6", target: "[2001:db8::1]", port: 8443, want: "[2001:db8::1]:8443"},
		{name: "already has port", target: "[2001:db8::1]:8443", port: 9443, want: ""},
		{name: "invalid colon target", target: "example.com:abc", port: 80, want: ""},
		{name: "url target", target: "http://example.com", port: 80, want: ""},
		{name: "bad port", target: "example.com", port: 70000, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := targetWithDetailsPort(tt.target, tt.port); got != tt.want {
				t.Fatalf("targetWithDetailsPort(%q, %v) = %q, want %q", tt.target, tt.port, got, tt.want)
			}
		})
	}
}

func TestExtractServiceInfoTruncatesBannerByRune(t *testing.T) {
	banner := ""
	for i := 0; i < 105; i++ {
		banner += "界"
	}
	_, _, got := extractServiceInfo(map[string]interface{}{"banner": banner})
	if !utf8.ValidString(got) {
		t.Fatalf("banner is not valid utf8: %q", got)
	}
	if len([]rune(got)) != 103 || got[len(got)-3:] != "..." {
		t.Fatalf("banner = %q, rune len %d", got, len([]rune(got)))
	}
}
