//go:build web

package api

import "testing"

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
