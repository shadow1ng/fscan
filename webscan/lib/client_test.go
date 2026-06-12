package lib

import "testing"

func TestNormalizeHTTPProxyURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "port shortcut", in: "8080", want: "http://127.0.0.1:8080"},
		{name: "ipv4 host port", in: "127.0.0.1:8080", want: "http://127.0.0.1:8080"},
		{name: "hostname port", in: "proxy.local:8080", want: "http://proxy.local:8080"},
		{name: "bracketed ipv6 port", in: "[::1]:8080", want: "http://[::1]:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeHTTPProxyURL(tt.in); got != tt.want {
				t.Fatalf("normalizeHTTPProxyURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
