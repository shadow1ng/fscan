package output

import "testing"

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantHost string
		wantPort int
		wantOK   bool
	}{
		{name: "ipv4", target: "192.168.1.1:80", wantHost: "192.168.1.1", wantPort: 80, wantOK: true},
		{name: "hostname", target: "example.com:443", wantHost: "example.com", wantPort: 443, wantOK: true},
		{name: "bracketed ipv6", target: "[2001:db8::1]:8443", wantHost: "2001:db8::1", wantPort: 8443, wantOK: true},
		{name: "bare ipv6 without port", target: "2001:db8::1", wantOK: false},
		{name: "invalid port", target: "example.com:abc", wantOK: false},
		{name: "port out of range", target: "example.com:65536", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, ok := splitHostPort(tt.target)
			if ok != tt.wantOK {
				t.Fatalf("splitHostPort(%q) ok = %v, want %v", tt.target, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if host != tt.wantHost || port != tt.wantPort {
				t.Fatalf("splitHostPort(%q) = (%q, %d), want (%q, %d)", tt.target, host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}
