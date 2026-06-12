package login

import "testing"

func TestRDPTargetHost(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
	}{
		{name: "ipv4 with port", target: "192.168.1.1:3389", want: "192.168.1.1"},
		{name: "hostname with port", target: "rdp.example.com:3389", want: "rdp.example.com"},
		{name: "bracketed ipv6 with port", target: "[2001:db8::1]:3389", want: "2001:db8::1"},
		{name: "bare ipv6 without port", target: "2001:db8::1", want: "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rdpTargetHost(tt.target); got != tt.want {
				t.Fatalf("rdpTargetHost(%q) = %q, want %q", tt.target, got, tt.want)
			}
		})
	}
}
