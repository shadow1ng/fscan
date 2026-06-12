package local

import "testing"

func TestLDAPURLUsesJoinHostPort(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		want string
	}{
		{name: "hostname", host: "dc.example.local", port: 389, want: "ldap://dc.example.local:389"},
		{name: "ipv4", host: "192.168.1.10", port: 389, want: "ldap://192.168.1.10:389"},
		{name: "ipv6", host: "2001:db8::10", port: 389, want: "ldap://[2001:db8::10]:389"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ldapURL(tt.host, tt.port); got != tt.want {
				t.Fatalf("ldapURL(%q, %d) = %q, want %q", tt.host, tt.port, got, tt.want)
			}
		})
	}
}
