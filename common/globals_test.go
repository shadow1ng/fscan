package common

import "testing"

func TestHostInfoTargetUsesBracketedIPv6(t *testing.T) {
	info := &HostInfo{Host: "2001:db8::1", Port: 443}
	if got, want := info.Target(), "[2001:db8::1]:443"; got != want {
		t.Fatalf("Target() = %q, want %q", got, want)
	}
}
