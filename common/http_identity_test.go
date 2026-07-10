package common

import "testing"

func TestHTTPUserAgent(t *testing.T) {
	if got := HTTPUserAgent(nil); got != DefaultHTTPUserAgent {
		t.Fatalf("HTTPUserAgent(nil) = %q, want %q", got, DefaultHTTPUserAgent)
	}

	config := NewConfig()
	config.HTTP.UserAgent = ""
	if got := HTTPUserAgent(config); got != DefaultHTTPUserAgent {
		t.Fatalf("HTTPUserAgent(empty) = %q, want %q", got, DefaultHTTPUserAgent)
	}

	config.HTTP.UserAgent = "Scanner-Test/1.0"
	if got := HTTPUserAgent(config); got != "Scanner-Test/1.0" {
		t.Fatalf("HTTPUserAgent(custom) = %q", got)
	}
}

func TestDefaultUserAgentIsStable(t *testing.T) {
	first := defaultUserAgent("")
	for i := 0; i < 100; i++ {
		if got := defaultUserAgent(""); got != first {
			t.Fatalf("default User-Agent changed between calls: %q != %q", got, first)
		}
	}
}
