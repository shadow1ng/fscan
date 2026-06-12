package web

import (
	"context"
	"net/http"
	"testing"

	"github.com/shadow1ng/fscan/webscan/lib"
)

type faviconRoundTripper struct {
	called bool
}

func (rt *faviconRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.called = true
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestFetchFaviconHashHonorsContext(t *testing.T) {
	previous := lib.Client
	rt := &faviconRoundTripper{}
	lib.Client = &http.Client{Transport: rt}
	defer func() { lib.Client = previous }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	hashes := NewWebTitlePlugin().fetchFaviconHash(ctx, "http://example.com")
	if !rt.called {
		t.Fatal("favicon client was not called")
	}
	if len(hashes.MMH3) != 0 || len(hashes.MD5) != 0 {
		t.Fatalf("fetchFaviconHash returned hashes for canceled context: %#v", hashes)
	}
}

func TestWebTitleURLUsesJoinHostPort(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"ipv4", webTitleURL("http", "127.0.0.1", 8080), "http://127.0.0.1:8080"},
		{"ipv6", webTitleURL("http", "::1", 8080), "http://[::1]:8080"},
		{"ipv6 display with port", webTitleDisplayURL("https", "2001:db8::1", 8443, false), "https://[2001:db8::1]:8443"},
		{"ipv6 display omit port", webTitleDisplayURL("https", "2001:db8::1", 443, true), "https://[2001:db8::1]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}
