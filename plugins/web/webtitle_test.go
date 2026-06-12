package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/shadow1ng/fscan/webscan/lib"
)

type faviconRoundTripper struct {
	called bool
}

func TestExtractTitleTruncatesByRune(t *testing.T) {
	title := strings.Repeat("界", 105)
	got := NewWebTitlePlugin().extractTitle("<html><title>" + title + "</title></html>")
	if !utf8.ValidString(got) || len([]rune(got)) != 103 || !strings.HasSuffix(got, "...") {
		t.Fatalf("extractTitle() = %q", got)
	}
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

func TestWebTitleHTTPClientsFallbackWhenGlobalsNil(t *testing.T) {
	previousClient, previousNoRedirect := lib.Client, lib.ClientNoRedirect
	previousGM, previousNoRedirectGM := lib.ClientGM, lib.ClientNoRedirectGM
	lib.Client, lib.ClientNoRedirect = nil, nil
	lib.ClientGM, lib.ClientNoRedirectGM = nil, nil
	defer func() {
		lib.Client, lib.ClientNoRedirect = previousClient, previousNoRedirect
		lib.ClientGM, lib.ClientNoRedirectGM = previousGM, previousNoRedirectGM
	}()

	clientNR, clientR := webTitleHTTPClients(false)
	if clientNR == nil || clientR == nil {
		t.Fatal("webTitleHTTPClients returned nil fallback client")
	}

	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientNR.CheckRedirect(req, []*http.Request{req}); err != http.ErrUseLastResponse {
		t.Fatalf("no-redirect fallback error = %v, want http.ErrUseLastResponse", err)
	}
}

func TestReadWebTitleBodyIsBounded(t *testing.T) {
	body := strings.NewReader(strings.Repeat("a", maxWebTitleBodyBytes+1024))
	got, err := readWebTitleBody(body)
	if err != nil {
		t.Fatalf("readWebTitleBody error = %v", err)
	}
	if len(got) != maxWebTitleBodyBytes {
		t.Fatalf("body len = %d, want %d", len(got), maxWebTitleBodyBytes)
	}
}
