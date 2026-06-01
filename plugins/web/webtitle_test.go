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
