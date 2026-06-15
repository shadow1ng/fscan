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

func TestResolveRedirectURL(t *testing.T) {
	p := NewWebTitlePlugin()
	base := "http://example.com/path"

	tests := []struct {
		name     string
		location string
		want     string
	}{
		{"absolute http", "http://other.com/page", "http://other.com/page"},
		{"absolute https", "https://other.com/page", "https://other.com/page"},
		{"relative path", "/admin/login", "http://example.com/admin/login"},
		{"relative no slash", "login", "http://example.com/login"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.resolveRedirectURL(base, tt.location)
			if got != tt.want {
				t.Fatalf("resolveRedirectURL(%q, %q) = %q, want %q", base, tt.location, got, tt.want)
			}
		})
	}
}

func TestResolveRedirectURLInvalidBase(t *testing.T) {
	p := NewWebTitlePlugin()
	got := p.resolveRedirectURL("://bad-url", "/path")
	if got != "" {
		t.Fatalf("expected empty string for invalid base, got %q", got)
	}
}

func TestResolveRedirectURLInvalidLocation(t *testing.T) {
	p := NewWebTitlePlugin()
	// 百分号开头的无效 URL
	got := p.resolveRedirectURL("http://example.com", "://")
	// net/url.Parse 对 "://" 不一定报错，只要不 panic 即可
	_ = got
}

func TestFormatHeaders(t *testing.T) {
	p := NewWebTitlePlugin()

	// 空 header
	if got := p.formatHeaders(http.Header{}); got != "" {
		t.Fatalf("empty headers = %q, want empty string", got)
	}

	// 单个 header
	h := http.Header{}
	h.Set("Content-Type", "text/html")
	got := p.formatHeaders(h)
	if !strings.Contains(got, "Content-Type") || !strings.Contains(got, "text/html") {
		t.Fatalf("formatHeaders missing expected content: %q", got)
	}

	// 多值 header
	h2 := http.Header{}
	h2.Add("X-Custom", "val1")
	h2.Add("X-Custom", "val2")
	got2 := p.formatHeaders(h2)
	if !strings.Contains(got2, "val1") || !strings.Contains(got2, "val2") {
		t.Fatalf("formatHeaders missing multi-value: %q", got2)
	}
}

func TestURLHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"127.0.0.1", "127.0.0.1"},
		{"example.com", "example.com"},
		{"::1", "[::1]"},
		{"[::1]", "[::1]"}, // 已经括起来的不要双重括号
	}
	for _, tt := range tests {
		got := urlHost(tt.input)
		if got != tt.want {
			t.Fatalf("urlHost(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestTruncateRunes(t *testing.T) {
	// 负数 maxRunes → 原样返回
	s := "hello"
	if got := truncateRunes(s, -1); got != s {
		t.Fatalf("truncateRunes negative = %q, want %q", got, s)
	}

	// 短于 maxRunes → 原样返回
	if got := truncateRunes("ab", 10); got != "ab" {
		t.Fatalf("truncateRunes short = %q, want %q", got, "ab")
	}

	// 超过 maxRunes → 截断加 "..."
	long := strings.Repeat("x", 5)
	got := truncateRunes(long, 3)
	if got != "xxx..." {
		t.Fatalf("truncateRunes long = %q, want %q", got, "xxx...")
	}

	// maxRunes=0 → 立刻截断
	if got := truncateRunes("hello", 0); got != "..." {
		t.Fatalf("truncateRunes zero = %q, want %q", got, "...")
	}
}

func TestExtractTitleInvalidUTF8(t *testing.T) {
	p := NewWebTitlePlugin()
	// 构造含非法 UTF-8 字节的 title
	html := "<html><title>\xff\xfe</title></html>"
	got := p.extractTitle(html)
	// 非法 UTF-8 应返回空
	if got != "" {
		t.Fatalf("extractTitle with invalid UTF-8 = %q, want empty", got)
	}
}

func TestExtractTitleNoMatch(t *testing.T) {
	p := NewWebTitlePlugin()
	got := p.extractTitle("<html><body>no title here</body></html>")
	if got != "" {
		t.Fatalf("extractTitle no match = %q, want empty", got)
	}
}

func TestWebTitleHTTPClientsGM(t *testing.T) {
	previousGM, previousNoRedirectGM := lib.ClientGM, lib.ClientNoRedirectGM
	defer func() {
		lib.ClientGM, lib.ClientNoRedirectGM = previousGM, previousNoRedirectGM
	}()

	// 设置 GM 客户端为非 nil
	lib.ClientGM = &http.Client{}
	lib.ClientNoRedirectGM = &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	clientNR, clientR := webTitleHTTPClients(true)
	if clientNR == nil || clientR == nil {
		t.Fatal("webTitleHTTPClients(GM) returned nil")
	}
}

func TestFirstHTTPClientAllNil(t *testing.T) {
	got := firstHTTPClient(nil, nil, nil)
	if got != http.DefaultClient {
		t.Fatalf("firstHTTPClient all nil = %v, want http.DefaultClient", got)
	}
}

func TestFetchFaviconHashNon200(t *testing.T) {
	previous := lib.Client
	lib.Client = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       http.NoBody,
			}, nil
		}),
	}
	defer func() { lib.Client = previous }()

	p := NewWebTitlePlugin()
	hashes := p.fetchFaviconHash(context.Background(), "http://example.com")
	if len(hashes.MMH3) != 0 || len(hashes.MD5) != 0 {
		t.Fatalf("fetchFaviconHash non-200 returned hashes: %#v", hashes)
	}
}

func TestFetchFaviconHashBadURL(t *testing.T) {
	p := NewWebTitlePlugin()
	// 无效 URL 应返回空 hash，不 panic
	hashes := p.fetchFaviconHash(context.Background(), "://bad")
	if len(hashes.MMH3) != 0 || len(hashes.MD5) != 0 {
		t.Fatalf("fetchFaviconHash bad URL returned hashes: %#v", hashes)
	}
}

// roundTripFunc 允许用函数实现 http.RoundTripper
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
