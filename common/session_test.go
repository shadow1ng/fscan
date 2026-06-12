package common

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestScanSessionLogMethodsHonorSilentConfig(t *testing.T) {
	loggerMu.Lock()
	silentLoggerRefs = 0
	resetLoggerLocked()
	loggerMu.Unlock()
	t.Cleanup(func() {
		loggerMu.Lock()
		silentLoggerRefs = 0
		resetLoggerLocked()
		loggerMu.Unlock()
	})

	cfg := NewConfig()
	cfg.Output.Silent = true
	session := NewScanSession(cfg, NewState(), &FlagVars{})

	session.LogDebug("debug")
	session.LogInfo("info")
	session.LogSuccess("success")
	session.LogVuln("vuln")
	session.LogError("error")

	loggerMu.Lock()
	defer loggerMu.Unlock()
	if globalLogger != nil {
		t.Fatal("silent session log methods initialized global logger")
	}
}

func TestScanSessionDialerCacheIsTimeoutAware(t *testing.T) {
	cfg := NewConfig()
	cfg.Timeout = 5 * time.Second
	session := NewScanSession(cfg, NewState(), &FlagVars{})

	shortTimeout := 100 * time.Millisecond
	longTimeout := 2 * time.Second

	shortDialer, err := session.getDialer(shortTimeout)
	if err != nil {
		t.Fatal(err)
	}
	shortDialerAgain, err := session.getDialer(shortTimeout)
	if err != nil {
		t.Fatal(err)
	}
	longDialer, err := session.getDialer(longTimeout)
	if err != nil {
		t.Fatal(err)
	}

	if shortDialer != shortDialerAgain {
		t.Fatal("same timeout should reuse the session dialer")
	}
	if shortDialer == longDialer {
		t.Fatal("different timeouts should not share one session dialer")
	}
	if got := session.createProxyConfig(shortTimeout).Timeout; got != shortTimeout {
		t.Fatalf("proxy timeout = %v, want %v", got, shortTimeout)
	}
}

func TestScanSessionHTTPDoUsesSessionState(t *testing.T) {
	previousState := GetGlobalState()
	globalState := NewState()
	SetGlobalState(globalState)
	t.Cleanup(func() { SetGlobalState(previousState) })

	sessionState := NewState()
	session := NewScanSession(NewConfig(), sessionState, &FlagVars{})
	client := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		}),
	}
	req, err := http.NewRequest(http.MethodHead, "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := session.HTTPDo(client, req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if got := sessionState.GetTCPSuccessPacketCount(); got != 1 {
		t.Fatalf("session TCP success count = %d, want 1", got)
	}
	if got := globalState.GetTCPSuccessPacketCount(); got != 0 {
		t.Fatalf("global TCP success count = %d, want 0", got)
	}
}

func TestScanSessionProxyStateComesFromConfig(t *testing.T) {
	direct := NewScanSession(NewConfig(), NewState(), &FlagVars{})
	if direct.ProxyEnabled() {
		t.Fatal("direct session should not report proxy enabled")
	}
	if direct.IsSOCKS5Proxy() {
		t.Fatal("direct session should not report SOCKS5")
	}
	if !direct.ProxyReliable() {
		t.Fatal("direct session should be reliable")
	}

	httpCfg := NewConfig()
	httpCfg.Network.HTTPProxy = "http://127.0.0.1:8080"
	httpSession := NewScanSession(httpCfg, NewState(), &FlagVars{})
	if !httpSession.ProxyEnabled() {
		t.Fatal("HTTP proxy session should report proxy enabled")
	}
	if httpSession.IsSOCKS5Proxy() {
		t.Fatal("HTTP proxy session should not report SOCKS5")
	}
	if !httpSession.ProxyReliable() {
		t.Fatal("HTTP proxy session should be reliable")
	}

	socksCfg := NewConfig()
	socksCfg.Network.Socks5Proxy = "127.0.0.1:1080"
	socksSession := NewScanSession(socksCfg, NewState(), &FlagVars{})
	if !socksSession.ProxyEnabled() {
		t.Fatal("SOCKS5 proxy session should report proxy enabled")
	}
	if !socksSession.IsSOCKS5Proxy() {
		t.Fatal("SOCKS5 proxy session should report SOCKS5")
	}
}

func TestParseProxyURLFallsBackWhenHostIsEmpty(t *testing.T) {
	host, username, password := parseProxyURL("127.0.0.1:8080", "127.0.0.1:8080")
	if host != "127.0.0.1:8080" {
		t.Fatalf("host = %q, want fallback address", host)
	}
	if username != "" || password != "" {
		t.Fatalf("unexpected credentials: %q/%q", username, password)
	}
}

func TestParseProxyURLExtractsAuthWithoutScheme(t *testing.T) {
	host, username, password := parseProxyURL("user:pass@127.0.0.1:8080", "user:pass@127.0.0.1:8080")
	if host != "127.0.0.1:8080" {
		t.Fatalf("host = %q, want proxy address", host)
	}
	if username != "user" || password != "pass" {
		t.Fatalf("credentials = %q/%q, want user/pass", username, password)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
