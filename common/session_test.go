package common

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/shadow1ng/fscan/common/output"
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

// TestScanSessionSaveResultUsesSink 测试 SaveResult 通过 ResultSink 分发
func TestScanSessionSaveResultUsesSink(t *testing.T) {
	preserveOutputAPIGlobals(t)

	cfg := NewConfig()
	cfg.Output.DisableSave = true
	SetGlobalConfig(cfg)
	flagVars = &FlagVars{DisableSave: true}
	_ = InitOutput()

	var sinkGot *output.ScanResult
	session := NewScanSession(cfg, NewState(), &FlagVars{})
	session.ResultSink = func(r *output.ScanResult) error {
		sinkGot = r
		return nil
	}

	result := &output.ScanResult{
		Type:   output.TypeHost,
		Target: "10.0.0.1",
		Status: "ALIVE",
	}
	if err := session.SaveResult(result); err != nil {
		t.Fatalf("session.SaveResult error = %v", err)
	}
	if sinkGot != result {
		t.Fatalf("ResultSink 未被调用或参数不符: got %v", sinkGot)
	}
}

// TestScanSessionSaveResultFallsBackToGlobal 测试无 sink 时回退到全局 SaveResult
func TestScanSessionSaveResultFallsBackToGlobal(t *testing.T) {
	preserveOutputAPIGlobals(t)

	cfg := NewConfig()
	cfg.Output.DisableSave = true
	SetGlobalConfig(cfg)
	flagVars = &FlagVars{DisableSave: true}
	_ = InitOutput()

	called := false
	SetResultCallback(func(payload interface{}) {
		called = true
	})

	session := NewScanSession(cfg, NewState(), &FlagVars{})
	// 不设置 ResultSink，应回退到全局

	result := &output.ScanResult{
		Type:   output.TypeHost,
		Target: "10.0.0.2",
		Status: "ALIVE",
	}
	if err := session.SaveResult(result); err != nil {
		t.Fatalf("session.SaveResult (fallback) error = %v", err)
	}
	if !called {
		t.Fatal("回退到全局 SaveResult 时应触发 ResultCallback")
	}
}

// TestScanSessionLogMethodsEnabledByDefault 测试非 Silent 配置下 Log 方法不被屏蔽
func TestScanSessionLogMethodsEnabledByDefault(t *testing.T) {
	cfg := NewConfig()
	cfg.Output.Silent = false
	session := NewScanSession(cfg, NewState(), &FlagVars{})
	if !session.loggingEnabled() {
		t.Fatal("非 Silent 配置下 loggingEnabled 应返回 true")
	}
}

// TestNilScanSessionLoggingEnabled 测试 nil session 的 loggingEnabled
func TestNilScanSessionLoggingEnabled(t *testing.T) {
	var session *ScanSession
	if !session.loggingEnabled() {
		t.Fatal("nil session 的 loggingEnabled 应返回 true（安全降级）")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
