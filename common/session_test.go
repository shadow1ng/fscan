package common

import (
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
