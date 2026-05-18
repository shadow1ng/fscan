package common

import "testing"

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
