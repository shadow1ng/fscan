package common

import "testing"

func preserveLoggerForTest(t *testing.T) {
	t.Helper()

	loggerMu.Lock()
	oldSilentRefs := silentLoggerRefs
	silentLoggerRefs = 0
	resetLoggerLocked()
	loggerMu.Unlock()

	t.Cleanup(func() {
		loggerMu.Lock()
		closeLoggerLocked()
		silentLoggerRefs = oldSilentRefs
		resetLoggerLocked()
		loggerMu.Unlock()
	})
}

func TestLoggerFacadeSilentLifecycle(t *testing.T) {
	preserveLoggerForTest(t)

	previousFlags := GetFlagVars()
	previousState := GetGlobalState()
	t.Cleanup(func() {
		flagVars = previousFlags
		SetGlobalState(previousState)
	})
	flagVars = &FlagVars{Silent: true, LogLevel: "debug"}
	SetGlobalState(NewState())

	InitLogger()
	LogDebug("debug")
	LogInfo("info")
	LogSuccess("success")
	LogVuln("vuln")
	LogError("error")
	CloseLogger()
}

func TestPushSilentLoggerReferenceCount(t *testing.T) {
	preserveLoggerForTest(t)

	restoreOne := PushSilentLogger()
	restoreTwo := PushSilentLogger()
	if silentLoggerRefs != 2 {
		t.Fatalf("silent refs = %d, want 2", silentLoggerRefs)
	}

	restoreOne()
	restoreOne()
	if silentLoggerRefs != 1 {
		t.Fatalf("silent refs after first restore = %d, want 1", silentLoggerRefs)
	}

	restoreTwo()
	if silentLoggerRefs != 0 {
		t.Fatalf("silent refs after second restore = %d, want 0", silentLoggerRefs)
	}
}
