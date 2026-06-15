package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shadow1ng/fscan/common/output"
)

func readTestFile(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}

func preserveOutputAPIGlobals(t *testing.T) {
	t.Helper()

	globalMu.RLock()
	oldConfig := globalConfig
	oldState := globalState
	globalMu.RUnlock()

	oldFlagVars := flagVars
	oldResultOutput := ResultOutput
	oldStdoutWriter := StdoutWriter

	t.Cleanup(func() {
		if ResultOutput != nil && ResultOutput != oldResultOutput {
			_ = ResultOutput.Close()
		}
		if StdoutWriter != nil && StdoutWriter != oldStdoutWriter {
			_ = StdoutWriter.Close()
		}
		ClearResultCallback()

		globalMu.Lock()
		globalConfig = oldConfig
		globalState = oldState
		globalMu.Unlock()

		flagVars = oldFlagVars
		ResultOutput = oldResultOutput
		StdoutWriter = oldStdoutWriter
	})

	ClearResultCallback()
	flagVars = &FlagVars{}
	ResultOutput = nil
	StdoutWriter = nil
	SetGlobalConfig(NewConfig())
	SetGlobalState(NewState())
}

func TestInitOutputValidationAndDefaultExtension(t *testing.T) {
	preserveOutputAPIGlobals(t)

	flagVars = &FlagVars{DisableSave: true}
	if err := InitOutput(); err != nil {
		t.Fatalf("InitOutput disable save error = %v", err)
	}
	if ResultOutput != nil {
		t.Fatalf("ResultOutput = %#v, want nil when save is disabled", ResultOutput)
	}

	flagVars = &FlagVars{OutputFormat: "txt"}
	if err := InitOutput(); err == nil || !strings.Contains(err.Error(), "output file not specified") {
		t.Fatalf("missing output error = %v", err)
	}

	flagVars = &FlagVars{Outputfile: "out.bad", OutputFormat: "xml"}
	if err := InitOutput(); err == nil || !strings.Contains(err.Error(), "invalid output format") {
		t.Fatalf("invalid format error = %v", err)
	}

	dir := t.TempDir()
	t.Chdir(dir)
	flagVars = &FlagVars{Outputfile: "result.txt", OutputFormat: "json"}
	if err := InitOutput(); err != nil {
		t.Fatalf("InitOutput json error = %v", err)
	}
	if ResultOutput == nil {
		t.Fatal("ResultOutput should be initialized")
	}
	if err := SaveResult(&output.ScanResult{
		Time:   time.Date(2026, 6, 13, 1, 2, 3, 0, time.UTC),
		Type:   output.TypeHost,
		Target: "127.0.0.1",
		Status: "ALIVE",
	}); err != nil {
		t.Fatalf("SaveResult json error = %v", err)
	}
	if err := CloseOutput(); err != nil {
		t.Fatalf("CloseOutput error = %v", err)
	}
	if content := readTestFile(t, filepath.Join(dir, "result.json")); !strings.Contains(content, "127.0.0.1") {
		t.Fatalf("result.json content = %q, want saved target", content)
	}
}

func TestCloseOutputWithStdoutWriter(t *testing.T) {
	preserveOutputAPIGlobals(t)

	// 初始化 silent 模式以创建 StdoutWriter
	flagVars = &FlagVars{Silent: true, DisableSave: true}
	if err := InitOutput(); err != nil {
		t.Fatalf("InitOutput silent error = %v", err)
	}
	if StdoutWriter == nil {
		t.Fatal("StdoutWriter 应在 Silent 模式下被初始化")
	}

	// CloseOutput 应正常关闭 StdoutWriter
	if err := CloseOutput(); err != nil {
		t.Fatalf("CloseOutput with StdoutWriter error = %v", err)
	}
}

func TestSaveResultFacadeCallbackAndDisabledSave(t *testing.T) {
	preserveOutputAPIGlobals(t)

	cfg := NewConfig()
	cfg.Output.DisableSave = true
	SetGlobalConfig(cfg)

	flagVars = &FlagVars{DisableSave: true}
	if err := InitOutput(); err != nil {
		t.Fatalf("InitOutput disable save error = %v", err)
	}

	called := false
	SetResultCallback(func(payload interface{}) {
		called = true
		data, ok := payload.(map[string]interface{})
		if !ok {
			t.Fatalf("callback payload type = %T", payload)
		}
		if data["type"] != string(output.TypeVuln) || data["target"] != "http://example.com" {
			t.Fatalf("callback payload = %#v", data)
		}
	})

	if err := SaveResult(nil); err != nil {
		t.Fatalf("SaveResult nil error = %v", err)
	}
	if called {
		t.Fatal("nil result should not notify callback")
	}

	if err := SaveResult(&output.ScanResult{
		Type:    output.TypeVuln,
		Target:  "http://example.com",
		Status:  "vulnerable",
		Details: map[string]interface{}{"type": "poc"},
	}); err != nil {
		t.Fatalf("SaveResult disabled save error = %v", err)
	}
	if !called {
		t.Fatal("callback was not notified")
	}
	if err := CloseOutput(); err != nil {
		t.Fatalf("CloseOutput disabled save error = %v", err)
	}
}
