package fscan

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shadow1ng/fscan/common"
	commonconfig "github.com/shadow1ng/fscan/common/config"
	"github.com/shadow1ng/fscan/common/i18n"
)

func TestBuildFlagVarsDefaults(t *testing.T) {
	fv := buildFlagVars(Config{}, Target{Host: "127.0.0.1"})

	if fv.Host != "127.0.0.1" {
		t.Fatalf("Host = %q", fv.Host)
	}
	if fv.Ports != commonconfig.MainPorts {
		t.Fatalf("Ports = %q, want MainPorts", fv.Ports)
	}
	if fv.ScanMode != formatPlugins(Config{Plugins: DefaultSafePlugins()}) {
		t.Fatalf("ScanMode = %q, want safe defaults", fv.ScanMode)
	}
	if !fv.DisableSave || !fv.Silent || !fv.DisableProgress {
		t.Fatalf("embedded defaults should disable output side effects")
	}
}

func TestBuildFlagVarsBlankPluginsUseSafeDefaults(t *testing.T) {
	fv := buildFlagVars(Config{Plugins: []string{" ", "\t"}}, Target{Host: "127.0.0.1"})

	if fv.ScanMode != formatPlugins(Config{Plugins: DefaultSafePlugins()}) {
		t.Fatalf("ScanMode = %q, want safe defaults", fv.ScanMode)
	}
}

func TestBuildFlagVarsTargetPortsOverride(t *testing.T) {
	fv := buildFlagVars(Config{Ports: []int{22, 80}}, Target{Host: "127.0.0.1", Ports: []int{3306, 22}})

	if fv.Ports != "22,3306" {
		t.Fatalf("Ports = %q, want sorted target override", fv.Ports)
	}
}

func TestValidateConfig(t *testing.T) {
	if err := validateConfig(Config{}, nil); err == nil {
		t.Fatal("expected missing target error")
	}
	if err := validateConfig(Config{}, []Target{{Host: "127.0.0.1", URL: "http://127.0.0.1"}}); err == nil {
		t.Fatal("expected host/url conflict")
	}
	if err := validateConfig(Config{Plugins: []string{"definitely-missing"}}, []Target{{Host: "127.0.0.1"}}); err == nil {
		t.Fatal("expected missing plugin error")
	}
	if err := validateConfig(Config{Plugins: []string{"webpoc"}}, []Target{{URL: "http://127.0.0.1"}}); err == nil {
		t.Fatal("expected unsafe plugin error")
	}
	if err := validateConfig(Config{Plugins: []string{"webpoc"}, AllowUnsafePlugins: true}, []Target{{URL: "http://127.0.0.1"}}); err != nil {
		t.Fatalf("unsafe plugin with opt-in failed: %v", err)
	}
	if err := ValidateConfig(Config{Targets: []Target{{Host: "127.0.0.1"}}}); err != nil {
		t.Fatalf("ValidateConfig with config targets failed: %v", err)
	}
	if err := validateConfig(Config{}, []Target{{Host: "127.0.0.1", Ports: []int{70000}}}); err == nil {
		t.Fatal("expected invalid port error")
	}
}

func TestIsSafePlugin(t *testing.T) {
	if !IsSafePlugin("ssh") {
		t.Fatal("ssh should be safe")
	}
	if IsSafePlugin("webpoc") {
		t.Fatal("webpoc should not be safe")
	}
	if IsSafePlugin("ms17010") {
		t.Fatal("active poc plugins should not be safe")
	}
	if IsSafePlugin("definitely-missing") {
		t.Fatal("unknown plugin should not be safe")
	}
}

func TestListPlugins(t *testing.T) {
	items := ListPlugins()
	if len(items) == 0 {
		t.Fatal("expected registered plugins")
	}
	for i := 1; i < len(items); i++ {
		if items[i-1].Name > items[i].Name {
			t.Fatalf("plugins not sorted: %q before %q", items[i-1].Name, items[i].Name)
		}
	}
	ssh, ok := GetPlugin("ssh")
	if !ok {
		t.Fatal("missing ssh plugin")
	}
	if ssh.Name != "ssh" {
		t.Fatalf("plugin name = %q, want ssh", ssh.Name)
	}
	if !ssh.Safe || !ssh.Default {
		t.Fatalf("ssh safe/default = %v/%v, want true/true", ssh.Safe, ssh.Default)
	}
	if !containsString(ssh.Types, PluginTypeService) {
		t.Fatalf("ssh types = %#v, want service", ssh.Types)
	}
	if !containsString(ssh.Capabilities, PluginCapabilityDetect) || !containsString(ssh.Capabilities, PluginCapabilityAuthCheck) {
		t.Fatalf("ssh capabilities = %#v, want detect/auth-check", ssh.Capabilities)
	}
	if !containsInt(ssh.Ports, 22) {
		t.Fatalf("ssh ports = %#v, want 22", ssh.Ports)
	}
	if _, ok := GetPlugin("definitely-missing"); ok {
		t.Fatal("unknown plugin should not exist")
	}
	webpoc, ok := GetPlugin("webpoc")
	if !ok {
		t.Fatal("missing webpoc plugin")
	}
	if webpoc.Safe {
		t.Fatal("webpoc should be marked unsafe")
	}
	if !containsString(webpoc.Types, PluginTypeWeb) {
		t.Fatalf("webpoc types = %#v, want web", webpoc.Types)
	}
	if !containsString(webpoc.Capabilities, PluginCapabilityPOC) {
		t.Fatalf("webpoc capabilities = %#v, want poc", webpoc.Capabilities)
	}
}

func TestScanHonorsCanceledContext(t *testing.T) {
	scanner := NewScanner(Config{
		DisablePing:  true,
		DisableBrute: true,
		Timeout:      time.Second,
		Plugins:      []string{"redis"},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := scanner.Scan(ctx, Target{Host: "127.0.0.1", Ports: []int{6379}})
	if err != context.Canceled {
		t.Fatalf("Scan error = %v, want context.Canceled", err)
	}
}

func TestScanCollectsResultsThroughSessionSink(t *testing.T) {
	listener := startFTPListener(t)
	defer listener.Close()

	var callbackCalls int32
	common.SetResultCallback(func(interface{}) {
		atomic.AddInt32(&callbackCalls, 1)
	})
	defer common.ClearResultCallback()

	var streamed int32
	scanner := NewScanner(Config{
		DisablePing:  true,
		DisableBrute: true,
		Timeout:      time.Second,
		Threads:      16,
		Plugins:      []string{"ftp"},
		OnResult: func(result Result) {
			atomic.AddInt32(&streamed, 1)
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	port := listener.Addr().(*net.TCPAddr).Port
	results, err := scanner.Scan(ctx, Target{Host: "127.0.0.1", Ports: []int{port}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("expected SDK results")
	}
	if got := atomic.LoadInt32(&streamed); got != int32(len(results)) {
		t.Fatalf("streamed length = %d, want %d", got, len(results))
	}
	if !hasResult(results, ResultTypePort, "open", "") {
		t.Fatalf("missing port result: %#v", results)
	}
	if !hasResult(results, ResultTypeService, "FTP", "ftp") {
		t.Fatalf("missing ftp plugin result: %#v", results)
	}
	if got := atomic.LoadInt32(&callbackCalls); got != 0 {
		t.Fatalf("global callback calls = %d, want 0", got)
	}
}

func TestScanEachStreamsResults(t *testing.T) {
	listener := startFTPListener(t)
	defer listener.Close()

	scanner := NewScanner(Config{
		DisablePing:  true,
		DisableBrute: true,
		Timeout:      time.Second,
		Threads:      16,
		Plugins:      []string{"ftp"},
	})

	var results []Result
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	port := listener.Addr().(*net.TCPAddr).Port
	err := scanner.ScanEach(ctx, func(result Result) error {
		results = append(results, result)
		return nil
	}, Target{Host: "127.0.0.1", Ports: []int{port}})
	if err != nil {
		t.Fatal(err)
	}
	if !hasResult(results, ResultTypePort, "open", "") {
		t.Fatalf("missing port result: %#v", results)
	}
	if !hasResult(results, ResultTypeService, "FTP", "ftp") {
		t.Fatalf("missing ftp plugin result: %#v", results)
	}
}

func TestScanUsesConfigTargets(t *testing.T) {
	listener := startFTPListener(t)
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	scanner := NewScanner(Config{
		Targets:      []Target{{Host: "127.0.0.1", Ports: []int{port}}},
		DisablePing:  true,
		DisableBrute: true,
		Timeout:      time.Second,
		Threads:      16,
		Plugins:      []string{"ftp"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := scanner.Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPortResult(results, port) {
		t.Fatalf("missing configured target port result: %#v", results)
	}
}

func TestScanReportReturnsSummaryAndStats(t *testing.T) {
	listener := startFTPListener(t)
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	scanner := NewScanner(Config{
		DisablePing:  true,
		DisableBrute: true,
		Timeout:      time.Second,
		Threads:      16,
		Plugins:      []string{"ftp"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	report, err := scanner.ScanReport(ctx, Target{Host: "127.0.0.1", Ports: []int{port}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) == 0 || report.Summary.Total != len(report.Results) {
		t.Fatalf("report summary/results mismatch: %#v", report)
	}
	if report.Stats.Duration <= 0 {
		t.Fatalf("report duration = %s, want positive", report.Stats.Duration)
	}
	if report.Stats.TasksCompleted == 0 {
		t.Fatalf("report stats = %#v, want completed tasks", report.Stats)
	}
}

func TestScanExplicitTargetsOverrideConfigTargets(t *testing.T) {
	configured := startFTPListener(t)
	defer configured.Close()
	explicit := startFTPListener(t)
	defer explicit.Close()

	configuredPort := configured.Addr().(*net.TCPAddr).Port
	explicitPort := explicit.Addr().(*net.TCPAddr).Port
	scanner := NewScanner(Config{
		Targets:      []Target{{Host: "127.0.0.1", Ports: []int{configuredPort}}},
		DisablePing:  true,
		DisableBrute: true,
		Timeout:      time.Second,
		Threads:      16,
		Plugins:      []string{"ftp"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := scanner.Scan(ctx, Target{Host: "127.0.0.1", Ports: []int{explicitPort}})
	if err != nil {
		t.Fatal(err)
	}
	if !hasPortResult(results, explicitPort) {
		t.Fatalf("missing explicit target port result: %#v", results)
	}
	if hasPortResult(results, configuredPort) {
		t.Fatalf("configured target should not run when explicit targets are passed: %#v", results)
	}
}

func TestScanEachReturnsHandlerError(t *testing.T) {
	listener := startFTPListener(t)
	defer listener.Close()

	scanner := NewScanner(Config{
		DisablePing:  true,
		DisableBrute: true,
		Timeout:      time.Second,
		Threads:      16,
		Plugins:      []string{"ftp"},
	})

	stopErr := errors.New("stop scan")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	port := listener.Addr().(*net.TCPAddr).Port
	err := scanner.ScanEach(ctx, func(Result) error {
		return stopErr
	}, Target{Host: "127.0.0.1", Ports: []int{port}})
	if !errors.Is(err, stopErr) {
		t.Fatalf("ScanEach error = %v, want %v", err, stopErr)
	}
}

func TestScanEachRequiresHandler(t *testing.T) {
	scanner := NewScanner(Config{Targets: []Target{{Host: "127.0.0.1"}}})

	if err := scanner.ScanEach(context.Background(), nil); err == nil {
		t.Fatal("expected missing handler error")
	}
}

func TestScanEachRunsConcurrent(t *testing.T) {
	first := startFTPListener(t)
	defer first.Close()
	second := startFTPListener(t)
	defer second.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	blocked := make(chan struct{})
	release := make(chan struct{})
	firstErr := make(chan error, 1)
	var blockOnce sync.Once

	go func() {
		scanner := NewScanner(Config{
			DisablePing:  true,
			DisableBrute: true,
			Timeout:      time.Second,
			Threads:      16,
			Plugins:      []string{"ftp"},
		})
		port := first.Addr().(*net.TCPAddr).Port
		firstErr <- scanner.ScanEach(ctx, func(result Result) error {
			if result.IsPort() {
				blockOnce.Do(func() { close(blocked) })
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		}, Target{Host: "127.0.0.1", Ports: []int{port}})
	}()

	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("first scan did not reach handler")
	}

	secondErr := make(chan error, 1)
	var secondResults []Result
	go func() {
		scanner := NewScanner(Config{
			DisablePing:  true,
			DisableBrute: true,
			Timeout:      time.Second,
			Threads:      16,
			Plugins:      []string{"ftp"},
		})
		port := second.Addr().(*net.TCPAddr).Port
		secondErr <- scanner.ScanEach(ctx, func(result Result) error {
			secondResults = append(secondResults, result)
			return nil
		}, Target{Host: "127.0.0.1", Ports: []int{port}})
	}()

	select {
	case err := <-secondErr:
		if err != nil {
			close(release)
			t.Fatalf("second scan failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("second scan blocked behind first scan")
	}
	if !hasResult(secondResults, ResultTypePort, "open", "") {
		close(release)
		t.Fatalf("missing second scan result: %#v", secondResults)
	}

	close(release)
	if err := <-firstErr; err != nil {
		t.Fatalf("first scan failed: %v", err)
	}
}

func TestScanDoesNotReplaceGlobalRuntime(t *testing.T) {
	listener := startFTPListener(t)
	defer listener.Close()

	previousConfig := common.GetGlobalConfig()
	previousState := common.GetGlobalState()
	previousFlags := *common.GetFlagVars()
	previousLanguage := i18n.GetLanguage()
	defer func() {
		common.SetGlobalConfig(previousConfig)
		common.SetGlobalState(previousState)
		*common.GetFlagVars() = previousFlags
		i18n.SetLanguage(previousLanguage)
	}()

	sentinelConfig := common.NewConfig()
	sentinelState := common.NewState()
	common.SetGlobalConfig(sentinelConfig)
	common.SetGlobalState(sentinelState)
	common.GetFlagVars().LogLevel = "sentinel"
	i18n.SetLanguage(i18n.LangEN)

	scanner := NewScanner(Config{
		DisablePing:  true,
		DisableBrute: true,
		Timeout:      time.Second,
		Threads:      16,
		Plugins:      []string{"ftp"},
		Language:     i18n.LangZH,
	})
	port := listener.Addr().(*net.TCPAddr).Port
	if _, err := scanner.Scan(context.Background(), Target{Host: "127.0.0.1", Ports: []int{port}}); err != nil {
		t.Fatal(err)
	}

	if common.GetGlobalConfig() != sentinelConfig {
		t.Fatal("SDK scan replaced global config")
	}
	if common.GetGlobalState() != sentinelState {
		t.Fatal("SDK scan replaced global state")
	}
	if common.GetFlagVars().LogLevel != "sentinel" {
		t.Fatal("SDK scan replaced global flags")
	}
	if got := i18n.GetLanguage(); got != i18n.LangEN {
		t.Fatalf("SDK scan leaked global language = %q, want %q", got, i18n.LangEN)
	}
}

func TestScanWithoutLanguageDoesNotTouchGlobalLanguage(t *testing.T) {
	listener := startFTPListener(t)
	defer listener.Close()

	previousLanguage := i18n.GetLanguage()
	defer i18n.SetLanguage(previousLanguage)
	i18n.SetLanguage(i18n.LangEN)

	scanner := NewScanner(Config{
		DisablePing:  true,
		DisableBrute: true,
		Timeout:      time.Second,
		Threads:      16,
		Plugins:      []string{"ftp"},
	})
	port := listener.Addr().(*net.TCPAddr).Port
	if _, err := scanner.Scan(context.Background(), Target{Host: "127.0.0.1", Ports: []int{port}}); err != nil {
		t.Fatal(err)
	}

	if got := i18n.GetLanguage(); got != i18n.LangEN {
		t.Fatalf("SDK scan leaked global language = %q, want %q", got, i18n.LangEN)
	}
}

func startFTPListener(t *testing.T) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = conn.Write([]byte("220 test FTP\r\n"))
				buf := make([]byte, 64)
				_, _ = conn.Read(buf)
			}(conn)
		}
	}()
	return listener
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func containsInt(items []int, value int) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func hasResult(results []Result, resultType, statusText, plugin string) bool {
	for _, result := range results {
		if result.Type != resultType || !strings.Contains(result.Status, statusText) {
			continue
		}
		if plugin == "" {
			return true
		}
		if result.Details != nil && result.Details["plugin"] == plugin {
			return true
		}
	}
	return false
}

func hasPortResult(results []Result, port int) bool {
	for _, result := range results {
		if !result.IsPort() {
			continue
		}
		if got, ok := result.Port(); ok && got == port {
			return true
		}
	}
	return false
}
