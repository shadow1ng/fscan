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

func TestDefaultSafePluginsReturnsIndependentCopy(t *testing.T) {
	a := DefaultSafePlugins()
	b := DefaultSafePlugins()
	if len(a) == 0 {
		t.Fatal("empty default safe plugins")
	}
	a[0] = "MODIFIED"
	if b[0] == "MODIFIED" {
		t.Fatal("DefaultSafePlugins returned shared slice")
	}
}

func TestGetPluginWhitespaceAndEmpty(t *testing.T) {
	if _, ok := GetPlugin(""); ok {
		t.Fatal("empty name should not exist")
	}
	if _, ok := GetPlugin("   "); ok {
		t.Fatal("whitespace name should not exist")
	}
	if info, ok := GetPlugin(" ssh "); !ok || info.Name != "ssh" {
		t.Fatalf("trimmed lookup failed: %#v/%v", info, ok)
	}
}

func TestPluginCapabilitiesEmpty(t *testing.T) {
	if caps := PluginCapabilities(""); caps != nil {
		t.Fatalf("empty name caps = %#v, want nil", caps)
	}
	if caps := PluginCapabilities("definitely-missing"); caps != nil {
		t.Fatalf("missing plugin caps = %#v, want nil", caps)
	}
}

func TestIsSafePluginWhitespace(t *testing.T) {
	if IsSafePlugin("") {
		t.Fatal("empty should not be safe")
	}
	if IsSafePlugin("   ") {
		t.Fatal("whitespace should not be safe")
	}
	if !IsSafePlugin(" ssh ") {
		t.Fatal("trimmed ssh should be safe")
	}
}

func TestValidateConfigPortOnConfig(t *testing.T) {
	if err := validateConfig(Config{Ports: []int{0}}, []Target{{Host: "127.0.0.1"}}); err == nil {
		t.Fatal("expected invalid config port error for port 0")
	}
	if err := validateConfig(Config{Ports: []int{99999}}, []Target{{Host: "127.0.0.1"}}); err == nil {
		t.Fatal("expected invalid config port error for port 99999")
	}
}

func TestValidateConfigEmptyTarget(t *testing.T) {
	if err := validateConfig(Config{}, []Target{{}}); err == nil {
		t.Fatal("expected empty target error")
	}
}

func TestBuildFlagVarsCustomValues(t *testing.T) {
	config := Config{
		Timeout:         10 * time.Second,
		WebTimeout:      15 * time.Second,
		Threads:         100,
		ModuleThreads:   50,
		MaxRetries:      5,
		MaxRedirects:    3,
		POCConcurrency:  10,
		ICMPRate:        0.5,
		DisablePing:     true,
		DisableTCPProbe: true,
		DisableBrute:    true,
		Domain:          "WORKGROUP",
		SSHKeyPath:      "/tmp/id_rsa",
		HTTPProxy:       "http://proxy:8080",
		Socks5Proxy:     "127.0.0.1:1080",
		Interface:       "eth0",
		POCPath:         "/tmp/pocs",
		POCName:         "test-poc",
		POCFull:         true,
		DisablePOCScan:  true,
		Language:        "zh",
		Usernames:       []string{"admin", "root"},
		Passwords:       []string{"pass1", "pass2"},
	}
	fv := buildFlagVars(config, Target{Host: "10.0.0.1"})

	if fv.TimeoutSec != 10 {
		t.Fatalf("TimeoutSec = %d, want 10", fv.TimeoutSec)
	}
	if fv.WebTimeout != 15 {
		t.Fatalf("WebTimeout = %d, want 15", fv.WebTimeout)
	}
	if fv.ThreadNum != 100 {
		t.Fatalf("ThreadNum = %d, want 100", fv.ThreadNum)
	}
	if fv.ModuleThreadNum != 50 {
		t.Fatalf("ModuleThreadNum = %d, want 50", fv.ModuleThreadNum)
	}
	if fv.MaxRetries != 5 {
		t.Fatalf("MaxRetries = %d, want 5", fv.MaxRetries)
	}
	if fv.MaxRedirects != 3 {
		t.Fatalf("MaxRedirects = %d, want 3", fv.MaxRedirects)
	}
	if fv.PocNum != 10 {
		t.Fatalf("PocNum = %d, want 10", fv.PocNum)
	}
	if fv.ICMPRate != 0.5 {
		t.Fatalf("ICMPRate = %f, want 0.5", fv.ICMPRate)
	}
	if !fv.DisablePing {
		t.Fatal("DisablePing should be true")
	}
	if !fv.DisableTcpProbe {
		t.Fatal("DisableTcpProbe should be true")
	}
	if !fv.DisableBrute {
		t.Fatal("DisableBrute should be true")
	}
	if fv.Domain != "WORKGROUP" {
		t.Fatalf("Domain = %q", fv.Domain)
	}
	if fv.SSHKeyPath != "/tmp/id_rsa" {
		t.Fatalf("SSHKeyPath = %q", fv.SSHKeyPath)
	}
	if fv.HTTPProxy != "http://proxy:8080" {
		t.Fatalf("HTTPProxy = %q", fv.HTTPProxy)
	}
	if fv.Socks5Proxy != "127.0.0.1:1080" {
		t.Fatalf("Socks5Proxy = %q", fv.Socks5Proxy)
	}
	if fv.Iface != "eth0" {
		t.Fatalf("Iface = %q", fv.Iface)
	}
	if fv.PocPath != "/tmp/pocs" {
		t.Fatalf("PocPath = %q", fv.PocPath)
	}
	if fv.PocName != "test-poc" {
		t.Fatalf("PocName = %q", fv.PocName)
	}
	if !fv.PocFull {
		t.Fatal("PocFull should be true")
	}
	if !fv.DisablePocScan {
		t.Fatal("DisablePocScan should be true")
	}
	if fv.Language != "zh" {
		t.Fatalf("Language = %q", fv.Language)
	}
	if fv.Username != "admin,root" {
		t.Fatalf("Username = %q", fv.Username)
	}
	if fv.Password != "pass1,pass2" {
		t.Fatalf("Password = %q", fv.Password)
	}
}

func TestBuildFlagVarsURLTarget(t *testing.T) {
	fv := buildFlagVars(Config{}, Target{URL: "https://example.com"})
	if fv.TargetURL != "https://example.com" {
		t.Fatalf("TargetURL = %q", fv.TargetURL)
	}
	if fv.Host != "" {
		t.Fatalf("Host should be empty for URL target, got %q", fv.Host)
	}
}

func TestFormatPortsEmpty(t *testing.T) {
	result := formatPorts(nil)
	if result != commonconfig.MainPorts {
		t.Fatalf("formatPorts(nil) = %q, want MainPorts", result)
	}
}

func TestFormatPortsSorted(t *testing.T) {
	result := formatPorts([]int{443, 22, 80})
	if result != "22,80,443" {
		t.Fatalf("formatPorts = %q, want sorted", result)
	}
}

func TestFormatPluginsAllowUnsafe(t *testing.T) {
	result := formatPlugins(Config{AllowUnsafePlugins: true})
	if result != "all" {
		t.Fatalf("formatPlugins(unsafe) = %q, want all", result)
	}
}

func TestFormatPluginsExplicit(t *testing.T) {
	result := formatPlugins(Config{Plugins: []string{"ssh", "ftp"}})
	if result != "ssh,ftp" {
		t.Fatalf("formatPlugins = %q, want ssh,ftp", result)
	}
}

func TestNormalizePluginsTrimsWhitespace(t *testing.T) {
	result := normalizePlugins([]string{" ssh ", "", " ftp "})
	if len(result) != 2 || result[0] != "ssh" || result[1] != "ftp" {
		t.Fatalf("normalizePlugins = %#v", result)
	}
}

func TestSecondsOrDefault(t *testing.T) {
	if got := secondsOrDefault(0, 3); got != 3 {
		t.Fatalf("secondsOrDefault(0, 3) = %d, want 3", got)
	}
	if got := secondsOrDefault(-1*time.Second, 5); got != 5 {
		t.Fatalf("secondsOrDefault(-1s, 5) = %d, want 5", got)
	}
	if got := secondsOrDefault(10*time.Second, 3); got != 10 {
		t.Fatalf("secondsOrDefault(10s, 3) = %d, want 10", got)
	}
	if got := secondsOrDefault(500*time.Millisecond, 3); got != 1 {
		t.Fatalf("secondsOrDefault(500ms, 3) = %d, want 1", got)
	}
}

func TestSNMPPluginRegistration(t *testing.T) {
	info, ok := GetPlugin("snmp")
	if !ok {
		t.Fatal("snmp plugin not registered")
	}
	if !info.Safe {
		t.Fatal("snmp should be safe")
	}
	if !info.Default {
		t.Fatal("snmp should be in default safe plugins")
	}
	if !containsString(info.Types, PluginTypeUDP) {
		t.Fatalf("snmp types = %#v, want udp", info.Types)
	}
	if containsString(info.Types, PluginTypeService) {
		t.Fatal("snmp should not be service type")
	}
	if !containsInt(info.Ports, 161) {
		t.Fatalf("snmp ports = %#v, want 161", info.Ports)
	}
	if !containsString(info.Capabilities, PluginCapabilityDetect) {
		t.Fatalf("snmp capabilities = %#v, want detect", info.Capabilities)
	}
}

func TestScanStatsAdd(t *testing.T) {
	var s ScanStats
	s.add(ScanStats{
		Duration:       2 * time.Second,
		TasksTotal:     10,
		TasksCompleted: 8,
		Packets:        100,
		TCPPackets:     80,
		UDPPackets:     20,
		HTTPPackets:    5,
	})
	s.add(ScanStats{
		Duration:       3 * time.Second,
		TasksTotal:     5,
		TasksCompleted: 5,
		Packets:        50,
		TCPPackets:     40,
		UDPPackets:     10,
	})
	if s.Duration != 5*time.Second {
		t.Fatalf("Duration = %s, want 5s", s.Duration)
	}
	if s.TasksTotal != 15 || s.TasksCompleted != 13 {
		t.Fatalf("Tasks = %d/%d, want 15/13", s.TasksTotal, s.TasksCompleted)
	}
	if s.Packets != 150 || s.TCPPackets != 120 || s.UDPPackets != 30 {
		t.Fatalf("Packets = %d/%d/%d", s.Packets, s.TCPPackets, s.UDPPackets)
	}
	if s.HTTPPackets != 5 {
		t.Fatalf("HTTPPackets = %d, want 5", s.HTTPPackets)
	}
}
