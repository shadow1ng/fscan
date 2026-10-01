package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

type targetRecorderPlugin struct {
	plugins.BasePlugin
	calls chan common.HostInfo
}

func (p *targetRecorderPlugin) Scan(_ context.Context, info *common.HostInfo, _ *common.ScanSession) *plugins.Result {
	p.calls <- *info
	return &plugins.Result{Skipped: true}
}

func registerTargetRecorder(t *testing.T, kind string, ports ...int) (string, chan common.HostInfo) {
	t.Helper()
	name := "scope_" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_"))
	calls := make(chan common.HostInfo, 16)
	plugins.RegisterWithTypes(name, func() plugins.Plugin {
		return &targetRecorderPlugin{BasePlugin: plugins.NewBasePlugin(name), calls: calls}
	}, ports, []string{kind})
	return name, calls
}

func TestServiceScanAcceptsExplicitHostPort(t *testing.T) {
	for _, target := range []string{"127.0.0.1:10001", "[::1]:10001"} {
		t.Run(target, func(t *testing.T) {
			name, calls := registerTargetRecorder(t, plugins.PluginTypeService, 10001)
			flags := &common.FlagVars{ScanMode: name, ThreadNum: 1, Silent: true}
			info := common.HostInfo{Host: target}
			cfg, state, err := common.BuildConfig(flags, &info)
			if err != nil {
				t.Fatal(err)
			}
			session := common.NewScanSession(cfg, state, flags)
			var wg sync.WaitGroup
			NewServiceScanStrategy().Execute(context.Background(), session, info, make(chan struct{}, 1), &wg)
			wg.Wait()
			if len(calls) != 1 {
				t.Fatalf("dispatched %d targets, want the explicit host:port", len(calls))
			}
			called := <-calls
			if got := called.Target(); got != target {
				t.Errorf("dispatched %q, want %q", got, target)
			}
		})
	}
}

func TestCachedTargetsRespectExclusions(t *testing.T) {
	name, calls := registerTargetRecorder(t, plugins.PluginTypeService, 10001, 10002, 10003)
	dir := t.TempDir()
	hostsFile := filepath.Join(dir, "hosts.txt")
	excludeFile := filepath.Join(dir, "exclude.txt")
	if err := os.WriteFile(hostsFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(excludeFile, []byte("192.0.2.2\n::1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	flags := &common.FlagVars{ScanMode: name, HostsFile: hostsFile, ExcludeHosts: "192.0.2.1,198.51.100.0/24", ExcludeHostsFile: excludeFile, ExcludePorts: "10002-10003", Silent: true}
	cfg := common.BuildConfigFromFlags(flags)
	state := common.NewState()
	state.SetHostPorts([]string{"127.0.0.1:10001", "127.0.0.1:10002", "127.0.0.1:10003", "192.0.2.1:10001", "192.0.2.2:10001", "198.51.100.20:10001", "[::1]:10001"})
	session := common.NewScanSession(cfg, state, flags)
	var wg sync.WaitGroup
	NewServiceScanStrategy().Execute(context.Background(), session, common.HostInfo{}, make(chan struct{}, 8), &wg)
	wg.Wait()
	if len(calls) != 1 {
		t.Fatalf("dispatched %d cached targets, want only the allowed target", len(calls))
	}
	called := <-calls
	if got := called.Target(); got != "127.0.0.1:10001" {
		t.Errorf("dispatched excluded target %q", got)
	}
}

func TestUDPDispatchRespectsExcludedPorts(t *testing.T) {
	name, calls := registerTargetRecorder(t, plugins.PluginTypeUDP, 10001, 10002)
	cfg := common.NewConfig()
	cfg.Mode = name
	cfg.Target.Ports = "10001,10002"
	cfg.Target.ExcludePorts = "10002"
	session := common.NewScanSession(cfg, common.NewState(), &common.FlagVars{})
	var wg sync.WaitGroup
	NewServiceScanStrategy().dispatchUDPPlugins(context.Background(), session, []string{"127.0.0.1"}, common.HostInfo{}, cfg, make(chan struct{}, 2), &wg)
	wg.Wait()
	if len(calls) != 1 {
		t.Fatalf("dispatched %d UDP targets, want 1", len(calls))
	}
	if got := (<-calls).Port; got != 10001 {
		t.Errorf("dispatched excluded UDP port %d", got)
	}
}

func TestServiceScanUsesSessionCache(t *testing.T) {
	name, calls := registerTargetRecorder(t, plugins.PluginTypeService, 10002)
	hostsFile := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(hostsFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	flags := &common.FlagVars{ScanMode: "all", HostsFile: hostsFile, Silent: true}
	cfg := common.BuildConfigFromFlags(flags)
	state := common.NewState()
	state.SetHostPorts([]string{"127.0.0.1:10003"})
	CacheServiceInfoWithState(state, "127.0.0.1", 10003, &ServiceInfo{Name: name})
	previous := globalState
	SetGlobalState(common.NewState())
	t.Cleanup(func() { SetGlobalState(previous) })
	session := common.NewScanSession(cfg, state, flags)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var wg sync.WaitGroup
	NewServiceScanStrategy().Execute(ctx, session, common.HostInfo{}, make(chan struct{}, 16), &wg)
	wg.Wait()
	if len(calls) != 1 {
		t.Fatalf("session service cache was ignored: dispatched %d matching plugins", len(calls))
	}
}
