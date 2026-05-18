package fscan

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shadow1ng/fscan/common"
	commonconfig "github.com/shadow1ng/fscan/common/config"
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
	if err := validateConfig(Config{}, []Target{{Host: "127.0.0.1", Ports: []int{70000}}}); err == nil {
		t.Fatal("expected invalid port error")
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
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

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
	if !hasResult(results, "PORT", "open", "") {
		t.Fatalf("missing port result: %#v", results)
	}
	if !hasResult(results, "SERVICE", "FTP", "ftp") {
		t.Fatalf("missing ftp plugin result: %#v", results)
	}
	if got := atomic.LoadInt32(&callbackCalls); got != 0 {
		t.Fatalf("global callback calls = %d, want 0", got)
	}
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
