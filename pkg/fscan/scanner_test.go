package fscan

import (
	"context"
	"testing"
	"time"

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
	if fv.ScanMode != "all" {
		t.Fatalf("ScanMode = %q, want all", fv.ScanMode)
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
