package common

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/shadow1ng/fscan/common/config"
	"github.com/shadow1ng/fscan/common/parsers"
)

func TestBuildConfigLoadsPortsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ports.txt")
	if err := os.WriteFile(path, []byte("# ports\n22\n8000-8002\n443,22\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := BuildConfig(&FlagVars{Ports: config.MainPorts, PortsFile: path}, &HostInfo{Host: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := parsers.ParsePort(cfg.Target.Ports), []int{22, 443, 8000, 8001, 8002}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ports = %v, want %v", got, want)
	}
}

func TestBuildConfigRejectsUnusablePortsFile(t *testing.T) {
	for _, contents := range []string{"", "# no ports\n", "invalid\n0\n65536\n"} {
		path := filepath.Join(t.TempDir(), "ports.txt")
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := BuildConfig(&FlagVars{Ports: "22", PortsFile: path}, &HostInfo{}); err == nil {
			t.Errorf("accepted unusable port file %q", contents)
		}
	}
	if _, _, err := BuildConfig(&FlagVars{PortsFile: filepath.Join(t.TempDir(), "missing.txt")}, &HostInfo{}); err == nil {
		t.Error("accepted missing port file")
	}
}
