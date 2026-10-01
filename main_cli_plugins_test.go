//go:build !web && !plugin_selective

package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/config"
	"github.com/shadow1ng/fscan/plugins"
)

func TestCLIPluginDefaultPorts(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "netbios", args: []string{"-m", "netbios"}, want: "137,139"},
		{name: "multiple plugins", args: []string{"-m", "ssh, netbios,ssh,"}, want: "22,137,139,2200,2222,22222"},
		{name: "nonstandard port", args: []string{"-m", "ssh", "-p", "2222"}, want: "2222"},
		{name: "explicit common ports", args: []string{"-m", "netbios", "-p", config.MainPorts}, want: config.MainPorts},
		{name: "ports file", args: []string{"-m", "netbios", "-pf", "ports.txt"}, want: config.MainPorts},
		{name: "all", args: []string{"-m", "all"}, want: config.MainPorts},
		{name: "web plugin", args: []string{"-m", "webtitle"}, want: config.MainPorts},
		{name: "web and service", args: []string{"-m", "ssh,webtitle"}, want: config.MainPorts},
		{name: "unknown plugin", args: []string{"-m", "ssh,unknown-plugin"}, want: config.MainPorts},
		{name: "alive only", args: []string{"-m", "netbios", "-ao"}, want: config.MainPorts},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setCLIArgs(t, append([]string{"-h", "127.0.0.1", "-silent"}, tt.args...)...)
			info := &common.HostInfo{}
			if err := common.Flag(info); err != nil {
				t.Fatal(err)
			}
			setPluginDefaultPorts(common.GetFlagVars())
			cfg, _, err := common.BuildConfig(common.GetFlagVars(), info)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Target.Ports != tt.want {
				t.Errorf("ports = %q, want %q", cfg.Target.Ports, tt.want)
			}
		})
	}
}

func TestPrintPluginList(t *testing.T) {
	var output bytes.Buffer
	if err := printPluginList(&output); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	names := plugins.All()
	slices.Sort(names)
	if len(lines) != len(names)+1 {
		t.Fatalf("got %d rows for %d plugins", len(lines)-1, len(names))
	}
	for i, name := range names {
		fields := strings.Fields(lines[i+1])
		if len(fields) != 5 {
			t.Fatalf("invalid plugin row: %q", lines[i+1])
		}
		if fields[0] != name || fields[len(fields)-1] != name {
			t.Errorf("plugin row = %q, want %s", lines[i+1], name)
		}
		if name == "netbios" && strings.Join(fields, " ") != "netbios service 137,139 -m netbios" {
			t.Errorf("netbios metadata = %q", lines[i+1])
		}
		if plugins.HasType(name, plugins.PluginTypeLocal) && fields[len(fields)-2] != "-local" {
			t.Errorf("local plugin usage = %q", lines[i+1])
		}
	}
}

func TestCLIListPluginsExitsWithoutTargetOrOutput(t *testing.T) {
	dir := t.TempDir()
	outputFile := filepath.Join(dir, "result.txt")
	setCLIArgs(t, "-list-plugins", "-silent", "-o", outputFile)
	output, err := os.CreateTemp(dir, "stdout-")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	previousStdout := os.Stdout
	os.Stdout = output
	t.Cleanup(func() { os.Stdout = previousStdout })
	if code := run(); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if _, err := os.Stat(outputFile); !os.IsNotExist(err) {
		t.Fatalf("listing initialized scan output: %v", err)
	}
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "netbios") || !strings.Contains(string(data), "137,139") {
		t.Fatalf("plugin list missing from output: %s", data)
	}
}

func setCLIArgs(t *testing.T, args ...string) {
	t.Helper()
	previousArgs := os.Args
	previousFlagSet := flag.CommandLine
	previousFlags := *common.GetFlagVars()
	t.Cleanup(func() {
		os.Args = previousArgs
		flag.CommandLine = previousFlagSet
		*common.GetFlagVars() = previousFlags
	})
	os.Args = append([]string{"fscan-test"}, args...)
	flag.CommandLine = flag.NewFlagSet("fscan-test", flag.ContinueOnError)
	*common.GetFlagVars() = common.FlagVars{}
}
