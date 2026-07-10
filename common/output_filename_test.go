package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveDefaultOutputFile(t *testing.T) {
	tests := []struct {
		name string
		fv   *FlagVars
		info *HostInfo
		want string
	}{
		{
			name: "cidr target",
			fv:   &FlagVars{OutputFormat: "txt"},
			info: &HostInfo{Host: "192.1.1.1/24"},
			want: "192.1.1.1_24.txt",
		},
		{
			name: "first of multiple targets",
			fv:   &FlagVars{OutputFormat: "json"},
			info: &HostInfo{Host: "10.0.0.1,10.0.0.2"},
			want: "10.0.0.1.json",
		},
		{
			name: "url uses authority",
			fv:   &FlagVars{TargetURL: "https://example.com:8443/path", OutputFormat: "csv"},
			info: &HostInfo{},
			want: "example.com_8443.csv",
		},
		{
			name: "explicit output is preserved",
			fv:   &FlagVars{Outputfile: filepath.Join("reports", "custom.log"), OutputFileExplicit: true, OutputFormat: "json"},
			info: &HostInfo{Host: "192.0.2.1"},
			want: filepath.Join("reports", "custom.log"),
		},
		{
			name: "no target fallback",
			fv:   &FlagVars{OutputFormat: "json"},
			info: &HostInfo{},
			want: "result.json",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolveDefaultOutputFile(test.fv, test.info)
			if test.fv.Outputfile != test.want {
				t.Fatalf("Outputfile = %q, want %q", test.fv.Outputfile, test.want)
			}
		})
	}
}

func TestResolveDefaultOutputFileUsesFirstFileTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("\n192.0.2.10\n192.0.2.11\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fv := &FlagVars{HostsFile: path, OutputFormat: "txt"}
	resolveDefaultOutputFile(fv, &HostInfo{})
	if fv.Outputfile != "192.0.2.10.txt" {
		t.Fatalf("Outputfile = %q", fv.Outputfile)
	}
}

func TestSanitizeOutputTarget(t *testing.T) {
	if got := sanitizeOutputTarget(`..\CON`); got != "_CON" {
		t.Fatalf("reserved target = %q", got)
	}
	if got := sanitizeOutputTarget("2001:db8::1"); got != "2001_db8_1" {
		t.Fatalf("IPv6 target = %q", got)
	}
	long := strings.Repeat("a", maxAutoOutputNameRunes+20)
	if got := sanitizeOutputTarget(long); len([]rune(got)) != maxAutoOutputNameRunes {
		t.Fatalf("long target length = %d", len([]rune(got)))
	}
}

func TestBuildConfigAppliesAutomaticOutputFile(t *testing.T) {
	fv := &FlagVars{OutputFormat: "json"}
	info := &HostInfo{Host: "203.0.113.0/24"}
	cfg, _, err := BuildConfig(fv, info)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if cfg.Output.File != "203.0.113.0_24.json" {
		t.Fatalf("Config output file = %q", cfg.Output.File)
	}
	if fv.Outputfile != cfg.Output.File {
		t.Fatalf("flag/config output mismatch: %q != %q", fv.Outputfile, cfg.Output.File)
	}
}
