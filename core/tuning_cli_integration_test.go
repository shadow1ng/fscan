package core

import (
	"flag"
	"os"
	"testing"
	"time"

	"github.com/shadow1ng/fscan/common"
)

func TestCLIExplicitDefaultTuningFlagsSurviveTuneConfig(t *testing.T) {
	oldArgs := os.Args
	oldFlagSet := flag.CommandLine
	oldFlagVars := *common.GetFlagVars()
	defer func() {
		os.Args = oldArgs
		flag.CommandLine = oldFlagSet
		*common.GetFlagVars() = oldFlagVars
	}()

	*common.GetFlagVars() = common.FlagVars{}
	flag.CommandLine = flag.NewFlagSet("fscan-test", flag.ContinueOnError)
	os.Args = []string{
		"fscan-test",
		"-silent",
		"-h", "127.0.0.1",
		"-time", "3",
		"-mt", "20",
		"-retry", "3",
		"-icmp-rate", "0.1",
		"-num", "20",
	}

	info := &common.HostInfo{}
	if err := common.Flag(info); err != nil {
		t.Fatalf("Flag error = %v", err)
	}

	cfg, _, err := common.BuildConfig(common.GetFlagVars(), info)
	if err != nil {
		t.Fatalf("BuildConfig error = %v", err)
	}
	if !cfg.TimeoutExplicit || !cfg.ModuleThreadNumExplicit ||
		!cfg.MaxRetriesExplicit || !cfg.Network.ICMPRateExplicit ||
		!cfg.POC.NumExplicit {
		t.Fatalf("explicit flags not propagated: timeout=%v mt=%v retry=%v icmp=%v num=%v",
			cfg.TimeoutExplicit,
			cfg.ModuleThreadNumExplicit,
			cfg.MaxRetriesExplicit,
			cfg.Network.ICMPRateExplicit,
			cfg.POC.NumExplicit)
	}

	ep := &EnvironmentProfile{
		Net: NetworkProfile{
			Env:       EnvLAN,
			RTTMedian: time.Millisecond,
			RTTStddev: 200 * time.Microsecond,
			LossRate:  0,
			Samples:   30,
		},
		System: SystemProfile{FDLimit: 65536, NumCPU: 8},
	}
	ep.TuneConfig(cfg, makeTestSession(cfg))

	if cfg.Timeout != 3*time.Second {
		t.Fatalf("Timeout = %v, want explicit default 3s", cfg.Timeout)
	}
	if cfg.ModuleThreadNum != 20 {
		t.Fatalf("ModuleThreadNum = %d, want explicit default 20", cfg.ModuleThreadNum)
	}
	if cfg.MaxRetries != 3 {
		t.Fatalf("MaxRetries = %d, want explicit default 3", cfg.MaxRetries)
	}
	if cfg.Network.ICMPRate != 0.1 {
		t.Fatalf("ICMPRate = %.2f, want explicit default 0.10", cfg.Network.ICMPRate)
	}
	if cfg.POC.Num != 20 {
		t.Fatalf("POC.Num = %d, want explicit default 20", cfg.POC.Num)
	}
}
