//go:build debug
// +build debug

package debug

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"

	"github.com/shadow1ng/fscan/common/i18n"
)

var (
	cpuProfile   *os.File
	traceFile    *os.File
	profilesPath = "./profiles"
)

func Start() {
	if err := os.MkdirAll(profilesPath, 0755); err != nil {
		fmt.Printf("[DEBUG] %s\n", i18n.Tr("debug_create_profiles_failed", err))
		return
	}

	var err error
	cpuProfile, err = os.Create(profilesPath + "/cpu.prof")
	if err != nil {
		fmt.Printf("[DEBUG] %s\n", i18n.Tr("debug_create_cpu_profile_failed", err))
	} else {
		if err := pprof.StartCPUProfile(cpuProfile); err != nil {
			fmt.Printf("[DEBUG] %s\n", i18n.Tr("debug_start_cpu_profile_failed", err))
			cpuProfile.Close()
			cpuProfile = nil
		} else {
			fmt.Printf("[DEBUG] %s\n", i18n.Tr("debug_cpu_profile_started", profilesPath))
		}
	}

	traceFile, err = os.Create(profilesPath + "/trace.out")
	if err != nil {
		fmt.Printf("[DEBUG] %s\n", i18n.Tr("debug_create_trace_failed", err))
	} else {
		if err := trace.Start(traceFile); err != nil {
			fmt.Printf("[DEBUG] %s\n", i18n.Tr("debug_start_trace_failed", err))
			traceFile.Close()
			traceFile = nil
		} else {
			fmt.Printf("[DEBUG] %s\n", i18n.Tr("debug_trace_started", profilesPath))
		}
	}

	fmt.Printf("[DEBUG] %s\n", i18n.Tr("debug_profiling_started", profilesPath))
}

func Stop() {
	if cpuProfile != nil {
		pprof.StopCPUProfile()
		cpuProfile.Close()
		fmt.Printf("[DEBUG] %s\n", i18n.GetText("debug_cpu_profile_saved"))
	}

	if traceFile != nil {
		trace.Stop()
		traceFile.Close()
		fmt.Printf("[DEBUG] %s\n", i18n.GetText("debug_trace_saved"))
	}

	memProfile, err := os.Create(profilesPath + "/mem.prof")
	if err != nil {
		fmt.Printf("[DEBUG] %s\n", i18n.Tr("debug_create_mem_profile_failed", err))
	} else {
		runtime.GC()
		if err := pprof.WriteHeapProfile(memProfile); err != nil {
			fmt.Printf("[DEBUG] %s\n", i18n.Tr("debug_write_mem_profile_failed", err))
		} else {
			fmt.Printf("[DEBUG] %s\n", i18n.Tr("debug_mem_profile_saved", profilesPath))
		}
		memProfile.Close()
	}

	goroutineProfile, err := os.Create(profilesPath + "/goroutine.prof")
	if err != nil {
		fmt.Printf("[DEBUG] %s\n", i18n.Tr("debug_create_goroutine_profile_failed", err))
	} else {
		if err := pprof.Lookup("goroutine").WriteTo(goroutineProfile, 0); err != nil {
			fmt.Printf("[DEBUG] %s\n", i18n.Tr("debug_write_goroutine_profile_failed", err))
		} else {
			fmt.Printf("[DEBUG] %s\n", i18n.Tr("debug_goroutine_profile_saved", profilesPath))
		}
		goroutineProfile.Close()
	}

	fmt.Printf("\n[DEBUG] %s\n", i18n.Tr("debug_profiles_saved", profilesPath))
	fmt.Printf("[DEBUG] %s\n", i18n.GetText("debug_view_methods"))
	fmt.Printf("  %s:      go tool pprof -http=:8081 %s/cpu.prof\n", i18n.GetText("debug_cpu_flamegraph"), profilesPath)
	fmt.Printf("  %s:      go tool pprof -http=:8081 %s/mem.prof\n", i18n.GetText("debug_mem_flamegraph"), profilesPath)
	fmt.Printf("  %s:        go tool pprof -http=:8081 %s/goroutine.prof\n", i18n.GetText("debug_goroutine_analysis"), profilesPath)
	fmt.Printf("  %s:      go tool trace %s/trace.out\n", i18n.GetText("debug_execution_timeline"), profilesPath)
}
