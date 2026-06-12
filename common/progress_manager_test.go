package common

import (
	"strings"
	"testing"
	"time"
)

func TestProgressTextHelpers(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{name: "ascii", in: "abc", want: 3},
		{name: "cjk", in: "中文", want: 4},
		{name: "mixed", in: "a中", want: 3},
		{name: "symbol", in: "★", want: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := displayWidth(tt.in); got != tt.want {
				t.Fatalf("displayWidth(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}

	truncateTests := []struct {
		name  string
		in    string
		width int
		want  string
	}{
		{name: "exact mixed width", in: "abc中文", width: 5, want: "abc中"},
		{name: "wide char does not fit", in: "中文", width: 1, want: ""},
		{name: "zero width", in: "abc", width: 0, want: ""},
		{name: "negative width", in: "abc", width: -1, want: ""},
	}
	for _, tt := range truncateTests {
		t.Run(tt.name, func(t *testing.T) {
			if got := truncateToWidth(tt.in, tt.width); got != tt.want {
				t.Fatalf("truncateToWidth(%q, %d) = %q, want %q", tt.in, tt.width, got, tt.want)
			}
		})
	}

	if got := stripAnsiCodes("\033[31mred\033[0m plain"); got != "red plain" {
		t.Fatalf("stripAnsiCodes removed ANSI = %q, want %q", got, "red plain")
	}
	if got := stripAnsiCodes("plain"); got != "plain" {
		t.Fatalf("stripAnsiCodes plain = %q, want plain", got)
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want string
	}{
		{name: "seconds", in: 1500 * time.Millisecond, want: "1.5s"},
		{name: "minutes", in: 90 * time.Second, want: "1.5m"},
		{name: "hours", in: 150 * time.Minute, want: "2.5h"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatDuration(tt.in); got != tt.want {
				t.Fatalf("formatDuration(%s) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestConcurrencyMonitorTaskStats(t *testing.T) {
	monitor := &ConcurrencyMonitor{}

	if status := monitor.GetConcurrencyStatus(); status != "" {
		t.Fatalf("initial status = %q, want empty", status)
	}

	monitor.StartPluginTask()
	monitor.StartPluginTask()

	active, total := monitor.GetPluginTaskStats()
	if active != 2 || total != 2 {
		t.Fatalf("stats after start = active %d total %d, want 2/2", active, total)
	}
	if status := monitor.GetConcurrencyStatus(); !strings.HasSuffix(status, ":2") {
		t.Fatalf("status after start = %q, want suffix :2", status)
	}

	monitor.FinishPluginTask()
	active, total = monitor.GetPluginTaskStats()
	if active != 1 || total != 2 {
		t.Fatalf("stats after one finish = active %d total %d, want 1/2", active, total)
	}

	monitor.FinishPluginTask()
	if status := monitor.GetConcurrencyStatus(); status != "" {
		t.Fatalf("status after all finish = %q, want empty", status)
	}
}
