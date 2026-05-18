package main

import (
	"context"
	"fmt"
	"time"

	fscan "github.com/shadow1ng/fscan/pkg/fscan"
)

func main() {
	scanner := fscan.NewScanner(fscan.Config{
		TaskID:       "task-001",
		Timeout:      3 * time.Second,
		Threads:      64,
		DisablePing:  true,
		DisableBrute: true,
		Plugins:      []string{"ssh", "mysql", "redis", "ftp"},
		OnProgress: func(p fscan.ScanProgress) {
			fmt.Printf("[progress] %d/%d tasks, %d packets, paused=%v, elapsed=%s\n",
				p.TasksCompleted, p.TasksTotal, p.Packets, p.Paused, p.Duration.Round(time.Millisecond))
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ctrl, reportCh, errCh := scanner.ScanWithController(ctx,
		fscan.Target{Host: "127.0.0.1", Ports: []int{21, 22, 3306, 6379}},
	)

	// Simulate a pause command from control plane after 1 second.
	go func() {
		time.Sleep(1 * time.Second)
		fmt.Println("[agent] pausing scan...")
		ctrl.Pause()

		// Check live stats while paused.
		stats := ctrl.Stats()
		fmt.Printf("[agent] stats while paused: completed=%d, packets=%d\n",
			stats.TasksCompleted, stats.Packets)

		time.Sleep(2 * time.Second)
		fmt.Println("[agent] resuming scan...")
		ctrl.Resume()
	}()

	report := <-reportCh
	if err := <-errCh; err != nil {
		fmt.Printf("[agent] scan error: %v\n", err)
		return
	}

	fmt.Printf("\n[agent] scan complete: %d results, %d vulns, %d services\n",
		report.Summary.Total, report.Summary.Vulns, report.Summary.Services)

	for _, result := range report.Results {
		taskID, _ := result.DetailString("task_id")
		fmt.Printf("  [%s] %s %s (task=%s)\n", result.Type, result.Target, result.Status, taskID)
	}
}
