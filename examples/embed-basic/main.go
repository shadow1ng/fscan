package main

import (
	"context"
	"fmt"
	"time"

	fscan "github.com/shadow1ng/fscan/pkg/fscan"
)

func main() {
	config := fscan.Config{
		Timeout:      3 * time.Second,
		Threads:      64,
		DisablePing:  true,
		DisableBrute: true,
		Plugins:      []string{"ssh", "mysql", "redis"},
	}
	target := fscan.Target{
		Host:  "127.0.0.1",
		Ports: []int{22, 3306, 6379},
	}
	if err := fscan.ValidateConfig(config, target); err != nil {
		panic(err)
	}

	scanner := fscan.NewScanner(config)
	results, err := scanner.Scan(context.Background(), target)
	if err != nil {
		panic(err)
	}

	summary := fscan.SummarizeResults(results)
	fmt.Printf("scan finished: %+v\n", summary)
	for _, result := range results {
		if result.IsService() || result.IsVuln() {
			fmt.Printf("%s %s %s\n", result.Type, result.Target, result.Status)
		}
	}
}
