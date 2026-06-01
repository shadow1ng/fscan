package main

import (
	"context"
	"fmt"
	"time"

	fscan "github.com/shadow1ng/fscan/pkg/fscan"
)

func main() {
	for _, plugin := range fscan.ListPlugins() {
		if plugin.Default {
			fmt.Printf("default plugin: %s ports=%v safe=%v\n", plugin.Name, plugin.Ports, plugin.Safe)
		}
	}

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

	var summary fscan.ResultSummary
	scanner := fscan.NewScanner(config)
	err := scanner.ScanEach(context.Background(), func(result fscan.Result) error {
		summary.Add(result)
		if service, ok := result.Service(); ok {
			fmt.Printf("service=%s target=%s\n", service, result.Target)
		}
		if result.IsCredential() {
			username, _ := result.Username()
			password, _ := result.Password()
			fmt.Printf("credential target=%s username=%s password=%s\n", result.Target, username, password)
		}
		return nil
	}, target)
	if err != nil {
		panic(err)
	}

	fmt.Printf("stream summary: %+v\n", summary)
}
