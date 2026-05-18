# fscan SDK

`pkg/fscan` exposes fscan as an embeddable Go scanner while keeping the CLI unchanged.

```go
package main

import (
	"context"
	"fmt"
	"time"

	fscan "github.com/shadow1ng/fscan/pkg/fscan"
)

func main() {
	scanner := fscan.NewScanner(fscan.Config{
		Timeout:      3 * time.Second,
		Threads:      128,
		DisablePing:  true,
		DisableBrute: true,
		Plugins:      []string{"ssh", "mysql", "redis"},
	})

	results, err := scanner.Scan(context.Background(), fscan.Target{
		Host:  "192.168.1.10",
		Ports: []int{22, 3306, 6379},
	})
	if err != nil {
		panic(err)
	}

	for _, result := range results {
		fmt.Printf("%s %s %s\n", result.Type, result.Target, result.Status)
	}
}
```

The SDK currently reuses fscan's existing scan core and plugin registry. Calls are serialized internally because the current core still keeps process-wide runtime state.
