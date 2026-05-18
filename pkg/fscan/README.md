# fscan SDK

`pkg/fscan` exposes fscan as an embeddable Go scanner while keeping the CLI unchanged.

See `examples/embed-basic` for slice-based collection and `examples/embed-stream` for streaming integration.

```go
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
		Threads:      128,
		DisablePing:  true,
		DisableBrute: true,
		Plugins:      []string{"ssh", "mysql", "redis"},
		OnResult: func(result fscan.Result) {
			if result.Type == fscan.ResultTypeService || result.Type == fscan.ResultTypeVuln {
				fmt.Printf("%s %s %s\n", result.Type, result.Target, result.Status)
			}
		},
	}
	if err := fscan.ValidateConfig(config, fscan.Target{Host: "192.168.1.10"}); err != nil {
		panic(err)
	}

	scanner := fscan.NewScanner(config)
	err := scanner.ScanEach(context.Background(), func(result fscan.Result) error {
		// Store, forward, or filter the result in the embedding system.
		return nil
	}, fscan.Target{
		Host:  "192.168.1.10",
		Ports: []int{22, 3306, 6379},
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("scan finished")
}
```

The SDK currently reuses fscan's existing scan core and plugin registry. Calls are serialized internally because the current core still keeps process-wide runtime state.

By default, the SDK runs a conservative service-oriented plugin set and blocks plugins with local side effects or active POC behavior. Set `AllowUnsafePlugins` only when the embedding system explicitly wants those capabilities.

## API surface

| Area | API |
| --- | --- |
| Scanning | `NewScanner`, `Scan`, `ScanEach` |
| Configuration | `Config`, `Target`, `CredentialPair`, `ValidateConfig` |
| Plugins | `DefaultSafePlugins`, `ListPlugins`, `GetPlugin`, `IsSafePlugin`, `PluginInfo` |
| Results | `Result`, `ResultTypeHost`, `ResultTypePort`, `ResultTypeService`, `ResultTypeVuln` |
| Result helpers | `Port`, `Service`, `Plugin`, `Username`, `Password`, `Banner`, `Vulnerability`, `URL`, `Protocol`, `IsWeb`, `IsCredential` |
| Summary | `SummarizeResults`, `ResultSummary.Add` |

Use `Scan` when you want all results returned as a slice. Use `ScanEach` when results should be streamed into another system; handler calls are serialized, and returning an error stops the scan and returns that error.
