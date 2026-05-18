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
report, err := scanner.ScanReport(context.Background(), fscan.Target{
	Host:  "192.168.1.10",
	Ports: []int{22, 3306, 6379},
})
if err != nil {
	panic(err)
}

fmt.Printf("scan finished: %+v stats=%+v\n", report.Summary, report.Stats)
for _, result := range report.Results {
	// Store, forward, or filter the result in the embedding system.
	if credential, ok := result.AsCredential(); ok {
		fmt.Printf("weak credential: %s %s:%s\n", credential.Target, credential.Username, credential.Password)
	}
}
}
```

The SDK currently reuses fscan's existing scan core and plugin registry. Embedded scans build per-session runtime state and can run concurrently.

By default, the SDK runs a conservative service-oriented plugin set and blocks plugins with local side effects or active POC behavior. Set `AllowUnsafePlugins` only when the embedding system explicitly wants those capabilities.

## API surface

| Area | API |
| --- | --- |
| Scanning | `NewScanner`, `Scan`, `ScanEach`, `ScanReport` |
| Configuration | `Config`, `Target`, `CredentialPair`, `ValidateConfig` |
| Plugins | `DefaultSafePlugins`, `ListPlugins`, `GetPlugin`, `IsSafePlugin`, `PluginCapabilities`, `PluginInfo` |
| Results | `Result`, `ResultTypeHost`, `ResultTypePort`, `ResultTypeService`, `ResultTypeVuln` |
| Result helpers | `Port`, `Service`, `Plugin`, `Username`, `Password`, `Banner`, `Vulnerability`, `URL`, `Protocol`, `IsWeb`, `IsCredential`, `AsPort`, `AsService`, `AsCredential`, `AsVulnerability` |
| Summary and stats | `ScanReport`, `ScanStats`, `SummarizeResults`, `ResultSummary.Add` |

Use `Scan` when you want all results returned as a slice. Use `ScanReport` when the embedding system also needs summary counts and runtime counters. Use `ScanEach` when results should be streamed into another system; handler calls are serialized, and returning an error stops the scan and returns that error.

Plugin capabilities are exposed as stable strings: `detect`, `auth-check`, `brute`, `poc`, and `local-effect`. Default embedded safe mode blocks `poc` and `local-effect` plugins unless `AllowUnsafePlugins` is set.
