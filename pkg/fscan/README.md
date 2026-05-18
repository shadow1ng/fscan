# fscan SDK

`pkg/fscan` exposes fscan as an embeddable Go scanner, designed for Agent and security platform integration.

## Quick Start

```go
import fscan "github.com/shadow1ng/fscan/pkg/fscan"

scanner := fscan.NewScanner(fscan.Config{
    Timeout:      3 * time.Second,
    Threads:      128,
    DisablePing:  true,
    Plugins:      []string{"ssh", "mysql", "redis"},
})

results, err := scanner.Scan(context.Background(), fscan.Target{
    Host:  "192.168.1.0/24",
    Ports: []int{22, 3306, 6379},
})
```

## Scan Modes

| Mode | API | Use Case |
|------|-----|----------|
| Collect | `Scan` / `ScanReport` | Get all results as a slice |
| Stream | `ScanEach` | Process results one-by-one, no memory accumulation |
| Controlled | `ScanWithController` | Agent integration with pause/resume and live stats |

### Basic: Collect All Results

```go
scanner := fscan.NewScanner(config)
report, err := scanner.ScanReport(ctx, target)

fmt.Printf("total=%d vulns=%d\n", report.Summary.Total, report.Summary.Vulns)
for _, r := range report.Results {
    if cred, ok := r.AsCredential(); ok {
        fmt.Printf("%s %s:%s\n", cred.Target, cred.Username, cred.Password)
    }
}
```

### Stream: Process Results Without Retention

```go
scanner := fscan.NewScanner(config)
err := scanner.ScanEach(ctx, func(result fscan.Result) error {
    // Forward to database, message queue, etc.
    return sendToBackend(result)
}, target)
```

### Controlled: Agent Integration

```go
scanner := fscan.NewScanner(fscan.Config{
    TaskID:       "task-001",
    Plugins:      []string{"ssh", "redis"},
    OnProgress: func(p fscan.ScanProgress) {
        reportHeartbeat(p.TasksCompleted, p.TasksTotal, p.Paused)
    },
})

ctrl, reportCh, errCh := scanner.ScanWithController(ctx, target)

// Control plane commands
ctrl.Pause()
stats := ctrl.Stats()  // live stats while paused
ctrl.Resume()

report := <-reportCh
err := <-errCh
```

## Agent Features

### ScanController

`ScanWithController` returns a `*ScanController` for runtime control:

| Method | Description |
|--------|-------------|
| `Pause()` | Pause task dispatch (in-flight tasks complete naturally) |
| `Resume()` | Resume task dispatch |
| `IsPaused()` | Check pause state |
| `Stats()` | Live `ScanStats` aggregated across all targets |

The controller is goroutine-safe. Pause takes effect at the task dispatch level -- already-running plugin tasks will finish, but no new tasks are dispatched until resumed.

### OnProgress

Set `Config.OnProgress` to receive periodic `ScanProgress` snapshots (~500ms interval):

```go
type ScanProgress struct {
    TasksTotal     int64
    TasksCompleted int64
    Duration       time.Duration
    Packets        int64
    TCPPackets     int64
    HTTPPackets    int64
    Paused         bool
}
```

Works with all scan modes. When used without `ScanWithController`, a lightweight internal controller is created for progress tracking.

### TaskID

Set `Config.TaskID` to inject a task identifier into every `Result.Details["task_id"]`. This lets the Agent associate scan results with control plane tasks without post-processing.

## Plugin Safety

By default, the SDK runs a conservative plugin set (service detection + auth check). Plugins with local side effects (`poc`, `local-effect`) are blocked unless `AllowUnsafePlugins` is set.

```go
// List available plugins
for _, p := range fscan.ListPlugins() {
    fmt.Printf("%s safe=%v caps=%v\n", p.Name, p.Safe, p.Capabilities)
}

// Check before use
if fscan.IsSafePlugin("webpoc") { ... }
```

Plugin capabilities: `detect`, `auth-check`, `brute`, `poc`, `local-effect`.

## API Reference

| Area | API |
|------|-----|
| Scanning | `NewScanner`, `Scan`, `ScanEach`, `ScanReport`, `ScanWithController` |
| Control | `ScanController` (`Pause`, `Resume`, `IsPaused`, `Stats`) |
| Configuration | `Config`, `Target`, `CredentialPair`, `ValidateConfig` |
| Progress | `OnProgress`, `ScanProgress`, `TaskID` |
| Plugins | `DefaultSafePlugins`, `ListPlugins`, `GetPlugin`, `IsSafePlugin`, `PluginCapabilities` |
| Results | `Result`, `ResultType*` constants |
| Result helpers | `Port`, `Service`, `Plugin`, `Username`, `Password`, `Banner`, `Vulnerability`, `URL`, `Protocol`, `IsWeb`, `IsCredential` |
| Typed views | `AsPort`, `AsService`, `AsCredential`, `AsVulnerability` |
| Summary | `ScanReport`, `ScanStats`, `SummarizeResults`, `ResultSummary.Add` |

## Examples

- [`examples/embed-basic`](../../examples/embed-basic) -- Minimal scan with result collection
- [`examples/embed-stream`](../../examples/embed-stream) -- Streaming results with plugin listing
- [`examples/embed-agent`](../../examples/embed-agent) -- Agent integration with pause/resume, progress, and TaskID
