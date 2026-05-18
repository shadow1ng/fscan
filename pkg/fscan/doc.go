// Package fscan exposes fscan as an embeddable scanner library.
//
// The package is intentionally thin: it reuses the existing scan core and
// plugin registry, while hiding CLI flags, stdout output, and result files from
// callers. Embedded scans build per-session runtime state and can run
// concurrently.
//
// Embedded callers can use ValidateConfig before starting a scan, IsSafePlugin
// or ListPlugins to build plugin allow lists, and ResultType* constants instead
// of matching raw result type strings. Result exposes helpers for common detail
// fields such as port, service, plugin, credentials, and web metadata. Use
// SummarizeResults or ResultSummary for aggregate counts. Use ScanEach for
// streaming consumption when callers do not want to retain the full result set
// in memory.
package fscan
