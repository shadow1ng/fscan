// Package fscan exposes fscan as an embeddable scanner library.
//
// The package is intentionally thin: it reuses the existing scan core and
// plugin registry, while hiding CLI flags, stdout output, and result files from
// callers. The first SDK surface is serialized internally because the current
// scan core still uses process-wide runtime state.
package fscan
