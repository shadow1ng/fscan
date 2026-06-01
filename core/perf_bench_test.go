package core

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

// =============================================================================
// Benchmark: containsFold vs strings.ToLower + strings.Contains
// =============================================================================

func BenchmarkContainsFold(b *testing.B) {
	err := errors.New("connection reset by peer: 192.168.1.1:445")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		containsFold(err.Error(), "connection reset")
	}
}

func BenchmarkStringsToLowerContains(b *testing.B) {
	err := errors.New("connection reset by peer: 192.168.1.1:445")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		strings.Contains(strings.ToLower(err.Error()), "connection reset")
	}
}

// =============================================================================
// Benchmark: fmt.Sprintf vs net.JoinHostPort + fmtPort
// =============================================================================

func BenchmarkFmtSprintfAddr(b *testing.B) {
	host := "192.168.1.1"
	port := 445
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = fmt.Sprintf("%s:%d", host, port)
	}
}

func BenchmarkJoinHostPortFmtPort(b *testing.B) {
	host := "192.168.1.1"
	port := 445
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = net.JoinHostPort(host, fmtPort(port))
	}
}

func BenchmarkFmtPort(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = fmtPort(445)
	}
}

// =============================================================================
// Benchmark: readFromConn buffer pre-allocation
// =============================================================================

func BenchmarkAppendFromNil(b *testing.B) {
	data := []byte("HTTP/1.1 200 OK\r\nServer: nginx")
	chunk := data[:10]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var result []byte
		result = append(result, chunk...)
		result = append(result, chunk...)
		_ = result
	}
}

func BenchmarkAppendPreAllocated(b *testing.B) {
	data := []byte("HTTP/1.1 200 OK\r\nServer: nginx")
	chunk := data[:10]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := make([]byte, 0, 4096)
		result = append(result, chunk...)
		result = append(result, chunk...)
		_ = result
	}
}

// =============================================================================
// Benchmark: AdaptiveTimeout computation under lock vs outside lock
// =============================================================================

func BenchmarkAdaptiveTimeoutComputation(b *testing.B) {
	at := NewAdaptiveTimeout(3000 * 1000000) // 3s in ns
	// Warm up: add 64 samples
	for i := 0; i < 64; i++ {
		at.Record(10 * 1000000) // 10ms in ns
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = at.Timeout()
	}
}
