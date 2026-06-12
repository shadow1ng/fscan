package core

import (
	"sync"
	"testing"
	"time"
)

// =============================================================================
// 单元测试：ScanMetrics 基本操作
// =============================================================================

func TestScanMetrics_Counters(t *testing.T) {
	m := &ScanMetrics{}

	m.RecordConnect(time.Millisecond)
	m.RecordConnect(2 * time.Millisecond)
	m.RecordRefused(500 * time.Microsecond)
	m.RecordTimeout()
	m.RecordExhausted()

	if m.Total() != 5 {
		t.Errorf("Total() = %d, want 5", m.Total())
	}

	snap := m.Snapshot()
	if snap.Connects != 2 {
		t.Errorf("Connects = %d, want 2", snap.Connects)
	}
	if snap.Refused != 1 {
		t.Errorf("Refused = %d, want 1", snap.Refused)
	}
	if snap.Timeouts != 1 {
		t.Errorf("Timeouts = %d, want 1", snap.Timeouts)
	}
	if snap.Exhausted != 1 {
		t.Errorf("Exhausted = %d, want 1", snap.Exhausted)
	}
}

// =============================================================================
// 单元测试：RTT EMA 收敛
// =============================================================================

func TestScanMetrics_RTT_EMA(t *testing.T) {
	m := &ScanMetrics{}

	// 喂入稳定的 10ms RTT
	for i := 0; i < 100; i++ {
		m.RecordConnect(10 * time.Millisecond)
	}

	fast := m.RTTFast()
	if fast < 9*time.Millisecond || fast > 11*time.Millisecond {
		t.Errorf("稳定 10ms 后 RTTFast = %v, 应该接近 10ms", fast)
	}

	ratio := m.RTTRatio()
	if ratio < 0.9 || ratio > 1.1 {
		t.Errorf("稳定状态 RTTRatio = %.2f, 应该接近 1.0", ratio)
	}
}

func TestScanMetrics_RTT_Trend(t *testing.T) {
	m := &ScanMetrics{}

	// 先喂入 100 个 5ms 建立基线
	for i := 0; i < 100; i++ {
		m.RecordConnect(5 * time.Millisecond)
	}

	// 再喂入 50 个 50ms（RTT 突增 10 倍）
	for i := 0; i < 50; i++ {
		m.RecordConnect(50 * time.Millisecond)
	}

	ratio := m.RTTRatio()
	// fast EMA 应该比 slow EMA 高（fast 跟踪快，slow 还没追上来）
	if ratio <= 1.0 {
		t.Errorf("RTT 突增后 RTTRatio = %.2f, 应该 > 1.0", ratio)
	}

	t.Logf("RTT 突增后: ratio=%.2f, fast=%v", ratio, m.RTTFast())
}

func TestScanMetrics_RTT_InsufficientSamples(t *testing.T) {
	m := &ScanMetrics{}

	// 少于 20 个样本
	for i := 0; i < 10; i++ {
		m.RecordConnect(time.Millisecond)
	}

	ratio := m.RTTRatio()
	if ratio != 1.0 {
		t.Errorf("样本不足时 RTTRatio = %.2f, 应该是 1.0", ratio)
	}
}

// =============================================================================
// 并发安全测试
// =============================================================================

func TestScanMetrics_ConcurrentSafety(t *testing.T) {
	m := &ScanMetrics{}
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(4)
		go func() { defer wg.Done(); m.RecordConnect(time.Millisecond) }()
		go func() { defer wg.Done(); m.RecordRefused(time.Millisecond) }()
		go func() { defer wg.Done(); m.RecordTimeout() }()
		go func() { defer wg.Done(); m.RecordExhausted() }()
	}

	wg.Wait()

	if m.Total() != 400 {
		t.Errorf("并发后 Total() = %d, want 400", m.Total())
	}

	// 验证 Snapshot 不 panic
	snap := m.Snapshot()
	if snap.Total() != 400 {
		t.Errorf("并发后 Snapshot.Total() = %d, want 400", snap.Total())
	}

	// 验证 RTTRatio 不 panic
	_ = m.RTTRatio()
}
