package core

import (
	"sync"
	"sync/atomic"
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

// =============================================================================
// 补充测试：按题目要求的函数名
// =============================================================================

// TestScanMetricsTotal — 各计数器各调一次，Total() 应返回 4
func TestScanMetricsTotal(t *testing.T) {
	m := &ScanMetrics{}
	m.RecordConnect(time.Millisecond)
	m.RecordRefused(time.Millisecond)
	m.RecordTimeout()
	m.RecordExhausted()
	if got := m.Total(); got != 4 {
		t.Errorf("Total() = %d, want 4", got)
	}
}

// TestScanMetricsSnapshot — 记录数据后 Snapshot() 返回正确快照
func TestScanMetricsSnapshot(t *testing.T) {
	m := &ScanMetrics{}
	m.RecordConnect(5 * time.Millisecond)
	m.RecordConnect(10 * time.Millisecond)
	m.RecordRefused(2 * time.Millisecond)
	m.RecordTimeout()
	m.RecordExhausted()

	snap := m.Snapshot()
	tests := []struct {
		name string
		got  int64
		want int64
	}{
		{"Connects", snap.Connects, 2},
		{"Refused", snap.Refused, 1},
		{"Timeouts", snap.Timeouts, 1},
		{"Exhausted", snap.Exhausted, 1},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("Snapshot.%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
	if snap.RTTFastNs <= 0 {
		t.Errorf("Snapshot.RTTFastNs = %d, want > 0", snap.RTTFastNs)
	}
}

// TestScanMetricsRTTRatio — 样本不足返回 1.0；20+ 个相同 RTT 接近 1.0
func TestScanMetricsRTTRatio(t *testing.T) {
	t.Run("样本不足返回1.0", func(t *testing.T) {
		m := &ScanMetrics{}
		for i := 0; i < 19; i++ {
			m.RecordConnect(time.Millisecond)
		}
		if r := m.RTTRatio(); r != 1.0 {
			t.Errorf("样本不足 RTTRatio() = %f, want 1.0", r)
		}
	})

	t.Run("稳定RTT接近1.0", func(t *testing.T) {
		m := &ScanMetrics{}
		for i := 0; i < 30; i++ {
			m.RecordConnect(10 * time.Millisecond)
		}
		r := m.RTTRatio()
		if r < 0.9 || r > 1.1 {
			t.Errorf("稳定RTT下 RTTRatio() = %f, want ~1.0", r)
		}
	})
}

// TestScanMetricsRTTFast — 初始为 0，记录后非零
func TestScanMetricsRTTFast(t *testing.T) {
	m := &ScanMetrics{}
	if m.RTTFast() != 0 {
		t.Errorf("初始 RTTFast() = %v, want 0", m.RTTFast())
	}
	m.RecordConnect(5 * time.Millisecond)
	if m.RTTFast() == 0 {
		t.Errorf("记录后 RTTFast() 仍为 0")
	}
}

// TestMetricsSnapshotTotal — MetricsSnapshot 各字段求和
func TestMetricsSnapshotTotal(t *testing.T) {
	snap := MetricsSnapshot{Connects: 1, Refused: 2, Timeouts: 3, Exhausted: 4}
	if got := snap.Total(); got != 10 {
		t.Errorf("MetricsSnapshot.Total() = %d, want 10", got)
	}
}

// TestUpdateEMA — 直接测 updateEMA 行为
func TestUpdateEMA(t *testing.T) {
	t.Run("target为0时直接设为sample", func(t *testing.T) {
		var a atomic.Int64
		updateEMA(&a, 100, 10)
		if got := a.Load(); got != 100 {
			t.Errorf("初始为0时 updateEMA 结果 = %d, want 100", got)
		}
	})

	t.Run("target非零时做EMA更新", func(t *testing.T) {
		var a atomic.Int64
		a.Store(200)
		// next = 200 + (100-200)/10 = 200 - 10 = 190
		updateEMA(&a, 100, 10)
		if got := a.Load(); got != 190 {
			t.Errorf("EMA更新结果 = %d, want 190", got)
		}
	})
}
