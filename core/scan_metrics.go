package core

import (
	"runtime"
	"sync/atomic"
	"time"
)

// ScanMetrics 扫描过程中的实时度量指标
// 所有方法均无锁，使用 atomic 操作，可在高并发下安全调用
type ScanMetrics struct {
	connects  atomic.Int64 // TCP 连接成功（端口开放）
	refused   atomic.Int64 // 连接被拒绝（端口关闭，快速 RTT）
	timeouts  atomic.Int64 // 连接超时（端口过滤/不可达）
	exhausted atomic.Int64 // 资源耗尽（fd/端口/内存不足）

	// RTT 追踪：双 EMA（指数移动平均）
	// fast EMA (α=0.1) 跟踪近期趋势
	// slow EMA (α=0.02) 作为基线参考
	rttFastNs  atomic.Int64 // 纳秒
	rttSlowNs  atomic.Int64 // 纳秒
	rttSamples atomic.Int64
}

func (m *ScanMetrics) RecordConnect(rtt time.Duration) {
	m.connects.Add(1)
	m.recordRTT(rtt)
}

func (m *ScanMetrics) RecordRefused(rtt time.Duration) {
	m.refused.Add(1)
	m.recordRTT(rtt)
}

func (m *ScanMetrics) RecordTimeout()  { m.timeouts.Add(1) }
func (m *ScanMetrics) RecordExhausted() { m.exhausted.Add(1) }

// recordRTT 更新 RTT 双 EMA（lock-free CAS）
func (m *ScanMetrics) recordRTT(rtt time.Duration) {
	ns := int64(rtt)
	if ns <= 0 {
		return
	}
	m.rttSamples.Add(1)

	// Fast EMA: α = 0.1 → new = old + (sample - old) / 10
	updateEMA(&m.rttFastNs, ns, 10)
	// Slow EMA: α = 0.02 → new = old + (sample - old) / 50
	updateEMA(&m.rttSlowNs, ns, 50)
}

func updateEMA(target *atomic.Int64, sample int64, divisor int64) {
	for {
		old := target.Load()
		if old == 0 {
			if target.CompareAndSwap(0, sample) {
				return
			}
			runtime.Gosched()
			continue
		}
		next := old + (sample-old)/divisor
		if target.CompareAndSwap(old, next) {
			return
		}
		runtime.Gosched()
	}
}

// Total 总操作数
func (m *ScanMetrics) Total() int64 {
	return m.connects.Load() + m.refused.Load() + m.timeouts.Load() + m.exhausted.Load()
}

// MetricsSnapshot 度量快照，用于计算窗口内增量
type MetricsSnapshot struct {
	Connects  int64
	Refused   int64
	Timeouts  int64
	Exhausted int64
	RTTFastNs int64
	RTTSlowNs int64
}

func (s MetricsSnapshot) Total() int64 {
	return s.Connects + s.Refused + s.Timeouts + s.Exhausted
}

func (m *ScanMetrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		Connects:  m.connects.Load(),
		Refused:   m.refused.Load(),
		Timeouts:  m.timeouts.Load(),
		Exhausted: m.exhausted.Load(),
		RTTFastNs: m.rttFastNs.Load(),
		RTTSlowNs: m.rttSlowNs.Load(),
	}
}

// RTTRatio 返回 fast/slow EMA 的比值
// > 1.0 表示延迟在上升（拥塞信号），< 1.0 表示延迟在下降
// 样本不足时返回 1.0
func (m *ScanMetrics) RTTRatio() float64 {
	if m.rttSamples.Load() < 20 {
		return 1.0
	}
	fast := m.rttFastNs.Load()
	slow := m.rttSlowNs.Load()
	if slow <= 0 {
		return 1.0
	}
	return float64(fast) / float64(slow)
}

// RTTFast 返回快速 EMA 值
func (m *ScanMetrics) RTTFast() time.Duration {
	return time.Duration(m.rttFastNs.Load())
}
