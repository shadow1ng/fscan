package core

import (
	"math"
	"sync"
	"time"
)

// AdaptiveTimeout 基于 RTT 采样的自适应超时计算器
// 算法：timeout = mean(RTT) + 4 * stddev(RTT)，clamp 到 [min, max]
// 冷启动阶段（样本不足）返回用户配置的固定超时
type AdaptiveTimeout struct {
	mu       sync.Mutex
	samples  []float64 // 环形缓冲区，单位 ms
	pos      int       // 写入位置
	count    int       // 已采集总数
	size     int       // 缓冲区容量
	minTO    time.Duration
	maxTO    time.Duration
	warmup   int // 冷启动所需最小样本数
	cachedTO time.Duration
	dirty    bool
}

// NewAdaptiveTimeout 创建自适应超时计算器
// maxTimeout: 用户配置的超时上限（即原始固定超时）
func NewAdaptiveTimeout(maxTimeout time.Duration) *AdaptiveTimeout {
	return &AdaptiveTimeout{
		samples: make([]float64, 64),
		size:    64,
		minTO:   100 * time.Millisecond,
		maxTO:   maxTimeout,
		warmup:  10,
	}
}

// Record 记录一次成功连接的 RTT
func (a *AdaptiveTimeout) Record(rtt time.Duration) {
	a.mu.Lock()
	a.samples[a.pos%a.size] = float64(rtt.Milliseconds())
	a.pos++
	a.count++
	a.dirty = true
	a.mu.Unlock()
}

// Timeout 获取当前推荐超时值
// 样本不足时返回 maxTO（冷启动）
func (a *AdaptiveTimeout) Timeout() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.count < a.warmup {
		return a.maxTO
	}

	if !a.dirty {
		return a.cachedTO
	}

	n := a.size
	if a.count < a.size {
		n = a.count
	}

	var sum float64
	for i := 0; i < n; i++ {
		sum += a.samples[i]
	}
	mean := sum / float64(n)

	var variance float64
	for i := 0; i < n; i++ {
		d := a.samples[i] - mean
		variance += d * d
	}
	stddev := math.Sqrt(variance / float64(n))

	ms := mean + 4*stddev
	to := time.Duration(ms) * time.Millisecond

	if to < a.minTO {
		to = a.minTO
	}
	if to > a.maxTO {
		to = a.maxTO
	}

	a.cachedTO = to
	a.dirty = false
	return to
}
