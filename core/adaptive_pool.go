package core

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/ants/v2"
	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
)

// HealthSignal 健康评估结果
type HealthSignal int

const (
	HealthUnknown   HealthSignal = iota // 样本不足，无法判断
	HealthGood                          // 一切正常，可以提速
	HealthOK                            // 正常，维持现状
	HealthStressed                      // 有压力信号，轻微降速
	HealthCongested                     // 明确拥塞，大幅降速
)

// AdaptivePool 自适应线程池（AIMD + 慢启动）
//
// 三阶段工作模式：
//  1. 慢启动：从 target/4 起步，每个检查周期翻倍，直到达到 target 或检测到拥塞
//  2. 稳态 AIMD：健康时加性增（+5% target），拥塞时乘性减（×0.5）
//  3. 恢复上限受 ceiling 约束，不会无限增长
//
// 健康评估基于两个信号：
//   - 资源耗尽率（fd/端口不足）
//   - RTT 趋势（fast EMA / slow EMA）
type AdaptivePool struct {
	pool    *ants.PoolWithFunc
	metrics *ScanMetrics

	// 并发控制
	target      int32 // 探测推荐的目标值
	ceiling     int32 // 绝对上限（用户指定或探测推荐）
	currentSize int32

	// 慢启动
	inSlowStart bool
	ssThreshold int32 // 慢启动阈值（拥塞后降为当前值）

	// 检查定时
	checkInterval time.Duration
	lastCheck     atomic.Int64 // UnixNano

	// 增量计算
	mu           sync.Mutex
	prevSnapshot MetricsSnapshot
}

// NewAdaptivePool 创建自适应线程池
// target: 目标并发数（来自 NetworkProfile.RecommendConcurrency）
// ceiling: 最大并发上限
// metrics: 共享的扫描度量（scanSinglePort 写入，pool 读取）
func NewAdaptivePool(target, ceiling int, fn func(interface{}), metrics *ScanMetrics) (*AdaptivePool, error) {
	// 慢启动初始值：target 的 25%，但不低于 10
	initial := target / 4
	if initial < 10 {
		initial = 10
	}
	if initial > target {
		initial = target
	}

	pool, err := ants.NewPoolWithFunc(initial, fn)
	if err != nil {
		return nil, err
	}

	return &AdaptivePool{
		pool:          pool,
		metrics:       metrics,
		target:        int32(target),
		ceiling:       int32(ceiling),
		currentSize:   int32(initial),
		inSlowStart:   true,
		ssThreshold:   int32(target),
		checkInterval: 500 * time.Millisecond,
	}, nil
}

// Invoke 提交任务
func (ap *AdaptivePool) Invoke(task interface{}) error {
	ap.maybeAdjust()
	return ap.pool.Invoke(task)
}

// maybeAdjust 周期性检查并调整并发数
func (ap *AdaptivePool) maybeAdjust() {
	last := ap.lastCheck.Load()
	now := time.Now().UnixNano()
	if now-last < int64(ap.checkInterval) {
		return
	}
	if !ap.lastCheck.CompareAndSwap(last, now) {
		return
	}

	ap.adjust()
}

func (ap *AdaptivePool) adjust() {
	health := ap.assessHealth()
	if health == HealthUnknown {
		return
	}

	current := int(atomic.LoadInt32(&ap.currentSize))
	target := int(atomic.LoadInt32(&ap.target))
	ceiling := int(atomic.LoadInt32(&ap.ceiling))

	var newSize int

	if ap.inSlowStart {
		newSize = ap.adjustSlowStart(health, current, target)
	} else {
		newSize = ap.adjustAIMD(health, current, target)
	}

	// 下限：ceiling 的 5%，但不低于 10
	minSize := ceiling / 20
	if minSize < 10 {
		minSize = 10
	}

	if newSize < minSize {
		newSize = minSize
	}
	if newSize > ceiling {
		newSize = ceiling
	}

	if newSize != current {
		ap.tune(newSize)

		// 显著变化时记录日志
		delta := newSize - current
		if delta < 0 {
			delta = -delta
		}
		if delta > current/5 {
			if newSize < current {
				common.LogInfo(i18n.Tr("adaptive_pool_decrease", current, newSize))
			} else {
				common.LogDebug(i18n.Tr("adaptive_pool_increase", current, newSize))
			}
		}
	}
}

func (ap *AdaptivePool) adjustSlowStart(health HealthSignal, current, target int) int {
	switch health {
	case HealthCongested, HealthStressed:
		// 退出慢启动，设置阈值
		ap.ssThreshold = int32(current)
		ap.inSlowStart = false
		common.LogDebug(i18n.Tr("adaptive_pool_slowstart_exit", current))
		return int(float64(current) * 0.5)
	default:
		// 翻倍
		newSize := current * 2
		if newSize >= target {
			newSize = target
			ap.inSlowStart = false
		}
		return newSize
	}
}

func (ap *AdaptivePool) adjustAIMD(health HealthSignal, current, target int) int {
	switch health {
	case HealthCongested:
		// 乘性减：×0.5
		newSize := int(float64(current) * 0.5)
		ap.ssThreshold = int32(newSize)
		return newSize
	case HealthStressed:
		// 温和降低：×0.85
		return int(float64(current) * 0.85)
	case HealthGood:
		// 加性增：+5% of target，至少 +1
		inc := target / 20
		if inc < 1 {
			inc = 1
		}
		return current + inc
	default:
		return current
	}
}

// assessHealth 综合健康评估
func (ap *AdaptivePool) assessHealth() HealthSignal {
	snap := ap.metrics.Snapshot()

	ap.mu.Lock()
	prev := ap.prevSnapshot
	ap.prevSnapshot = snap
	ap.mu.Unlock()

	// 计算本周期增量
	deltaTotal := snap.Total() - prev.Total()
	deltaExhausted := snap.Exhausted - prev.Exhausted

	// 样本不足
	if deltaTotal < 30 {
		return HealthUnknown
	}

	exhaustRate := float64(deltaExhausted) / float64(deltaTotal)
	rttRatio := ap.metrics.RTTRatio()

	// 多信号综合判断
	switch {
	case exhaustRate > 0.15:
		return HealthCongested
	case rttRatio > 2.5:
		return HealthCongested
	case exhaustRate > 0.05:
		return HealthStressed
	case rttRatio > 1.8:
		return HealthStressed
	case exhaustRate < 0.01 && rttRatio < 1.3:
		return HealthGood
	default:
		return HealthOK
	}
}

func (ap *AdaptivePool) tune(newSize int) {
	ap.pool.Tune(newSize)
	atomic.StoreInt32(&ap.currentSize, int32(newSize))
}

// Running 返回当前运行中的 goroutine 数量
func (ap *AdaptivePool) Running() int { return ap.pool.Running() }

// Cap 返回当前池容量
func (ap *AdaptivePool) Cap() int { return int(atomic.LoadInt32(&ap.currentSize)) }

// Release 释放线程池
func (ap *AdaptivePool) Release() { ap.pool.Release() }

// Wait 等待所有任务完成
func (ap *AdaptivePool) Wait() {
	for ap.pool.Running() > 0 {
		time.Sleep(10 * time.Millisecond)
	}
}
