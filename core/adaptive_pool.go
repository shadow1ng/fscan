package core

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/ants/v2"
	"github.com/shadow1ng/fscan/common"
)

// AdaptivePool 自适应线程池
// 封装 ants.PoolWithFunc，支持根据资源耗尽率动态调整线程数
type AdaptivePool struct {
	pool  *ants.PoolWithFunc
	state *common.State

	initialSize int
	minSize     int
	maxSize     int
	currentSize int32 // 原子操作

	// 监控参数
	checkInterval      time.Duration
	lastCheckNano      int64 // 原子, UnixNano
	lastExhaustedCount int64
	lastPacketCount    int64

	// 阈值
	exhaustedThreshold float64 // 资源耗尽率阈值（触发降级）
	recoveryThreshold  float64 // 恢复阈值（允许升级）

	mu sync.Mutex
}

// NewAdaptivePool 创建自适应线程池
func NewAdaptivePool(size int, fn func(interface{}), state *common.State) (*AdaptivePool, error) {
	// 移除 WithPreAlloc(true)，在大规模扫描时预分配可能导致内存问题
	pool, err := ants.NewPoolWithFunc(size, fn)
	if err != nil {
		return nil, err
	}

	minSize := size / 4
	if minSize < 10 {
		minSize = 10
	}

	return &AdaptivePool{
		pool:               pool,
		state:              state,
		initialSize:        size,
		minSize:            minSize,
		maxSize:            size,
		currentSize:        int32(size),
		checkInterval:      time.Second,
		exhaustedThreshold: 0.10, // 10% 资源耗尽率触发降级
		recoveryThreshold:  0.02, // 2% 以下允许恢复
	}, nil
}

// Invoke 提交任务，并在适当时机检查是否需要调整线程数
func (ap *AdaptivePool) Invoke(task interface{}) error {
	ap.maybeAdjust()
	return ap.pool.Invoke(task)
}

// maybeAdjust 检查并可能调整线程池大小
// 使用原子 CAS 进行时间检查，99%+ 的调用零锁开销
func (ap *AdaptivePool) maybeAdjust() {
	lastCheck := atomic.LoadInt64(&ap.lastCheckNano)
	now := time.Now().UnixNano()
	if now-lastCheck < int64(ap.checkInterval) {
		return
	}
	if !atomic.CompareAndSwapInt64(&ap.lastCheckNano, lastCheck, now) {
		return // 其他 goroutine 已在检查
	}

	// 获取当前计数
	currentExhausted := ap.state.GetResourceExhaustedCount()
	currentPackets := ap.state.GetPacketCount()

	ap.mu.Lock()
	// 计算增量（本周期内的耗尽率）
	deltaExhausted := currentExhausted - ap.lastExhaustedCount
	deltaPackets := currentPackets - ap.lastPacketCount

	ap.lastExhaustedCount = currentExhausted
	ap.lastPacketCount = currentPackets
	ap.mu.Unlock()

	// 需要足够的样本才能判断
	if deltaPackets < 100 {
		return
	}

	rate := float64(deltaExhausted) / float64(deltaPackets)
	currentSize := int(atomic.LoadInt32(&ap.currentSize))

	if rate > ap.exhaustedThreshold && currentSize > ap.minSize {
		// 降级：减少 20% 线程
		newSize := int(float64(currentSize) * 0.8)
		if newSize < ap.minSize {
			newSize = ap.minSize
		}
		ap.tune(newSize)
		common.LogInfo(fmt.Sprintf("[AdaptivePool] 资源耗尽率 %.1f%%, 线程数 %d -> %d", rate*100, currentSize, newSize))
	} else if rate < ap.recoveryThreshold && currentSize < ap.maxSize {
		// 恢复：增加 10% 线程（保守恢复）
		newSize := int(float64(currentSize) * 1.1)
		if newSize > ap.maxSize {
			newSize = ap.maxSize
		}
		if newSize > currentSize {
			ap.tune(newSize)
		}
	}
}

// tune 调整线程池大小
func (ap *AdaptivePool) tune(newSize int) {
	ap.pool.Tune(newSize)
	atomic.StoreInt32(&ap.currentSize, int32(newSize))
}

// Running 返回当前运行中的 goroutine 数量
func (ap *AdaptivePool) Running() int {
	return ap.pool.Running()
}

// Cap 返回当前池容量
func (ap *AdaptivePool) Cap() int {
	return int(atomic.LoadInt32(&ap.currentSize))
}

// Release 释放线程池
func (ap *AdaptivePool) Release() {
	ap.pool.Release()
}

// Wait 等待所有任务完成
func (ap *AdaptivePool) Wait() {
	// ants 没有原生 Wait，通过 Running() == 0 轮询
	for ap.pool.Running() > 0 {
		time.Sleep(10 * time.Millisecond)
	}
}
