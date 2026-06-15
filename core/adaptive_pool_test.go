package core

import (
	"sync/atomic"
	"testing"
	"time"
)

// newTestPool 测试辅助：创建测试用的自适应线程池
func newTestPool(t *testing.T, size int, fn func(interface{})) (*AdaptivePool, *ScanMetrics) {
	t.Helper()
	metrics := &ScanMetrics{}
	pool, err := NewAdaptivePool(size, size, fn, metrics)
	if err != nil {
		t.Fatalf("创建线程池失败: %v", err)
	}
	return pool, metrics
}

// TestAdaptivePool_DowngradeOnHighExhaustion 验证资源耗尽率高时降低线程数
func TestAdaptivePool_DowngradeOnHighExhaustion(t *testing.T) {
	pool, metrics := newTestPool(t, 100, func(interface{}) {})
	defer pool.Release()

	// 慢启动先跑到 target
	pool.inSlowStart = false
	pool.tune(100)

	initialCap := pool.Cap()

	// 模拟高资源耗尽率：20%
	for i := 0; i < 200; i++ {
		if i < 40 {
			metrics.RecordExhausted()
		} else {
			metrics.RecordConnect(time.Millisecond)
		}
	}

	// 触发调整
	for i := 0; i < 20; i++ {
		_ = pool.Invoke(nil)
		time.Sleep(time.Millisecond * 30)
	}

	finalCap := pool.Cap()

	if finalCap >= initialCap {
		t.Errorf("应该降级: 初始 %d, 最终 %d", initialCap, finalCap)
	}

	if finalCap < 10 {
		t.Errorf("降到 minSize 以下: %d", finalCap)
	}

	t.Logf("降级成功: %d -> %d", initialCap, finalCap)
}

// TestAdaptivePool_SlowStart 验证慢启动行为
func TestAdaptivePool_SlowStart(t *testing.T) {
	metrics := &ScanMetrics{}
	pool, err := NewAdaptivePool(100, 100, func(interface{}) {}, metrics)
	if err != nil {
		t.Fatalf("创建线程池失败: %v", err)
	}
	defer pool.Release()

	// 初始应该是 target/4 = 25
	initialCap := pool.Cap()
	if initialCap > 30 {
		t.Errorf("慢启动初始值应该 <= 30, got %d", initialCap)
	}

	if !pool.inSlowStart {
		t.Error("应该处于慢启动状态")
	}

	t.Logf("慢启动初始: cap=%d, inSlowStart=%v", initialCap, pool.inSlowStart)
}

// TestAdaptivePool_MinSizeBoundary 验证不会降到 minSize 以下
func TestAdaptivePool_MinSizeBoundary(t *testing.T) {
	pool, metrics := newTestPool(t, 40, func(interface{}) {})
	defer pool.Release()

	pool.inSlowStart = false
	pool.tune(40)

	// 极端耗尽
	for i := 0; i < 500; i++ {
		metrics.RecordExhausted()
	}

	for i := 0; i < 50; i++ {
		_ = pool.Invoke(nil)
		time.Sleep(time.Millisecond * 15)
	}

	finalCap := pool.Cap()
	if finalCap < 10 {
		t.Errorf("线程数 < 10: %d", finalCap)
	}

	t.Logf("最小边界测试通过: cap=%d", finalCap)
}

// TestAdaptivePool_NotEnoughSamples 验证样本不足时不调整
func TestAdaptivePool_NotEnoughSamples(t *testing.T) {
	pool, metrics := newTestPool(t, 100, func(interface{}) {})
	defer pool.Release()

	pool.inSlowStart = false
	pool.tune(100)
	initialCap := pool.Cap()

	// 只 20 个样本，不足 30 的阈值
	for i := 0; i < 20; i++ {
		metrics.RecordExhausted()
	}

	for i := 0; i < 10; i++ {
		_ = pool.Invoke(nil)
	}
	time.Sleep(time.Millisecond * 50)

	finalCap := pool.Cap()
	if finalCap != initialCap {
		t.Errorf("样本不足时不应该调整: %d -> %d", initialCap, finalCap)
	}
}

// TestAdaptivePool_Wait 验证 Wait 方法
func TestAdaptivePool_Wait(t *testing.T) {
	pool, _ := newTestPool(t, 10, func(interface{}) {
		time.Sleep(time.Millisecond * 50)
	})
	defer pool.Release()

	pool.inSlowStart = false
	pool.tune(10)

	for i := 0; i < 20; i++ {
		_ = pool.Invoke(nil)
	}

	start := time.Now()
	pool.Wait()
	duration := time.Since(start)

	if duration > 300*time.Millisecond {
		t.Errorf("Wait 耗时过长: %v", duration)
	}

	t.Logf("Wait 测试通过: %v", duration)
}

// =============================================================================
// maybeReduceTarget 补充覆盖
// =============================================================================

// TestMaybeReduceTarget_NoOpWhenRTTLow rttRatio <= 3.0 时不修改 target
func TestMaybeReduceTarget_NoOpWhenRTTLow(t *testing.T) {
	metrics := &ScanMetrics{}
	pool, err := NewAdaptivePool(100, 100, func(interface{}) {}, metrics)
	if err != nil {
		t.Fatalf("创建线程池失败: %v", err)
	}
	defer pool.Release()

	initialTarget := atomic.LoadInt32(&pool.target)

	// RTTRatio 样本不足（< 20）返回 1.0，远低于 3.0 阈值
	pool.maybeReduceTarget()

	afterTarget := atomic.LoadInt32(&pool.target)
	if afterTarget != initialTarget {
		t.Errorf("rttRatio <= 3.0 时 target 不应改变: %d -> %d", initialTarget, afterTarget)
	}
}

// TestMaybeReduceTarget_ReducesWhenRTTHigh rttRatio > 3.0 时压低 target 10%
func TestMaybeReduceTarget_ReducesWhenRTTHigh(t *testing.T) {
	metrics := &ScanMetrics{}
	pool, err := NewAdaptivePool(200, 200, func(interface{}) {}, metrics)
	if err != nil {
		t.Fatalf("创建线程池失败: %v", err)
	}
	defer pool.Release()

	// 伪造 RTT：让 fastEMA >> slowEMA，ratio > 3.0
	// 方法：先用大 RTT 建立 fastEMA，再用小 RTT 建立 slowEMA
	// 更直接：直接操作 atomic 字段（包内测试可以访问）
	for i := 0; i < 25; i++ {
		metrics.RecordConnect(10 * time.Millisecond) // 先建 baseline
	}
	// 现在把 fastEMA 人为拉高（写入一个远大于 slowEMA 的值）
	pool.metrics.rttFastNs.Store(int64(400 * time.Millisecond))
	pool.metrics.rttSlowNs.Store(int64(10 * time.Millisecond))

	initialTarget := atomic.LoadInt32(&pool.target)

	pool.maybeReduceTarget()

	afterTarget := atomic.LoadInt32(&pool.target)
	if afterTarget >= initialTarget {
		t.Errorf("rttRatio > 3.0 时 target 应被压低: %d -> %d", initialTarget, afterTarget)
	}

	// 验证是 ×0.9
	expected := int32(float64(initialTarget) * 0.9)
	if afterTarget != expected {
		t.Errorf("target 应为 %d (×0.9), 实际 %d", expected, afterTarget)
	}
}

// TestMaybeReduceTarget_ClampToMinTarget target 压低后不低于 ceiling/5 或 10
func TestMaybeReduceTarget_ClampToMinTarget(t *testing.T) {
	metrics := &ScanMetrics{}
	// ceiling=20, minTarget = max(20/5, 10) = 10
	// target=10, newTarget = int(10*0.9) = 9 → 被 clamp 到 10 → newTarget == target → 不更新
	pool, err := NewAdaptivePool(10, 20, func(interface{}) {}, metrics)
	if err != nil {
		t.Fatalf("创建线程池失败: %v", err)
	}
	defer pool.Release()

	// 强制设置 target=10（初始值就是 10，但确认一下）
	atomic.StoreInt32(&pool.target, 10)

	// 伪造 rttRatio > 3.0
	for i := 0; i < 25; i++ {
		metrics.RecordConnect(10 * time.Millisecond)
	}
	pool.metrics.rttFastNs.Store(int64(400 * time.Millisecond))
	pool.metrics.rttSlowNs.Store(int64(10 * time.Millisecond))

	pool.maybeReduceTarget()

	afterTarget := atomic.LoadInt32(&pool.target)
	// newTarget=9 < minTarget=10 → clamp 到 10 → 10 == target → 不写入
	if afterTarget != 10 {
		t.Errorf("clamp 后 target 应保持 10, 实际 %d", afterTarget)
	}
}

// TestMaybeReduceTarget_LargeCeilingMinTarget ceiling 足够大时 minTarget = ceiling/5
func TestMaybeReduceTarget_LargeCeilingMinTarget(t *testing.T) {
	metrics := &ScanMetrics{}
	// ceiling=100, minTarget = 100/5 = 20
	// target=21 → newTarget = int(21*0.9) = 18 → clamp 到 20
	pool, err := NewAdaptivePool(21, 100, func(interface{}) {}, metrics)
	if err != nil {
		t.Fatalf("创建线程池失败: %v", err)
	}
	defer pool.Release()

	atomic.StoreInt32(&pool.target, 21)
	atomic.StoreInt32(&pool.ceiling, 100)

	for i := 0; i < 25; i++ {
		metrics.RecordConnect(10 * time.Millisecond)
	}
	pool.metrics.rttFastNs.Store(int64(400 * time.Millisecond))
	pool.metrics.rttSlowNs.Store(int64(10 * time.Millisecond))

	pool.maybeReduceTarget()

	afterTarget := atomic.LoadInt32(&pool.target)
	// newTarget=18 < minTarget=20 → store 20; 20 < 21 → 更新
	if afterTarget != 20 {
		t.Errorf("应 clamp 到 minTarget=20, 实际 %d", afterTarget)
	}
}
