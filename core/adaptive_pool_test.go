package core

import (
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
