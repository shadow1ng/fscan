package core

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// 集成测试 1：探测 → 参数调整 → 线程池创建 完整链路
// 验证从 NetworkProfile 到 TuneConfig 到 AdaptivePool 的端到端数据流
// =============================================================================

func TestIntegration_ProbeToPool_LAN(t *testing.T) {
	// 模拟内网探测结果
	profile := classifyNetwork(
		makeDurations([]int{1, 1, 2, 2, 2, 3, 3, 3, 4, 5}), // ms
		0, 10,
	)

	if profile.Env != EnvLAN {
		t.Fatalf("探测环境 = %v, want LAN", profile.Env)
	}

	// 构建 Config + TuneConfig
	config := makeDefaultConfig()
	session := makeTestSession(config)
	sys := ProbeSystem()

	ep := &EnvironmentProfile{Net: *profile, System: sys}
	ep.TuneConfig(config, session)

	// 验证参数被合理调整
	if config.Timeout > 3*time.Second {
		t.Errorf("内网 Timeout = %v, 不应 > 3s", config.Timeout)
	}
	if config.MaxRetries != 1 {
		t.Errorf("内网零丢包 MaxRetries = %d, want 1", config.MaxRetries)
	}

	// 用调整后的参数创建线程池
	target, ceiling := profile.RecommendConcurrency(config.ThreadNum, config.ThreadNumExplicit)
	metrics := &ScanMetrics{}
	pool, err := NewAdaptivePool(target, ceiling, func(interface{}) {}, metrics)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	if pool.Cap() <= 0 {
		t.Errorf("池容量 = %d, 应该 > 0", pool.Cap())
	}

	t.Logf("内网完整链路: Timeout=%v MT=%d Retry=%d ICMP=%.2f target=%d ceiling=%d poolCap=%d",
		config.Timeout, config.ModuleThreadNum, config.MaxRetries,
		config.Network.ICMPRate, target, ceiling, pool.Cap())
}

func TestIntegration_ProbeToPool_Internet(t *testing.T) {
	profile := classifyNetwork(
		makeDurations([]int{60, 70, 80, 90, 100, 110, 120, 130, 140, 150}),
		0, 10,
	)

	if profile.Env != EnvInternet {
		t.Fatalf("探测环境 = %v, want Internet", profile.Env)
	}

	config := makeDefaultConfig()
	session := makeTestSession(config)
	ep := &EnvironmentProfile{Net: *profile, System: SystemProfile{FDLimit: 4096, NumCPU: 4}}
	ep.TuneConfig(config, session)

	target, ceiling := profile.RecommendConcurrency(config.ThreadNum, config.ThreadNumExplicit)
	metrics := &ScanMetrics{}
	pool, err := NewAdaptivePool(target, ceiling, func(interface{}) {}, metrics)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	// 公网并发应该明显低于默认 600
	if target >= 600 {
		t.Errorf("公网 target = %d, 应该 < 600", target)
	}

	t.Logf("公网完整链路: Timeout=%v MT=%d Retry=%d target=%d ceiling=%d poolCap=%d",
		config.Timeout, config.ModuleThreadNum, config.MaxRetries, target, ceiling, pool.Cap())
}

// =============================================================================
// 集成测试 2：AdaptivePool + ScanMetrics 联动
// 验证：任务执行 → metrics 记录 → 池读取 metrics → 做出调整决策
// =============================================================================

func TestIntegration_PoolMetrics_HealthyTraffic(t *testing.T) {
	metrics := &ScanMetrics{}
	var taskCount atomic.Int64

	pool, err := NewAdaptivePool(100, 100, func(i interface{}) {
		taskCount.Add(1)
	}, metrics)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	pool.inSlowStart = false
	pool.tune(100)

	// 注入健康 metrics
	for i := 0; i < 200; i++ {
		metrics.RecordConnect(time.Millisecond)
	}

	// 运行任务
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = pool.Invoke(nil)
		}()
	}
	wg.Wait()
	pool.Wait()

	// 触发调整
	pool.lastCheck.Store(0)
	pool.adjust()

	if pool.Cap() < 90 {
		t.Errorf("健康流量池容量不应大幅下降: cap = %d", pool.Cap())
	}

	t.Logf("健康流量: tasks=%d connects=%d cap=%d",
		taskCount.Load(), metrics.Snapshot().Connects, pool.Cap())
}

func TestIntegration_PoolMetrics_ExhaustedTraffic(t *testing.T) {
	metrics := &ScanMetrics{}

	pool, err := NewAdaptivePool(100, 100, func(i interface{}) {}, metrics)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	pool.inSlowStart = false
	pool.tune(100)

	// 直接向 metrics 注入大量资源耗尽事件（模拟扫描过程中的 fd 不足）
	for i := 0; i < 200; i++ {
		metrics.RecordExhausted()
	}

	// 手动触发调整（清除时间守卫）
	pool.lastCheck.Store(0)
	pool.adjust()

	// 资源耗尽率 100% → 应该降速
	if pool.Cap() >= 100 {
		t.Errorf("资源耗尽后池应该降速: cap = %d", pool.Cap())
	}

	t.Logf("资源耗尽: exhausted=%d cap=%d", metrics.Snapshot().Exhausted, pool.Cap())
}

// =============================================================================
// 集成测试 3：慢启动 → 稳态 AIMD 过渡
// 验证慢启动阶段的翻倍行为和过渡到稳态的时机
// =============================================================================

func TestIntegration_SlowStartToSteady(t *testing.T) {
	metrics := &ScanMetrics{}

	pool, err := NewAdaptivePool(100, 100, func(i interface{}) {
		metrics.RecordConnect(time.Millisecond)
	}, metrics)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	if !pool.inSlowStart {
		t.Fatal("初始应该在慢启动状态")
	}

	initialCap := pool.Cap()
	t.Logf("慢启动初始: cap=%d", initialCap)

	// 喂入足够的健康 metrics
	for i := 0; i < 100; i++ {
		metrics.RecordConnect(time.Millisecond)
	}

	// 模拟多次调整周期
	caps := []int{initialCap}
	for i := 0; i < 10; i++ {
		pool.lastCheck.Store(0) // 强制触发检查
		pool.adjust()
		caps = append(caps, pool.Cap())
	}

	// 验证：容量应该逐步增长
	growing := false
	for i := 1; i < len(caps); i++ {
		if caps[i] > caps[i-1] {
			growing = true
			break
		}
	}
	if !growing {
		t.Errorf("慢启动期间容量没有增长: %v", caps)
	}

	// 最终应该退出慢启动
	finalCap := pool.Cap()
	if finalCap < initialCap {
		t.Errorf("最终容量 %d < 初始 %d, 不合理", finalCap, initialCap)
	}

	t.Logf("慢启动过渡: %v, inSlowStart=%v", caps, pool.inSlowStart)
}

// =============================================================================
// 集成测试 4：拥塞 → 降速 → 恢复 完整周期
// =============================================================================

func TestIntegration_CongestionRecovery(t *testing.T) {
	metrics := &ScanMetrics{}

	pool, err := NewAdaptivePool(200, 200, func(i interface{}) {}, metrics)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	// 直接到稳态，满容量
	pool.inSlowStart = false
	pool.tune(200)

	// === 阶段 1: 正常运行 ===
	for i := 0; i < 100; i++ {
		metrics.RecordConnect(time.Millisecond)
	}
	pool.lastCheck.Store(0)
	pool.adjust()
	normalCap := pool.Cap()
	t.Logf("正常阶段: cap=%d", normalCap)

	// === 阶段 2: 突发拥塞（大量资源耗尽）===
	for i := 0; i < 200; i++ {
		metrics.RecordExhausted()
	}
	pool.lastCheck.Store(0)
	pool.adjust()
	congestedCap := pool.Cap()

	if congestedCap >= normalCap {
		t.Errorf("拥塞后应降速: normal=%d congested=%d", normalCap, congestedCap)
	}
	t.Logf("拥塞阶段: cap=%d (降幅 %d%%)", congestedCap, (normalCap-congestedCap)*100/normalCap)

	// === 阶段 3: 恢复（大量成功连接）===
	for i := 0; i < 500; i++ {
		metrics.RecordConnect(time.Millisecond)
	}

	// 多次调整模拟恢复过程
	for i := 0; i < 20; i++ {
		pool.lastCheck.Store(0)
		pool.adjust()
	}
	recoveredCap := pool.Cap()

	if recoveredCap <= congestedCap {
		t.Errorf("恢复后应提速: congested=%d recovered=%d", congestedCap, recoveredCap)
	}

	// 恢复后不应超过 ceiling
	if recoveredCap > 200 {
		t.Errorf("恢复后不应超过 ceiling: cap=%d ceiling=200", recoveredCap)
	}

	t.Logf("恢复阶段: cap=%d", recoveredCap)
}

// =============================================================================
// 集成测试 5：RTT 趋势检测 → 池调整
// 验证 ScanMetrics 的 RTT EMA 趋势信号能正确传导到池的健康判断
// =============================================================================

func TestIntegration_RTTTrend_DrivesPoolAdjustment(t *testing.T) {
	metrics := &ScanMetrics{}

	pool, err := NewAdaptivePool(100, 100, func(i interface{}) {}, metrics)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	pool.inSlowStart = false
	pool.tune(100)

	// 建立基线：100 个 5ms RTT
	for i := 0; i < 200; i++ {
		metrics.RecordConnect(5 * time.Millisecond)
	}
	pool.lastCheck.Store(0)
	pool.adjust()
	baselineCap := pool.Cap()

	// RTT 突增到 100ms（20 倍）
	for i := 0; i < 100; i++ {
		metrics.RecordConnect(100 * time.Millisecond)
	}

	ratio := metrics.RTTRatio()
	if ratio <= 1.0 {
		t.Logf("RTT ratio = %.2f, EMA 可能还没追上（正常）", ratio)
	}

	// 多次调整看池是否响应
	for i := 0; i < 5; i++ {
		pool.lastCheck.Store(0)
		pool.adjust()
	}
	afterRTTSpike := pool.Cap()

	t.Logf("RTT 趋势: baseline_cap=%d after_spike=%d rtt_ratio=%.2f",
		baselineCap, afterRTTSpike, ratio)

	// 如果 ratio 足够高，池应该降速
	if ratio > 2.0 && afterRTTSpike >= baselineCap {
		t.Errorf("RTT ratio=%.2f 但池没有降速: %d -> %d", ratio, baselineCap, afterRTTSpike)
	}
}

// =============================================================================
// 集成测试 6：不同网络环境下的参数一致性
// 验证同一组目标在不同环境下参数调整的合理递进关系
// =============================================================================

func TestIntegration_ParameterProgression(t *testing.T) {
	environments := []struct {
		name    string
		rtts    []int // ms
		loss    int   // failures out of 10
		wantEnv NetworkEnv
	}{
		{"内网", []int{1, 1, 2, 2, 3, 3, 4, 4, 5, 5}, 0, EnvLAN},
		{"局域网", []int{10, 15, 20, 25, 30, 35, 40, 45, 48, 49}, 0, EnvWAN},
		{"公网", []int{60, 70, 80, 90, 100, 120, 140, 160, 180, 195}, 0, EnvInternet},
		{"慢速", []int{200, 300, 400, 500, 600, 700, 800, 900, 1000, 1500}, 0, EnvSlow},
	}

	type params struct {
		timeout  time.Duration
		mt       int
		retry    int
		icmpRate float64
	}

	var results []params

	for _, env := range environments {
		profile := classifyNetwork(makeDurations(env.rtts), env.loss, 10)
		if profile.Env != env.wantEnv {
			t.Errorf("%s: env = %v, want %v", env.name, profile.Env, env.wantEnv)
		}

		config := makeDefaultConfig()
		session := makeTestSession(config)
		ep := &EnvironmentProfile{
			Net:    *profile,
			System: SystemProfile{FDLimit: 65536, NumCPU: 8},
		}
		ep.TuneConfig(config, session)

		results = append(results, params{
			timeout:  config.Timeout,
			mt:       config.ModuleThreadNum,
			retry:    config.MaxRetries,
			icmpRate: config.Network.ICMPRate,
		})

		t.Logf("%s: Timeout=%v MT=%d Retry=%d ICMP=%.2f",
			env.name, config.Timeout, config.ModuleThreadNum, config.MaxRetries, config.Network.ICMPRate)
	}

	// 验证递进关系：从内网到慢速，Timeout 应递增
	for i := 1; i < len(results); i++ {
		if results[i].timeout < results[i-1].timeout {
			t.Errorf("Timeout 不递增: %v (env[%d]) < %v (env[%d])",
				results[i].timeout, i, results[i-1].timeout, i-1)
		}
	}

	// ICMPRate 应递减（内网最高，慢速最低）
	for i := 1; i < len(results); i++ {
		if results[i].icmpRate > results[i-1].icmpRate {
			t.Errorf("ICMPRate 不递减: %.2f (env[%d]) > %.2f (env[%d])",
				results[i].icmpRate, i, results[i-1].icmpRate, i-1)
		}
	}
}

// =============================================================================
// 集成测试 7：用户显式 -t + 网络探测 完整流程
// 验证用户指定值作为 ceiling 但探测仍然影响其他参数
// =============================================================================

func TestIntegration_ExplicitThreadNum_WithProbe(t *testing.T) {
	profile := classifyNetwork(
		makeDurations([]int{100, 120, 140, 160, 180, 200, 220, 240, 260, 300}),
		2, 12, // 部分丢包
	)

	config := makeDefaultConfig()
	config.ThreadNum = 200
	config.ThreadNumExplicit = true
	session := makeTestSession(config)

	ep := &EnvironmentProfile{
		Net:    *profile,
		System: SystemProfile{FDLimit: 4096, NumCPU: 4},
	}
	ep.TuneConfig(config, session)

	// ThreadNum 不应被修改（fd limit 允许范围内）
	// 但 Timeout、ModuleThreadNum 等应根据探测调整
	if config.Timeout == 3*time.Second {
		t.Error("即使 -t 显式，Timeout 仍应根据探测调整")
	}

	// 创建池
	target, ceiling := profile.RecommendConcurrency(config.ThreadNum, config.ThreadNumExplicit)
	if ceiling != 200 {
		t.Errorf("显式 -t 200 的 ceiling = %d, want 200", ceiling)
	}
	if target > 200 {
		t.Errorf("target = %d, 不应超过 ceiling 200", target)
	}

	metrics := &ScanMetrics{}
	pool, err := NewAdaptivePool(target, ceiling, func(interface{}) {}, metrics)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	t.Logf("显式 -t 200: Timeout=%v MT=%d Retry=%d target=%d ceiling=%d cap=%d",
		config.Timeout, config.ModuleThreadNum, config.MaxRetries, target, ceiling, pool.Cap())
}

// =============================================================================
// 集成测试 8：AdaptiveTimeout + ScanMetrics 双 RTT 追踪
// 验证两个 RTT 追踪器独立工作不干扰
// =============================================================================

func TestIntegration_DualRTTTracking(t *testing.T) {
	adaptiveTO := NewAdaptiveTimeout(3 * time.Second)
	metrics := &ScanMetrics{}

	// 喂入相同的 RTT 数据到两个追踪器
	for i := 0; i < 50; i++ {
		rtt := 10 * time.Millisecond
		adaptiveTO.Record(rtt)
		metrics.RecordConnect(rtt)
	}

	// AdaptiveTimeout 用于连接超时
	toValue := adaptiveTO.Timeout()
	// ScanMetrics 用于池健康判断
	rttFast := metrics.RTTFast()
	ratio := metrics.RTTRatio()

	if toValue > 3*time.Second {
		t.Errorf("AdaptiveTimeout 应该 < 初始值: %v", toValue)
	}
	if rttFast < 8*time.Millisecond || rttFast > 12*time.Millisecond {
		t.Errorf("ScanMetrics RTTFast 应接近 10ms: %v", rttFast)
	}
	if ratio < 0.8 || ratio > 1.2 {
		t.Errorf("稳定 RTT 的 ratio 应接近 1.0: %.2f", ratio)
	}

	t.Logf("双追踪: AdaptiveTO=%v, MetricsFast=%v, Ratio=%.2f", toValue, rttFast, ratio)
}

// =============================================================================
// 集成测试 9：丢包环境下 Retry + ModuleThreadNum 联动
// 验证高丢包同时影响重试和并发
// =============================================================================

func TestIntegration_LossyNetwork_RetryAndConcurrency(t *testing.T) {
	lossRates := []float64{0.0, 0.05, 0.10, 0.20, 0.40}

	type result struct {
		loss  float64
		retry int
		mt    int
	}
	var results []result

	for _, loss := range lossRates {
		profile := &NetworkProfile{
			Env:       EnvInternet,
			RTTMedian: 80 * time.Millisecond,
			RTTStddev: 20 * time.Millisecond,
			LossRate:  loss,
			Samples:   20,
		}

		config := makeDefaultConfig()
		session := makeTestSession(config)
		ep := &EnvironmentProfile{
			Net:    *profile,
			System: SystemProfile{FDLimit: 65536, NumCPU: 8},
		}
		ep.TuneConfig(config, session)

		results = append(results, result{loss, config.MaxRetries, config.ModuleThreadNum})
	}

	// 重试次数应随丢包率单调递增
	for i := 1; i < len(results); i++ {
		if results[i].retry < results[i-1].retry {
			t.Errorf("Retry 不递增: loss=%.2f retry=%d < loss=%.2f retry=%d",
				results[i].loss, results[i].retry, results[i-1].loss, results[i-1].retry)
		}
	}

	// 高丢包时 ModuleThreadNum 应降低
	if results[len(results)-1].mt >= results[0].mt {
		t.Errorf("40%%丢包的 MT(%d) 应 < 0%%丢包的 MT(%d)",
			results[len(results)-1].mt, results[0].mt)
	}

	for _, r := range results {
		t.Logf("loss=%.0f%%: Retry=%d MT=%d", r.loss*100, r.retry, r.mt)
	}
}
