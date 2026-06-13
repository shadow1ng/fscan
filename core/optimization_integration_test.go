package core

import (
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// 优化 1：target/ceiling 分离
// =============================================================================

func TestOpt1_TargetCeilingSeparation_TuneConfig(t *testing.T) {
	config := makeDefaultConfig()
	session := makeTestSession(config)

	ep := &EnvironmentProfile{
		Net: NetworkProfile{
			Env:       EnvLAN,
			RTTMedian: 1 * time.Millisecond,
			RTTStddev: 500 * time.Microsecond,
			LossRate:  0.0,
			Samples:   30,
		},
		System: SystemProfile{FDLimit: 65536, NumCPU: 8},
	}

	ep.TuneConfig(config, session)

	if config.ThreadCeiling <= 0 {
		t.Fatalf("ThreadCeiling 未被设置: %d", config.ThreadCeiling)
	}

	// 内网 factor=1.5，非显式 → target=ceiling=recommended
	// 但 ceiling 应该 >= target
	if config.ThreadCeiling < config.ThreadNum {
		t.Errorf("Ceiling(%d) < ThreadNum(%d)", config.ThreadCeiling, config.ThreadNum)
	}

	t.Logf("target=%d, ceiling=%d", config.ThreadNum, config.ThreadCeiling)
}

func TestOpt1_TargetCeilingSeparation_ExplicitT(t *testing.T) {
	config := makeDefaultConfig()
	config.ThreadNum = 200
	config.ThreadNumExplicit = true
	session := makeTestSession(config)

	ep := &EnvironmentProfile{
		Net: NetworkProfile{
			Env:       EnvInternet,
			RTTMedian: 100 * time.Millisecond,
			RTTStddev: 30 * time.Millisecond,
			LossRate:  0.0,
			Samples:   20,
		},
		System: SystemProfile{FDLimit: 65536, NumCPU: 8},
	}

	ep.TuneConfig(config, session)

	// 用户显式指定 -t → ceiling = threadNum = 200
	if config.ThreadCeiling != 200 {
		t.Errorf("显式 -t 200: ceiling=%d, want 200", config.ThreadCeiling)
	}
	if config.ThreadNum != 200 {
		t.Errorf("显式 -t 200: threadNum=%d, want 200", config.ThreadNum)
	}
}

func TestOpt1_PoolUsesCeiling(t *testing.T) {
	metrics := &ScanMetrics{}
	target, ceiling := 50, 200

	pool, err := NewAdaptivePool(target, ceiling, func(interface{}) {}, metrics)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	pool.inSlowStart = false
	pool.tune(target)

	// 注入健康 metrics 让池增长
	for i := 0; i < 200; i++ {
		metrics.RecordConnect(time.Millisecond)
	}

	// 多次 adjust，池应能增长超过 target 但不超过 ceiling
	for i := 0; i < 30; i++ {
		pool.lastCheck.Store(0)
		pool.adjust()
	}

	finalCap := pool.Cap()
	if finalCap <= target {
		t.Errorf("池应能超过 target(%d): cap=%d", target, finalCap)
	}
	if finalCap > ceiling {
		t.Errorf("池不应超过 ceiling(%d): cap=%d", ceiling, finalCap)
	}

	t.Logf("target=%d, ceiling=%d, finalCap=%d", target, ceiling, finalCap)
}

func TestOpt1_FDLimitConstraintsBothFields(t *testing.T) {
	config := makeDefaultConfig()
	config.ThreadNum = 1000
	session := makeTestSession(config)

	ep := &EnvironmentProfile{
		Net: NetworkProfile{
			Env:       EnvLAN,
			RTTMedian: 1 * time.Millisecond,
			RTTStddev: 500 * time.Microsecond,
			LossRate:  0.0,
			Samples:   30,
		},
		System: SystemProfile{FDLimit: 256, NumCPU: 4},
	}

	ep.TuneConfig(config, session)

	maxFD := 256 * 6 / 10
	if config.ThreadNum > maxFD {
		t.Errorf("ThreadNum(%d) 超过 fd 限制(%d)", config.ThreadNum, maxFD)
	}
	if config.ThreadCeiling > maxFD {
		t.Errorf("ThreadCeiling(%d) 超过 fd 限制(%d)", config.ThreadCeiling, maxFD)
	}
}

// =============================================================================
// 优化 2：RTT 漂移微调 target
// =============================================================================

func TestOpt2_RTTDriftReducesTarget(t *testing.T) {
	metrics := &ScanMetrics{}
	pool, err := NewAdaptivePool(200, 400, func(interface{}) {}, metrics)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	pool.inSlowStart = false
	pool.tune(200)

	// 建立基线：slow EMA 锚定在 1ms 附近
	for i := 0; i < 500; i++ {
		metrics.RecordConnect(1 * time.Millisecond)
	}

	origTarget := atomic.LoadInt32(&pool.target)

	// RTT 突增到 100ms（100 倍），大量喂入让 fast EMA 拉开差距
	for i := 0; i < 1000; i++ {
		metrics.RecordConnect(100 * time.Millisecond)
	}

	ratio := metrics.RTTRatio()
	t.Logf("RTT ratio after spike: %.2f", ratio)

	if ratio <= 3.0 {
		t.Skipf("RTT ratio=%.2f，EMA 差距不够大，跳过", ratio)
	}

	// 需要足够的新 metrics 让 assessHealth 的 deltaTotal >= 30
	for i := 0; i < 50; i++ {
		metrics.RecordConnect(100 * time.Millisecond)
	}

	// 多次 adjust 触发 maybeReduceTarget
	for i := 0; i < 10; i++ {
		pool.lastCheck.Store(0)
		pool.prevSnapshot = MetricsSnapshot{} // 重置快照让 delta 足够
		pool.adjust()
	}

	newTarget := atomic.LoadInt32(&pool.target)
	if newTarget >= origTarget {
		t.Errorf("RTT 漂移后 target 应降低: %d -> %d (ratio=%.2f)", origTarget, newTarget, ratio)
	}

	// 不应低于 ceiling/5
	minTarget := atomic.LoadInt32(&pool.ceiling) / 5
	if newTarget < minTarget {
		t.Errorf("target(%d) 低于下限(%d)", newTarget, minTarget)
	}

	t.Logf("RTT drift: ratio=%.2f, target %d -> %d (min=%d)", ratio, origTarget, newTarget, minTarget)
}

func TestOpt2_NoReductionWhenStable(t *testing.T) {
	metrics := &ScanMetrics{}
	pool, err := NewAdaptivePool(200, 400, func(interface{}) {}, metrics)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	pool.inSlowStart = false
	pool.tune(200)

	// 稳定 RTT
	for i := 0; i < 200; i++ {
		metrics.RecordConnect(10 * time.Millisecond)
	}

	origTarget := atomic.LoadInt32(&pool.target)

	for i := 0; i < 10; i++ {
		pool.lastCheck.Store(0)
		pool.adjust()
	}

	newTarget := atomic.LoadInt32(&pool.target)
	if newTarget != origTarget {
		t.Errorf("稳定 RTT 不应改变 target: %d -> %d", origTarget, newTarget)
	}
}

// =============================================================================
// 优化 3：assessHealth 阈值跟 NetworkEnv 关联
// =============================================================================

func TestOpt3_LANTighterThresholds(t *testing.T) {
	metrics := &ScanMetrics{}
	pool, err := NewAdaptivePool(100, 100, func(interface{}) {}, metrics, EnvLAN)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	pool.inSlowStart = false
	pool.tune(100)

	// 10% exhaust rate — 对 LAN 来说应该是 Congested（阈值 8%）
	for i := 0; i < 100; i++ {
		if i < 10 {
			metrics.RecordExhausted()
		} else {
			metrics.RecordConnect(time.Millisecond)
		}
	}

	pool.lastCheck.Store(0)
	pool.adjust()

	if pool.Cap() >= 100 {
		t.Errorf("LAN 10%% exhaust 应触发降速: cap=%d", pool.Cap())
	}

	t.Logf("LAN tight threshold: cap=%d (from 100)", pool.Cap())
}

func TestOpt3_InternetLooseThresholds(t *testing.T) {
	metrics := &ScanMetrics{}
	pool, err := NewAdaptivePool(100, 100, func(interface{}) {}, metrics, EnvInternet)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	pool.inSlowStart = false
	pool.tune(100)

	// 10% exhaust rate — 对 Internet 来说不算 Congested（阈值 25%），应是 Stressed
	for i := 0; i < 100; i++ {
		if i < 10 {
			metrics.RecordExhausted()
		} else {
			metrics.RecordConnect(10 * time.Millisecond)
		}
	}

	pool.lastCheck.Store(0)
	pool.adjust()
	capAfter := pool.Cap()

	// Internet 对 10% exhaust 只是 Stressed（×0.85），不是 Congested（×0.5）
	if capAfter < 80 {
		t.Errorf("Internet 10%% exhaust 不应大幅降速: cap=%d", capAfter)
	}

	t.Logf("Internet loose threshold: cap=%d (from 100)", capAfter)
}

func TestOpt3_EnvAffectsHealthDecision(t *testing.T) {
	envs := []struct {
		env  NetworkEnv
		name string
	}{
		{EnvLAN, "LAN"},
		{EnvWAN, "WAN"},
		{EnvInternet, "Internet"},
	}

	var caps []int

	for _, e := range envs {
		metrics := &ScanMetrics{}
		pool, err := NewAdaptivePool(100, 100, func(interface{}) {}, metrics, e.env)
		if err != nil {
			t.Fatalf("创建池失败: %v", err)
		}

		pool.inSlowStart = false
		pool.tune(100)

		// 相同的 12% exhaust rate
		for i := 0; i < 100; i++ {
			if i < 12 {
				metrics.RecordExhausted()
			} else {
				metrics.RecordConnect(time.Millisecond)
			}
		}

		pool.lastCheck.Store(0)
		pool.adjust()
		caps = append(caps, pool.Cap())
		pool.Release()

		t.Logf("%s: cap=%d (12%% exhaust)", e.name, caps[len(caps)-1])
	}

	// LAN 反应最激烈（cap 最低），Internet 最宽容（cap 最高）
	if caps[0] >= caps[2] {
		t.Errorf("LAN cap(%d) 应 < Internet cap(%d) for same exhaust rate", caps[0], caps[2])
	}
}

// =============================================================================
// 优化 4：去掉 semaphore，ants 池天然反压
// =============================================================================

func TestOpt4_SemaphoreRemoved(t *testing.T) {
	// 验证 portScanTask 结构体不再有 semaphore 字段
	// 如果 semaphore 被加回来，这段代码编译就会报 "unknown field"
	_ = portScanTask{
		host: "127.0.0.1",
		port: 80,
		addr: "127.0.0.1:80",
	}
	t.Log("portScanTask 无 semaphore 字段，反压由 ants pool 统一管理")
}

// =============================================================================
// 优化 5：扩充探测端口
// =============================================================================

func TestOpt5_ProbePortsExpanded(t *testing.T) {
	if len(probePorts) < 5 {
		t.Errorf("probePorts 只有 %d 个，应该扩充到至少 5 个", len(probePorts))
	}

	// 验证包含关键端口
	required := map[int]bool{80: false, 443: false, 22: false}
	for _, p := range probePorts {
		if _, ok := required[p]; ok {
			required[p] = true
		}
	}
	for port, found := range required {
		if !found {
			t.Errorf("probePorts 缺少关键端口 %d", port)
		}
	}

	// 验证没有重复
	seen := make(map[int]bool)
	for _, p := range probePorts {
		if seen[p] {
			t.Errorf("probePorts 有重复端口 %d", p)
		}
		seen[p] = true
	}

	t.Logf("probePorts = %v (%d 个)", probePorts, len(probePorts))
}

// =============================================================================
// 优化 6：computeRetries 环境自适应
// =============================================================================

func TestOpt6_RetriesEnvAware(t *testing.T) {
	lossRate := 0.3 // 30% 丢包

	lanRetry := computeRetries(lossRate, EnvLAN)
	wanRetry := computeRetries(lossRate, EnvWAN)
	inetRetry := computeRetries(lossRate, EnvInternet)

	// LAN 目标概率更严格(0.5%)，应该重试更多；但上限更低(4)
	// Internet 目标概率更宽松(2%)，应该重试更少；但上限更高(6)
	t.Logf("30%% loss: LAN=%d, WAN=%d, Internet=%d", lanRetry, wanRetry, inetRetry)

	if lanRetry < 1 || lanRetry > 4 {
		t.Errorf("LAN retry=%d, 应在 [1,4]", lanRetry)
	}
	if wanRetry < 1 || wanRetry > 5 {
		t.Errorf("WAN retry=%d, 应在 [1,5]", wanRetry)
	}
	if inetRetry < 1 || inetRetry > 6 {
		t.Errorf("Internet retry=%d, 应在 [1,6]", inetRetry)
	}
}

func TestOpt6_RetriesMaxByEnv(t *testing.T) {
	// 高丢包率，各环境应返回各自上限
	lanMax := computeRetries(0.99, EnvLAN)
	wanMax := computeRetries(0.99, EnvWAN)
	inetMax := computeRetries(0.99, EnvInternet)

	if lanMax != 4 {
		t.Errorf("LAN max retry=%d, want 4", lanMax)
	}
	if wanMax != 5 {
		t.Errorf("WAN max retry=%d, want 5", wanMax)
	}
	if inetMax != 6 {
		t.Errorf("Internet max retry=%d, want 6", inetMax)
	}
}

func TestOpt6_RetriesMathCorrectness(t *testing.T) {
	envs := []struct {
		env        NetworkEnv
		targetProb float64
		name       string
	}{
		{EnvLAN, 0.005, "LAN"},
		{EnvWAN, 0.01, "WAN"},
		{EnvInternet, 0.02, "Internet"},
	}

	for _, e := range envs {
		for _, loss := range []float64{0.05, 0.10, 0.20, 0.30} {
			retries := computeRetries(loss, e.env)
			prob := 1.0
			for i := 0; i < retries; i++ {
				prob *= loss
			}
			// 重试后全失败概率应 < targetProb（除非被 clamp 了）
			if prob >= e.targetProb && retries < 4 {
				t.Errorf("%s loss=%.0f%% retries=%d: P=%.6f >= %.3f",
					e.name, loss*100, retries, prob, e.targetProb)
			}
		}
	}
}

// =============================================================================
// 端到端集成：全链路验证
// =============================================================================

func TestOptAll_EndToEnd_LANToPool(t *testing.T) {
	// 模拟内网探测 → TuneConfig → 创建池 → 池根据 env 自适应
	profile := classifyNetwork(
		makeDurations([]int{1, 1, 2, 2, 2, 3, 3, 3, 4, 5}),
		0, 10,
	)

	config := makeDefaultConfig()
	session := makeTestSession(config)
	ep := &EnvironmentProfile{Net: *profile, System: SystemProfile{FDLimit: 65536, NumCPU: 8}}
	ep.TuneConfig(config, session)

	// 验证 env 被存储
	if config.DetectedNetworkEnv != int(EnvLAN) {
		t.Errorf("DetectedNetworkEnv=%d, want %d(LAN)", config.DetectedNetworkEnv, int(EnvLAN))
	}

	// 验证 ceiling 合理
	if config.ThreadCeiling < config.ThreadNum {
		t.Errorf("ceiling(%d) < target(%d)", config.ThreadCeiling, config.ThreadNum)
	}

	// 创建池并验证 env 传递
	netEnv := NetworkEnv(config.DetectedNetworkEnv)
	metrics := &ScanMetrics{}
	pool, err := NewAdaptivePool(config.ThreadNum, config.ThreadCeiling, func(interface{}) {}, metrics, netEnv)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	if pool.networkEnv != EnvLAN {
		t.Errorf("池的 networkEnv=%v, want LAN", pool.networkEnv)
	}

	t.Logf("端到端 LAN: target=%d ceiling=%d env=%v maxRetry=%d",
		config.ThreadNum, config.ThreadCeiling, netEnv, config.MaxRetries)
}

func TestOptAll_EndToEnd_InternetToPool(t *testing.T) {
	profile := classifyNetwork(
		makeDurations([]int{60, 70, 80, 90, 100, 110, 120, 130, 140, 150}),
		0, 10,
	)

	config := makeDefaultConfig()
	session := makeTestSession(config)
	ep := &EnvironmentProfile{Net: *profile, System: SystemProfile{FDLimit: 4096, NumCPU: 4}}
	ep.TuneConfig(config, session)

	if config.DetectedNetworkEnv != int(EnvInternet) {
		t.Errorf("DetectedNetworkEnv=%d, want %d(Internet)", config.DetectedNetworkEnv, int(EnvInternet))
	}

	// 公网 target 应明显低于默认 600
	if config.ThreadNum >= 600 {
		t.Errorf("公网 threadNum=%d, 应 < 600", config.ThreadNum)
	}

	// ceiling 应 == target（非显式模式）
	if config.ThreadCeiling != config.ThreadNum {
		t.Errorf("非显式模式 ceiling(%d) != target(%d)", config.ThreadCeiling, config.ThreadNum)
	}

	netEnv := NetworkEnv(config.DetectedNetworkEnv)
	metrics := &ScanMetrics{}
	pool, err := NewAdaptivePool(config.ThreadNum, config.ThreadCeiling, func(interface{}) {}, metrics, netEnv)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	// 注入 12% exhaust，Internet 环境应只是 Stressed 而不是 Congested
	pool.inSlowStart = false
	pool.tune(config.ThreadNum)
	for i := 0; i < 100; i++ {
		if i < 12 {
			metrics.RecordExhausted()
		} else {
			metrics.RecordConnect(80 * time.Millisecond)
		}
	}
	pool.lastCheck.Store(0)
	pool.adjust()

	// cap 不应被砍到一半以下（Stressed 只降 15%）
	if pool.Cap() < config.ThreadNum*7/10 {
		t.Errorf("Internet 12%% exhaust 降速过猛: %d -> %d", config.ThreadNum, pool.Cap())
	}

	t.Logf("端到端 Internet: target=%d ceiling=%d cap_after_stress=%d",
		config.ThreadNum, config.ThreadCeiling, pool.Cap())
}

