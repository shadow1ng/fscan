package core

import (
	"math"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// computeRetries 边界
// =============================================================================

func TestComputeRetries_EdgeCases(t *testing.T) {
	tests := []struct {
		lossRate float64
		wantMin  int
		wantMax  int
		desc     string
	}{
		{-0.5, 1, 1, "负数丢包率: 视为零"},
		{-1.0, 1, 1, "负一: 视为零"},
		{0.0, 1, 1, "精确零"},
		{0.001, 1, 1, "精确边界 0.001"},
		{0.0009, 1, 1, "低于 0.001 边界"},
		{0.0011, 1, 6, "高于 0.001 边界"},
		{0.95, 6, 6, "精确边界 0.95"},
		{0.949, 1, 6, "低于 0.95 边界"},
		{0.951, 6, 6, "高于 0.95 边界"},
		{1.0, 6, 6, "精确 1.0"},
		{1.5, 6, 6, "超过 1.0"},
		{100.0, 6, 6, "极大值"},
		{math.SmallestNonzeroFloat64, 1, 1, "最小正浮点数"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := computeRetries(tt.lossRate)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("computeRetries(%v) = %d, want [%d, %d]",
					tt.lossRate, got, tt.wantMin, tt.wantMax)
			}
			if got < 1 || got > 6 {
				t.Errorf("computeRetries(%v) = %d, 超出 [1,6] 范围", tt.lossRate, got)
			}
		})
	}
}

func TestComputeRetries_NaN_Inf(t *testing.T) {
	// 确保不 panic
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		got := computeRetries(v)
		if got < 1 || got > 6 {
			t.Errorf("computeRetries(%v) = %d, 超出 [1,6] 范围", v, got)
		}
	}
}

// =============================================================================
// computeICMPRate 边界
// =============================================================================

func TestComputeICMPRate_EdgeCases(t *testing.T) {
	tests := []struct {
		env     NetworkEnv
		fdLimit int
		desc    string
	}{
		{EnvLAN, 1, "fd=1: 极小"},
		{EnvLAN, -1, "fd=负数: 应被忽略"},
		{EnvLAN, 0, "fd=0: 未知"},
		{EnvLAN, math.MaxInt32, "fd=极大"},
		{NetworkEnv(99), 1024, "未知环境类型"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			net := &NetworkProfile{Env: tt.env}
			sys := &SystemProfile{FDLimit: tt.fdLimit}
			got := computeICMPRate(net, sys)
			if got <= 0 || math.IsNaN(got) || math.IsInf(got, 0) {
				t.Errorf("computeICMPRate(env=%v, fd=%d) = %v, 无效值", tt.env, tt.fdLimit, got)
			}
		})
	}
}

// =============================================================================
// classifyEnv 精确边界值
// =============================================================================

func TestClassifyEnv_ExactBoundaries(t *testing.T) {
	tests := []struct {
		median   time.Duration
		lossRate float64
		want     NetworkEnv
		desc     string
	}{
		// RTT 边界
		{4999 * time.Microsecond, 0.0, EnvLAN, "4.999ms → LAN"},
		{5 * time.Millisecond, 0.0, EnvWAN, "精确 5ms → WAN"},
		{49999 * time.Microsecond, 0.0, EnvWAN, "49.999ms → WAN"},
		{50 * time.Millisecond, 0.0, EnvInternet, "精确 50ms → Internet"},
		{199999 * time.Microsecond, 0.0, EnvInternet, "199.999ms → Internet"},
		{200 * time.Millisecond, 0.0, EnvSlow, "精确 200ms → Slow"},

		// 丢包率边界
		{1 * time.Millisecond, 0.009, EnvLAN, "丢包 0.9% → LAN"},
		{1 * time.Millisecond, 0.01, EnvWAN, "精确 1% → WAN (不满足 < 0.01)"},
		{1 * time.Millisecond, 0.011, EnvWAN, "丢包 1.1% → WAN (超过 LAN 阈值)"},
		{20 * time.Millisecond, 0.049, EnvWAN, "丢包 4.9% → WAN"},
		{20 * time.Millisecond, 0.05, EnvInternet, "精确 5% → Internet (不满足 < 0.05)"},
		{20 * time.Millisecond, 0.051, EnvInternet, "丢包 5.1% → Internet"},
		{1 * time.Millisecond, 0.099, EnvInternet, "丢包 9.9% → Internet"},
		{1 * time.Millisecond, 0.10, EnvInternet, "精确 10% → Internet (< 判断)"},
		{1 * time.Millisecond, 0.101, EnvSlow, "丢包 10.1% → Slow"},

		// 零值
		{0, 0.0, EnvLAN, "零 RTT 零丢包 → LAN"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := classifyEnv(tt.median, tt.lossRate)
			if got != tt.want {
				t.Errorf("classifyEnv(median=%v, loss=%.4f) = %v, want %v",
					tt.median, tt.lossRate, got, tt.want)
			}
		})
	}
}

// =============================================================================
// classifyNetwork 边界
// =============================================================================

func TestClassifyNetwork_EdgeCases(t *testing.T) {
	t.Run("单个 RTT 样本", func(t *testing.T) {
		p := classifyNetwork([]time.Duration{5 * time.Millisecond}, 0, 1)
		if p.Samples != 1 {
			t.Errorf("samples = %d, want 1", p.Samples)
		}
		// stddev 应该是 0
		if p.RTTStddev != 0 {
			t.Errorf("单样本 stddev = %v, want 0", p.RTTStddev)
		}
	})

	t.Run("所有 RTT 相同", func(t *testing.T) {
		rtts := make([]time.Duration, 50)
		for i := range rtts {
			rtts[i] = 10 * time.Millisecond
		}
		p := classifyNetwork(rtts, 0, 50)
		if p.RTTStddev != 0 {
			t.Errorf("全相同 RTT stddev = %v, want 0", p.RTTStddev)
		}
		if p.RTTMedian != 10*time.Millisecond {
			t.Errorf("median = %v, want 10ms", p.RTTMedian)
		}
	})

	t.Run("极大 RTT 值", func(t *testing.T) {
		rtts := []time.Duration{time.Hour, time.Hour, time.Hour}
		p := classifyNetwork(rtts, 0, 3)
		if p.Env != EnvSlow {
			t.Errorf("env = %v, want Slow", p.Env)
		}
	})

	t.Run("混合极端值", func(t *testing.T) {
		rtts := []time.Duration{time.Microsecond, time.Hour}
		p := classifyNetwork(rtts, 0, 2)
		// 不 panic 就行
		if p.Samples != 2 {
			t.Errorf("samples = %d, want 2", p.Samples)
		}
	})

	t.Run("全部失败无响应", func(t *testing.T) {
		p := classifyNetwork(nil, 100, 100)
		if p.Env != EnvWAN {
			t.Errorf("env = %v, want WAN (default)", p.Env)
		}
	})

	t.Run("failures > total (异常输入)", func(t *testing.T) {
		rtts := []time.Duration{time.Millisecond}
		p := classifyNetwork(rtts, 10, 5) // failures > total
		// lossRate = 1 - 1/5 = 0.8, 不应 panic
		if p.LossRate < 0 {
			t.Errorf("lossRate = %.2f, 不应为负", p.LossRate)
		}
	})

	t.Run("total=0", func(t *testing.T) {
		p := classifyNetwork(nil, 0, 0)
		// 不 panic
		if p.Samples != 0 {
			t.Errorf("samples = %d, want 0", p.Samples)
		}
	})
}

// =============================================================================
// RecommendConcurrency 边界
// =============================================================================

func TestRecommendConcurrency_EdgeCases(t *testing.T) {
	tests := []struct {
		env      NetworkEnv
		loss     float64
		userT    int
		explicit bool
		desc     string
	}{
		{EnvLAN, 0.0, 0, false, "userThreadNum=0"},
		{EnvLAN, 0.0, 1, false, "userThreadNum=1"},
		{EnvLAN, 0.0, -1, false, "userThreadNum 负数"},
		{EnvLAN, 0.0, math.MaxInt32, false, "userThreadNum 极大"},
		{EnvLAN, 0.99, 600, false, "99% 丢包"},
		{EnvLAN, 1.0, 600, false, "100% 丢包"},
		{EnvSlow, 0.0, 1, true, "慢速+显式+1"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			p := &NetworkProfile{Env: tt.env, LossRate: tt.loss, Samples: 10}
			target, ceiling := p.RecommendConcurrency(tt.userT, tt.explicit)
			// 不 panic，且 target >= 1（clamp 保底 10 或 userT）
			if target < 0 || ceiling < 0 {
				t.Errorf("target=%d ceiling=%d, 不应为负", target, ceiling)
			}
			if tt.explicit && ceiling != tt.userT && tt.userT > 0 {
				t.Errorf("显式模式 ceiling=%d, want %d", ceiling, tt.userT)
			}
			t.Logf("env=%v loss=%.2f userT=%d explicit=%v → target=%d ceiling=%d",
				tt.env, tt.loss, tt.userT, tt.explicit, target, ceiling)
		})
	}
}

// =============================================================================
// ScanMetrics 边界
// =============================================================================

func TestScanMetrics_EdgeCases(t *testing.T) {
	t.Run("RTT=0", func(t *testing.T) {
		m := &ScanMetrics{}
		m.RecordConnect(0)
		// 不 panic
		if m.Total() != 1 {
			t.Errorf("Total = %d, want 1", m.Total())
		}
	})

	t.Run("负数 RTT", func(t *testing.T) {
		m := &ScanMetrics{}
		m.RecordConnect(-time.Millisecond)
		// 不 panic，负数 RTT 应被忽略
		if m.rttSamples.Load() != 0 {
			t.Errorf("负数 RTT 不应计入采样: got %d", m.rttSamples.Load())
		}
	})

	t.Run("极大 RTT", func(t *testing.T) {
		m := &ScanMetrics{}
		m.RecordConnect(time.Hour)
		if m.RTTFast() != time.Hour {
			t.Errorf("首个样本 RTTFast = %v, want 1h", m.RTTFast())
		}
	})

	t.Run("EMA 首个样本初始化", func(t *testing.T) {
		m := &ScanMetrics{}
		m.RecordConnect(10 * time.Millisecond)
		if m.rttFastNs.Load() != int64(10*time.Millisecond) {
			t.Errorf("首个样本应直接设置 EMA: got %d", m.rttFastNs.Load())
		}
	})

	t.Run("空 Snapshot", func(t *testing.T) {
		m := &ScanMetrics{}
		snap := m.Snapshot()
		if snap.Total() != 0 {
			t.Errorf("空 metrics Snapshot.Total = %d, want 0", snap.Total())
		}
	})

	t.Run("RTTRatio 单侧为零", func(t *testing.T) {
		m := &ScanMetrics{}
		// 手动设置一个但不设另一个——不应该发生，但防御
		m.rttFastNs.Store(1000)
		m.rttSlowNs.Store(0)
		m.rttSamples.Store(30)
		ratio := m.RTTRatio()
		if ratio != 1.0 {
			t.Errorf("slow=0 时 ratio = %.2f, want 1.0", ratio)
		}
	})

	t.Run("大量操作不溢出", func(t *testing.T) {
		m := &ScanMetrics{}
		for i := 0; i < 100000; i++ {
			m.RecordConnect(time.Millisecond)
		}
		if m.Total() != 100000 {
			t.Errorf("Total = %d, want 100000", m.Total())
		}
		ratio := m.RTTRatio()
		if math.IsNaN(ratio) || math.IsInf(ratio, 0) {
			t.Errorf("大量样本后 ratio = %v, 不应为 NaN/Inf", ratio)
		}
	})
}

// =============================================================================
// TuneConfig 边界
// =============================================================================

func TestTuneConfig_EdgeCases(t *testing.T) {
	t.Run("RTTMedian=0 RTTStddev=0", func(t *testing.T) {
		config := makeDefaultConfig()
		session := makeTestSession(config)
		ep := &EnvironmentProfile{
			Net:    NetworkProfile{Env: EnvLAN, RTTMedian: 0, RTTStddev: 0, Samples: 10},
			System: SystemProfile{FDLimit: 65536},
		}
		ep.TuneConfig(config, session)
		// Timeout: median(0) + 4*stddev(0) = 0 → minTO = 0+200ms → clamp to 1s
		if config.Timeout < time.Second {
			t.Errorf("零 RTT Timeout = %v, 应该 >= 1s", config.Timeout)
		}
	})

	t.Run("RTTStddev 远大于 RTTMedian", func(t *testing.T) {
		config := makeDefaultConfig()
		session := makeTestSession(config)
		ep := &EnvironmentProfile{
			Net:    NetworkProfile{Env: EnvInternet, RTTMedian: 10 * time.Millisecond, RTTStddev: 5 * time.Second, Samples: 10},
			System: SystemProfile{FDLimit: 65536},
		}
		ep.TuneConfig(config, session)
		// Timeout = 10ms + 4*5s = 20.01s → clamp to 10s
		if config.Timeout != 10*time.Second {
			t.Errorf("极大 stddev Timeout = %v, 应该被 clamp 到 10s", config.Timeout)
		}
	})

	t.Run("ThreadNum=0", func(t *testing.T) {
		config := makeDefaultConfig()
		config.ThreadNum = 0
		session := makeTestSession(config)
		ep := &EnvironmentProfile{
			Net:    NetworkProfile{Env: EnvLAN, RTTMedian: time.Millisecond, RTTStddev: time.Millisecond, Samples: 10},
			System: SystemProfile{FDLimit: 65536},
		}
		ep.TuneConfig(config, session)
		// ModuleThreadNum = 0/30 = 0 → clamp to 5
		if config.ModuleThreadNum < 5 {
			t.Errorf("ThreadNum=0 时 ModuleThreadNum = %d, 应该 >= 5", config.ModuleThreadNum)
		}
	})

	t.Run("多次调用 TuneConfig", func(t *testing.T) {
		config := makeDefaultConfig()
		session := makeTestSession(config)
		ep := &EnvironmentProfile{
			Net:    NetworkProfile{Env: EnvLAN, RTTMedian: time.Millisecond, RTTStddev: time.Millisecond, LossRate: 0.0, Samples: 10},
			System: SystemProfile{FDLimit: 65536},
		}

		ep.TuneConfig(config, session)
		first := config.Timeout

		// 第二次调用——已经调整过的值不等于默认值，应被视为"显式"
		ep.TuneConfig(config, session)
		second := config.Timeout

		if first != second {
			t.Errorf("多次调用 TuneConfig 不应重复调整: %v vs %v", first, second)
		}
	})

	t.Run("fd limit = ThreadNum 精确值", func(t *testing.T) {
		config := makeDefaultConfig()
		config.ThreadNum = 600
		session := makeTestSession(config)
		ep := &EnvironmentProfile{
			Net:    NetworkProfile{Samples: 0},
			System: SystemProfile{FDLimit: 1000}, // 1000 * 0.6 = 600
		}
		ep.TuneConfig(config, session)
		// ThreadNum(600) == maxConcurrency(600), 不应触发约束
		if config.ThreadNum != 600 {
			t.Errorf("fd=1000 时 ThreadNum = %d, 不应被约束", config.ThreadNum)
		}
	})

	t.Run("fd limit 精确低于 ThreadNum", func(t *testing.T) {
		config := makeDefaultConfig()
		config.ThreadNum = 600
		session := makeTestSession(config)
		ep := &EnvironmentProfile{
			Net:    NetworkProfile{Samples: 0},
			System: SystemProfile{FDLimit: 999}, // 999 * 0.6 = 599
		}
		ep.TuneConfig(config, session)
		if config.ThreadNum > 599 {
			t.Errorf("fd=999 时 ThreadNum = %d, 应该 <= 599", config.ThreadNum)
		}
	})
}

// =============================================================================
// AdaptivePool 边界
// =============================================================================

func TestAdaptivePool_EdgeCases(t *testing.T) {
	t.Run("target=1", func(t *testing.T) {
		metrics := &ScanMetrics{}
		pool, err := NewAdaptivePool(1, 1, func(interface{}) {}, metrics)
		if err != nil {
			t.Fatalf("创建失败: %v", err)
		}
		defer pool.Release()
		// initial = max(1/4, 10) = 10 → 但 10 > target(1)... 看实现
		// 实际上 initial = min(max(1/4, 10), 1) = 1... 不对
		// initial = target/4 = 0, 但 < 10, 所以 initial = 10
		// 但 initial > target(1)... initial = min(10, 1) = 1
		// 看代码：if initial > target { initial = target }
		if pool.Cap() != 1 {
			t.Errorf("target=1 时 cap = %d, want 1", pool.Cap())
		}
	})

	t.Run("target=0", func(t *testing.T) {
		metrics := &ScanMetrics{}
		pool, err := NewAdaptivePool(0, 0, func(interface{}) {}, metrics)
		// ants 可能拒绝 size=0
		if err != nil {
			t.Logf("target=0 正确返回错误: %v", err)
			return
		}
		defer pool.Release()
		t.Logf("target=0 cap = %d", pool.Cap())
	})

	t.Run("ceiling < target", func(t *testing.T) {
		metrics := &ScanMetrics{}
		pool, err := NewAdaptivePool(100, 50, func(interface{}) {}, metrics)
		if err != nil {
			t.Fatalf("创建失败: %v", err)
		}
		defer pool.Release()
		// initial = 100/4 = 25, 不超过 ceiling
		if pool.Cap() > 50 {
			t.Errorf("ceiling=50 但 cap = %d", pool.Cap())
		}
	})

	t.Run("高频 Invoke 不 panic", func(t *testing.T) {
		metrics := &ScanMetrics{}
		pool, err := NewAdaptivePool(10, 10, func(interface{}) {
			time.Sleep(time.Millisecond)
		}, metrics)
		if err != nil {
			t.Fatalf("创建失败: %v", err)
		}
		defer pool.Release()
		pool.inSlowStart = false
		pool.tune(10)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = pool.Invoke(nil)
			}()
		}
		wg.Wait()
		pool.Wait()
	})

	t.Run("assessHealth 零增量", func(t *testing.T) {
		metrics := &ScanMetrics{}
		pool, err := NewAdaptivePool(100, 100, func(interface{}) {}, metrics)
		if err != nil {
			t.Fatalf("创建失败: %v", err)
		}
		defer pool.Release()

		// 初始化 prevSnapshot 后不产生新数据
		pool.prevSnapshot = metrics.Snapshot()
		health := pool.assessHealth()
		if health != HealthUnknown {
			t.Errorf("零增量应返回 HealthUnknown, got %v", health)
		}
	})
}

// =============================================================================
// pickSamples 边界
// =============================================================================

func TestPickSamples_EdgeCases(t *testing.T) {
	t.Run("maxSamples=0", func(t *testing.T) {
		s := pickSamples([]string{"a", "b"}, 0)
		if len(s) != 0 {
			t.Errorf("maxSamples=0 应返回空, got %d", len(s))
		}
	})

	t.Run("maxSamples=1", func(t *testing.T) {
		s := pickSamples([]string{"a", "b", "c"}, 1)
		if len(s) != 1 {
			t.Errorf("maxSamples=1 应返回 1 个, got %d", len(s))
		}
	})

	t.Run("hosts 等于 maxSamples", func(t *testing.T) {
		hosts := []string{"a", "b", "c"}
		s := pickSamples(hosts, 3)
		if len(s) != 3 {
			t.Errorf("应返回全部, got %d", len(s))
		}
	})
}

// =============================================================================
// isTimeoutError / isConnectionRefused 边界
// =============================================================================

func TestIsTimeoutError_EdgeCases(t *testing.T) {
	if isTimeoutError(nil) {
		t.Error("nil 不应判为 timeout")
	}
}

func TestIsConnectionRefused_EdgeCases(t *testing.T) {
	if isConnectionRefused(nil) {
		t.Error("nil 不应判为 refused")
	}
}

// =============================================================================
// NetworkEnv.String 覆盖
// =============================================================================

func TestNetworkEnv_String(t *testing.T) {
	for _, env := range []NetworkEnv{EnvLAN, EnvWAN, EnvInternet, EnvSlow} {
		s := env.String()
		if s == "" {
			t.Errorf("NetworkEnv(%d).String() = 空", env)
		}
	}
	// 未知值
	s := NetworkEnv(99).String()
	if s == "" {
		t.Error("未知 NetworkEnv.String() = 空")
	}
}

// =============================================================================
// clampInt / clampDuration 边界
// =============================================================================

func TestClampInt(t *testing.T) {
	tests := []struct {
		v, min, max, want int
	}{
		{5, 1, 10, 5},
		{0, 1, 10, 1},
		{15, 1, 10, 10},
		{-5, -10, -1, -5},
		{5, 5, 5, 5},  // min == max == v
		{3, 5, 5, 5},  // v < min == max
		{10, 5, 5, 5}, // v > min == max
	}

	for _, tt := range tests {
		got := clampInt(tt.v, tt.min, tt.max)
		if got != tt.want {
			t.Errorf("clampInt(%d, %d, %d) = %d, want %d", tt.v, tt.min, tt.max, got, tt.want)
		}
	}
}

func TestClampDuration(t *testing.T) {
	got := clampDuration(5*time.Second, time.Second, 10*time.Second)
	if got != 5*time.Second {
		t.Errorf("got %v, want 5s", got)
	}
	got = clampDuration(0, time.Second, 10*time.Second)
	if got != time.Second {
		t.Errorf("got %v, want 1s", got)
	}
	got = clampDuration(time.Hour, time.Second, 10*time.Second)
	if got != 10*time.Second {
		t.Errorf("got %v, want 10s", got)
	}
}

// =============================================================================
// isExplicit 边界
// =============================================================================

func TestIsExplicit(t *testing.T) {
	config := makeDefaultConfig()
	// 默认值 → 非显式
	if isExplicit(config, "time") {
		t.Error("默认 Timeout 不应视为显式")
	}
	if isExplicit(config, "mt") {
		t.Error("默认 ModuleThreadNum 不应视为显式")
	}
	if isExplicit(config, "retry") {
		t.Error("默认 MaxRetries 不应视为显式")
	}
	if isExplicit(config, "icmp-rate") {
		t.Error("默认 ICMPRate 不应视为显式")
	}
	if isExplicit(config, "num") {
		t.Error("默认 PocNum 不应视为显式")
	}

	// 未知 flag
	if isExplicit(config, "nonexistent") {
		t.Error("未知 flag 不应视为显式")
	}

	// ThreadNumExplicit
	config.ThreadNumExplicit = true
	if !isExplicit(config, "t") {
		t.Error("ThreadNumExplicit=true 应视为显式")
	}

	config = makeDefaultConfig()
	config.TimeoutExplicit = true
	config.ModuleThreadNumExplicit = true
	config.MaxRetriesExplicit = true
	config.Network.ICMPRateExplicit = true
	config.POC.NumExplicit = true
	if !isExplicit(config, "time") || !isExplicit(config, "mt") ||
		!isExplicit(config, "retry") || !isExplicit(config, "icmp-rate") ||
		!isExplicit(config, "num") {
		t.Error("显式标记为 true 时默认值也应视为显式")
	}
}
