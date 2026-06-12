package core

import (
	"testing"
	"time"
)

// =============================================================================
// 单元测试：classifyEnv — 网络环境分类
// =============================================================================

func TestClassifyEnv(t *testing.T) {
	tests := []struct {
		median   time.Duration
		lossRate float64
		wantEnv  NetworkEnv
		desc     string
	}{
		{1 * time.Millisecond, 0.0, EnvLAN, "1ms 零丢包 → 内网"},
		{3 * time.Millisecond, 0.005, EnvLAN, "3ms 0.5%丢包 → 内网"},
		{5 * time.Millisecond, 0.0, EnvWAN, "5ms 零丢包 → 局域网边界"},
		{20 * time.Millisecond, 0.02, EnvWAN, "20ms 2%丢包 → 局域网"},
		{50 * time.Millisecond, 0.03, EnvInternet, "50ms 3%丢包 → 公网边界"},
		{100 * time.Millisecond, 0.05, EnvInternet, "100ms 5%丢包 → 公网"},
		{300 * time.Millisecond, 0.05, EnvSlow, "300ms → 慢速"},
		{50 * time.Millisecond, 0.15, EnvSlow, "50ms 15%丢包 → 高丢包归类慢速"},
		{1 * time.Millisecond, 0.20, EnvSlow, "低延迟但高丢包 → 慢速"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := classifyEnv(tt.median, tt.lossRate)
			if got != tt.wantEnv {
				t.Errorf("classifyEnv(median=%v, loss=%.2f) = %v, want %v",
					tt.median, tt.lossRate, got, tt.wantEnv)
			}
		})
	}
}

// =============================================================================
// 单元测试：classifyNetwork — 从 RTT 样本推导 profile
// =============================================================================

func TestClassifyNetwork(t *testing.T) {
	t.Run("内网 RTT 分布", func(t *testing.T) {
		rtts := makeDurations([]int{1, 1, 1, 2, 2, 2, 3, 3, 4, 5}) // ms
		p := classifyNetwork(rtts, 0, 10)

		if p.Env != EnvLAN {
			t.Errorf("env = %v, want LAN", p.Env)
		}
		if p.RTTMedian > 5*time.Millisecond {
			t.Errorf("median = %v, want < 5ms", p.RTTMedian)
		}
		if p.LossRate != 0 {
			t.Errorf("lossRate = %.2f, want 0", p.LossRate)
		}
	})

	t.Run("公网 RTT 分布（低丢包）", func(t *testing.T) {
		rtts := makeDurations([]int{60, 70, 80, 90, 100, 110, 120, 150, 200, 300}) // ms
		p := classifyNetwork(rtts, 0, 10) // 无丢包

		if p.Env != EnvInternet {
			t.Errorf("env = %v, want Internet", p.Env)
		}
		if p.LossRate != 0 {
			t.Errorf("lossRate = %.2f, want 0", p.LossRate)
		}
	})

	t.Run("高丢包归类为慢速", func(t *testing.T) {
		rtts := makeDurations([]int{60, 70, 80, 90, 100}) // ms, 5 responded
		p := classifyNetwork(rtts, 5, 10)                  // 50% loss

		if p.Env != EnvSlow {
			t.Errorf("env = %v, want Slow (高丢包)", p.Env)
		}
	})

	t.Run("零样本降级", func(t *testing.T) {
		p := classifyNetwork(nil, 5, 5)
		if p.Env != EnvWAN {
			t.Errorf("env = %v, want WAN (default)", p.Env)
		}
		if p.Samples != 0 {
			t.Errorf("samples = %d, want 0", p.Samples)
		}
	})
}

// =============================================================================
// 单元测试：RecommendConcurrency
// =============================================================================

func TestRecommendConcurrency(t *testing.T) {
	tests := []struct {
		env       NetworkEnv
		lossRate  float64
		userT     int
		explicit  bool
		wantTMin  int
		wantTMax  int
		wantCeil  int
		desc      string
	}{
		{EnvLAN, 0.0, 600, false, 800, 1000, -1, "内网自动: ×1.5"},
		{EnvWAN, 0.0, 600, false, 550, 650, -1, "局域网自动: ×1.0"},
		{EnvInternet, 0.0, 600, false, 200, 280, -1, "公网自动: ×0.4"},
		{EnvSlow, 0.0, 600, false, 80, 100, -1, "慢速自动: ×0.15"},
		{EnvInternet, 0.0, 200, true, 70, 100, 200, "公网显式: target<ceiling"},
		{EnvLAN, 0.0, 100, true, 100, 160, 100, "内网显式: ceiling=用户值"},
		{EnvInternet, 0.15, 600, false, 170, 240, -1, "公网高丢包: 进一步压缩"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			p := &NetworkProfile{Env: tt.env, LossRate: tt.lossRate, Samples: 10}
			target, ceiling := p.RecommendConcurrency(tt.userT, tt.explicit)

			if target < tt.wantTMin || target > tt.wantTMax {
				t.Errorf("target = %d, want [%d, %d]", target, tt.wantTMin, tt.wantTMax)
			}

			if tt.explicit && ceiling != tt.wantCeil {
				t.Errorf("ceiling = %d, want %d", ceiling, tt.wantCeil)
			}
		})
	}
}

// =============================================================================
// 单元测试：pickSamples
// =============================================================================

func TestPickSamples(t *testing.T) {
	hosts := make([]string, 100)
	for i := range hosts {
		hosts[i] = "host"
	}

	s := pickSamples(hosts, 10)
	if len(s) != 10 {
		t.Errorf("pickSamples(100, 10) = %d items, want 10", len(s))
	}

	s = pickSamples(hosts[:5], 10)
	if len(s) != 5 {
		t.Errorf("pickSamples(5, 10) = %d items, want 5", len(s))
	}

	s = pickSamples(nil, 10)
	if len(s) != 0 {
		t.Errorf("pickSamples(nil, 10) = %d items, want 0", len(s))
	}
}

// =============================================================================
// 辅助
// =============================================================================

func makeDurations(ms []int) []time.Duration {
	ds := make([]time.Duration, len(ms))
	for i, m := range ms {
		ds[i] = time.Duration(m) * time.Millisecond
	}
	return ds
}
