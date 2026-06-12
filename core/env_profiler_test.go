package core

import (
	"math"
	"testing"
	"time"

	"github.com/shadow1ng/fscan/common"
)

// =============================================================================
// 单元测试：computeRetries — 丢包率到重试次数的推导
// =============================================================================

func TestComputeRetries(t *testing.T) {
	tests := []struct {
		lossRate float64
		wantMin  int
		wantMax  int
		desc     string
	}{
		{0.0, 1, 1, "零丢包: 只需 1 次"},
		{0.001, 1, 1, "极低丢包: 1 次"},
		{0.05, 2, 2, "5% 丢包: 0.05^2=0.0025 < 0.01"},
		{0.10, 2, 3, "10% 丢包: ceil(log(0.01)/log(0.1))=2, 但边界取 ceil 可能是 3"},
		{0.20, 3, 3, "20% 丢包: 0.2^3=0.008 < 0.01"},
		{0.30, 3, 4, "30% 丢包"},
		{0.50, 6, 6, "50% 丢包: ceil(log(0.01)/log(0.5))=7 但上限 6"},
		{0.80, 6, 6, "80% 丢包: 需要很多次但上限 6"},
		{0.95, 6, 6, "95% 丢包: 触顶"},
		{1.0, 6, 6, "100% 丢包: 触顶"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := computeRetries(tt.lossRate)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("computeRetries(%.2f) = %d, want [%d, %d]",
					tt.lossRate, got, tt.wantMin, tt.wantMax)
			}

			// 验证数学正确性：lossRate^got < 0.01
			// 跳过：零丢包、极高丢包（触顶上限 6 时数学不满足，属于设计取舍）
			if tt.lossRate > 0.001 && tt.lossRate < 0.45 {
				prob := math.Pow(tt.lossRate, float64(got))
				if prob >= 0.01 {
					t.Errorf("lossRate=%.2f retries=%d: P(全失败)=%.4f >= 0.01, 重试不够",
						tt.lossRate, got, prob)
				}
			}
		})
	}
}

// =============================================================================
// 单元测试：computeICMPRate
// =============================================================================

func TestComputeICMPRate(t *testing.T) {
	tests := []struct {
		env     NetworkEnv
		fdLimit int
		wantMin float64
		wantMax float64
		desc    string
	}{
		{EnvLAN, 65536, 0.4, 0.6, "内网高 fd: 高速"},
		{EnvWAN, 65536, 0.2, 0.4, "局域网高 fd: 中速"},
		{EnvInternet, 65536, 0.05, 0.15, "公网: 保守"},
		{EnvSlow, 65536, 0.03, 0.08, "慢速: 极保守"},
		{EnvLAN, 256, 0.01, 0.2, "内网低 fd: 受限"},
		{EnvLAN, 0, 0.4, 0.6, "fd 未知: 按环境"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			net := &NetworkProfile{Env: tt.env}
			sys := &SystemProfile{FDLimit: tt.fdLimit}
			got := computeICMPRate(net, sys)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("computeICMPRate(env=%v, fd=%d) = %.3f, want [%.3f, %.3f]",
					tt.env, tt.fdLimit, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

// =============================================================================
// 集成测试：TuneConfig — 完整参数调整流程
// =============================================================================

func TestTuneConfig_LAN(t *testing.T) {
	config := makeDefaultConfig()
	session := makeTestSession(config)

	ep := &EnvironmentProfile{
		Net: NetworkProfile{
			Env:       EnvLAN,
			RTTMin:    500 * time.Microsecond,
			RTTMedian: 1 * time.Millisecond,
			RTTP95:    3 * time.Millisecond,
			RTTStddev: 500 * time.Microsecond,
			LossRate:  0.0,
			Samples:   30,
		},
		System: SystemProfile{FDLimit: 65536, NumCPU: 8},
	}

	ep.TuneConfig(config, session)

	// Timeout: median(1ms) + 4*stddev(0.5ms) = 3ms → clamp to 1s 下限
	if config.Timeout < time.Second || config.Timeout > 2*time.Second {
		t.Errorf("LAN Timeout = %v, 内网应该在 1-2s", config.Timeout)
	}

	// MaxRetries: 零丢包 → 1
	if config.MaxRetries != 1 {
		t.Errorf("LAN MaxRetries = %d, 零丢包应该是 1", config.MaxRetries)
	}

	// ICMPRate: 内网应该比默认 0.1 高
	if config.Network.ICMPRate <= 0.1 {
		t.Errorf("LAN ICMPRate = %.2f, 应该 > 0.1", config.Network.ICMPRate)
	}

	// ModuleThreadNum: 基于 ThreadNum/30
	if config.ModuleThreadNum < 5 {
		t.Errorf("LAN ModuleThreadNum = %d, 应该 >= 5", config.ModuleThreadNum)
	}

	t.Logf("LAN 参数: Timeout=%v, MT=%d, Retry=%d, ICMP=%.2f, POC=%d",
		config.Timeout, config.ModuleThreadNum, config.MaxRetries, config.Network.ICMPRate, config.POC.Num)
}

func TestTuneConfig_Internet(t *testing.T) {
	config := makeDefaultConfig()
	session := makeTestSession(config)

	ep := &EnvironmentProfile{
		Net: NetworkProfile{
			Env:       EnvInternet,
			RTTMin:    50 * time.Millisecond,
			RTTMedian: 100 * time.Millisecond,
			RTTP95:    250 * time.Millisecond,
			RTTStddev: 40 * time.Millisecond,
			LossRate:  0.08,
			Samples:   25,
		},
		System: SystemProfile{FDLimit: 1024, NumCPU: 4},
	}

	ep.TuneConfig(config, session)

	// Timeout: median(100ms) + 4*stddev(40ms) = 260ms → 但 minTO = 3*100+200 = 500ms
	if config.Timeout < 500*time.Millisecond || config.Timeout > 5*time.Second {
		t.Errorf("Internet Timeout = %v, 公网应该在 500ms-5s", config.Timeout)
	}

	// MaxRetries: 8% 丢包 → ceil(log(0.01)/log(0.08)) ≈ 2
	if config.MaxRetries < 2 || config.MaxRetries > 3 {
		t.Errorf("Internet MaxRetries = %d, 8%%丢包应该是 2-3", config.MaxRetries)
	}

	// ICMPRate: 公网应该偏低
	if config.Network.ICMPRate > 0.2 {
		t.Errorf("Internet ICMPRate = %.2f, 应该 <= 0.2", config.Network.ICMPRate)
	}

	t.Logf("Internet 参数: Timeout=%v, MT=%d, Retry=%d, ICMP=%.2f, POC=%d",
		config.Timeout, config.ModuleThreadNum, config.MaxRetries, config.Network.ICMPRate, config.POC.Num)
}

func TestTuneConfig_SlowLossy(t *testing.T) {
	config := makeDefaultConfig()
	session := makeTestSession(config)

	ep := &EnvironmentProfile{
		Net: NetworkProfile{
			Env:       EnvSlow,
			RTTMin:    200 * time.Millisecond,
			RTTMedian: 500 * time.Millisecond,
			RTTP95:    2 * time.Second,
			RTTStddev: 300 * time.Millisecond,
			LossRate:  0.25,
			Samples:   15,
		},
		System: SystemProfile{FDLimit: 512, NumCPU: 2},
	}

	ep.TuneConfig(config, session)

	// Timeout: median(500ms) + 4*stddev(300ms) = 1700ms, minTO = 500*3+200 = 1700ms
	if config.Timeout < time.Second {
		t.Errorf("Slow Timeout = %v, 慢速网络应该 >= 1s", config.Timeout)
	}

	// MaxRetries: 25% 丢包 → ceil(log(0.01)/log(0.25)) ≈ 4
	if config.MaxRetries < 3 || config.MaxRetries > 5 {
		t.Errorf("Slow MaxRetries = %d, 25%%丢包应该是 3-5", config.MaxRetries)
	}

	// ICMPRate: 慢速 + 低 fd → 应该很低
	if config.Network.ICMPRate > 0.1 {
		t.Errorf("Slow ICMPRate = %.2f, 应该 <= 0.1", config.Network.ICMPRate)
	}

	t.Logf("Slow 参数: Timeout=%v, MT=%d, Retry=%d, ICMP=%.2f, POC=%d",
		config.Timeout, config.ModuleThreadNum, config.MaxRetries, config.Network.ICMPRate, config.POC.Num)
}

// =============================================================================
// 集成测试：用户显式指定时不覆盖
// =============================================================================

func TestTuneConfig_ExplicitOverride(t *testing.T) {
	config := makeDefaultConfig()
	config.Timeout = 5 * time.Second       // 用户设了 -time 5
	config.ModuleThreadNum = 50            // 用户设了 -mt 50
	config.MaxRetries = 1                  // 用户设了 -retry 1
	config.Network.ICMPRate = 0.8          // 用户设了 -icmp-rate 0.8
	config.POC.Num = 100                   // 用户设了 -num 100
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

	// 所有非默认值都不应被覆盖
	if config.Timeout != 5*time.Second {
		t.Errorf("用户 Timeout 被覆盖: %v", config.Timeout)
	}
	if config.ModuleThreadNum != 50 {
		t.Errorf("用户 ModuleThreadNum 被覆盖: %d", config.ModuleThreadNum)
	}
	if config.MaxRetries != 1 {
		t.Errorf("用户 MaxRetries 被覆盖: %d", config.MaxRetries)
	}
	if config.Network.ICMPRate != 0.8 {
		t.Errorf("用户 ICMPRate 被覆盖: %.2f", config.Network.ICMPRate)
	}
	if config.POC.Num != 100 {
		t.Errorf("用户 PocNum 被覆盖: %d", config.POC.Num)
	}
}

// =============================================================================
// 集成测试：fd limit 约束
// =============================================================================

func TestTuneConfig_FDLimitConstraint(t *testing.T) {
	config := makeDefaultConfig()
	config.ThreadNum = 600
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

	// 600 线程 > 256 * 0.6 = 153 → 应该被约束
	maxExpected := 256 * 6 / 10
	if config.ThreadNum > maxExpected {
		t.Errorf("ThreadNum = %d, 应该 <= %d (fd_limit=256)", config.ThreadNum, maxExpected)
	}

	t.Logf("fd limit 约束: ThreadNum=%d (max=%d)", config.ThreadNum, maxExpected)
}

// =============================================================================
// 集成测试：零样本时不调整
// =============================================================================

func TestTuneConfig_NoSamples(t *testing.T) {
	config := makeDefaultConfig()
	session := makeTestSession(config)

	origTimeout := config.Timeout
	origRetry := config.MaxRetries
	origICMP := config.Network.ICMPRate

	ep := &EnvironmentProfile{
		Net:    NetworkProfile{Samples: 0},
		System: SystemProfile{FDLimit: 65536},
	}

	ep.TuneConfig(config, session)

	if config.Timeout != origTimeout {
		t.Errorf("零样本不应改 Timeout: %v -> %v", origTimeout, config.Timeout)
	}
	if config.MaxRetries != origRetry {
		t.Errorf("零样本不应改 MaxRetries: %d -> %d", origRetry, config.MaxRetries)
	}
	if config.Network.ICMPRate != origICMP {
		t.Errorf("零样本不应改 ICMPRate: %.2f -> %.2f", origICMP, config.Network.ICMPRate)
	}
}

// =============================================================================
// 辅助
// =============================================================================

func makeDefaultConfig() *common.Config {
	return &common.Config{
		Timeout:         3 * time.Second,
		ThreadNum:       600,
		ModuleThreadNum: 20,
		MaxRetries:      3,
		Network:         common.NetworkConfig{ICMPRate: 0.1},
		POC:             common.POCConfig{Num: 20},
		Output:          common.OutputConfig{LogLevel: "base,info,success"},
	}
}

func makeTestSession(config *common.Config) *common.ScanSession {
	return common.NewScanSession(config, common.NewState(), &common.FlagVars{})
}
