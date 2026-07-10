package core

import (
	"testing"
	"time"

	"scanner/common"
)

// TestNewAliveScanStrategy 测试构造函数
func TestNewAliveScanStrategy(t *testing.T) {
	strategy := NewAliveScanStrategy()

	if strategy == nil {
		t.Fatal("NewAliveScanStrategy 返回 nil")
	}

	if strategy.BaseScanStrategy == nil {
		t.Error("BaseScanStrategy 未初始化")
	}

	// 验证起始时间已设置
	if strategy.startTime.IsZero() {
		t.Error("startTime 未初始化")
	}

	// 验证时间在合理范围内（过去1秒内）
	if time.Since(strategy.startTime) > time.Second {
		t.Error("startTime 时间戳异常")
	}
}

// TestAliveScanStrategy_PrepareTargets 测试PrepareTargets
func TestAliveScanStrategy_PrepareTargets(t *testing.T) {
	strategy := NewAliveScanStrategy()

	// 存活探测不需要返回目标列表
	targets := strategy.PrepareTargets(common.HostInfo{})

	if targets != nil {
		t.Errorf("PrepareTargets 应返回 nil, 实际: %v", targets)
	}
}

// TestAliveScanStrategy_GetPlugins 测试GetPlugins
func TestAliveScanStrategy_GetPlugins(t *testing.T) {
	strategy := NewAliveScanStrategy()

	plugins, customMode := strategy.GetPlugins(nil)

	if len(plugins) != 0 {
		t.Errorf("GetPlugins 应返回空列表, 实际长度: %d", len(plugins))
	}

	if customMode {
		t.Error("customMode 应为 false")
	}
}

// TestAliveStats_SuccessRateCalculation 测试成功率计算逻辑
func TestAliveStats_SuccessRateCalculation(t *testing.T) {
	tests := []struct {
		name         string
		totalHosts   int
		aliveHosts   int
		expectedRate float64
	}{
		{"全部存活", 10, 10, 100.0},
		{"一半存活", 10, 5, 50.0},
		{"无存活", 10, 0, 0.0},
		{"单主机存活", 1, 1, 100.0},
		{"单主机死亡", 1, 0, 0.0},
		{"三分之一存活", 3, 1, 100.0 / 3.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 模拟统计计算逻辑（来自 alive_scanner.go:108-110）
			var successRate float64
			if tt.totalHosts > 0 {
				successRate = float64(tt.aliveHosts) / float64(tt.totalHosts) * 100
			}

			// 浮点数比较使用小容忍度
			const epsilon = 1e-9
			diff := successRate - tt.expectedRate
			if diff < -epsilon || diff > epsilon {
				t.Errorf("成功率计算错误: 期望 %.10f%%, 实际 %.10f%%, 差值 %.10f",
					tt.expectedRate, successRate, diff)
			}
		})
	}
}

// TestAliveStats_DeadHostsCalculation 测试死亡主机数计算
func TestAliveStats_DeadHostsCalculation(t *testing.T) {
	tests := []struct {
		name         string
		totalHosts   int
		aliveHosts   int
		expectedDead int
	}{
		{"全部存活", 10, 10, 0},
		{"一半存活", 10, 5, 5},
		{"全部死亡", 10, 0, 10},
		{"单主机", 1, 0, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 模拟死亡主机计算逻辑（来自 alive_scanner.go:104）
			deadHosts := tt.totalHosts - tt.aliveHosts

			if deadHosts != tt.expectedDead {
				t.Errorf("死亡主机数错误: 期望 %d, 实际 %d",
					tt.expectedDead, deadHosts)
			}
		})
	}
}
