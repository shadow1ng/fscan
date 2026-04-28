package core

/*
service_probe_strategy_test.go - SmartProbeStrategy 策略逻辑测试

测试重点：
1. 新探测策略 - 使用 Probe.Ports 和 Rarity 排序
2. 动态超时 - 使用 TotalWaitMS
3. NULL 回退 - 隐式 NULL 探测器匹配

说明：
- 只测试策略逻辑，不测试实际的网络IO（那是集成测试的职责）
*/

import (
	"context"
	"testing"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/core/portfinger"
)

// =============================================================================
// 测试1：新探测策略（使用 Probe.Ports）
// =============================================================================

// TestNewStrategy_ProbePortsUsed 验证新策略使用 Probe.Ports 字段
func TestNewStrategy_ProbePortsUsed(t *testing.T) {
	v := portfinger.GetGlobalVScan()

	// 验证端口80有对应的探测器
	probes := v.GetProbesForPort(80)
	if len(probes) == 0 {
		t.Error("端口 80 应该有探测器")
	}

	// 验证 GetRequest 探测器在列表中
	found := false
	for _, p := range probes {
		if p.Name == "GetRequest" {
			found = true
			t.Logf("✓ GetRequest 探测器存在于端口 80 的探测器列表中 (rarity=%d)", p.Rarity)
			break
		}
	}
	if !found {
		t.Error("GetRequest 探测器应该在端口 80 的列表中")
	}
}

// TestNewStrategy_RaritySorting 验证探测器按 Rarity 排序
func TestNewStrategy_RaritySorting(t *testing.T) {
	v := portfinger.GetGlobalVScan()

	probes := v.GetProbesForPort(80)
	if len(probes) < 2 {
		t.Skip("端口 80 的探测器数量不足，跳过排序测试")
	}

	// 验证按 rarity 从低到高排序
	for i := 1; i < len(probes); i++ {
		prev := probes[i-1].Rarity
		curr := probes[i].Rarity
		// 0 视为 10
		if prev == 0 {
			prev = 10
		}
		if curr == 0 {
			curr = 10
		}
		if prev > curr {
			t.Errorf("探测器未按 rarity 排序: [%d]=%d > [%d]=%d",
				i-1, probes[i-1].Rarity, i, probes[i].Rarity)
		}
	}

	t.Logf("✓ 端口 80 的 %d 个探测器已按 rarity 排序", len(probes))
}

// =============================================================================
// 测试2：SSL 端口探测
// =============================================================================

// TestSSLProbes_Port443 验证 443 端口的 SSL 探测器
func TestSSLProbes_Port443(t *testing.T) {
	v := portfinger.GetGlobalVScan()

	// 获取 ports 包含 443 的探测器
	probes := v.GetProbesForPort(443)
	t.Logf("端口 443 的 ports 探测器: %d 个", len(probes))

	// 获取 sslports 包含 443 的探测器
	sslProbes := v.GetSSLProbesForPort(443)
	t.Logf("端口 443 的 sslports 探测器: %d 个", len(sslProbes))

	// 至少应该有一些 SSL 相关探测器
	if len(probes) == 0 && len(sslProbes) == 0 {
		t.Error("端口 443 应该有探测器")
	}

	// 验证 TLSSessionReq 存在
	for _, p := range probes {
		if p.Name == "TLSSessionReq" {
			t.Logf("✓ TLSSessionReq 存在于 ports 列表")
			return
		}
	}
	for _, p := range sslProbes {
		if p.Name == "TLSSessionReq" {
			t.Logf("✓ TLSSessionReq 存在于 sslports 列表")
			return
		}
	}
}

// =============================================================================
// 测试3：Intensity 过滤
// =============================================================================

// TestIntensityFilter 验证 intensity 过滤功能
func TestIntensityFilter(t *testing.T) {
	// 创建测试探测器
	probes := []*portfinger.Probe{
		{Name: "p1", Rarity: 1},
		{Name: "p2", Rarity: 5},
		{Name: "p3", Rarity: 9},
	}

	// intensity=5 应该过滤掉 rarity=9 的探测器
	filtered := portfinger.FilterProbesByIntensity(probes, 5)
	if len(filtered) != 2 {
		t.Errorf("intensity=5 应该返回 2 个探测器，实际返回 %d", len(filtered))
	}

	// 验证 rarity=9 的探测器被过滤
	for _, p := range filtered {
		if p.Rarity > 5 {
			t.Errorf("rarity=%d 的探测器不应该通过 intensity=5 的过滤", p.Rarity)
		}
	}

	t.Log("✓ Intensity 过滤功能正常")
}

// =============================================================================
// 测试4：Scanner 创建和基本功能
// =============================================================================

// TestSmartPortInfoScanner_Creation 验证 Scanner 可以正常创建
func TestSmartPortInfoScanner_Creation(t *testing.T) {
	config := common.GetGlobalConfig()
	if config == nil {
		config = &common.Config{}
		config.PortMap = make(map[int][]string)
	}

	// 使用 nil 连接（实际测试中会使用真实连接）
	scanner := NewSmartPortInfoScanner(context.Background(), "127.0.0.1", 80, nil, 3*time.Second, config, nil)

	if scanner == nil {
		t.Fatal("Scanner 创建失败")
	}

	if scanner.Port != 80 {
		t.Errorf("端口设置错误: 期望 80, 实际 %d", scanner.Port)
	}

	t.Log("✓ Scanner 创建成功")
}

// =============================================================================
// 测试5：动态超时常量
// =============================================================================

// TestDefaultConstants 验证默认常量值
func TestDefaultConstants(t *testing.T) {
	// 验证默认等待时间
	if defaultTotalWaitMS != 3000 {
		t.Errorf("defaultTotalWaitMS 应该是 3000，实际是 %d", defaultTotalWaitMS)
	}

	// 验证默认 intensity
	if defaultIntensity != 7 {
		t.Errorf("defaultIntensity 应该是 7，实际是 %d", defaultIntensity)
	}

	t.Logf("✓ 默认常量: TotalWaitMS=%d, Intensity=%d", defaultTotalWaitMS, defaultIntensity)
}

// =============================================================================
// 测试6：端口范围解析
// =============================================================================

// TestPortInRange 验证端口范围解析
func TestPortInRange(t *testing.T) {
	tests := []struct {
		port     int
		portsStr string
		expected bool
	}{
		{80, "80", true},
		{80, "80,443", true},
		{8080, "8000-9000", true},
		{7999, "8000-9000", false},
		{443, "80,443,8080", true},
		{22, "80,443,8080", false},
	}

	for _, tt := range tests {
		result := portfinger.PortInRange(tt.port, tt.portsStr)
		if result != tt.expected {
			t.Errorf("PortInRange(%d, %q) = %v, want %v",
				tt.port, tt.portsStr, result, tt.expected)
		}
	}

	t.Log("✓ 端口范围解析功能正常")
}

// =============================================================================
// 测试7：真实场景模拟
// =============================================================================

// TestRealWorldScenario_CommonPorts 验证常见端口的探测器配置
func TestRealWorldScenario_CommonPorts(t *testing.T) {
	v := portfinger.GetGlobalVScan()

	scenarios := []struct {
		port        int
		description string
	}{
		{80, "HTTP"},
		{443, "HTTPS"},
		{8080, "HTTP-Alt"},
		{8443, "HTTPS-Alt"},
	}

	for _, s := range scenarios {
		probes := v.GetProbesForPort(s.port)
		sslProbes := v.GetSSLProbesForPort(s.port)
		total := len(probes) + len(sslProbes)

		t.Logf("端口 %d (%s): ports=%d, sslports=%d, 总计=%d",
			s.port, s.description, len(probes), len(sslProbes), total)
	}
}
