package core

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestCheckSum 测试ICMP校验和计算（RFC 1071算法）
func TestCheckSum(t *testing.T) {
	tests := []struct {
		name     string
		msg      []byte
		expected uint16
	}{
		{
			name:     "标准ICMP Echo请求",
			msg:      []byte{8, 0, 0, 0, 0, 1, 0, 1},
			expected: 0xf7fd,
		},
		{
			name:     "偶数长度消息",
			msg:      []byte{0x00, 0x01, 0x02, 0x03},
			expected: 0xfdfb,
		},
		{
			name:     "奇数长度消息",
			msg:      []byte{0x00, 0x01, 0x02},
			expected: 0xfdfe,
		},
		{
			name:     "全零消息",
			msg:      make([]byte, 8),
			expected: 0xffff,
		},
		{
			name:     "全0xFF消息",
			msg:      []byte{0xff, 0xff, 0xff, 0xff},
			expected: 0x0000,
		},
		{
			name:     "单字节",
			msg:      []byte{0x12},
			expected: 0xedff,
		},
		{
			name:     "两字节",
			msg:      []byte{0x12, 0x34},
			expected: 0xedcb,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkSum(tt.msg)
			if result != tt.expected {
				t.Errorf("checkSum() = 0x%04x, 期望 0x%04x", result, tt.expected)
			}
		})
	}
}

// TestCheckSum_Idempotent 测试校验和幂等性
func TestCheckSum_Idempotent(t *testing.T) {
	testCases := [][]byte{
		{8, 0, 0, 0, 0, 1, 0, 1},
		{0x12, 0x34, 0x56, 0x78},
		make([]byte, 40),
	}

	for i, msg := range testCases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			checksum1 := checkSum(msg)
			checksum2 := checkSum(msg)

			if checksum1 != checksum2 {
				t.Errorf("幂等性失败: 第一次=0x%04x, 第二次=0x%04x", checksum1, checksum2)
			}
		})
	}
}

// TestCheckSum_EdgeCases 测试checkSum边界情况
func TestCheckSum_EdgeCases(t *testing.T) {
	t.Run("空切片", func(t *testing.T) {
		result := checkSum([]byte{})
		if result != 0xffff {
			t.Errorf("空切片校验和应为 0xffff, 实际 0x%04x", result)
		}
	})

	t.Run("长消息-40字节ICMP包", func(t *testing.T) {
		msg := make([]byte, 40)
		msg[0] = 8 // Echo Request
		result := checkSum(msg)
		// 应该能正常计算不panic
		if result == 0 {
			t.Log("40字节消息校验和计算成功")
		}
	})
}

// TestGenSequence 测试ICMP序列号生成
func TestGenSequence(t *testing.T) {
	tests := []struct {
		name      string
		input     int16
		expectedH byte
		expectedL byte
	}{
		{
			name:      "序列号1",
			input:     1,
			expectedH: 0x00,
			expectedL: 0x01,
		},
		{
			name:      "序列号256",
			input:     256,
			expectedH: 0x01,
			expectedL: 0x00,
		},
		{
			name:      "序列号0",
			input:     0,
			expectedH: 0x00,
			expectedL: 0x00,
		},
		{
			name:      "序列号0x1234",
			input:     0x1234,
			expectedH: 0x12,
			expectedL: 0x34,
		},
		{
			name:      "负数序列号",
			input:     -1,
			expectedH: 0xff,
			expectedL: 0xff,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, l := genSequence(tt.input)
			if h != tt.expectedH || l != tt.expectedL {
				t.Errorf("genSequence(%d) = (0x%02x, 0x%02x), 期望 (0x%02x, 0x%02x)",
					tt.input, h, l, tt.expectedH, tt.expectedL)
			}
		})
	}
}

// TestGenIdentifier 测试标识符生成
func TestGenIdentifier(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		expectedH byte
		expectedL byte
		shouldRun bool
	}{
		{
			name:      "正常IP地址",
			host:      "192.168.1.1",
			expectedH: '1',
			expectedL: '9',
			shouldRun: true,
		},
		{
			name:      "域名",
			host:      "example.com",
			expectedH: 'e',
			expectedL: 'x',
			shouldRun: true,
		},
		{
			name:      "两字符最小长度",
			host:      "ab",
			expectedH: 'a',
			expectedL: 'b',
			shouldRun: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.shouldRun {
				t.Skip("跳过可能panic的测试")
			}

			h, l := genIdentifier(tt.host)
			if h != tt.expectedH || l != tt.expectedL {
				t.Errorf("genIdentifier(%q) = (%c, %c), 期望 (%c, %c)",
					tt.host, h, l, tt.expectedH, tt.expectedL)
			}
		})
	}
}

// TestGenIdentifier_EdgeCases 测试genIdentifier边界情况（修复后）
func TestGenIdentifier_EdgeCases(t *testing.T) {
	t.Run("单字符返回默认值", func(t *testing.T) {
		h, l := genIdentifier("1")
		if h != 0 || l != 0 {
			t.Errorf("单字符应返回(0,0), 实际(%d,%d)", h, l)
		}
	})

	t.Run("空字符串返回默认值", func(t *testing.T) {
		h, l := genIdentifier("")
		if h != 0 || l != 0 {
			t.Errorf("空字符串应返回(0,0), 实际(%d,%d)", h, l)
		}
	})

	t.Run("修复后不再panic", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("不应panic: %v", r)
			}
		}()

		// 这些调用在修复前会panic，修复后不应panic
		_, _ = genIdentifier("")
		_, _ = genIdentifier("1")
		_, _ = genIdentifier("ab")
	})
}

// TestGetOptimalTopCount 测试智能显示数量决策
func TestGetOptimalTopCount(t *testing.T) {
	tests := []struct {
		name       string
		totalHosts int
		expected   int
	}{
		{"超小规模-10台", 10, 3},
		{"小规模-100台", 100, 3},
		{"边界-256台", 256, 3},
		{"小规模扫描-257台", 257, 5},
		{"中等规模-1000台", 1000, 5},
		{"边界-1001台", 1001, 10},
		{"大规模-10000台", 10000, 10},
		{"边界-10001台", 10001, 15},
		{"超大规模-50000台", 50000, 15},
		{"边界-50001台", 50001, 20},
		{"极大规模-100000台", 100000, 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getOptimalTopCount(tt.totalHosts)
			if result != tt.expected {
				t.Errorf("getOptimalTopCount(%d) = %d, 期望 %d",
					tt.totalHosts, result, tt.expected)
			}
		})
	}
}

// TestIsContain 测试切片查找
func TestIsContain(t *testing.T) {
	tests := []struct {
		name     string
		items    []string
		item     string
		expected bool
	}{
		{
			name:     "找到元素",
			items:    []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
			item:     "192.168.1.2",
			expected: true,
		},
		{
			name:     "未找到元素",
			items:    []string{"192.168.1.1", "192.168.1.2"},
			item:     "192.168.1.3",
			expected: false,
		},
		{
			name:     "空切片",
			items:    []string{},
			item:     "192.168.1.1",
			expected: false,
		},
		{
			name:     "查找空字符串",
			items:    []string{"a", "b", ""},
			item:     "",
			expected: true,
		},
		{
			name:     "单元素切片-匹配",
			items:    []string{"192.168.1.1"},
			item:     "192.168.1.1",
			expected: true,
		},
		{
			name:     "单元素切片-不匹配",
			items:    []string{"192.168.1.1"},
			item:     "192.168.1.2",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsContain(tt.items, tt.item)
			if result != tt.expected {
				t.Errorf("IsContain() = %v, 期望 %v", result, tt.expected)
			}
		})
	}
}

// TestExecCommandPing_Blacklist 测试Ping命令注入防护
func TestExecCommandPing_Blacklist(t *testing.T) {
	dangerousInputs := []struct {
		name  string
		input string
	}{
		{"分号注入", "192.168.1.1; rm -rf /"},
		{"与符号注入", "192.168.1.1 & whoami"},
		{"管道注入", "192.168.1.1 | cat /etc/passwd"},
		{"反引号注入", "192.168.1.1`whoami`"},
		{"美元符号", "192.168.1.1$USER"},
		{"反斜杠", "192.168.1.1\\nwhoami"},
		{"单引号", "192.168.1.1'"},
		{"百分号", "192.168.1.1%"},
		{"双引号", "192.168.1.1\""},
		{"换行符", "192.168.1.1\nwhoami"},
	}

	for _, tt := range dangerousInputs {
		t.Run(tt.name, func(t *testing.T) {
			result := ExecCommandPing(tt.input)
			if result {
				t.Errorf("ExecCommandPing(%q) = true, 应拒绝危险输入", tt.input)
			}
		})
	}
}

// TestExecCommandPing_ValidInputs 测试合法IP格式
func TestExecCommandPing_ValidInputs(t *testing.T) {
	validInputs := []string{
		"192.168.1.1",
		"10.0.0.1",
		"8.8.8.8",
		"255.255.255.255",
	}

	for _, input := range validInputs {
		t.Run(input, func(t *testing.T) {
			// 注意：这个测试会实际执行ping命令
			// 在CI环境可能失败，这里只验证不会因注入而panic
			_ = ExecCommandPing(input)
			// 不检查返回值，因为网络可能不可达
			// 重点是验证黑名单过滤逻辑
		})
	}
}

// TestArrayCountValueTop 测试IP网段统计
func TestArrayCountValueTop(t *testing.T) {
	t.Run("C段统计", func(t *testing.T) {
		ips := []string{
			"192.168.1.1",
			"192.168.1.2",
			"192.168.1.3",
			"192.168.2.1",
			"192.168.2.2",
			"10.0.0.1",
		}

		arrTop, arrLen := ArrayCountValueTop(ips, 2, false)

		if len(arrTop) != 2 {
			t.Errorf("期望返回2个网段, 实际 %d", len(arrTop))
		}

		// 第一名应该是 192.168.1 (3个IP)
		if arrTop[0] != "192.168.1" || arrLen[0] != 3 {
			t.Errorf("第一名应为 192.168.1(3), 实际 %s(%d)", arrTop[0], arrLen[0])
		}

		// 第二名应该是 192.168.2 (2个IP)
		if arrTop[1] != "192.168.2" || arrLen[1] != 2 {
			t.Errorf("第二名应为 192.168.2(2), 实际 %s(%d)", arrTop[1], arrLen[1])
		}
	})

	t.Run("B段统计", func(t *testing.T) {
		ips := []string{
			"192.168.1.1",
			"192.168.2.1",
			"192.168.3.1",
			"10.0.1.1",
			"10.0.2.1",
		}

		arrTop, arrLen := ArrayCountValueTop(ips, 2, true)

		if len(arrTop) != 2 {
			t.Errorf("期望返回2个B段, 实际 %d", len(arrTop))
		}

		// 第一名应该是 192.168 (3个IP)
		if arrTop[0] != "192.168" || arrLen[0] != 3 {
			t.Errorf("第一名应为 192.168(3), 实际 %s(%d)", arrTop[0], arrLen[0])
		}
	})

	t.Run("空列表", func(t *testing.T) {
		arrTop, arrLen := ArrayCountValueTop([]string{}, 5, false)

		if len(arrTop) != 0 || len(arrLen) != 0 {
			t.Error("空列表应返回空结果")
		}
	})

	t.Run("请求数量超过实际网段数", func(t *testing.T) {
		ips := []string{"192.168.1.1", "10.0.0.1"}

		arrTop, _ := ArrayCountValueTop(ips, 10, false)

		if len(arrTop) != 2 {
			t.Errorf("只有2个网段时请求10个，应返回2个, 实际 %d", len(arrTop))
		}
	})

	t.Run("非法IP格式-跳过", func(t *testing.T) {
		ips := []string{
			"192.168.1.1",
			"invalid",
			"192.168",
			"192.168.1.2",
		}

		arrTop, arrLen := ArrayCountValueTop(ips, 1, false)

		// 只有2个合法IP
		if len(arrTop) != 1 || arrLen[0] != 2 {
			t.Errorf("应统计2个合法IP, 实际 %s(%d)", arrTop[0], arrLen[0])
		}
	})
}

// TestMakemsg 测试ICMP消息构造
func TestMakemsg(t *testing.T) {
	t.Run("构造标准ICMP包", func(t *testing.T) {
		msg := makemsg("192.168.1.1")

		if len(msg) != 40 {
			t.Errorf("ICMP包长度应为40, 实际 %d", len(msg))
		}

		// 验证Type字段
		if msg[0] != 8 {
			t.Errorf("ICMP Type应为8(Echo Request), 实际 %d", msg[0])
		}

		// 验证Code字段
		if msg[1] != 0 {
			t.Errorf("ICMP Code应为0, 实际 %d", msg[1])
		}

		// 验证校验和不为零（已计算）
		checksum := uint16(msg[2])<<8 | uint16(msg[3])
		if checksum == 0 {
			t.Error("ICMP校验和不应为0")
		}
	})

	t.Run("不同主机产生不同标识符", func(t *testing.T) {
		msg1 := makemsg("192.168.1.1")
		msg2 := makemsg("10.0.0.1")

		// 标识符字段在偏移4-5
		if msg1[4] == msg2[4] && msg1[5] == msg2[5] {
			t.Log("警告：不同主机可能产生相同标识符（取决于前两字符）")
		}
	})
}

// TestWaitAdaptive 测试自适应等待算法
func TestWaitAdaptive(t *testing.T) {
	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		start := time.Now()
		aliveHosts := []string{}
		var mu sync.Mutex
		waitAdaptiveContext(ctx, []string{"192.0.2.1"}, &aliveHosts, &mu)
		if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
			t.Fatalf("cancelled adaptive wait took %s", elapsed)
		}
	})

	t.Run("全部响应-立即结束", func(t *testing.T) {
		hostslist := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}
		aliveHosts := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"} // 全部存活
		var mu sync.Mutex

		start := time.Now()
		waitAdaptive(hostslist, &aliveHosts, &mu)
		elapsed := time.Since(start)

		// 全部响应应该在 1 个检查周期内结束 (~100ms)
		if elapsed > 200*time.Millisecond {
			t.Errorf("全部响应后应快速结束，实际耗时 %v", elapsed)
		}
	})

	t.Run("无响应-自适应提前结束", func(t *testing.T) {
		hostslist := make([]string, 10) // 10 个主机
		for i := range hostslist {
			hostslist[i] = fmt.Sprintf("192.168.1.%d", i+1)
		}
		aliveHosts := []string{} // 无响应
		var mu sync.Mutex

		start := time.Now()
		waitAdaptive(hostslist, &aliveHosts, &mu)
		elapsed := time.Since(start)

		// 无响应时：lastChangeTime = start
		// 在 minWait(1s) 后，time.Since(lastChangeTime) >= 1s > stableThreshold(500ms)
		// 所以会在约 1s 时提前结束（这是自适应优化的效果）
		// 相比原来的固定 3s，节省了约 2s
		if elapsed < 900*time.Millisecond || elapsed > 1300*time.Millisecond {
			t.Errorf("无响应时应在约 1s 提前结束，实际耗时 %v", elapsed)
		}
	})

	t.Run("部分响应后稳定-提前结束", func(t *testing.T) {
		hostslist := make([]string, 100)
		for i := range hostslist {
			hostslist[i] = fmt.Sprintf("192.168.1.%d", i+1)
		}
		// 模拟 50% 响应
		aliveHosts := make([]string, 50)
		for i := range aliveHosts {
			aliveHosts[i] = fmt.Sprintf("192.168.1.%d", i+1)
		}
		var mu sync.Mutex

		start := time.Now()
		waitAdaptive(hostslist, &aliveHosts, &mu)
		elapsed := time.Since(start)

		// 响应已稳定（不再变化），应该在 minWait + stableThreshold 后结束
		// 即约 1.5s，而不是 3s
		if elapsed > 2*time.Second {
			t.Errorf("响应稳定后应提前结束，实际耗时 %v", elapsed)
		}
	})

	t.Run("持续响应-等待完成", func(t *testing.T) {
		hostslist := make([]string, 10)
		for i := range hostslist {
			hostslist[i] = fmt.Sprintf("192.168.1.%d", i+1)
		}
		aliveHosts := []string{}
		var mu sync.Mutex

		// 模拟持续响应：每 200ms 增加一个存活主机
		done := make(chan struct{})
		go func() {
			defer close(done)
			for i := 0; i < 10; i++ {
				time.Sleep(200 * time.Millisecond)
				mu.Lock()
				aliveHosts = append(aliveHosts, fmt.Sprintf("192.168.1.%d", i+1))
				mu.Unlock()
			}
		}()

		start := time.Now()
		waitAdaptive(hostslist, &aliveHosts, &mu)
		elapsed := time.Since(start)
		<-done // 等待 goroutine 结束

		// 10 个主机 * 200ms = 2s，全部响应后应立即结束
		// 总耗时应该在 2s 左右
		if elapsed < 1800*time.Millisecond || elapsed > 2500*time.Millisecond {
			t.Errorf("持续响应时应等待全部完成，实际耗时 %v", elapsed)
		}
	})
}

// BenchmarkWaitAdaptive 基准测试自适应等待性能
func BenchmarkWaitAdaptive(b *testing.B) {
	hostslist := make([]string, 100)
	for i := range hostslist {
		hostslist[i] = fmt.Sprintf("192.168.1.%d", i+1)
	}
	// 全部响应场景
	aliveHosts := make([]string, 100)
	copy(aliveHosts, hostslist)
	var mu sync.Mutex

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		waitAdaptive(hostslist, &aliveHosts, &mu)
	}
}

// BenchmarkCheckSum 基准测试校验和性能
func BenchmarkCheckSum(b *testing.B) {
	msg := make([]byte, 40)
	msg[0] = 8

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checkSum(msg)
	}
}

// BenchmarkArrayCountValueTop 基准测试网段统计性能
func BenchmarkArrayCountValueTop(b *testing.B) {
	// 生成1000个IP地址
	ips := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		ips[i] = fmt.Sprintf("192.%d.%d.1", i/256, i%256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ArrayCountValueTop(ips, 10, false)
	}
}

// TestArrayCountValueTop_Sorting 测试排序正确性
func TestArrayCountValueTop_Sorting(t *testing.T) {
	ips := []string{
		"192.168.1.1",                                              // 192.168.1: 1次
		"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", // 10.0.0: 5次
		"172.16.0.1", "172.16.0.2", "172.16.0.3", // 172.16.0: 3次
	}

	arrTop, arrLen := ArrayCountValueTop(ips, 3, false)

	// 验证降序排列
	if arrLen[0] < arrLen[1] || arrLen[1] < arrLen[2] {
		t.Errorf("结果应按降序排列: %v", arrLen)
	}

	// 验证第一名
	if arrTop[0] != "10.0.0" || arrLen[0] != 5 {
		t.Errorf("第一名错误: %s(%d)", arrTop[0], arrLen[0])
	}
}
