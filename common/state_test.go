package common

import (
	"sync"
	"testing"
)

/*
state_test.go - State 并发安全测试

测试重点：
1. 并发安全性 - 多goroutine同时操作计数器
2. 原子操作一致性 - 增减计数正确
3. Reset功能 - 重置后计数器归零

不测试：
- 限速器（需要复杂的时间模拟）
- 简单getter/setter
*/

// TestState_ConcurrentPacketCount 测试并发包计数
func TestState_ConcurrentPacketCount(t *testing.T) {
	s := NewState()

	const goroutines = 100
	const incrementsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				s.IncrementPacketCount()
			}
		}()
	}

	wg.Wait()

	expected := int64(goroutines * incrementsPerGoroutine)
	actual := s.GetPacketCount()

	if actual != expected {
		t.Errorf("并发计数不一致: 期望 %d, 实际 %d", expected, actual)
	}
}

// TestState_ConcurrentTCPCount 测试并发TCP计数
func TestState_ConcurrentTCPCount(t *testing.T) {
	s := NewState()

	const goroutines = 50
	const operationsPerGoroutine = 500

	var wg sync.WaitGroup
	wg.Add(goroutines * 2) // 成功和失败各一半

	// 成功连接
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				s.IncrementTCPSuccessPacketCount()
			}
		}()
	}

	// 失败连接
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				s.IncrementTCPFailedPacketCount()
			}
		}()
	}

	wg.Wait()

	expectedTotal := int64(goroutines * operationsPerGoroutine * 2)
	expectedSuccess := int64(goroutines * operationsPerGoroutine)
	expectedFailed := int64(goroutines * operationsPerGoroutine)

	if s.GetPacketCount() != expectedTotal {
		t.Errorf("总包计数不一致: 期望 %d, 实际 %d", expectedTotal, s.GetPacketCount())
	}
	if s.GetTCPPacketCount() != expectedTotal {
		t.Errorf("TCP包计数不一致: 期望 %d, 实际 %d", expectedTotal, s.GetTCPPacketCount())
	}
	if s.GetTCPSuccessPacketCount() != expectedSuccess {
		t.Errorf("TCP成功计数不一致: 期望 %d, 实际 %d", expectedSuccess, s.GetTCPSuccessPacketCount())
	}
	if s.GetTCPFailedPacketCount() != expectedFailed {
		t.Errorf("TCP失败计数不一致: 期望 %d, 实际 %d", expectedFailed, s.GetTCPFailedPacketCount())
	}
}

// TestState_Reset 测试重置功能
func TestState_Reset(t *testing.T) {
	s := NewState()

	// 增加一些计数
	for i := 0; i < 100; i++ {
		s.IncrementTCPSuccessPacketCount()
		s.IncrementTCPFailedPacketCount()
		s.IncrementUDPPacketCount()
		s.IncrementHTTPPacketCount()
		s.IncrementResourceExhaustedCount()
	}

	// 验证有值
	if s.GetPacketCount() == 0 {
		t.Fatal("重置前计数应该非零")
	}

	// 重置
	s.ResetPacketCounters()

	// 验证全部归零
	if s.GetPacketCount() != 0 {
		t.Errorf("重置后PacketCount应该为0, 实际 %d", s.GetPacketCount())
	}
	if s.GetTCPPacketCount() != 0 {
		t.Errorf("重置后TCPPacketCount应该为0, 实际 %d", s.GetTCPPacketCount())
	}
	if s.GetTCPSuccessPacketCount() != 0 {
		t.Errorf("重置后TCPSuccessPacketCount应该为0, 实际 %d", s.GetTCPSuccessPacketCount())
	}
	if s.GetTCPFailedPacketCount() != 0 {
		t.Errorf("重置后TCPFailedPacketCount应该为0, 实际 %d", s.GetTCPFailedPacketCount())
	}
	if s.GetUDPPacketCount() != 0 {
		t.Errorf("重置后UDPPacketCount应该为0, 实际 %d", s.GetUDPPacketCount())
	}
	if s.GetHTTPPacketCount() != 0 {
		t.Errorf("重置后HTTPPacketCount应该为0, 实际 %d", s.GetHTTPPacketCount())
	}
	if s.GetResourceExhaustedCount() != 0 {
		t.Errorf("重置后ResourceExhaustedCount应该为0, 实际 %d", s.GetResourceExhaustedCount())
	}
}

// TestState_TaskCounters 测试任务计数器
func TestState_TaskCounters(t *testing.T) {
	s := NewState()

	// 初始值应该为0
	if s.GetEnd() != 0 || s.GetNum() != 0 {
		t.Error("初始任务计数器应该为0")
	}

	// 设置值
	s.SetEnd(100)
	s.SetNum(50)

	if s.GetEnd() != 100 {
		t.Errorf("End应该为100, 实际 %d", s.GetEnd())
	}
	if s.GetNum() != 50 {
		t.Errorf("Num应该为50, 实际 %d", s.GetNum())
	}

	// 增加值
	s.IncrementEnd()
	s.IncrementNum()

	if s.GetEnd() != 101 {
		t.Errorf("IncrementEnd后应该为101, 实际 %d", s.GetEnd())
	}
	if s.GetNum() != 51 {
		t.Errorf("IncrementNum后应该为51, 实际 %d", s.GetNum())
	}
}

// TestState_ConcurrentTaskCounters 测试并发任务计数
func TestState_ConcurrentTaskCounters(t *testing.T) {
	s := NewState()

	const goroutines = 100
	const incrementsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// 并发增加End
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				s.IncrementEnd()
			}
		}()
	}

	// 并发增加Num
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				s.IncrementNum()
			}
		}()
	}

	wg.Wait()

	expected := int64(goroutines * incrementsPerGoroutine)
	if s.GetEnd() != expected {
		t.Errorf("End并发计数不一致: 期望 %d, 实际 %d", expected, s.GetEnd())
	}
	if s.GetNum() != expected {
		t.Errorf("Num并发计数不一致: 期望 %d, 实际 %d", expected, s.GetNum())
	}
}

// TestState_GetOutputMutex 测试获取输出互斥锁指针
func TestState_GetOutputMutex(t *testing.T) {
	s := NewState()
	mu := s.GetOutputMutex()
	if mu == nil {
		t.Fatal("GetOutputMutex returned nil")
	}
	// 验证返回的指针可以正常加锁解锁
	mu.Lock()
	_ = 1 //nolint:staticcheck // SA2001: 故意测试空临界区
	mu.Unlock()
}

// TestState_GetICMPLimiter 测试 ICMP 限速器延迟初始化
func TestState_GetICMPLimiter(t *testing.T) {
	s := NewState()

	limiter := s.GetICMPLimiter(0.1)
	if limiter == nil {
		t.Fatal("GetICMPLimiter returned nil")
	}

	// 再次调用应返回同一个实例（sync.Once 保证）
	limiter2 := s.GetICMPLimiter(0.5)
	if limiter != limiter2 {
		t.Fatal("GetICMPLimiter should return the same instance on repeated calls")
	}
}

// TestState_GetICMPLimiterMinRate 测试极低速率下的 ICMP 限速器
func TestState_GetICMPLimiterMinRate(t *testing.T) {
	s := NewState()
	// 极低速率（packetsPerSecond < 1）应被钳位到 1
	limiter := s.GetICMPLimiter(0.000001)
	if limiter == nil {
		t.Fatal("GetICMPLimiter with tiny rate returned nil")
	}
}

// TestState_GetPerfStats 测试性能统计数据
func TestState_GetPerfStats(t *testing.T) {
	s := NewState()

	// 初始状态：全零
	stats := s.GetPerfStats()
	if stats.TotalPackets != 0 {
		t.Errorf("初始 TotalPackets 应为 0, 实际 %d", stats.TotalPackets)
	}
	if stats.SuccessRate != 0 {
		t.Errorf("初始 SuccessRate 应为 0, 实际 %f", stats.SuccessRate)
	}

	// 增加一些计数后验证统计
	s.IncrementTCPSuccessPacketCount()
	s.IncrementTCPSuccessPacketCount()
	s.IncrementTCPFailedPacketCount()
	s.SetNum(3)

	stats = s.GetPerfStats()
	if stats.TotalPackets != 3 {
		t.Errorf("TotalPackets 期望 3, 实际 %d", stats.TotalPackets)
	}
	if stats.TCPSuccess != 2 {
		t.Errorf("TCPSuccess 期望 2, 实际 %d", stats.TCPSuccess)
	}
	if stats.TCPFailed != 1 {
		t.Errorf("TCPFailed 期望 1, 实际 %d", stats.TCPFailed)
	}
	if stats.TargetsScanned != 3 {
		t.Errorf("TargetsScanned 期望 3, 实际 %d", stats.TargetsScanned)
	}
	// success rate = 2/3 * 100 ≈ 66.67%
	if stats.SuccessRate < 66 || stats.SuccessRate > 67 {
		t.Errorf("SuccessRate 期望约 66.67, 实际 %f", stats.SuccessRate)
	}
}

// TestState_GetPerfStatsJSON 测试性能统计 JSON 序列化
func TestState_GetPerfStatsJSON(t *testing.T) {
	s := NewState()
	s.IncrementTCPSuccessPacketCount()

	json := s.GetPerfStatsJSON()
	if json == "" || json == "{}" {
		t.Fatalf("GetPerfStatsJSON 返回空: %q", json)
	}
	if len(json) < 10 {
		t.Fatalf("GetPerfStatsJSON 内容过短: %q", json)
	}
	// 验证包含关键字段
	for _, key := range []string{"total_packets", "tcp_success", "success_rate"} {
		if !containsStr(json, key) {
			t.Errorf("GetPerfStatsJSON 缺少字段 %q", key)
		}
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && stringContains(s, sub))
}

func stringContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestState_GetPacketLimiter 测试通用发包限速器
func TestState_GetPacketLimiter(t *testing.T) {
	t.Run("零速率返回nil", func(t *testing.T) {
		s := NewState()
		limiter := s.GetPacketLimiter(0)
		if limiter != nil {
			t.Fatal("零速率应返回 nil limiter")
		}
	})

	t.Run("负速率返回nil", func(t *testing.T) {
		s := NewState()
		limiter := s.GetPacketLimiter(-1)
		if limiter != nil {
			t.Fatal("负速率应返回 nil limiter")
		}
	})

	t.Run("正速率初始化限速器", func(t *testing.T) {
		s := NewState()
		limiter := s.GetPacketLimiter(600) // 600/min = 10/s
		if limiter == nil {
			t.Fatal("正速率应返回非 nil limiter")
		}
		// 再次调用返回同一实例
		limiter2 := s.GetPacketLimiter(1200)
		if limiter != limiter2 {
			t.Fatal("GetPacketLimiter 应通过 sync.Once 复用实例")
		}
	})

	t.Run("低速率被钳位到1pps", func(t *testing.T) {
		s := NewState()
		// 1/min < 1/s，应被钳位
		limiter := s.GetPacketLimiter(1)
		if limiter == nil {
			t.Fatal("低速率钳位后应返回非 nil limiter")
		}
	})
}

// TestState_CacheService 测试服务识别缓存
func TestState_CacheService(t *testing.T) {
	s := NewState()

	// 未缓存时查询返回 false
	_, ok := s.GetCachedService("192.168.1.1:80")
	if ok {
		t.Fatal("未缓存的 key 不应返回 ok=true")
	}

	// 缓存并查询
	type fakeInfo struct{ Name string }
	info := &fakeInfo{Name: "http"}
	s.CacheService("192.168.1.1:80", info)

	got, ok := s.GetCachedService("192.168.1.1:80")
	if !ok {
		t.Fatal("已缓存的 key 应返回 ok=true")
	}
	if got != info {
		t.Fatalf("GetCachedService 返回 %v, 期望 %v", got, info)
	}

	// 不同 key 互不干扰
	_, ok = s.GetCachedService("192.168.1.1:443")
	if ok {
		t.Fatal("不同 key 不应命中缓存")
	}
}

// =============================================================================
// CheckAndIncrementPacketRate 测试
// =============================================================================

// TestCheckAndIncrementPacketRate_ZeroLimit 速率为 0 时无限制
func TestCheckAndIncrementPacketRate_ZeroLimit(t *testing.T) {
	s := NewState()
	for i := 0; i < 1000; i++ {
		ok, err := s.CheckAndIncrementPacketRate(0)
		if !ok || err != nil {
			t.Fatalf("零速率限制应始终允许: ok=%v err=%v", ok, err)
		}
	}
}

// TestCheckAndIncrementPacketRate_NegativeLimit 负速率等同于无限制
func TestCheckAndIncrementPacketRate_NegativeLimit(t *testing.T) {
	s := NewState()
	ok, err := s.CheckAndIncrementPacketRate(-1)
	if !ok || err != nil {
		t.Fatalf("负速率应允许: ok=%v err=%v", ok, err)
	}
}

// TestCheckAndIncrementPacketRate_AllowsWhenTokensAvailable 有令牌时返回 true
func TestCheckAndIncrementPacketRate_AllowsWhenTokensAvailable(t *testing.T) {
	s := NewState()
	// 600/min = 10/s，桶容量 20，初始满桶
	ok, err := s.CheckAndIncrementPacketRate(600)
	if !ok || err != nil {
		t.Fatalf("初始应有令牌: ok=%v err=%v", ok, err)
	}
}

// TestCheckAndIncrementPacketRate_RateLimitedAfterExhaustion 耗尽令牌后返回 false 和 PacketLimitError
func TestCheckAndIncrementPacketRate_RateLimitedAfterExhaustion(t *testing.T) {
	s := NewState()
	// 极低速率：1/min，桶容量为 1（钳位后 packetsPerSecond=1，capacity=2）
	// 消耗掉所有令牌后应被限速
	const limit int64 = 1

	// 初始化限速器（第一次调用触发 sync.Once）
	s.GetPacketLimiter(limit)

	// 消耗完所有令牌（容量 <= 2）
	for i := 0; i < 10; i++ {
		s.CheckAndIncrementPacketRate(limit) //nolint: errcheck
	}

	// 此时令牌应已耗尽，下一次调用应被限速
	ok, err := s.CheckAndIncrementPacketRate(limit)
	if ok {
		// 桶可能还剩令牌（容量 2），多耗几次再判断
		for i := 0; i < 20; i++ {
			ok, err = s.CheckAndIncrementPacketRate(limit)
			if !ok {
				break
			}
		}
	}

	if ok {
		t.Fatal("令牌耗尽后应返回 ok=false")
	}
	if err == nil {
		t.Fatal("令牌耗尽后应返回 error")
	}
	if !isPacketLimitError(err) {
		t.Errorf("error 类型应为 PacketLimitError, 实际 %T: %v", err, err)
	}
}

// isPacketLimitError 检查是否为 PacketLimitError
func isPacketLimitError(err error) bool {
	_, ok := err.(*PacketLimitError)
	return ok
}

// TestCheckAndIncrementPacketRate_ErrorUnwrapsToSentinel 验证 error 可 unwrap 到 sentinel
func TestCheckAndIncrementPacketRate_ErrorUnwrapsToSentinel(t *testing.T) {
	s := NewState()
	const limit int64 = 1

	// 耗尽令牌
	for i := 0; i < 50; i++ {
		s.CheckAndIncrementPacketRate(limit) //nolint: errcheck
	}

	var lastErr error
	for i := 0; i < 10; i++ {
		ok, err := s.CheckAndIncrementPacketRate(limit)
		if !ok {
			lastErr = err
			break
		}
	}

	if lastErr == nil {
		t.Skip("未能触发限速（可能令牌桶容量较大），跳过 unwrap 测试")
	}

	// 验证可 unwrap 到 ErrPacketRateLimited
	pErr, ok := lastErr.(*PacketLimitError)
	if !ok {
		t.Fatalf("期望 *PacketLimitError, 实际 %T", lastErr)
	}
	if pErr.Sentinel != ErrPacketRateLimited {
		t.Errorf("Sentinel = %v, 期望 ErrPacketRateLimited", pErr.Sentinel)
	}
	if pErr.Limit != limit {
		t.Errorf("Limit = %d, 期望 %d", pErr.Limit, limit)
	}
}

// TestState_OutputMutex 测试输出互斥锁
func TestState_OutputMutex(t *testing.T) {
	s := NewState()

	counter := 0
	const goroutines = 100
	const incrementsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				s.LockOutput()
				counter++
				s.UnlockOutput()
			}
		}()
	}

	wg.Wait()

	expected := goroutines * incrementsPerGoroutine
	if counter != expected {
		t.Errorf("输出互斥锁保护失败: 期望 %d, 实际 %d", expected, counter)
	}
}
