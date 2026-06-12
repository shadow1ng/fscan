package core

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shadow1ng/fscan/common"
)

// =============================================================================
// 辅助：启动本地 TCP 监听器
// =============================================================================

// startListeners 启动 N 个本地 TCP 监听端口，返回地址列表和清理函数
func startListeners(t *testing.T, n int) (addrs []string, hosts []string, ports []int, cleanup func()) {
	t.Helper()
	var listeners []net.Listener

	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			t.Fatalf("启动监听失败: %v", err)
		}
		listeners = append(listeners, ln)
		addr := ln.Addr().String()
		addrs = append(addrs, addr)

		host, portStr, _ := net.SplitHostPort(addr)
		hosts = append(hosts, host)
		var port int
		fmt.Sscanf(portStr, "%d", &port)
		ports = append(ports, port)

		// 后台 accept（不处理连接，只让 connect 成功）
		go func(l net.Listener) {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}(ln)
	}

	return addrs, hosts, ports, func() {
		for _, l := range listeners {
			l.Close()
		}
	}
}

// makeRealSession 创建用于真实网络测试的 session
func makeRealSession(t *testing.T) (*common.Config, *common.ScanSession) {
	t.Helper()
	config := &common.Config{
		Timeout:         3 * time.Second,
		ThreadNum:       100,
		ModuleThreadNum: 10,
		MaxRetries:      3,
		Network:         common.NetworkConfig{ICMPRate: 0.1},
		POC:             common.POCConfig{Num: 20},
		Output:          common.OutputConfig{LogLevel: "base,info,success"},
	}
	session := common.NewScanSession(config, common.NewState(), &common.FlagVars{})
	return config, session
}

// =============================================================================
// 真实测试 1：ProbeNetwork 对 localhost 探测
// =============================================================================

func TestReal_ProbeNetwork_Localhost(t *testing.T) {
	_, hosts, _, cleanup := startListeners(t, 3)
	defer cleanup()

	_, session := makeRealSession(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	profile := ProbeNetwork(ctx, hosts, session)

	if profile.Samples == 0 {
		t.Fatal("localhost 探测应该有样本")
	}

	// localhost 应该是内网环境
	if profile.Env != EnvLAN {
		t.Errorf("localhost env = %v, want LAN", profile.Env)
	}

	// RTT 应该 < 10ms
	if profile.RTTMedian > 10*time.Millisecond {
		t.Errorf("localhost RTT median = %v, 应该 < 10ms", profile.RTTMedian)
	}

	// 丢包率应该为 0 或极低
	if profile.LossRate > 0.1 {
		t.Errorf("localhost loss = %.2f, 应该接近 0", profile.LossRate)
	}

	t.Logf("localhost 探测: env=%v RTT_median=%v RTT_p95=%v loss=%.2f%% samples=%d",
		profile.Env, profile.RTTMedian, profile.RTTP95, profile.LossRate*100, profile.Samples)
}

// =============================================================================
// 真实测试 2：ProbeNetwork 对不可达目标
// =============================================================================

func TestReal_ProbeNetwork_Unreachable(t *testing.T) {
	_, session := makeRealSession(t)
	// 使用 RFC 5737 保留地址段，保证不可达
	hosts := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	profile := ProbeNetwork(ctx, hosts, session)

	// 不可达目标应该返回默认 profile 或高丢包
	t.Logf("不可达探测: env=%v samples=%d loss=%.2f%%",
		profile.Env, profile.Samples, profile.LossRate*100)
}

// =============================================================================
// 真实测试 3：ProbeNetwork 混合可达与不可达
// =============================================================================

func TestReal_ProbeNetwork_Mixed(t *testing.T) {
	_, hosts, _, cleanup := startListeners(t, 2)
	defer cleanup()

	// 混合真实主机和不可达地址
	mixed := append(hosts, "192.0.2.1", "192.0.2.2")

	_, session := makeRealSession(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	profile := ProbeNetwork(ctx, mixed, session)

	if profile.Samples == 0 {
		t.Error("混合探测应该有一些成功样本")
	}

	t.Logf("混合探测: env=%v RTT=%v samples=%d loss=%.2f%%",
		profile.Env, profile.RTTMedian, profile.Samples, profile.LossRate*100)
}

// =============================================================================
// 真实测试 4：ProbeSystem
// =============================================================================

func TestReal_ProbeSystem(t *testing.T) {
	sys := ProbeSystem()

	if sys.NumCPU <= 0 {
		t.Errorf("NumCPU = %d, 应该 > 0", sys.NumCPU)
	}

	t.Logf("系统探测: NumCPU=%d FDLimit=%d", sys.NumCPU, sys.FDLimit)

	// Linux/macOS 上 FDLimit 应该 > 0
	// Windows 上可能为 0（设计如此）
	if sys.FDLimit < 0 {
		t.Errorf("FDLimit = %d, 不应为负", sys.FDLimit)
	}
}

// =============================================================================
// 真实测试 5：完整链路 —— 探测 → 调参 → 池创建 → 真实任务执行
// =============================================================================

func TestReal_E2E_ProbeAndScan(t *testing.T) {
	addrs, hosts, _, cleanup := startListeners(t, 5)
	defer cleanup()

	config, session := makeRealSession(t)

	// 第一步：探测
	ctx := context.Background()
	profile := ProbeNetwork(ctx, hosts, session)
	sys := ProbeSystem()
	ep := &EnvironmentProfile{Net: *profile, System: sys}

	// 第二步：调参
	ep.TuneConfig(config, session)

	// 第三步：创建池
	target, ceiling := profile.RecommendConcurrency(config.ThreadNum, false)
	metrics := &ScanMetrics{}

	var successCount atomic.Int64

	pool, err := NewAdaptivePool(target, ceiling, func(i interface{}) {
		addr := i.(string)
		conn, err := net.DialTimeout("tcp", addr, config.Timeout)
		if err != nil {
			metrics.RecordTimeout()
			return
		}
		defer conn.Close()
		successCount.Add(1)
		metrics.RecordConnect(time.Millisecond)
	}, metrics)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	// 跳过慢启动测试主要流程
	pool.inSlowStart = false
	pool.tune(target)

	// 第四步：提交任务
	var wg sync.WaitGroup
	for _, addr := range addrs {
		wg.Add(1)
		a := addr
		go func() {
			defer wg.Done()
			_ = pool.Invoke(a)
		}()
	}
	wg.Wait()
	pool.Wait()

	// 第五步：验证
	if successCount.Load() != int64(len(addrs)) {
		t.Errorf("成功连接 %d/%d", successCount.Load(), len(addrs))
	}

	snap := metrics.Snapshot()
	if snap.Connects != int64(len(addrs)) {
		t.Errorf("metrics.Connects = %d, want %d", snap.Connects, len(addrs))
	}

	t.Logf("E2E: profile=%v timeout=%v mt=%d retry=%d target=%d connects=%d",
		profile.Env, config.Timeout, config.ModuleThreadNum, config.MaxRetries,
		target, snap.Connects)
}

// =============================================================================
// 真实测试 6：大量连接的自适应行为
// =============================================================================

func TestReal_AdaptivePool_ManyConnections(t *testing.T) {
	_, hosts, ports, cleanup := startListeners(t, 3)
	defer cleanup()

	metrics := &ScanMetrics{}
	var successCount, failCount atomic.Int64

	pool, err := NewAdaptivePool(50, 50, func(i interface{}) {
		addr := i.(string)
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		rtt := time.Since(start)
		if err != nil {
			failCount.Add(1)
			metrics.RecordTimeout()
			return
		}
		defer conn.Close()
		successCount.Add(1)
		metrics.RecordConnect(rtt)
	}, metrics)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	pool.inSlowStart = false
	pool.tune(50)

	// 提交 300 个连接任务（对 3 个端口各 100 次）
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		for j, host := range hosts {
			addr := fmt.Sprintf("%s:%d", host, ports[j])
			wg.Add(1)
			go func(a string) {
				defer wg.Done()
				_ = pool.Invoke(a)
			}(addr)
		}
	}
	wg.Wait()
	pool.Wait()

	total := successCount.Load() + failCount.Load()
	if total != 300 {
		t.Errorf("总任务 %d, want 300", total)
	}

	snap := metrics.Snapshot()
	t.Logf("大量连接: success=%d fail=%d connects=%d timeouts=%d cap=%d rtt_ratio=%.2f",
		successCount.Load(), failCount.Load(), snap.Connects, snap.Timeouts, pool.Cap(), metrics.RTTRatio())

	// localhost 连接应该几乎全部成功
	if successCount.Load() < 280 {
		t.Errorf("localhost 成功率过低: %d/300", successCount.Load())
	}
}

// =============================================================================
// 真实测试 7：连接关闭端口 + 开放端口混合
// =============================================================================

func TestReal_MixedOpenClosed(t *testing.T) {
	_, hosts, ports, cleanup := startListeners(t, 2)
	defer cleanup()

	metrics := &ScanMetrics{}

	pool, err := NewAdaptivePool(20, 20, func(i interface{}) {
		addr := i.(string)
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		rtt := time.Since(start)
		if err != nil {
			if isConnectionRefused(err) {
				metrics.RecordRefused(rtt)
			} else {
				metrics.RecordTimeout()
			}
			return
		}
		defer conn.Close()
		metrics.RecordConnect(rtt)
	}, metrics)
	if err != nil {
		t.Fatalf("创建池失败: %v", err)
	}
	defer pool.Release()

	pool.inSlowStart = false
	pool.tune(20)

	var wg sync.WaitGroup

	// 连接开放端口
	for i := 0; i < 20; i++ {
		addr := fmt.Sprintf("%s:%d", hosts[0], ports[0])
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			_ = pool.Invoke(a)
		}(addr)
	}

	// 连接关闭端口（用一个不存在的端口）
	for i := 0; i < 20; i++ {
		addr := fmt.Sprintf("127.0.0.1:%d", 1) // port 1 通常关闭
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			_ = pool.Invoke(a)
		}(addr)
	}

	wg.Wait()
	pool.Wait()

	snap := metrics.Snapshot()
	t.Logf("混合端口: connects=%d refused=%d timeouts=%d total=%d",
		snap.Connects, snap.Refused, snap.Timeouts, snap.Total())

	// 开放端口应该全部连接成功
	if snap.Connects < 18 {
		t.Errorf("开放端口连接数 = %d, 应该接近 20", snap.Connects)
	}

	// RTT ratio 应该合理（不会因为 refused 而异常）
	ratio := metrics.RTTRatio()
	if ratio > 3.0 || ratio < 0.3 {
		t.Errorf("混合流量 RTT ratio = %.2f, 不合理", ratio)
	}
}

// =============================================================================
// 真实测试 8：Context 取消时的探测行为
// =============================================================================

func TestReal_ProbeNetwork_ContextCancel(t *testing.T) {
	_, hosts, _, cleanup := startListeners(t, 3)
	defer cleanup()

	_, session := makeRealSession(t)

	// 立即取消的 context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	profile := ProbeNetwork(ctx, hosts, session)

	// 应该优雅返回默认 profile 或部分结果
	t.Logf("取消探测: env=%v samples=%d", profile.Env, profile.Samples)
}

// =============================================================================
// 真实测试 9：AdaptiveTimeout 真实 RTT 收敛
// =============================================================================

func TestReal_AdaptiveTimeout_Convergence(t *testing.T) {
	addrs, _, _, cleanup := startListeners(t, 1)
	defer cleanup()

	at := NewAdaptiveTimeout(3 * time.Second)

	// 初始应该返回最大超时
	if at.Timeout() != 3*time.Second {
		t.Errorf("冷启动 Timeout = %v, want 3s", at.Timeout())
	}

	// 做 20 次真实连接采样
	for i := 0; i < 20; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addrs[0], time.Second)
		rtt := time.Since(start)
		if err != nil {
			t.Fatalf("连接失败: %v", err)
		}
		conn.Close()
		at.Record(rtt)
	}

	// 采样够后 Timeout 应远小于 3s（localhost RTT 通常 < 1ms）
	converged := at.Timeout()
	if converged >= 3*time.Second {
		t.Errorf("采样后 Timeout = %v, 应该 < 3s", converged)
	}
	if converged < 100*time.Millisecond {
		t.Logf("Timeout 收敛到 %v（localhost，正常）", converged)
	}

	t.Logf("AdaptiveTimeout 收敛: 3s -> %v (%d 个样本)", converged, 20)
}

// =============================================================================
// 真实测试 10：完整 TuneConfig 对真实探测数据
// =============================================================================

func TestReal_TuneConfig_WithRealProbe(t *testing.T) {
	_, hosts, _, cleanup := startListeners(t, 5)
	defer cleanup()

	config, session := makeRealSession(t)

	ctx := context.Background()
	profile := ProbeNetwork(ctx, hosts, session)
	sys := ProbeSystem()

	origTimeout := config.Timeout
	origMT := config.ModuleThreadNum
	origRetry := config.MaxRetries
	origICMP := config.Network.ICMPRate

	ep := &EnvironmentProfile{Net: *profile, System: sys}
	ep.TuneConfig(config, session)

	t.Logf("真实调参:")
	t.Logf("  Timeout:  %v -> %v", origTimeout, config.Timeout)
	t.Logf("  MT:       %d -> %d", origMT, config.ModuleThreadNum)
	t.Logf("  Retry:    %d -> %d", origRetry, config.MaxRetries)
	t.Logf("  ICMPRate: %.2f -> %.2f", origICMP, config.Network.ICMPRate)
	t.Logf("  PocNum:   20 -> %d", config.POC.Num)
	t.Logf("  ThreadNum: %d (fd_limit=%d)", config.ThreadNum, sys.FDLimit)

	// localhost 环境下的基本验证
	if config.Timeout > 3*time.Second {
		t.Errorf("localhost Timeout = %v, 不应高于默认 3s", config.Timeout)
	}
	if config.MaxRetries > 3 {
		t.Errorf("localhost Retry = %d, 不应高于默认 3", config.MaxRetries)
	}
}
