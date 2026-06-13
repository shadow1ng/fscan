package common

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/juju/ratelimit"
)

/*
state.go - 运行时状态管理

可变状态，有明确的所有权和线程安全保护。
所有修改通过方法进行，原子操作保证并发安全。
*/

// =============================================================================
// State - 可变运行时状态
// =============================================================================

// State 扫描器运行时状态 - 线程安全
type State struct {
	// 计数器 - 原子操作
	packetCount            atomic.Int64
	tcpPacketCount         atomic.Int64
	tcpSuccessPacketCount  atomic.Int64
	tcpFailedPacketCount   atomic.Int64
	udpPacketCount         atomic.Int64
	httpPacketCount        atomic.Int64
	resourceExhaustedCount atomic.Int64

	// 任务计数
	end atomic.Int64
	num atomic.Int64

	// 时间
	startTime time.Time

	// 输出互斥锁
	outputMutex sync.Mutex

	// 限速器 - 统一使用令牌桶算法
	icmpLimiter    *ratelimit.Bucket // ICMP包限速（秒级平滑）
	packetLimiter  *ratelimit.Bucket // 通用发包限速
	icmpInitOnce   sync.Once
	packetInitOnce sync.Once

	// 运行时目标数据（解析后填充）
	urls      []string
	hostPorts []string
	urlsMu    sync.RWMutex

	// Shell状态（插件设置）
	forwardShellActive int32 // 使用int32以便原子操作
	reverseShellActive int32
	socks5ProxyActive  int32

	// 服务识别缓存（per-session，避免跨扫描污染）
	// key: "host:port", value: interface{}（core.ServiceInfo 指针）
	serviceCache sync.Map
}

// NewState 创建新的状态对象
func NewState() *State {
	return &State{
		startTime: time.Now(),
	}
}

// =============================================================================
// 包计数器方法 - 原子操作
// =============================================================================

// IncrementPacketCount 增加总包计数
func (s *State) IncrementPacketCount() int64 {
	return s.packetCount.Add(1)
}

// IncrementTCPSuccessPacketCount 增加TCP成功连接包计数
func (s *State) IncrementTCPSuccessPacketCount() int64 {
	s.tcpSuccessPacketCount.Add(1)
	s.tcpPacketCount.Add(1)
	return s.packetCount.Add(1)
}

// IncrementTCPFailedPacketCount 增加TCP失败连接包计数
func (s *State) IncrementTCPFailedPacketCount() int64 {
	s.tcpFailedPacketCount.Add(1)
	s.tcpPacketCount.Add(1)
	return s.packetCount.Add(1)
}

// IncrementUDPPacketCount 增加UDP包计数
func (s *State) IncrementUDPPacketCount() int64 {
	s.udpPacketCount.Add(1)
	return s.packetCount.Add(1)
}

// IncrementHTTPPacketCount 增加HTTP包计数
func (s *State) IncrementHTTPPacketCount() int64 {
	s.httpPacketCount.Add(1)
	return s.packetCount.Add(1)
}

// IncrementResourceExhaustedCount 增加资源耗尽错误计数
func (s *State) IncrementResourceExhaustedCount() {
	s.resourceExhaustedCount.Add(1)
}

// =============================================================================
// 获取计数器方法 - 原子操作
// =============================================================================

// GetPacketCount 获取总包计数
func (s *State) GetPacketCount() int64 {
	return s.packetCount.Load()
}

// GetTCPPacketCount 获取TCP包计数
func (s *State) GetTCPPacketCount() int64 {
	return s.tcpPacketCount.Load()
}

// GetTCPSuccessPacketCount 获取TCP成功连接包计数
func (s *State) GetTCPSuccessPacketCount() int64 {
	return s.tcpSuccessPacketCount.Load()
}

// GetTCPFailedPacketCount 获取TCP失败连接包计数
func (s *State) GetTCPFailedPacketCount() int64 {
	return s.tcpFailedPacketCount.Load()
}

// GetUDPPacketCount 获取UDP包计数
func (s *State) GetUDPPacketCount() int64 {
	return s.udpPacketCount.Load()
}

// GetHTTPPacketCount 获取HTTP包计数
func (s *State) GetHTTPPacketCount() int64 {
	return s.httpPacketCount.Load()
}

// GetResourceExhaustedCount 获取资源耗尽错误计数
func (s *State) GetResourceExhaustedCount() int64 {
	return s.resourceExhaustedCount.Load()
}

// ResetPacketCounters 重置所有包计数器
func (s *State) ResetPacketCounters() {
	s.packetCount.Store(0)
	s.tcpPacketCount.Store(0)
	s.tcpSuccessPacketCount.Store(0)
	s.tcpFailedPacketCount.Store(0)
	s.udpPacketCount.Store(0)
	s.httpPacketCount.Store(0)
	s.resourceExhaustedCount.Store(0)
}

// =============================================================================
// 任务计数器方法
// =============================================================================

// GetEnd 获取结束计数
func (s *State) GetEnd() int64 {
	return s.end.Load()
}

// GetNum 获取数量计数
func (s *State) GetNum() int64 {
	return s.num.Load()
}

// IncrementEnd 增加结束计数
func (s *State) IncrementEnd() int64 {
	return s.end.Add(1)
}

// IncrementNum 增加数量计数
func (s *State) IncrementNum() int64 {
	return s.num.Add(1)
}

// SetEnd 设置结束计数
func (s *State) SetEnd(val int64) {
	s.end.Store(val)
}

// SetNum 设置数量计数
func (s *State) SetNum(val int64) {
	s.num.Store(val)
}

// =============================================================================
// 时间和进度方法
// =============================================================================

// GetStartTime 获取开始时间
func (s *State) GetStartTime() time.Time {
	return s.startTime
}

// =============================================================================
// 输出互斥锁方法
// =============================================================================

// LockOutput 锁定输出
func (s *State) LockOutput() {
	s.outputMutex.Lock()
}

// UnlockOutput 解锁输出
func (s *State) UnlockOutput() {
	s.outputMutex.Unlock()
}

// GetOutputMutex 获取输出互斥锁指针
func (s *State) GetOutputMutex() *sync.Mutex {
	return &s.outputMutex
}

// =============================================================================
// ICMP 限速器方法
// =============================================================================

// GetICMPLimiter 获取 ICMP 令牌桶限速器（延迟初始化）
func (s *State) GetICMPLimiter(icmpRate float64) *ratelimit.Bucket {
	s.icmpInitOnce.Do(func() {
		const (
			maxRate    = 1.0 * 1024 * 1024 // 1MB/s 基准速率
			packetSize = 70                // ICMP 包平均大小
		)

		adjustedRate := maxRate * icmpRate
		packetsPerSecond := adjustedRate / float64(packetSize)
		if packetsPerSecond < 1 {
			packetsPerSecond = 1
		}

		bucketLimit := int64(packetsPerSecond)

		packetTime := time.Second / time.Duration(packetsPerSecond)

		s.icmpLimiter = ratelimit.NewBucketWithQuantum(
			packetTime,
			bucketLimit,
			int64(1),
		)
	})
	return s.icmpLimiter
}

// =============================================================================
// 性能统计导出
// =============================================================================

// PerfStatsData 性能统计数据结构
type PerfStatsData struct {
	TotalPackets      int64   `json:"total_packets"`
	TCPPackets        int64   `json:"tcp_packets"`
	TCPSuccess        int64   `json:"tcp_success"`
	TCPFailed         int64   `json:"tcp_failed"`
	UDPPackets        int64   `json:"udp_packets"`
	HTTPPackets       int64   `json:"http_packets"`
	ResourceExhausted int64   `json:"resource_exhausted"`
	ScanDurationMs    int64   `json:"scan_duration_ms"`
	PacketsPerSecond  float64 `json:"packets_per_second"`
	SuccessRate       float64 `json:"success_rate"`
	TargetsScanned    int64   `json:"targets_scanned"`
}

// GetPerfStats 获取性能统计数据
func (s *State) GetPerfStats() PerfStatsData {
	duration := time.Since(s.startTime)
	durationMs := duration.Milliseconds()
	totalPackets := s.packetCount.Load()
	tcpSuccess := s.tcpSuccessPacketCount.Load()
	tcpFailed := s.tcpFailedPacketCount.Load()
	tcpTotal := s.tcpPacketCount.Load()

	var pps float64
	if durationMs > 0 {
		pps = float64(totalPackets) / (float64(durationMs) / 1000.0)
	}

	var successRate float64
	if tcpTotal > 0 {
		successRate = float64(tcpSuccess) / float64(tcpTotal) * 100.0
	}

	return PerfStatsData{
		TotalPackets:      totalPackets,
		TCPPackets:        tcpTotal,
		TCPSuccess:        tcpSuccess,
		TCPFailed:         tcpFailed,
		UDPPackets:        s.udpPacketCount.Load(),
		HTTPPackets:       s.httpPacketCount.Load(),
		ResourceExhausted: s.resourceExhaustedCount.Load(),
		ScanDurationMs:    durationMs,
		PacketsPerSecond:  pps,
		SuccessRate:       successRate,
		TargetsScanned:    s.num.Load(),
	}
}

// GetPerfStatsJSON 获取性能统计 JSON 字符串
func (s *State) GetPerfStatsJSON() string {
	stats := s.GetPerfStats()
	data, err := json.Marshal(stats)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// =============================================================================
// 运行时目标数据方法
// =============================================================================

// GetURLs 获取URL列表
func (s *State) GetURLs() []string {
	s.urlsMu.RLock()
	defer s.urlsMu.RUnlock()
	return s.urls
}

// SetURLs 设置URL列表
func (s *State) SetURLs(urls []string) {
	s.urlsMu.Lock()
	defer s.urlsMu.Unlock()
	s.urls = urls
}

// GetHostPorts 获取主机端口列表
func (s *State) GetHostPorts() []string {
	s.urlsMu.RLock()
	defer s.urlsMu.RUnlock()
	return s.hostPorts
}

// SetHostPorts 设置主机端口列表
func (s *State) SetHostPorts(hostPorts []string) {
	s.urlsMu.Lock()
	defer s.urlsMu.Unlock()
	s.hostPorts = hostPorts
}

// ClearHostPorts 清空主机端口列表
func (s *State) ClearHostPorts() {
	s.urlsMu.Lock()
	defer s.urlsMu.Unlock()
	s.hostPorts = nil
}

// =============================================================================
// Shell状态方法
// =============================================================================

// IsForwardShellActive 检查正向Shell是否活跃
func (s *State) IsForwardShellActive() bool {
	return atomic.LoadInt32(&s.forwardShellActive) == 1
}

// SetForwardShellActive 设置正向Shell活跃状态
func (s *State) SetForwardShellActive(active bool) {
	if active {
		atomic.StoreInt32(&s.forwardShellActive, 1)
	} else {
		atomic.StoreInt32(&s.forwardShellActive, 0)
	}
}

// IsReverseShellActive 检查反向Shell是否活跃
func (s *State) IsReverseShellActive() bool {
	return atomic.LoadInt32(&s.reverseShellActive) == 1
}

// SetReverseShellActive 设置反向Shell活跃状态
func (s *State) SetReverseShellActive(active bool) {
	if active {
		atomic.StoreInt32(&s.reverseShellActive, 1)
	} else {
		atomic.StoreInt32(&s.reverseShellActive, 0)
	}
}

// IsSocks5ProxyActive 检查SOCKS5代理是否活跃
func (s *State) IsSocks5ProxyActive() bool {
	return atomic.LoadInt32(&s.socks5ProxyActive) == 1
}

// SetSocks5ProxyActive 设置SOCKS5代理活跃状态
func (s *State) SetSocks5ProxyActive(active bool) {
	if active {
		atomic.StoreInt32(&s.socks5ProxyActive, 1)
	} else {
		atomic.StoreInt32(&s.socks5ProxyActive, 0)
	}
}

// =============================================================================
// 发包频率控制方法 - 统一使用令牌桶算法
// =============================================================================

// GetPacketLimiter 获取通用发包限速器（延迟初始化）
// rateLimit: 每分钟允许的包数，转换为令牌桶的秒级速率
func (s *State) GetPacketLimiter(rateLimit int64) *ratelimit.Bucket {
	s.packetInitOnce.Do(func() {
		if rateLimit <= 0 {
			return
		}

		// 将每分钟包数转换为每秒速率
		packetsPerSecond := float64(rateLimit) / 60.0
		if packetsPerSecond < 1 {
			packetsPerSecond = 1
		}

		// 令牌填充间隔
		fillInterval := time.Second / time.Duration(packetsPerSecond)

		// 桶容量设为每秒速率的2倍，允许小突发
		bucketCapacity := int64(packetsPerSecond * 2)
		if bucketCapacity < 1 {
			bucketCapacity = 1
		}

		s.packetLimiter = ratelimit.NewBucketWithQuantum(
			fillInterval,
			bucketCapacity,
			1,
		)
	})
	return s.packetLimiter
}

// CheckAndIncrementPacketRate 检查并消耗发包令牌
// 返回: (可以发包, 错误)
// 使用令牌桶算法，统一与ICMP限速器的实现方式
func (s *State) CheckAndIncrementPacketRate(rateLimit int64) (bool, error) {
	if rateLimit <= 0 {
		return true, nil
	}

	limiter := s.GetPacketLimiter(rateLimit)
	if limiter == nil {
		return true, nil
	}

	// 尝试获取一个令牌（非阻塞）
	if limiter.TakeAvailable(1) < 1 {
		return false, &PacketLimitError{
			Sentinel: ErrPacketRateLimited,
			Limit:    rateLimit,
		}
	}

	return true, nil
}

// =============================================================================
// 服务识别缓存 - per-session，消除跨扫描污染
// =============================================================================

// CacheService 缓存服务信息
func (s *State) CacheService(key string, info interface{}) {
	s.serviceCache.Store(key, info)
}

// GetCachedService 获取缓存的服务信息
func (s *State) GetCachedService(key string) (interface{}, bool) {
	return s.serviceCache.Load(key)
}
