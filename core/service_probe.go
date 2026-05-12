package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/core/portfinger"
)

// 默认超时时间常量
const (
	defaultTotalWaitMS = 3000 // 服务探测默认等待时间
	defaultIntensity   = 7    // 默认探测强度 (1-9)
)

// sslSecondProbes SSL服务二次探测的探针名称
var sslSecondProbes = []string{"TerminalServerCookie", "TerminalServer"}

// Probe PortFinger探测器类型别名 - 简化引用
type (
	Probe = portfinger.Probe
	// Match PortFinger匹配规则类型别名
	Match = portfinger.Match
)

// PortFinger全局访问 - 简化探测器访问
var (
	v           = portfinger.GetGlobalVScan()
	null        = portfinger.GetNullProbe()
	commonProbe = portfinger.GetCommonProbe()
	DecodeData  = portfinger.DecodeData
)

// readBufPool 读取缓冲区对象池，复用 2KB 缓冲区减少 GC 压力
var readBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 2*1024)
		return &buf
	},
}

// ServiceInfo 定义服务识别的结果信息
type ServiceInfo struct {
	Name    string            // 服务名称,如 http、ssh 等
	Banner  string            // 服务返回的横幅信息
	Version string            // 服务版本号
	Extras  map[string]string // 其他额外信息,如操作系统、产品名等
}

// Result 定义单次探测的结果
type Result struct {
	Service Service           // 识别出的服务信息
	Banner  string            // 服务横幅
	Extras  map[string]string // 额外信息
	Send    []byte            // 发送的探测数据
	Recv    []byte            // 接收到的响应数据
}

// Service 定义服务的基本信息
type Service struct {
	Name   string            // 服务名称
	Extras map[string]string // 服务的额外属性
}

// Info 定义单个端口探测的上下文信息
type Info struct {
	Address          string              // 目标IP地址
	Port             int                 // 目标端口
	Conn             net.Conn            // 网络连接
	Result           Result              // 探测结果
	Found            bool                // 是否成功识别服务
	ctx              context.Context     // 扫描级 context
	config           *common.Config      // 配置引用
	session          *common.ScanSession // 会话引用
	readTimeoutMS    int                 // 当前读取超时时间（毫秒）
	maxReadTimeoutMS int                 // RTT 自适应上限（毫秒），0 表示不限制
}

// SmartPortInfoScanner 智能服务识别器：保持nmap准确性，优化网络交互
type SmartPortInfoScanner struct {
	Address string
	Port    int
	Conn    net.Conn
	Timeout time.Duration
	info    *Info
	config  *common.Config      // 配置引用
	session *common.ScanSession // 会话引用
}

// 预定义的基础探测器已在PortFinger.go中定义，这里不再重复定义

// NewSmartPortInfoScanner 创建智能服务识别器
func NewSmartPortInfoScanner(ctx context.Context, addr string, port int, conn net.Conn, timeout time.Duration, config *common.Config, session *common.ScanSession) *SmartPortInfoScanner {
	return &SmartPortInfoScanner{
		Address: addr,
		Port:    port,
		Conn:    conn,
		Timeout: timeout,
		config:  config,
		session: session,
		info: &Info{
			Address: addr,
			Port:    port,
			Conn:    conn,
			ctx:     ctx,
			config:  config,
			session: session,
			Result: Result{
				Service: Service{},
			},
		},
	}
}

// Close 关闭Scanner持有的连接（包括探测过程中可能创建的新连接）
func (s *SmartPortInfoScanner) Close() {
	if s.info != nil && s.info.Conn != nil {
		_ = s.info.Conn.Close()
		s.info.Conn = nil
	}
}

// SmartIdentify 智能服务识别：Banner优先 + 优化的探测策略
// 返回值: (服务信息, 错误)
// 注意：TCP连接成功后，端口必然开放，不应该再改变这个判断
func (s *SmartPortInfoScanner) SmartIdentify() (*ServiceInfo, error) {
	// 第一阶段：读取初始Banner（大部分服务会主动发送）
	_, _ = s.tryInitialBanner()

	// 如果初始Banner已识别，返回结果
	if s.info.Found {
		serviceInfo := s.buildServiceInfo()
		// SSL 多阶段探测
		serviceInfo = s.performSSLSecondStage(serviceInfo)
		return serviceInfo, nil
	}

	// 第二阶段：智能探测策略（减少探测器数量）
	s.smartProbeStrategy()

	// 构造返回结果
	serviceInfo := s.buildServiceInfo()

	// SSL 多阶段探测（对所有服务进行检查）
	serviceInfo = s.performSSLSecondStage(serviceInfo)

	return serviceInfo, nil
}

// tryInitialBanner 尝试读取服务主动发送的Banner
// 返回值: (响应数据, 错误)
func (s *SmartPortInfoScanner) tryInitialBanner() ([]byte, error) {
	// 读取初始响应
	response, err := s.info.Read()
	if err != nil {
		return nil, err
	}

	if len(response) > 0 {
		// 使用原有的nmap指纹库解析Banner，保持准确性
		_ = s.info.tryProbes(response, []*Probe{null, commonProbe})
	}

	return response, nil
}


// smartProbeStrategy 智能探测策略
// 改进版：使用 nmap-service-probes.txt 中的 ports 字段和 rarity 排序
func (s *SmartPortInfoScanner) smartProbeStrategy() {
	usedProbes := make(map[string]struct{})

	// 阶段1：尝试端口特定探测器（使用 Probe.Ports，按 Rarity 排序）
	// 注意：端口特定探测器不按 intensity 过滤，因为它们是专门为该端口设计的
	portProbes := v.GetProbesForPort(s.Port)
	if len(portProbes) > 0 {
		if s.tryProbeList(portProbes, usedProbes) {
			return
		}
	}

	// 阶段2：尝试 SSL 端口探测器（使用 Probe.SSLPorts）
	sslProbes := v.GetSSLProbesForPort(s.Port)
	if len(sslProbes) > 0 {
		if s.tryProbeList(sslProbes, usedProbes) {
			return
		}
	}

	// 阶段3：回退到通用探测器（按 Rarity 排序，按 intensity 过滤）
	allProbes := v.GetAllProbesSortedByRarity()
	allProbes = portfinger.FilterProbesByIntensity(allProbes, defaultIntensity)
	// 限制回退探测器数量，避免过度探测
	maxFallback := 5
	if len(allProbes) > maxFallback {
		allProbes = allProbes[:maxFallback]
	}
	s.tryProbeList(allProbes, usedProbes)

	// 如果所有探测都失败，标记为未知服务
	if s.info.Result.Service.Name == "" {
		s.info.Result.Service.Name = "unknown"
	}
}

// tryProbeList 尝试探测器列表
// 使用 Probe.TotalWaitMS 设置动态超时，实现隐式 NULL 回退
func (s *SmartPortInfoScanner) tryProbeList(probes []*Probe, usedProbes map[string]struct{}) bool {
	for _, probe := range probes {
		if _, used := usedProbes[probe.Name]; used {
			continue
		}
		usedProbes[probe.Name] = struct{}{}

		// 优先使用预解码数据
		probeData := probe.DecodedData
		if probeData == nil {
			var err error
			probeData, err = DecodeData(probe.Data)
			if err != nil {
				continue
			}
		}

		// 使用 TotalWaitMS 设置动态超时
		waitMS := probe.TotalWaitMS
		if waitMS <= 0 {
			waitMS = defaultTotalWaitMS
		}
		s.info.setReadTimeout(waitMS)

		response := s.info.Connect(probeData)
		if len(response) == 0 {
			// 连接可能被关闭（如服务端返回 EOF），尝试重建连接后继续下一个探针
			s.reconnectIfNeeded()
			continue
		}

		// 尝试匹配（GetInfo 会自动遍历 fallback 数组，包含 NULL 回退）
		s.info.GetInfo(response, probe)
		if s.info.Found {
			return true
		}
	}

	return false
}

// reconnectIfNeeded 强制重建连接
// 当探针收到空响应时调用，说明连接可能已被服务端关闭
func (s *SmartPortInfoScanner) reconnectIfNeeded() {
	// 关闭旧连接
	if s.info.Conn != nil {
		_ = s.info.Conn.Close()
		s.info.Conn = nil
		s.Conn = nil
	}

	// 重新建立连接
	newConn, err := s.session.DialTCP(s.info.ctx, "tcp", fmt.Sprintf("%s:%d", s.Address, s.Port), s.Timeout)
	if err != nil {
		return
	}

	s.info.Conn = newConn
	s.Conn = newConn
}

// performSSLSecondStage 执行 SSL 多阶段探测
// 参考 gonmap 的策略：ssl → ssl-specific probes → https
func (s *SmartPortInfoScanner) performSSLSecondStage(serviceInfo *ServiceInfo) *ServiceInfo {
	if serviceInfo.Name != "ssl" {
		// 不是SSL服务，直接返回
		return serviceInfo
	}
	// 第二阶段：SSL 专用探测器（如 RDP）
	for _, probeName := range sslSecondProbes {
		probe, exists := v.ProbesMapKName[probeName]
		if !exists {
			continue
		}

		probeData := probe.DecodedData
		if probeData == nil {
			var decErr error
			probeData, decErr = DecodeData(probe.Data)
			if decErr != nil || len(probeData) == 0 {
				continue
			}
		}
		if len(probeData) == 0 {
			continue
		}
		response := s.info.Connect(probeData)
		if len(response) == 0 {
			continue
		}

		// 尝试识别服务
		s.info.GetInfo(response, &probe)
		if s.info.Found && s.info.Result.Service.Name != "ssl" {
			return s.buildServiceInfo()
		}
	}

	// 第三阶段：尝试 HTTPS（通过 TLS 发送 HTTP GET）
	if serviceInfo.Name == "ssl" {
		newServiceInfo := s.tryHTTPSProbe()
		if newServiceInfo != nil {
			return newServiceInfo
		}
	}

	return serviceInfo
}

// tryHTTPSProbe 尝试 HTTPS 探测
func (s *SmartPortInfoScanner) tryHTTPSProbe() *ServiceInfo {
	// 使用 GetRequest 探测器
	probe, exists := v.ProbesMapKName["GetRequest"]
	if !exists {
		return nil
	}

	probeData := probe.DecodedData
	if probeData == nil {
		var decErr error
		probeData, decErr = DecodeData(probe.Data)
		if decErr != nil || len(probeData) == 0 {
			return nil
		}
	}
	if len(probeData) == 0 {
		return nil
	}
	response := s.info.Connect(probeData)
	if len(response) == 0 {
		return nil
	}

	// 尝试识别服务
	s.info.GetInfo(response, &probe)
	if s.info.Found {
		serviceInfo := s.buildServiceInfo()
		// 自动转换 http → https
		if serviceInfo.Name == "http" {
			serviceInfo.Name = "https"
		}
		return serviceInfo
	}

	return nil
}

// buildServiceInfo 构建ServiceInfo结果
func (s *SmartPortInfoScanner) buildServiceInfo() *ServiceInfo {
	result := &s.info.Result

	serviceInfo := &ServiceInfo{
		Name:    result.Service.Name,
		Banner:  result.Banner,
		Version: result.Service.Extras["version"],
		Extras:  make(map[string]string),
	}

	// 复制额外信息
	for k, v := range result.Service.Extras {
		serviceInfo.Extras[k] = v
	}
	return serviceInfo
}

// tryProbes 尝试使用指定的探测器列表检查响应
func (i *Info) tryProbes(response []byte, probes []*Probe) bool {
	for _, probe := range probes {
		i.GetInfo(response, probe)
		if i.Found {
			return true
		}
	}
	return false
}

// GetInfo 分析响应数据并提取服务信息
func (i *Info) GetInfo(response []byte, probe *Probe) {
	// 响应数据有效性检查
	if len(response) <= 0 {
		common.LogDebug("响应数据为空")
		return
	}

	result := &i.Result
	var (
		softMatch Match
		softFound bool
	)

	// 遍历 fallback 数组尝试匹配（参考 Nmap 的 servicescan_read_handler）
	// fallback 数组顺序: [自身, fallback指令中的探测器..., NULL探测器(TCP)]
	for depth := 0; depth < portfinger.MaxFallbacks+1; depth++ {
		fallback := probe.Fallbacks[depth]
		if fallback == nil {
			break
		}

		// 尝试匹配当前 fallback 探测器的规则
		if matched, match := i.processMatches(response, fallback.Matchs); matched {
			return // 硬匹配成功，直接返回
		} else if match != nil && !softFound {
			// 记录第一个软匹配
			softFound = true
			softMatch = *match
		}
	}

	// 处理未找到匹配的情况
	if !i.Found {
		i.handleNoMatch(response, result, softFound, softMatch)
	}
}

// processMatches 处理匹配规则集
func (i *Info) processMatches(response []byte, matches *[]Match) (bool, *Match) {
	var softMatch *Match

	for _, match := range *matches {
		if !match.MatchPattern(response) {
			continue
		}

		if !match.IsSoft {
			i.handleHardMatch(response, &match)
			return true, nil
		} else if softMatch == nil {
			tmpMatch := match
			softMatch = &tmpMatch
		}
	}

	return false, softMatch
}

// handleHardMatch 处理硬匹配结果
func (i *Info) handleHardMatch(response []byte, match *Match) {
	result := &i.Result
	extras := match.ParseVersionInfo(response)
	extrasMap := extras.ToMap()

	result.Service.Name = match.Service
	result.Extras = extrasMap
	result.Banner = portfinger.TrimBanner(string(response))
	result.Service.Extras = extrasMap

	// 特殊处理 microsoft-ds 服务
	if result.Service.Name == "microsoft-ds" {
		common.LogDebug("特殊处理 microsoft-ds 服务")
		result.Service.Extras["hostname"] = result.Banner
	}

	i.Found = true
	common.LogDebug(fmt.Sprintf("服务识别结果: %s, Banner: %s", result.Service.Name, result.Banner))
}

// handleNoMatch 处理未找到匹配的情况
func (i *Info) handleNoMatch(response []byte, result *Result, softFound bool, softMatch Match) {
	result.Banner = portfinger.TrimBanner(string(response))

	if !softFound {
		// 尝试识别 HTTP 服务（大小写不敏感）
		bannerLower := strings.ToLower(result.Banner)
		if strings.Contains(bannerLower, "http/") ||
			strings.Contains(bannerLower, "html") {
			common.LogDebug("识别为HTTP服务")
			result.Service.Name = "http"
		} else {
			common.LogDebug("未知服务")
			result.Service.Name = "unknown"
		}
	} else {
		extras := softMatch.ParseVersionInfo(response)
		result.Service.Extras = extras.ToMap()
		result.Service.Name = softMatch.Service
		i.Found = true
		common.LogDebug(fmt.Sprintf("软匹配服务: %s", result.Service.Name))
	}
}

// Connect 发送数据并获取响应
func (i *Info) Connect(msg []byte) []byte {
	_ = i.Write(msg)
	reply, _ := i.Read()
	return reply
}

// setReadTimeout 设置读取超时时间（毫秒）
func (i *Info) setReadTimeout(ms int) {
	if ms > 0 {
		i.readTimeoutMS = ms
	}
}

// getReadTimeout 获取当前读取超时时间
func (i *Info) getReadTimeout() time.Duration {
	ms := defaultReadTimeoutMS
	if i.readTimeoutMS > 0 {
		ms = i.readTimeoutMS
	}
	if i.maxReadTimeoutMS > 0 && ms > i.maxReadTimeoutMS {
		ms = i.maxReadTimeoutMS
	}
	return time.Duration(ms) * time.Millisecond
}

// WrTimeout 默认读写超时时间(秒)
const WrTimeout = 3

// currentReadTimeoutMS 当前读取超时时间（毫秒），用于动态调整
var defaultReadTimeoutMS = WrTimeout * 1000

// Write 写入数据到连接
func (i *Info) Write(msg []byte) error {
	if i.Conn == nil {
		return nil
	}

	// 设置写入超时
	_ = i.Conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(WrTimeout)))

	// 写入数据
	_, err := i.Conn.Write(msg)
	if err != nil && strings.Contains(err.Error(), "close") {
		// 关闭旧连接并清理
		oldConn := i.Conn
		i.Conn = nil
		_ = oldConn.Close()

		// 尝试重新连接 - 支持SOCKS5代理
		newConn, retryErr := i.session.DialTCP(i.ctx, "tcp", fmt.Sprintf("%s:%d", i.Address, i.Port), time.Duration(6)*time.Second)
		if retryErr != nil {
			return retryErr
		}

		// 设置新连接并重试写入
		i.Conn = newConn
		_ = i.Conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(WrTimeout)))
		_, err = i.Conn.Write(msg)

		// 如果重试写入失败，清理新连接
		if err != nil {
			_ = i.Conn.Close()
			i.Conn = nil
		}
	}

	// 记录发送的数据
	if err == nil {
		i.Result.Send = msg
	}

	return err
}

// Read 从连接读取响应
func (i *Info) Read() ([]byte, error) {
	if i.Conn == nil {
		return nil, nil
	}

	// 设置读取超时（使用动态超时）
	_ = i.Conn.SetReadDeadline(time.Now().Add(i.getReadTimeout()))

	// 读取数据
	result, err := readFromConn(i.Conn)
	if err != nil && strings.Contains(err.Error(), "close") {
		return result, err
	}

	// 记录接收到的数据
	if len(result) > 0 {
		i.Result.Recv = result
	}

	return result, err
}

// readFromConn 从连接读取数据的辅助函数
// 使用 sync.Pool 复用缓冲区，减少高并发扫描时的 GC 压力
func readFromConn(conn net.Conn) ([]byte, error) {
	const size = 2 * 1024

	// 从对象池获取缓冲区
	bufInterface := readBufPool.Get()
	bufPtr, ok := bufInterface.(*[]byte)
	if !ok || bufPtr == nil {
		buf := make([]byte, size)
		bufPtr = &buf
	}
	buf := *bufPtr
	defer readBufPool.Put(bufPtr)

	var result []byte

	for {
		count, err := conn.Read(buf)

		if count > 0 {
			result = append(result, buf[:count]...)
		}

		if err != nil {
			if len(result) > 0 {
				return result, nil
			}
			if errors.Is(err, io.EOF) {
				return result, nil
			}
			return result, err
		}

		if count < size {
			return result, nil
		}
	}
}
