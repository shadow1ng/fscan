package core

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/common/output"
	"github.com/shadow1ng/fscan/common/parsers"
)

// proxyFailurePatterns 代理连接失败的错误模式（小写）
var proxyFailurePatterns = []string{
	"connection reset by peer",
	"connection refused",
	"no route to host",
	"network is unreachable",
	"host is unreachable",
	"general socks server failure",
	"connection not allowed",
	"host unreachable",
	"network unreachable",
	"connection refused by destination host",
}

// resourceExhaustedPatterns 资源耗尽类错误模式
var resourceExhaustedPatterns = []string{
	"too many open files",
	"no buffer space available",
	"cannot assign requested address",
	"connection reset by peer",
	"发包受限",
}

// resultCollector 结果收集器，用于并发安全地收集扫描结果
type resultCollector struct {
	mu     sync.Mutex
	addrs  map[string]struct{}
	stream chan<- string
}

func newResultCollector(stream chan<- string) *resultCollector {
	return &resultCollector{
		addrs:  make(map[string]struct{}),
		stream: stream,
	}
}

func (c *resultCollector) Add(addr string) {
	c.mu.Lock()
	if _, dup := c.addrs[addr]; dup {
		c.mu.Unlock()
		return
	}
	c.addrs[addr] = struct{}{}
	c.mu.Unlock()
	if c.stream != nil {
		c.stream <- addr
	}
}

func (c *resultCollector) GetAll() []string {
	c.mu.Lock()
	result := make([]string, 0, len(c.addrs))
	for addr := range c.addrs {
		result = append(result, addr)
	}
	c.mu.Unlock()
	return result
}

// portScanTask 端口扫描任务（轻量级，用于滑动窗口调度）
type portScanTask struct {
	host      string
	port      int
	semaphore chan struct{} // 完成时释放窗口槽位
}

// failedPortInfo 失败端口信息
type failedPortInfo struct {
	Host string
	Port int
	Addr string
}

// failedPortCollector 失败端口收集器，用于记录需要重扫的端口
type failedPortCollector struct {
	mu    sync.Mutex
	ports []failedPortInfo
}

// Add 添加失败的端口
func (f *failedPortCollector) Add(host string, port int, addr string) {
	f.mu.Lock()
	f.ports = append(f.ports, failedPortInfo{
		Host: host,
		Port: port,
		Addr: addr,
	})
	f.mu.Unlock()
}

// Count 获取失败端口数量
func (f *failedPortCollector) Count() int {
	f.mu.Lock()
	count := len(f.ports)
	f.mu.Unlock()
	return count
}

// EnhancedPortScan 高性能端口扫描函数
// 使用滑动窗口调度 + 自适应线程池 + 流式迭代器
// stream: 可选，非 nil 时每发现开放端口立即发送 addr，扫描结束后关闭
func EnhancedPortScan(ctx context.Context, hosts []string, ports string, timeout int64, session *common.ScanSession, stream chan<- string) []string {
	config := session.Config
	state := session.State
	common.LogDebug(fmt.Sprintf("[PortScan] 开始: %d个主机, 线程数=%d", len(hosts), config.ThreadNum))

	// 大规模扫描预筛：跨多个 /24 时先做网段探活，跳过空网段
	if len(hosts) > subnetProbeThreshold {
		hosts = probeSubnets(ctx, hosts, time.Duration(timeout)*time.Second, session)
		if len(hosts) == 0 {
			common.LogInfo(i18n.GetText("port_scan_no_alive_subnet"))
			if stream != nil {
				close(stream)
			}
			return nil
		}
	}

	// 解析端口和排除端口
	portList := parsers.ParsePort(ports)
	if len(portList) == 0 {
		common.LogError(i18n.Tr("invalid_port", ports))
		if stream != nil {
			close(stream)
		}
		return nil
	}
	common.LogDebug(fmt.Sprintf("[PortScan] 端口解析完成: %d个端口", len(portList)))

	// 使用config中的排除端口配置
	excludePorts := parsers.ParsePort(config.Target.ExcludePorts)
	exclude := make(map[int]struct{}, len(excludePorts))
	for _, p := range excludePorts {
		exclude[p] = struct{}{}
	}

	// 检查代理可靠性，如果存在全回显问题则警告
	if common.IsProxyEnabled() && !common.IsProxyReliable() {
		common.LogError("检测到代理存在全回显问题，端口扫描结果可能不准确")
	}

	// 创建流式迭代器（O(1) 内存，端口喷洒策略）
	iter := NewSocketIterator(hosts, portList, exclude)
	totalTasks := iter.Total()
	common.LogDebug(fmt.Sprintf("[PortScan] 总任务数: %d", totalTasks))

	// 使用传入的配置
	threadNum := config.ThreadNum

	// 大规模扫描警告和线程数自动调整
	if totalTasks > 100000 {
		common.LogInfo(fmt.Sprintf("大规模扫描: %d 个目标 (%d主机 × %d端口)", totalTasks, len(hosts), len(portList)))
		// 如果任务数超过100万且线程数大于300，自动降低线程数
		if totalTasks > 1000000 && threadNum > 300 {
			oldThreadNum := threadNum
			threadNum = 300
			common.LogInfo(fmt.Sprintf("自动调整线程数: %d -> %d (大规模扫描优化)", oldThreadNum, threadNum))
		}
	}

	// 初始化端口扫描进度条
	if totalTasks > 0 && config.Output.ShowProgress {
		description := fmt.Sprintf("端口扫描中（%d线程）", threadNum)
		common.InitProgressBar(int64(totalTasks), description)
	}
	common.LogDebug("[PortScan] 进度条初始化完成")

	// 初始化并发控制
	to := time.Duration(timeout) * time.Second
	adaptiveTO := NewAdaptiveTimeout(to)
	var count int64
	collector := newResultCollector(stream)
	failedCollector := &failedPortCollector{}
	var wg sync.WaitGroup

	common.LogDebug(fmt.Sprintf("[PortScan] 开始创建线程池, size=%d", threadNum))
	// 创建自适应线程池（支持动态调整）
	pool, err := NewAdaptivePool(threadNum, func(task interface{}) {
		taskInfo, ok := task.(portScanTask)
		if !ok {
			return
		}
		defer func() {
			<-taskInfo.semaphore // 释放窗口槽位
			wg.Done()
		}()

		addr := fmt.Sprintf("%s:%d", taskInfo.host, taskInfo.port)
		scanSinglePort(ctx, taskInfo.host, taskInfo.port, addr, adaptiveTO, &count, collector, failedCollector, session)
		common.UpdateProgressBar(1)
	}, state)
	if err != nil {
		common.LogError(i18n.Tr("thread_pool_create_failed", err))
		if stream != nil {
			close(stream)
		}
		return nil
	}
	common.LogDebug("[PortScan] 线程池创建成功")
	defer pool.Release()

	common.LogDebug("[PortScan] 开始滑动窗口调度")
	// 滑动窗口调度：维护固定数量的"飞行中"任务
	slidingWindowSchedule(iter, pool, &wg, threadNum)
	common.LogDebug("[PortScan] 滑动窗口调度完成")

	// 收集结果
	aliveAddrs := collector.GetAll()

	// 关闭流式通知 channel
	if stream != nil {
		close(stream)
	}

	// 完成端口扫描进度条
	if common.IsProgressActive() {
		common.FinishProgressBar()
	}

	common.LogInfo(i18n.Tr("port_scan_complete", count))

	// 检查扫描失败率，如果过高则警告用户
	resourceErrors := state.GetResourceExhaustedCount()
	failedCount := failedCollector.Count()

	if failedCount > 0 {
		failureRate := float64(failedCount) / float64(totalTasks) * 100

		if failureRate > 20 {
			// 失败率超过20%，严重警告
			common.LogError(i18n.Tr("scan_failure_rate_high", fmt.Sprintf("%.1f%%", failureRate), failedCount, totalTasks))
			common.LogError(i18n.GetText("scan_failure_reason"))
			common.LogError(i18n.Tr("scan_reduce_threads_suggestion", threadNum))
		} else if failureRate > 5 {
			// 失败率5-20%，一般警告
			common.LogInfo(i18n.Tr("scan_partial_failure", fmt.Sprintf("%.1f%%", failureRate), failedCount, totalTasks))
			common.LogInfo(i18n.Tr("scan_reduce_threads_accuracy", threadNum))
		}
	}

	if resourceErrors > 0 {
		common.LogError(i18n.Tr("resource_exhausted_warning", resourceErrors))
	}

	return aliveAddrs
}

// slidingWindowSchedule 滑动窗口调度器
// 核心思想：维护固定数量的"飞行中"任务，一个完成立即补充新的
// 优势：避免任务队列堆积，内存使用恒定
func slidingWindowSchedule(iter *SocketIterator, pool *AdaptivePool, wg *sync.WaitGroup, windowSize int) {
	// 使用信号量控制窗口大小
	semaphore := make(chan struct{}, windowSize)

	for {
		host, port, ok := iter.Next()
		if !ok {
			break
		}

		// 获取窗口槽位（阻塞直到有空位）
		semaphore <- struct{}{}

		wg.Add(1)
		task := portScanTask{
			host:      host,
			port:      port,
			semaphore: semaphore,
		}
		if err := pool.Invoke(task); err != nil {
			<-semaphore
			wg.Done()
		}
	}

	// 等待所有任务完成
	wg.Wait()
}

// connectWithRetry 带重试的TCP连接 - 只对资源耗尽错误重试
func connectWithRetry(ctx context.Context, session *common.ScanSession, addr string, timeout time.Duration, maxRetries int) (net.Conn, error) {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		conn, err := session.DialTCP(ctx, "tcp", addr, timeout)

		if err == nil {
			return conn, nil
		}

		lastErr = err

		// 只对资源耗尽类错误重试，端口关闭直接返回
		if !isResourceExhaustedError(err) {
			return nil, err
		}

		// 记录资源耗尽错误
		session.State.IncrementResourceExhaustedCount()

		// 指数退避：200ms → 600ms → 1200ms
		if attempt < maxRetries-1 {
			waitTime := time.Duration(200*(1<<uint(attempt))) * time.Millisecond
			time.Sleep(waitTime)
		}
	}

	return nil, lastErr
}

// isResourceExhaustedError 判断是否为资源耗尽类错误
func isResourceExhaustedError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	for _, pattern := range resourceExhaustedPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// buildServiceLogMessage 构建服务识别的日志信息
// 格式: addr service [Product:xxx ||Version:xxx] Banner:(xxx)
func buildServiceLogMessage(addr string, serviceInfo *ServiceInfo, isWeb bool) string {
	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("%-21s", addr))

	if serviceInfo.Name != "unknown" {
		msg.WriteString(fmt.Sprintf(" %-8s", serviceInfo.Name))
	}

	// 构建 [Product:xxx ||Version:xxx] 格式
	var info []string
	if product, ok := serviceInfo.Extras["vendor_product"]; ok && product != "" {
		info = append(info, fmt.Sprintf("Product:%s", product))
	}
	if serviceInfo.Version != "" {
		info = append(info, fmt.Sprintf("Version:%s", serviceInfo.Version))
	}
	if len(info) > 0 {
		msg.WriteString(fmt.Sprintf(" [%s]", strings.Join(info, " ||")))
	}

	// Banner 信息
	if len(serviceInfo.Banner) > 0 {
		banner := strings.TrimSpace(serviceInfo.Banner)
		if len(banner) > 80 {
			banner = banner[:80] + "..."
		}
		msg.WriteString(fmt.Sprintf(" Banner:(%s)", banner))
	}

	return msg.String()
}

// scanSinglePort 扫描单个端口并进行服务识别（重构后的简洁版本）
func scanSinglePort(ctx context.Context, host string, port int, addr string, adaptiveTO *AdaptiveTimeout, count *int64, collector *resultCollector, failedCollector *failedPortCollector, session *common.ScanSession) {
	config := session.Config
	timeout := adaptiveTO.Timeout()
	// 步骤1：建立连接
	start := time.Now()
	conn, err := connectWithRetry(ctx, session, addr, timeout, 2)
	if err != nil {
		handleConnectionFailure(err, host, port, addr, failedCollector)
		return
	}
	adaptiveTO.Record(time.Since(start))

	// 步骤1.5：代理连接深度验证（防止透明代理/全回显代理的假连接问题）
	valid, verifyMethod := verifyProxyConnectionDeep(conn, addr)
	if !valid {
		common.LogDebug(fmt.Sprintf("代理验证失败 %s: %s", addr, verifyMethod))
		_ = conn.Close()
		return
	}

	// 步骤1.6：如果使用了代理且进行了数据交互，需要重建连接
	// 因为验证阶段可能读取了Banner或发送了HTTP GET探测，污染了连接状态
	if common.IsProxyEnabled() && verifyMethod != "direct" {
		_ = conn.Close()
		// 重新建立干净的连接用于服务识别
		conn, err = connectWithRetry(ctx, session, addr, timeout, 2)
		if err != nil {
			handleConnectionFailure(err, host, port, addr, failedCollector)
			return
		}
	}

	// 步骤2：记录开放端口
	atomic.AddInt64(count, 1)
	collector.Add(addr)
	saveOpenPort(host, port)

	// 步骤3：服务识别（Scanner负责关闭连接，包括探测中可能创建的新连接）
	scanner := NewSmartPortInfoScanner(ctx, host, port, conn, timeout, config, session)
	// 服务探测超时自适应：用 RTT 采样值约束读超时上限
	// 下限 500ms：服务处理需要时间，不能太激进
	if rttTO := adaptiveTO.Timeout(); rttTO < timeout {
		maxMS := int(rttTO.Milliseconds()) * 6
		if maxMS < 500 {
			maxMS = 500
		}
		scanner.info.maxReadTimeoutMS = maxMS
	}
	defer scanner.Close()
	serviceInfo, _ := scanner.SmartIdentify()

	// 步骤4：处理结果
	processServiceResult(host, port, addr, serviceInfo, config, session)
}

// handleConnectionFailure 处理连接失败
// 只收集资源耗尽类错误，timeout 是正常的扫描结果（防火墙 drop）不计入失败
func handleConnectionFailure(err error, host string, port int, addr string, failedCollector *failedPortCollector) {
	if isResourceExhaustedError(err) {
		failedCollector.Add(host, port, addr)
	}
}

// verifyProxyConnectionDeep 深度验证代理连接是否真正可用
// 防止透明代理/全回显代理的假连接问题
// 返回: (是否有效, 验证方式)
//
// 优化策略：
// 1. 快速 Banner 检测 (100ms) - 大部分服务会主动发送数据
// 2. 轻量探测 (发送 \r\n) - 触发某些服务响应，同时不污染协议状态
// 3. 短超时等待 (500ms) - 平衡准确性和性能
func verifyProxyConnectionDeep(conn net.Conn, addr string) (bool, string) {
	// 无代理或SOCKS5代理：跳过深度验证
	// SOCKS5协议层已验证连接可达性，连接成功即端口开放
	if !common.IsProxyEnabled() || common.IsSOCKS5Proxy() {
		return true, "direct"
	}

	buf := make([]byte, 256)

	// 阶段1: 读取 Banner (500ms)
	// 大部分服务（SSH、FTP、SMTP、MySQL等）会主动发送欢迎消息
	// 不能等太久，否则代理可能因空闲而关闭连接
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, _ := conn.Read(buf)
	_ = conn.SetReadDeadline(time.Time{})

	if n > 0 {
		if isProxyErrorResponse(buf[:n]) {
			common.LogDebug(fmt.Sprintf("代理返回错误响应 %s", addr))
			return false, "proxy_error"
		}
		return true, "banner"
	}

	// 阶段2: HTTP 探针探测（参考 fscanx）
	// 使用 HTTP GET 而非 CRLF，因为：
	// - 大部分服务会对 HTTP 请求有明确响应（即使是错误响应）
	// - 在透明代理环境下能更有效地检测真实连接状态
	// - 即使是非 HTTP 服务也会返回某种响应或关闭连接
	httpProbe := []byte("GET / HTTP/1.0\r\n\r\n")
	_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	_, writeErr := conn.Write(httpProbe)
	_ = conn.SetWriteDeadline(time.Time{})

	if writeErr != nil && isConnectionClosed(writeErr) {
		common.LogDebug(fmt.Sprintf("探测写入失败 %s: %v", addr, writeErr))
		return false, "write_failed"
	}

	// 阶段3: 等待探测响应 (2s)
	// TUN 模式下代理链路延迟较大，需要更长超时
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, readErr := conn.Read(buf)
	_ = conn.SetReadDeadline(time.Time{})

	if n > 0 {
		if isProxyErrorResponse(buf[:n]) {
			common.LogDebug(fmt.Sprintf("代理探测返回错误 %s", addr))
			return false, "proxy_error"
		}
		return true, "probe"
	}

	// 阶段4: 最终判断
	if readErr != nil {
		errLower := strings.ToLower(readErr.Error())
		for _, pattern := range proxyFailurePatterns {
			if strings.Contains(errLower, pattern) {
				common.LogDebug(fmt.Sprintf("代理连接被拒绝 %s: %v", addr, readErr))
				return false, "proxy_reject"
			}
		}
	}

	// 无响应 = 端口关闭（参考 fscanx 方案）
	// 在透明代理环境下，ProxyReliable 检测可能被污染，不可信
	// 因此采用更保守的策略：无响应一律判定为关闭
	// 这样可以避免透明代理导致的全端口误报问题
	common.LogDebug(fmt.Sprintf("代理连接无响应，判定为端口关闭 %s", addr))
	return false, "no_response"
}

// isProxyErrorResponse 检查是否为代理错误响应
// 支持 SOCKS5 错误码和常见代理错误模式
func isProxyErrorResponse(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// SOCKS5 错误响应检查
	// SOCKS5 响应格式: [VER][REP][RSV][ATYP]...
	// REP 字段: 0x00=成功, 0x01-0x08=各种失败
	if len(data) >= 2 && data[0] == 0x05 {
		rep := data[1]
		if rep >= 0x01 && rep <= 0x08 {
			return true
		}
	}

	// 检查常见的代理错误文本
	dataStr := strings.ToLower(string(data))
	proxyErrorTexts := []string{
		"connection refused",
		"host unreachable",
		"network unreachable",
		"connection timed out",
		"proxy error",
		"gateway error",
		"bad gateway",
		"502",
		"503",
	}

	for _, errText := range proxyErrorTexts {
		if strings.Contains(dataStr, errText) {
			return true
		}
	}

	return false
}

// isConnectionClosed 检查错误是否表示连接已关闭
func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())
	closedPatterns := []string{
		"broken pipe",
		"connection reset",
		"connection refused",
		"use of closed network connection",
		"connection was forcibly closed",
	}

	for _, pattern := range closedPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// saveOpenPort 保存开放端口结果
func saveOpenPort(host string, port int) {
	_ = common.SaveResult(&output.ScanResult{
		Time:    time.Now(),
		Type:    output.TypePort,
		Target:  host,
		Status:  "open",
		Details: map[string]interface{}{"port": port},
	})
}

// processServiceResult 处理服务识别结果
func processServiceResult(host string, port int, addr string, serviceInfo *ServiceInfo, config *common.Config, session *common.ScanSession) {
	if serviceInfo == nil {
		// 服务识别失败，尝试 HTTP 回退探测
		if !tryHTTPFallbackDetection(host, port, addr, config, session) {
			common.LogInfo(i18n.Tr("port_open", addr))
		}
		return
	}

	// 保存并输出服务信息
	details := buildServiceDetails(port, serviceInfo)
	isWeb := IsWebServiceByFingerprint(serviceInfo)

	if isWeb {
		details["is_web"] = true
		MarkAsWebService(host, port, serviceInfo)
	}

	_ = common.SaveResult(&output.ScanResult{
		Time:    time.Now(),
		Type:    output.TypeService,
		Target:  fmt.Sprintf("%s:%d", host, port),
		Status:  "identified",
		Details: details,
	})

	common.LogInfo(buildServiceLogMessage(addr, serviceInfo, isWeb))
}

// buildServiceDetails 构建服务详情 map
func buildServiceDetails(port int, info *ServiceInfo) map[string]interface{} {
	details := map[string]interface{}{
		"port":    port,
		"service": info.Name,
	}

	if info.Version != "" {
		details["version"] = info.Version
	}

	extraKeyMap := map[string]string{
		"vendor_product": "product",
		"os":             "os",
		"info":           "info",
	}

	for k, v := range info.Extras {
		if v == "" {
			continue
		}
		if mappedKey, ok := extraKeyMap[k]; ok {
			details[mappedKey] = v
		}
	}

	if len(info.Banner) > 0 {
		details["banner"] = strings.TrimSpace(info.Banner)
	}

	return details
}

// tryHTTPFallbackDetection 尝试HTTP回退探测，返回是否成功识别为HTTP服务
func tryHTTPFallbackDetection(host string, port int, addr string, config *common.Config, session *common.ScanSession) bool {
	// 使用WebDetection进行HTTP协议探测
	webDetector := GetWebPortDetector()
	if !webDetector.DetectHTTPServiceOnly(host, port, config, session) {
		return false
	}

	// HTTP探测成功，标记为Web服务
	webServiceInfo := &ServiceInfo{
		Name:    "http",
		Version: "",
		Banner:  "",
		Extras:  map[string]string{"detected_by": "http_probe"},
	}
	MarkAsWebService(host, port, webServiceInfo)

	// 保存HTTP服务结果
	details := map[string]interface{}{
		"port":        port,
		"service":     "http",
		"is_web":      true,
		"detected_by": "http_probe",
	}
	_ = common.SaveResult(&output.ScanResult{
		Time:    time.Now(),
		Type:    output.TypeService,
		Target:  fmt.Sprintf("%s:%d", host, port),
		Status:  "identified",
		Details: details,
	})

	common.LogInfo(i18n.Tr("port_open_http", addr))
	return true
}

// =============================================================================
// 网段预筛 — 大规模扫描时跳过空 /24 网段
// =============================================================================

// subnetProbeThreshold 触发网段预筛的主机数阈值（超过 1 个 /24）
const subnetProbeThreshold = 256

// subnetProbePorts 逐主机探活用的端口（轮换）
var subnetProbePorts = []int{80, 443, 22, 445, 3389, 8080, 3306, 6379}

// gatewayProbePorts 网关启发式探测端口（网关常开的服务）
var gatewayProbePorts = []int{22, 80, 443, 23, 8080, 161, 53, 3389}

// gatewayOffsets 网关候选地址偏移量
var gatewayOffsets = []string{".1", ".254"}

// subnetProbeTimeout 每个探测的超时
const subnetProbeTimeout = 1500 * time.Millisecond

// subnetProbeConcurrency 网段探活全局并发数
const subnetProbeConcurrency = 500

// probeSubnets 对每个 /24 网段做探活，返回属于存活网段的主机列表
// 两阶段策略：
//
//	阶段 1（快速）：对每个子网的 .1/.254 网关做多端口探测，命中即标记存活
//	阶段 2（兜底）：未命中的子网，逐主机单端口轮换扫描
func probeSubnets(ctx context.Context, hosts []string, timeout time.Duration, session *common.ScanSession) []string {
	// 按 /24 分组
	subnets := make(map[string][]string)
	for _, h := range hosts {
		prefix := subnetPrefix(h)
		if prefix != "" {
			subnets[prefix] = append(subnets[prefix], h)
		}
	}

	if len(subnets) <= 1 {
		return hosts
	}

	common.LogInfo(fmt.Sprintf("网段预筛: %d 个 /24 子网, %d 个主机", len(subnets), len(hosts)))

	aliveSubnets := sync.Map{}
	var wg sync.WaitGroup
	limiter := make(chan struct{}, subnetProbeConcurrency)

	// ── 阶段 1：网关启发式 ──────────────────────────────────
	// 对每个子网的 .1 和 .254 打多个端口，命中率高且速度极快
	for prefix := range subnets {
		for _, suffix := range gatewayOffsets {
			gw := prefix + suffix
			for _, port := range gatewayProbePorts {
				wg.Add(1)
				limiter <- struct{}{}
				go func(pfx, addr string) {
					defer func() { <-limiter; wg.Done() }()
					conn, err := net.DialTimeout("tcp", addr, subnetProbeTimeout)
					if err == nil {
						_ = conn.Close()
						aliveSubnets.Store(pfx, true)
					}
				}(prefix, fmt.Sprintf("%s:%d", gw, port))
			}
		}
	}
	wg.Wait()

	// 统计阶段 1 命中
	gwHits := 0
	aliveSubnets.Range(func(_, _ interface{}) bool { gwHits++; return true })

	// ── 阶段 2：逐主机兜底（仅对网关未命中的子网）──────────
	for prefix, subnetHosts := range subnets {
		if _, alive := aliveSubnets.Load(prefix); alive {
			continue // 网关已命中，跳过
		}

		for i, host := range subnetHosts {
			select {
			case <-ctx.Done():
				goto done
			default:
			}

			if _, alive := aliveSubnets.Load(prefix); alive {
				break
			}

			port := subnetProbePorts[i%len(subnetProbePorts)]
			wg.Add(1)
			limiter <- struct{}{}

			go func(pfx, h string, p int) {
				defer func() { <-limiter; wg.Done() }()
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", h, p), subnetProbeTimeout)
				if err == nil {
					_ = conn.Close()
					aliveSubnets.Store(pfx, true)
				}
			}(prefix, host, port)
		}
	}

done:
	wg.Wait()

	// 统计
	aliveCount := 0
	aliveSubnets.Range(func(_, _ interface{}) bool { aliveCount++; return true })

	if aliveCount == 0 {
		return nil
	}

	result := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if _, alive := aliveSubnets.Load(subnetPrefix(h)); alive {
			result = append(result, h)
		}
	}

	skipped := len(subnets) - aliveCount
	common.LogInfo(fmt.Sprintf("网段预筛完成: %d 个存活 (网关命中 %d), %d 个跳过, 剩余 %d 主机",
		aliveCount, gwHits, skipped, len(result)))
	return result
}

// subnetPrefix 提取 IP 的 /24 前缀（如 "10.1.1"）
func subnetPrefix(ip string) string {
	lastDot := strings.LastIndex(ip, ".")
	if lastDot <= 0 {
		return ""
	}
	return ip[:lastDot]
}
