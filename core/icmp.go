package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/common/output"
	"golang.org/x/net/icmp"
)

// pingForbiddenChars 命令注入防护 - 禁止的字符
var pingForbiddenChars = []string{";", "&", "|", "`", "$", "\\", "'", "%", "\"", "\n"}

// pingErrorKeywords ping 失败的关键词（跨平台）
var pingErrorKeywords = []string{
	// Windows
	"TTL expired",
	"Destination host unreachable",
	"Destination net unreachable",
	"Request timed out",
	"General failure",
	"transmit failed",
	// Linux/macOS
	"Time to live exceeded",
	"100% packet loss",
	"Network is unreachable",
	"No route to host",
}

// CheckLive 检测主机存活状态
// 支持 ICMP/Ping 探测，并在响应率过低时自动启用 TCP 补充探测
func CheckLive(ctx context.Context, hostslist []string, Ping bool, session *common.ScanSession) []string {
	config := session.Config
	state := session.State
	// 创建局部WaitGroup
	var livewg sync.WaitGroup

	// 创建局部存活主机列表，预分配容量避免频繁扩容
	aliveHosts := make([]string, 0, len(hostslist))
	var aliveHostsMu sync.Mutex // 保护aliveHosts并发访问
	existHosts := make(map[string]struct{}, len(hostslist))

	// 创建主机通道
	chanHosts := make(chan string, len(hostslist))

	// 处理存活主机
	go handleAliveHosts(chanHosts, hostslist, Ping, &aliveHosts, &aliveHostsMu, existHosts, config, &livewg)

	// 根据Ping参数选择检测方式
	if Ping {
		// 使用ping方式探测
		RunPing(hostslist, chanHosts, &livewg)
	} else {
		probeWithICMP(hostslist, chanHosts, &aliveHosts, &aliveHostsMu, config, state, &livewg)
	}

	// 等待所有检测完成
	livewg.Wait()
	close(chanHosts)

	// TCP 补充探测：当 ICMP/Ping 响应率过低时自动启用
	// 这对防火墙过滤 ICMP 的环境特别有用
	aliveHosts = tcpSupplementaryProbe(ctx, hostslist, aliveHosts, session)

	// 输出存活统计信息
	printAliveStats(aliveHosts, hostslist)

	return aliveHosts
}

// tcpSupplementaryProbe TCP 补充探测
// 当 ICMP 响应率过低时（<10%），对未响应主机进行 TCP 探测
func tcpSupplementaryProbe(ctx context.Context, allHosts []string, aliveHosts []string, session *common.ScanSession) []string {
	if session.Config.DisableTcpProbe || session.Config.Mode == "icmp" {
		return aliveHosts
	}

	totalHosts := len(allHosts)
	if totalHosts == 0 {
		return aliveHosts
	}

	// 计算 ICMP 响应率
	responseRate := float64(len(aliveHosts)) / float64(totalHosts)

	// 响应率高于阈值，无需补充探测
	if responseRate >= tcpProbeThreshold {
		return aliveHosts
	}

	// 获取未响应的主机
	unrespondedHosts := getUnrespondedHosts(allHosts, aliveHosts)
	if len(unrespondedHosts) == 0 {
		return aliveHosts
	}

	// 提示用户正在进行 TCP 补充探测
	common.LogInfo(i18n.Tr("tcp_probe_low_icmp_rate", fmt.Sprintf("%.1f%%", responseRate*100), len(unrespondedHosts)))

	// 执行 TCP 补充探测
	tcpAliveHosts := runTcpProbeForHosts(ctx, unrespondedHosts, session)

	// 合并结果
	if len(tcpAliveHosts) > 0 {
		aliveHosts = append(aliveHosts, tcpAliveHosts...)
		common.LogInfo(i18n.Tr("tcp_probe_found", len(tcpAliveHosts)))
	}

	return aliveHosts
}

// IsContain 检查切片中是否包含指定元素
func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

func handleAliveHosts(chanHosts chan string, hostslist []string, isPing bool, aliveHosts *[]string, aliveHostsMu *sync.Mutex, existHosts map[string]struct{}, config *common.Config, livewg *sync.WaitGroup) {
	for ip := range chanHosts {
		if _, ok := existHosts[ip]; !ok && IsContain(hostslist, ip) {
			existHosts[ip] = struct{}{}

			// 加锁保护aliveHosts并发写入
			aliveHostsMu.Lock()
			*aliveHosts = append(*aliveHosts, ip)
			aliveHostsMu.Unlock()

			// 使用Output系统保存存活主机信息
			protocol := "ICMP"
			if isPing {
				protocol = "PING"
			}

			result := &output.ScanResult{
				Time:   time.Now(),
				Type:   output.TypeHost,
				Target: ip,
				Status: "alive",
				Details: map[string]interface{}{
					"protocol": protocol,
				},
			}
			_ = common.SaveResult(result)

			// 保留原有的控制台输出
			if !config.Output.Silent {
				common.LogInfo(i18n.Tr("host_alive", ip, protocol))
			}
		}
		livewg.Done()
	}
}

// probeWithICMP 使用ICMP方式探测
func probeWithICMP(hostslist []string, chanHosts chan string, aliveHosts *[]string, aliveHostsMu *sync.Mutex, config *common.Config, state *common.State, livewg *sync.WaitGroup) {
	// 代理模式下自动禁用ICMP，直接降级为Ping
	// ICMP在代理环境无法正常工作
	if shouldDisableICMP() {
		if !config.Output.Silent {
			common.LogInfo(i18n.GetText("proxy_mode_disable_icmp"))
		}
		RunPing(hostslist, chanHosts, livewg)
		return
	}

	// 尝试监听本地ICMP
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err == nil {
		RunIcmp1(hostslist, conn, chanHosts, aliveHosts, aliveHostsMu, config, state, livewg)
		return
	}

	common.LogError(i18n.Tr("icmp_listen_failed", err))
	common.LogInfo(i18n.GetText("trying_no_listen_icmp"))

	// 尝试无监听ICMP探测
	conn2, err := net.DialTimeout("ip4:icmp", "127.0.0.1", 3*time.Second)
	if err == nil {
		defer func() { _ = conn2.Close() }()
		RunIcmp2(hostslist, chanHosts, config, state, livewg)
		return
	}

	common.LogError(i18n.Tr("icmp_connect_failed", err))
	common.LogError(i18n.GetText("insufficient_privileges"))
	common.LogInfo(i18n.GetText("switching_to_ping"))

	// 降级使用ping探测
	RunPing(hostslist, chanHosts, livewg)
}

// shouldDisableICMP 检查是否应该禁用ICMP
// 这是一个内部辅助函数，用于检查代理状态
func shouldDisableICMP() bool {
	// 尝试导入proxy包的状态检查（避免循环依赖）
	// 实际实现中会通过全局配置检查
	// 这里暂时返回false，实际集成时会正确处理
	return false
}

// getOptimalTopCount 根据扫描规模智能决定显示数量
func getOptimalTopCount(totalHosts int) int {
	switch {
	case totalHosts > 50000: // 超大规模扫描
		return 20
	case totalHosts > 10000: // 大规模扫描
		return 15
	case totalHosts > 1000: // 中等规模扫描
		return 10
	case totalHosts > 256: // 小规模扫描
		return 5
	default:
		return 3
	}
}

// printAliveStats 打印存活统计信息
func printAliveStats(aliveHosts []string, hostslist []string) {
	// 智能计算显示数量
	topCount := getOptimalTopCount(len(hostslist))

	// 大规模扫描时输出 /16 网段统计
	if len(hostslist) > 1000 {
		arrTop, arrLen := ArrayCountValueTop(aliveHosts, topCount, true)
		for i := 0; i < len(arrTop); i++ {
			common.LogInfo(i18n.Tr("segment_16_alive", arrTop[i], arrLen[i]))
		}
	}

	// 输出 /24 网段统计
	if len(hostslist) > 256 {
		arrTop, arrLen := ArrayCountValueTop(aliveHosts, topCount, false)
		for i := 0; i < len(arrTop); i++ {
			common.LogInfo(i18n.Tr("segment_24_alive", arrTop[i], arrLen[i]))
		}
	}
}

// ICMP 自适应等待参数
const (
	icmpCheckInterval   = 100 * time.Millisecond // 检查间隔，避免 CPU 空转
	icmpMinWaitTime     = 1 * time.Second        // 最小等待时间，确保基础响应收集
	icmpStableThreshold = 500 * time.Millisecond // 无新响应稳定阈值，超过此时间无新响应则提前结束
)

// waitAdaptive 自适应等待 ICMP 响应
// 算法：监控响应增量，连续一段时间无新响应则提前结束
// 保守原则：
//   - 必须等待最小时间 (1s)，确保基础响应收集
//   - 只有"连续 500ms 无新响应"才提前结束
//   - 保留原有最大等待时间作为兜底
func waitAdaptive(hostslist []string, aliveHosts *[]string, aliveHostsMu *sync.Mutex) {
	totalHosts := len(hostslist)

	// 根据主机数量设置最大超时时间（保持原有逻辑作为兜底）
	maxWait := 6 * time.Second
	if totalHosts <= 256 {
		maxWait = 3 * time.Second
	}

	start := time.Now()
	lastAliveCount := 0
	lastChangeTime := start

	for {
		time.Sleep(icmpCheckInterval) // 避免 CPU 空转

		// 读取当前存活数
		aliveHostsMu.Lock()
		aliveCount := len(*aliveHosts)
		aliveHostsMu.Unlock()

		elapsed := time.Since(start)

		// 条件1：所有主机都已响应，立即结束
		if aliveCount >= totalHosts {
			common.LogDebug(fmt.Sprintf("[ICMP] 全部响应，耗时 %v", elapsed.Round(time.Millisecond)))
			break
		}

		// 条件2：超过最大等待时间，兜底结束
		if elapsed >= maxWait {
			common.LogDebug(fmt.Sprintf("[ICMP] 达到最大等待时间 %v，存活 %d/%d", maxWait, aliveCount, totalHosts))
			break
		}

		// 条件3：自适应提前结束
		// 必须满足：已过最小等待时间 + 连续一段时间没有新响应
		if elapsed >= icmpMinWaitTime {
			if aliveCount > lastAliveCount {
				// 有新响应，更新状态
				lastChangeTime = time.Now()
				lastAliveCount = aliveCount
			} else if time.Since(lastChangeTime) >= icmpStableThreshold {
				// 连续 500ms 没有新响应，认为响应已稳定，提前结束
				common.LogDebug(fmt.Sprintf("[ICMP] 响应稳定，提前结束，耗时 %v，存活 %d/%d",
					elapsed.Round(time.Millisecond), aliveCount, totalHosts))
				break
			}
		} else {
			// 最小等待期内，持续更新状态
			if aliveCount > lastAliveCount {
				lastChangeTime = time.Now()
				lastAliveCount = aliveCount
			}
		}
	}
}

// RunIcmp1 使用ICMP批量探测主机存活(监听模式)
func RunIcmp1(hostslist []string, conn *icmp.PacketConn, chanHosts chan string, aliveHosts *[]string, aliveHostsMu *sync.Mutex, config *common.Config, state *common.State, livewg *sync.WaitGroup) {
	// 使用atomic.Bool保证并发安全
	var endflag atomic.Bool
	var listenerWg sync.WaitGroup

	// 去重集合：过滤重复的ICMP响应
	seen := make(map[string]struct{}, len(hostslist))

	// 启动监听协程
	listenerWg.Add(1)
	go func() {
		defer listenerWg.Done()
		defer func() {
			if r := recover(); r != nil {
				common.LogError(i18n.Tr("icmp_listener_panic", r))
			}
		}()

		for {
			if endflag.Load() {
				return
			}

			// 设置读取超时避免无限期阻塞
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

			// 接收ICMP响应
			msg := make([]byte, 100)
			_, sourceIP, err := conn.ReadFrom(msg)

			if err != nil {
				// 超时错误正常，其他错误则退出
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					continue
				}
				return
			}

			if sourceIP != nil && !endflag.Load() {
				ipStr := sourceIP.String()

				if _, dup := seen[ipStr]; dup {
					continue
				}
				seen[ipStr] = struct{}{}

				livewg.Add(1)
				select {
				case chanHosts <- ipStr:
					// 发送成功
				default:
					// channel已满，回退计数器
					livewg.Done()
				}
			}
		}
	}()

	// 发送ICMP请求（批量预构建 + 令牌桶限速）
	// 预构建所有 ICMP 包和目标地址，减少发送循环中的开销
	type icmpPacket struct {
		data []byte
		dst  net.Addr
	}
	packets := make([]icmpPacket, 0, len(hostslist))
	for _, host := range hostslist {
		dst, _ := common.DNSCache.ResolveIP(host)
		packets = append(packets, icmpPacket{data: makemsg(host), dst: dst})
	}

	limiter := state.GetICMPLimiter(config.Network.ICMPRate)
	for i := range packets {
		limiter.Wait(1)
		_, _ = conn.WriteTo(packets[i].data, packets[i].dst)
	}

	// 自适应等待响应
	// 算法：监控响应增量，连续一段时间无新响应则提前结束
	// 保守原则：保留最大等待时间兜底，确保不漏掉慢响应主机
	waitAdaptive(hostslist, aliveHosts, aliveHostsMu)

	endflag.Store(true)
	_ = conn.Close()
	listenerWg.Wait()
}

// RunIcmp2 使用ICMP并发探测主机存活(无监听模式)
func RunIcmp2(hostslist []string, chanHosts chan string, config *common.Config, state *common.State, livewg *sync.WaitGroup) {
	// 控制并发数
	num := 1000
	if len(hostslist) < num {
		num = len(hostslist)
	}

	var wg sync.WaitGroup
	limiter := make(chan struct{}, num)
	rateLimiter := state.GetICMPLimiter(config.Network.ICMPRate) // 获取速率限制器

	// 并发探测
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}

		go func(host string) {
			defer func() {
				<-limiter
				wg.Done()
			}()

			rateLimiter.Wait(1) // 等待令牌，控制发包速率
			if icmpalive(host) {
				livewg.Add(1)
				select {
				case chanHosts <- host:
					// 发送成功
				default:
					// channel已满，回退计数器
					livewg.Done()
				}
			}
		}(host)
	}

	wg.Wait()
	close(limiter)
}

// icmpalive 检测主机ICMP是否存活
func icmpalive(host string) bool {
	startTime := time.Now()

	// 建立ICMP连接
	conn, err := net.DialTimeout("ip4:icmp", host, 6*time.Second)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	// 设置超时时间
	if err := conn.SetDeadline(startTime.Add(6 * time.Second)); err != nil {
		return false
	}

	// 构造并发送ICMP请求
	msg := makemsg(host)
	if _, err := conn.Write(msg); err != nil {
		return false
	}

	// 接收ICMP响应
	receive := make([]byte, 60)
	if _, err := conn.Read(receive); err != nil {
		return false
	}

	return true
}

// RunPing 使用系统Ping命令并发探测主机存活
func RunPing(hostslist []string, chanHosts chan string, livewg *sync.WaitGroup) {
	var wg sync.WaitGroup
	// 并发数根据主机数动态调整，上限 200
	concurrency := len(hostslist)
	if concurrency > 200 {
		concurrency = 200
	}
	limiter := make(chan struct{}, concurrency)

	// 并发探测
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}

		go func(host string) {
			defer func() {
				<-limiter
				wg.Done()
			}()

			if ExecCommandPing(host) {
				livewg.Add(1)
				select {
				case chanHosts <- host:
					// 发送成功
				default:
					// channel已满，回退计数器
					livewg.Done()
				}
			}
		}(host)
	}

	wg.Wait()
}

// containsPingError 检查 ping 输出是否包含错误关键词
func containsPingError(output string) bool {
	outputLower := strings.ToLower(output)
	for _, keyword := range pingErrorKeywords {
		if strings.Contains(outputLower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

// ExecCommandPing 执行系统Ping命令检测主机存活
func ExecCommandPing(ip string) bool {
	// 过滤黑名单字符（命令注入防护）
	for _, char := range pingForbiddenChars {
		if strings.Contains(ip, char) {
			return false
		}
	}

	var command *exec.Cmd
	// 根据操作系统选择不同的ping命令
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+ip+" && echo true || echo false")
	case "darwin":
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -W 1 "+ip+" && echo true || echo false")
	default: // linux
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -w 1 "+ip+" && echo true || echo false")
	}

	// 捕获命令输出
	var outinfo bytes.Buffer
	command.Stdout = &outinfo

	// 执行命令
	if err := command.Start(); err != nil {
		return false
	}

	if err := command.Wait(); err != nil {
		return false
	}

	// 分析输出结果
	output := outinfo.String()
	return strings.Contains(output, "true") && strings.Count(output, ip) > 2 && !containsPingError(output)
}

// makemsg 构造ICMP echo请求消息
func makemsg(host string) []byte {
	msg := make([]byte, 40)

	// 获取标识符
	id0, id1 := genIdentifier(host)

	// 设置ICMP头部
	msg[0] = 8                      // Type: Echo Request
	msg[1] = 0                      // Code: 0
	msg[2] = 0                      // Checksum高位(待计算)
	msg[3] = 0                      // Checksum低位(待计算)
	msg[4], msg[5] = id0, id1       // Identifier
	msg[6], msg[7] = genSequence(1) // Sequence Number

	// 计算校验和
	check := checkSum(msg[0:40])
	msg[2] = byte(check >> 8)  // 设置校验和高位
	msg[3] = byte(check & 255) // 设置校验和低位

	return msg
}

// checkSum 计算ICMP校验和
func checkSum(msg []byte) uint16 {
	sum := 0
	length := len(msg)

	// 按16位累加
	for i := 0; i < length-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}

	// 处理奇数长度情况
	if length%2 == 1 {
		sum += int(msg[length-1]) * 256
	}

	// 将高16位加到低16位
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	// 取反得到校验和
	return uint16(^sum)
}

// genSequence 生成ICMP序列号
func genSequence(v int16) (byte, byte) {
	ret1 := byte(v >> 8)  // 高8位
	ret2 := byte(v & 255) // 低8位
	return ret1, ret2
}

// genIdentifier 根据主机地址生成标识符
func genIdentifier(host string) (byte, byte) {
	if len(host) < 2 {
		return 0, 0
	}
	return host[0], host[1]
}

// ArrayCountValueTop 统计IP地址段存活数量并返回TOP N结果
func ArrayCountValueTop(arrInit []string, length int, flag bool) (arrTop []string, arrLen []int) {
	if len(arrInit) == 0 {
		return
	}

	// 统计各网段出现次数，预分配容量
	segmentCounts := make(map[string]int, len(arrInit)/4)
	for _, ip := range arrInit {
		segments := strings.Split(ip, ".")
		if len(segments) != 4 {
			continue
		}

		// 根据flag确定统计B段还是C段
		var segment string
		if flag {
			segment = fmt.Sprintf("%s.%s", segments[0], segments[1]) // B段
		} else {
			segment = fmt.Sprintf("%s.%s.%s", segments[0], segments[1], segments[2]) // C段
		}

		segmentCounts[segment]++
	}

	// 创建副本用于排序
	sortMap := make(map[string]int)
	for k, v := range segmentCounts {
		sortMap[k] = v
	}

	// 获取TOP N结果
	for i := 0; i < length && len(sortMap) > 0; i++ {
		maxSegment := ""
		maxCount := 0

		// 查找当前最大值
		for segment, count := range sortMap {
			if count > maxCount {
				maxCount = count
				maxSegment = segment
			}
		}

		// 添加到结果集
		arrTop = append(arrTop, maxSegment)
		arrLen = append(arrLen, maxCount)

		// 从待处理map中删除已处理项
		delete(sortMap, maxSegment)
	}

	return
}

// =============================================================================
// TCP 补充探测 - 当 ICMP 响应率过低时自动启用
// =============================================================================

// tcpProbeCommonPorts TCP 探测使用的常用端口
// 这些端口在大多数服务器上至少有一个开放
var tcpProbeCommonPorts = []int{80, 443, 22, 445}

// tcpProbeTimeout TCP 探测超时时间（较短，只做存活判断）
const tcpProbeTimeout = 1 * time.Second

// tcpProbeThreshold TCP 补充探测触发阈值
// 当 ICMP 响应率低于此值时，自动启用 TCP 补充探测
const tcpProbeThreshold = 0.1 // 10%

// tcpProbeAlive 使用 TCP 并行探测主机是否存活
// 同时连接所有常用端口，任一响应即返回
func tcpProbeAlive(ctx context.Context, session *common.ScanSession, host string) bool {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	result := make(chan bool, len(tcpProbeCommonPorts))
	for _, port := range tcpProbeCommonPorts {
		go func(p int) {
			addr := fmt.Sprintf("%s:%d", host, p)
			conn, err := session.DialTCP(ctx, "tcp", addr, tcpProbeTimeout)
			if err == nil {
				_ = conn.Close()
				result <- true
				return
			}
			result <- false
		}(port)
	}

	for range tcpProbeCommonPorts {
		if <-result {
			return true
		}
	}
	return false
}

// runTcpProbeForHosts 对指定主机列表进行 TCP 补充探测
// 返回存活的主机列表
func runTcpProbeForHosts(ctx context.Context, hosts []string, session *common.ScanSession) []string {
	config := session.Config
	if len(hosts) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	aliveHosts := make([]string, 0)

	// 并发控制，根据主机数动态调整，上限 200
	concurrency := len(hosts)
	if concurrency > 200 {
		concurrency = 200
	}
	limiter := make(chan struct{}, concurrency)

	for _, host := range hosts {
		wg.Add(1)
		limiter <- struct{}{}

		go func(h string) {
			defer func() {
				<-limiter
				wg.Done()
			}()

			if tcpProbeAlive(ctx, session, h) {
				mu.Lock()
				aliveHosts = append(aliveHosts, h)
				mu.Unlock()

				// 保存结果
				result := &output.ScanResult{
					Time:   time.Now(),
					Type:   output.TypeHost,
					Target: h,
					Status: "alive",
					Details: map[string]interface{}{
						"protocol": "TCP",
					},
				}
				_ = common.SaveResult(result)

				if !config.Output.Silent {
					common.LogInfo(i18n.Tr("host_alive", h, "TCP"))
				}
			}
		}(host)
	}

	wg.Wait()
	return aliveHosts
}

// getUnrespondedHosts 获取未响应的主机列表
func getUnrespondedHosts(allHosts []string, aliveHosts []string) []string {
	aliveSet := make(map[string]struct{}, len(aliveHosts))
	for _, h := range aliveHosts {
		aliveSet[h] = struct{}{}
	}

	unresponded := make([]string, 0, len(allHosts)-len(aliveHosts))
	for _, h := range allHosts {
		if _, alive := aliveSet[h]; !alive {
			unresponded = append(unresponded, h)
		}
	}
	return unresponded
}
