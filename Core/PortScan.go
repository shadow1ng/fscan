package Core

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Addr 表示待扫描的地址
type Addr struct {
	ip   string // IP地址
	port int    // 端口号
}

// ScanResult 扫描结果
type ScanResult struct {
	Address string       // IP地址
	Port    int         // 端口号
	Service *ServiceInfo // 服务信息
}

// PortScan 执行端口扫描
// hostslist: 待扫描的主机列表
// ports: 待扫描的端口范围
// timeout: 超时时间(秒)
// 返回活跃地址列表
func PortScan(hostslist []string, ports string, timeout int64) []string {
	var results []ScanResult
	var aliveAddrs []string
	var mu sync.Mutex

	// 解析并验证端口列表
	probePorts := Common.ParsePort(ports)
	if len(probePorts) == 0 {
		Common.LogError(fmt.Sprintf("端口格式错误: %s", ports))
		return aliveAddrs
	}

	// 排除指定端口
	probePorts = excludeNoPorts(probePorts)

	// 初始化并发控制
	workers := Common.ThreadNum
	addrs := make(chan Addr, 100)      // 待扫描地址通道
	scanResults := make(chan ScanResult, 100) // 扫描结果通道
	var wg sync.WaitGroup
	var workerWg sync.WaitGroup

	// 启动扫描工作协程
	for i := 0; i < workers; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for addr := range addrs {
				PortConnect(addr, scanResults, timeout, &wg)
			}
		}()
	}

	// 启动结果处理协程
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range scanResults {
			mu.Lock()
			results = append(results, result)
			aliveAddr := fmt.Sprintf("%s:%d", result.Address, result.Port)
			aliveAddrs = append(aliveAddrs, aliveAddr)
			mu.Unlock()
		}
	}()

	// 分发扫描任务
	for _, port := range probePorts {
		for _, host := range hostslist {
			wg.Add(1)
			addrs <- Addr{host, port}
		}
	}

	// 等待所有任务完成
	close(addrs)
	workerWg.Wait()
	wg.Wait()
	close(scanResults)
	resultWg.Wait()

	return aliveAddrs
}

// PortConnect 执行单个端口连接检测
// addr: 待检测的地址
// results: 结果通道
// timeout: 超时时间
// wg: 等待组
func PortConnect(addr Addr, results chan<- ScanResult, timeout int64, wg *sync.WaitGroup) {
	defer wg.Done()

	var isOpen bool
	var err error
	var conn net.Conn

	// 尝试建立TCP连接
	conn, err = Common.WrapperTcpWithTimeout("tcp4",
		fmt.Sprintf("%s:%v", addr.ip, addr.port),
		time.Duration(timeout)*time.Second)
	if err == nil {
		defer conn.Close()
		isOpen = true
	}

	if err != nil || !isOpen {
		return
	}

	// 记录开放端口
	address := fmt.Sprintf("%s:%d", addr.ip, addr.port)
	Common.LogSuccess(fmt.Sprintf("端口开放 %s", address))

	// 保存端口扫描结果
	portResult := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.PORT,
		Target: addr.ip,
		Status: "open",
		Details: map[string]interface{}{
			"port": addr.port,
		},
	}
	Common.SaveResult(portResult)

	// 构造扫描结果
	result := ScanResult{
		Address: addr.ip,
		Port:    addr.port,
	}

	// 执行服务识别
	if !Common.SkipFingerprint && conn != nil {
		scanner := NewPortInfoScanner(addr.ip, addr.port, conn, time.Duration(timeout)*time.Second)
		if serviceInfo, err := scanner.Identify(); err == nil {
			result.Service = serviceInfo

			// 构造服务识别日志
			var logMsg strings.Builder
			logMsg.WriteString(fmt.Sprintf("服务识别 %s => ", address))

			if serviceInfo.Name != "unknown" {
				logMsg.WriteString(fmt.Sprintf("[%s]", serviceInfo.Name))
			}

			if serviceInfo.Version != "" {
				logMsg.WriteString(fmt.Sprintf(" 版本:%s", serviceInfo.Version))
			}

			// 收集服务详细信息
			details := map[string]interface{}{
				"port":    addr.port,
				"service": serviceInfo.Name,
			}

			// 添加版本信息
			if serviceInfo.Version != "" {
				details["version"] = serviceInfo.Version
			}

			// 添加产品信息
			if v, ok := serviceInfo.Extras["vendor_product"]; ok && v != "" {
				details["product"] = v
				logMsg.WriteString(fmt.Sprintf(" 产品:%s", v))
			}

			// 添加操作系统信息
			if v, ok := serviceInfo.Extras["os"]; ok && v != "" {
				details["os"] = v
				logMsg.WriteString(fmt.Sprintf(" 系统:%s", v))
			}

			// 添加额外信息
			if v, ok := serviceInfo.Extras["info"]; ok && v != "" {
				details["info"] = v
				logMsg.WriteString(fmt.Sprintf(" 信息:%s", v))
			}

			// 添加Banner信息
			if len(serviceInfo.Banner) > 0 && len(serviceInfo.Banner) < 100 {
				details["banner"] = strings.TrimSpace(serviceInfo.Banner)
				logMsg.WriteString(fmt.Sprintf(" Banner:[%s]", strings.TrimSpace(serviceInfo.Banner)))
			}

			// 保存服务识别结果
			serviceResult := &Common.ScanResult{
				Time:    time.Now(),
				Type:    Common.SERVICE,
				Target:  addr.ip,
				Status:  "identified",
				Details: details,
			}
			Common.SaveResult(serviceResult)

			Common.LogSuccess(logMsg.String())
		}
	}

	results <- result
}

// NoPortScan 生成端口列表(不进行扫描)
// hostslist: 主机列表
// ports: 端口范围
// 返回地址列表
func NoPortScan(hostslist []string, ports string) []string {
	var AliveAddress []string

	// 解析并排除端口
	probePorts := excludeNoPorts(Common.ParsePort(ports))

	// 生成地址列表
	for _, port := range probePorts {
		for _, host := range hostslist {
			address := fmt.Sprintf("%s:%d", host, port)
			AliveAddress = append(AliveAddress, address)
		}
	}

	return AliveAddress
}

// excludeNoPorts 排除指定的端口
// ports: 原始端口列表
// 返回过滤后的端口列表
func excludeNoPorts(ports []int) []int {
	noPorts := Common.ParsePort(Common.ExcludePorts)
	if len(noPorts) == 0 {
		return ports
	}

	// 使用map过滤端口
	temp := make(map[int]struct{})
	for _, port := range ports {
		temp[port] = struct{}{}
	}

	// 移除需要排除的端口
	for _, port := range noPorts {
		delete(temp, port)
	}

	// 转换为有序切片
	var newPorts []int
	for port := range temp {
		newPorts = append(newPorts, port)
	}
	sort.Ints(newPorts)

	return newPorts
}
