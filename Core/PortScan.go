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
	Port    int          // 端口号
	Service *ServiceInfo // 服务信息
}

func PortScan(hostslist []string, ports string, timeout int64) []string {
	var results []ScanResult
	var aliveAddrs []string // 新增：存储活跃地址
	var mu sync.Mutex

	// 解析端口列表
	probePorts := Common.ParsePort(ports)
	if len(probePorts) == 0 {
		Common.LogError(fmt.Sprintf("端口格式错误: %s", ports))
		return aliveAddrs
	}

	// 排除指定端口
	probePorts = excludeNoPorts(probePorts)

	// 创建通道
	workers := Common.ThreadNum
	addrs := make(chan Addr, 100)
	scanResults := make(chan ScanResult, 100)
	var wg sync.WaitGroup
	var workerWg sync.WaitGroup

	// 启动扫描协程
	for i := 0; i < workers; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for addr := range addrs {
				PortConnect(addr, scanResults, timeout, &wg)
			}
		}()
	}

	// 接收扫描结果
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range scanResults {
			mu.Lock()
			results = append(results, result)
			// 构造活跃地址字符串
			aliveAddr := fmt.Sprintf("%s:%d", result.Address, result.Port)
			aliveAddrs = append(aliveAddrs, aliveAddr)
			mu.Unlock()
		}
	}()

	// 添加扫描目标
	for _, port := range probePorts {
		for _, host := range hostslist {
			wg.Add(1)
			addrs <- Addr{host, port}
		}
	}

	close(addrs)
	workerWg.Wait()
	wg.Wait()
	close(scanResults)
	resultWg.Wait()

	return aliveAddrs
}

func PortConnect(addr Addr, results chan<- ScanResult, timeout int64, wg *sync.WaitGroup) {
	defer wg.Done()

	var isOpen bool
	var err error
	var conn net.Conn

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

	address := fmt.Sprintf("%s:%d", addr.ip, addr.port)
	Common.LogSuccess(fmt.Sprintf("端口开放 %s", address))

	// 保存端口开放信息
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

	// 创建扫描结果
	result := ScanResult{
		Address: addr.ip,
		Port:    addr.port,
	}

	// 服务识别
	if !Common.SkipFingerprint && conn != nil {
		scanner := NewPortInfoScanner(addr.ip, addr.port, conn, time.Duration(timeout)*time.Second)
		if serviceInfo, err := scanner.Identify(); err == nil {
			result.Service = serviceInfo

			// 构造日志消息
			var logMsg strings.Builder
			logMsg.WriteString(fmt.Sprintf("服务识别 %s => ", address))

			if serviceInfo.Name != "unknown" {
				logMsg.WriteString(fmt.Sprintf("[%s]", serviceInfo.Name))
			}

			if serviceInfo.Version != "" {
				logMsg.WriteString(fmt.Sprintf(" 版本:%s", serviceInfo.Version))
			}

			// 构造服务详情
			details := map[string]interface{}{
				"port":    addr.port,
				"service": serviceInfo.Name,
			}

			if serviceInfo.Version != "" {
				details["version"] = serviceInfo.Version
			}
			if v, ok := serviceInfo.Extras["vendor_product"]; ok && v != "" {
				details["product"] = v
				logMsg.WriteString(fmt.Sprintf(" 产品:%s", v))
			}
			if v, ok := serviceInfo.Extras["os"]; ok && v != "" {
				details["os"] = v
				logMsg.WriteString(fmt.Sprintf(" 系统:%s", v))
			}
			if v, ok := serviceInfo.Extras["info"]; ok && v != "" {
				details["info"] = v
				logMsg.WriteString(fmt.Sprintf(" 信息:%s", v))
			}
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

	for _, port := range noPorts {
		delete(temp, port)
	}

	// 转换为切片并排序
	var newPorts []int
	for port := range temp {
		newPorts = append(newPorts, port)
	}
	sort.Ints(newPorts)

	return newPorts
}
