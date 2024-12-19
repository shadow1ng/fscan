package Core

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"sort"
	"sync"
	"time"
)

// Addr 表示待扫描的地址
type Addr struct {
	ip   string // IP地址
	port int    // 端口号
}

// PortScan 执行端口扫描
func PortScan(hostslist []string, ports string, timeout int64) []string {
	var AliveAddress []string

	// 解析端口列表
	probePorts := Common.ParsePort(ports)
	if len(probePorts) == 0 {
		fmt.Printf("[-] 端口格式错误: %s, 请检查端口格式\n", ports)
		return AliveAddress
	}

	// 排除指定端口
	probePorts = excludeNoPorts(probePorts)

	// 创建通道
	workers := Common.ThreadNum
	addrs := make(chan Addr, 100)
	results := make(chan string, 100)
	var wg sync.WaitGroup

	// 接收扫描结果
	go collectResults(&AliveAddress, results, &wg)

	// 启动扫描协程
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range addrs {
				PortConnect(addr, results, timeout, &wg)
				wg.Done()
			}
		}()
	}

	// 添加扫描目标
	for _, port := range probePorts {
		for _, host := range hostslist {
			wg.Add(1)
			addrs <- Addr{host, port}
		}
	}

	wg.Wait()
	close(addrs)
	close(results)
	return AliveAddress
}

// collectResults 收集扫描结果
func collectResults(aliveAddrs *[]string, results <-chan string, wg *sync.WaitGroup) {
	for found := range results {
		*aliveAddrs = append(*aliveAddrs, found)
		wg.Done()
	}
}

// PortConnect 尝试连接指定端口
func PortConnect(addr Addr, respondingHosts chan<- string, timeout int64, wg *sync.WaitGroup) {
	// 建立TCP连接
	conn, err := Common.WrapperTcpWithTimeout("tcp4",
		fmt.Sprintf("%s:%v", addr.ip, addr.port),
		time.Duration(timeout)*time.Second)

	if err != nil {
		return
	}
	defer conn.Close()

	// 记录开放端口
	address := fmt.Sprintf("%s:%d", addr.ip, addr.port)
	result := fmt.Sprintf("[+] 端口开放 %s", address)
	Common.LogSuccess(result)

	wg.Add(1)
	respondingHosts <- address
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
