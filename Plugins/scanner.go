package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Config"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"github.com/shadow1ng/fscan/common"
	"strconv"
	"strings"
	"sync"
)

func Scan(info Config.HostInfo) {
	fmt.Println("[*] 开始信息扫描...")

	// 本地信息收集模块
	if common.Scantype == "localinfo" {
		ch := make(chan struct{}, common.Threads)
		wg := sync.WaitGroup{}
		AddScan("localinfo", info, &ch, &wg)
		wg.Wait()
		common.LogWG.Wait()
		close(common.Results)
		fmt.Printf("[✓] 扫描完成 %v/%v\n", common.End, common.Num)
		return
	}

	// 解析目标主机IP
	Hosts, err := common.ParseIP(info.Host, common.HostFile, common.NoHosts)
	if err != nil {
		fmt.Printf("[!] 解析主机错误: %v\n", err)
		return
	}

	// 初始化配置
	lib.Inithttp()
	ch := make(chan struct{}, common.Threads)
	wg := sync.WaitGroup{}
	var AlivePorts []string

	if len(Hosts) > 0 || len(common.HostPort) > 0 {
		// ICMP存活性检测
		if (common.NoPing == false && len(Hosts) > 1) || common.Scantype == "icmp" {
			Hosts = CheckLive(Hosts, common.Ping)
			fmt.Printf("[+] ICMP存活主机数量: %d\n", len(Hosts))
			if common.Scantype == "icmp" {
				common.LogWG.Wait()
				return
			}
		}

		// 端口扫描策略
		AlivePorts = executeScanStrategy(Hosts, common.Scantype)

		// 处理自定义端口
		if len(common.HostPort) > 0 {
			AlivePorts = append(AlivePorts, common.HostPort...)
			AlivePorts = common.RemoveDuplicate(AlivePorts)
			common.HostPort = nil
			fmt.Printf("[+] 总计存活端口: %d\n", len(AlivePorts))
		}

		// 执行扫描任务
		fmt.Println("[*] 开始漏洞扫描...")
		for _, targetIP := range AlivePorts {
			hostParts := strings.Split(targetIP, ":")
			if len(hostParts) != 2 {
				fmt.Printf("[!] 无效的目标地址格式: %s\n", targetIP)
				continue
			}
			info.Host, info.Ports = hostParts[0], hostParts[1]

			executeScanTasks(info, common.Scantype, &ch, &wg)
		}
	}

	// URL扫描
	for _, url := range common.Urls {
		info.Url = url
		AddScan("web", info, &ch, &wg)
	}

	// 等待所有任务完成
	wg.Wait()
	common.LogWG.Wait()
	close(common.Results)
	fmt.Printf("[✓] 扫描已完成: %v/%v\n", common.End, common.Num)
}

// executeScanStrategy 执行端口扫描策略
func executeScanStrategy(Hosts []string, scanType string) []string {
	switch scanType {
	case "webonly", "webpoc":
		return NoPortScan(Hosts, common.Ports)
	case "hostname":
		common.Ports = "139"
		return NoPortScan(Hosts, common.Ports)
	default:
		if len(Hosts) > 0 {
			ports := PortScan(Hosts, common.Ports, common.Timeout)
			fmt.Printf("[+] 存活端口数量: %d\n", len(ports))
			if scanType == "portscan" {
				common.LogWG.Wait()
				return nil
			}
			return ports
		}
	}
	return nil
}

// executeScanTasks 执行扫描任务
func executeScanTasks(info Config.HostInfo, scanType string, ch *chan struct{}, wg *sync.WaitGroup) {
	if scanType == "all" || scanType == "main" {
		// 根据端口选择扫描插件
		switch info.Ports {
		case "135":
			AddScan("findnet", info, ch, wg)
			if common.IsWmi {
				AddScan("wmiexec", info, ch, wg)
			}
		case "445":
			AddScan("ms17010", info, ch, wg)
		case "9000":
			AddScan("web", info, ch, wg)
			AddScan("fcgi", info, ch, wg)
		default:
			// 查找对应端口的插件
			for name, plugin := range Config.PluginManager {
				if strconv.Itoa(plugin.Port) == info.Ports {
					AddScan(name, info, ch, wg)
					return
				}
			}
			// 默认执行Web扫描
			AddScan("web", info, ch, wg)
		}
	} else {
		// 直接使用指定的扫描类型
		AddScan(scanType, info, ch, wg)
	}
}

// Mutex用于保护共享资源的并发访问
var Mutex = &sync.Mutex{}

// AddScan 添加扫描任务到并发队列
func AddScan(scantype string, info Config.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	// 获取信号量，控制并发数
	*ch <- struct{}{}
	// 添加等待组计数
	wg.Add(1)

	// 启动goroutine执行扫描任务
	go func() {
		defer func() {
			wg.Done() // 完成任务后减少等待组计数
			<-*ch     // 释放信号量
		}()

		// 增加总任务数
		Mutex.Lock()
		common.Num += 1
		Mutex.Unlock()

		// 执行扫描
		ScanFunc(&scantype, &info)

		// 增加已完成任务数
		Mutex.Lock()
		common.End += 1
		Mutex.Unlock()
	}()
}

// ScanFunc 执行扫描插件
func ScanFunc(name *string, info *Config.HostInfo) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("[!] 扫描错误 %v:%v - %v\n", info.Host, info.Ports, err)
		}
	}()

	// 检查插件是否存在
	plugin, exists := Config.PluginManager[*name]
	if !exists {
		fmt.Printf("[*] 扫描类型 %v 无对应插件，已跳过\n", *name)
		return
	}

	// 直接调用扫描函数
	if err := plugin.ScanFunc(info); err != nil {
		fmt.Printf("[!] 扫描错误 %v:%v - %v\n", info.Host, info.Ports, err)
	}
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
