package Core

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Config"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"strconv"
	"strings"
	"sync"
)

func Scan(info Config.HostInfo) {
	fmt.Println("[*] 开始信息扫描...")

	// 本地信息收集模块
	if Common.Scantype == "localinfo" {
		ch := make(chan struct{}, Common.Threads)
		wg := sync.WaitGroup{}
		AddScan("localinfo", info, &ch, &wg)
		wg.Wait()
		Common.LogWG.Wait()
		close(Common.Results)
		fmt.Printf("[✓] 扫描完成 %v/%v\n", Common.End, Common.Num)
		return
	}

	// 解析目标主机IP
	Hosts, err := Common.ParseIP(info.Host, Common.HostFile, Common.NoHosts)
	if err != nil {
		fmt.Printf("[!] 解析主机错误: %v\n", err)
		return
	}

	// 初始化配置
	lib.Inithttp()
	ch := make(chan struct{}, Common.Threads)
	wg := sync.WaitGroup{}
	var AlivePorts []string

	if len(Hosts) > 0 || len(Common.HostPort) > 0 {
		// ICMP存活性检测
		if (Common.NoPing == false && len(Hosts) > 1) || Common.Scantype == "icmp" {
			Hosts = CheckLive(Hosts, Common.Ping)
			fmt.Printf("[+] ICMP存活主机数量: %d\n", len(Hosts))
			if Common.Scantype == "icmp" {
				Common.LogWG.Wait()
				return
			}
		}

		// 端口扫描策略
		AlivePorts = executeScanStrategy(Hosts, Common.Scantype)

		// 处理自定义端口
		if len(Common.HostPort) > 0 {
			AlivePorts = append(AlivePorts, Common.HostPort...)
			AlivePorts = Common.RemoveDuplicate(AlivePorts)
			Common.HostPort = nil
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

			executeScanTasks(info, Common.Scantype, &ch, &wg)
		}
	}

	// URL扫描
	for _, url := range Common.Urls {
		info.Url = url
		AddScan("web", info, &ch, &wg)
	}

	// 等待所有任务完成
	wg.Wait()
	Common.LogWG.Wait()
	close(Common.Results)
	fmt.Printf("[✓] 扫描已完成: %v/%v\n", Common.End, Common.Num)
}

// executeScanStrategy 执行端口扫描策略
func executeScanStrategy(Hosts []string, scanType string) []string {
	switch scanType {
	case "webonly", "webpoc":
		return NoPortScan(Hosts, Common.Ports)
	case "hostname":
		Common.Ports = "139"
		return NoPortScan(Hosts, Common.Ports)
	default:
		if len(Hosts) > 0 {
			ports := PortScan(Hosts, Common.Ports, Common.Timeout)
			fmt.Printf("[+] 存活端口数量: %d\n", len(ports))
			if scanType == "portscan" {
				Common.LogWG.Wait()
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
			if Common.IsWmi {
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
		Common.Num += 1
		Mutex.Unlock()

		// 执行扫描
		ScanFunc(&scantype, &info)

		// 增加已完成任务数
		Mutex.Lock()
		Common.End += 1
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
