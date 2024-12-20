package Core

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"strconv"
	"strings"
	"sync"
)

// Scan 执行扫描主流程
func Scan(info Common.HostInfo) {
	fmt.Println("[*] 开始信息扫描...")

	Common.ParseScanMode(Common.ScanMode)

	ch := make(chan struct{}, Common.ThreadNum)
	wg := sync.WaitGroup{}

	// 本地信息收集模式
	if Common.IsLocalScan() {
		executeScans([]Common.HostInfo{info}, &ch, &wg)
		finishScan(&wg)
		return
	}

	// 初始化并解析目标
	hosts, err := Common.ParseIP(info.Host, Common.HostsFile, Common.ExcludeHosts)
	if err != nil {
		fmt.Printf("[-] 解析主机错误: %v\n", err)
		return
	}
	lib.Inithttp()

	// 执行目标扫描
	executeScan(hosts, info, &ch, &wg)
	finishScan(&wg)
}

// executeScan 执行主扫描流程
func executeScan(hosts []string, info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	var targetInfos []Common.HostInfo

	// 处理主机和端口扫描
	if len(hosts) > 0 || len(Common.HostPort) > 0 {
		// ICMP存活性检测
		if (Common.DisablePing == false && len(hosts) > 1) || Common.IsICMPScan() {
			hosts = CheckLive(hosts, Common.UsePing)
			fmt.Printf("[+] ICMP存活主机数量: %d\n", len(hosts))
			if Common.IsICMPScan() {
				return
			}
		}

		// 获取存活端口
		var alivePorts []string
		if Common.IsWebScan() {
			alivePorts = NoPortScan(hosts, Common.Ports)
		} else if len(hosts) > 0 {
			alivePorts = PortScan(hosts, Common.Ports, Common.Timeout)
			fmt.Printf("[+] 存活端口数量: %d\n", len(alivePorts))
			if Common.IsPortScan() {
				return
			}
		}

		// 处理自定义端口
		if len(Common.HostPort) > 0 {
			alivePorts = append(alivePorts, Common.HostPort...)
			alivePorts = Common.RemoveDuplicate(alivePorts)
			Common.HostPort = nil
			fmt.Printf("[+] 总计存活端口: %d\n", len(alivePorts))
		}

		targetInfos = prepareTargetInfos(alivePorts, info)
	}

	// 准备URL扫描目标
	for _, url := range Common.URLs {
		urlInfo := info
		urlInfo.Url = url
		targetInfos = append(targetInfos, urlInfo)
	}

	// 执行扫描任务
	if len(targetInfos) > 0 {
		fmt.Println("[*] 开始漏洞扫描...")
		executeScans(targetInfos, ch, wg)
	}
}

// prepareTargetInfos 准备扫描目标信息
func prepareTargetInfos(alivePorts []string, baseInfo Common.HostInfo) []Common.HostInfo {
	var infos []Common.HostInfo
	for _, targetIP := range alivePorts {
		hostParts := strings.Split(targetIP, ":")
		if len(hostParts) != 2 {
			fmt.Printf("[-] 无效的目标地址格式: %s\n", targetIP)
			continue
		}
		info := baseInfo
		info.Host = hostParts[0]
		info.Ports = hostParts[1]
		infos = append(infos, info)
	}
	return infos
}

// executeScans 统一执行扫描任务
func executeScans(targets []Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	mode := Common.GetScanMode()

	// 判断是否是预设模式（大写开头）
	if plugins := Common.GetPluginsForMode(mode); plugins != nil {
		// 使用预设模式的插件组
		for _, target := range targets {
			targetPort, _ := strconv.Atoi(target.Ports) // 转换目标端口为整数
			for _, pluginName := range plugins {
				// 获取插件信息
				plugin, exists := Common.PluginManager[pluginName]
				if !exists {
					continue
				}

				// 检查插件是否有默认端口配置
				if len(plugin.Ports) > 0 {
					// 只有当目标端口在插件支持的端口列表中才执行
					if plugin.HasPort(targetPort) {
						AddScan(pluginName, target, ch, wg)
					}
				} else {
					// 对于没有指定端口的插件，始终执行
					AddScan(pluginName, target, ch, wg)
				}
			}
		}
	} else {
		// 使用单个插件模式，直接执行不做端口检查
		for _, target := range targets {
			AddScan(mode, target, ch, wg)
		}
	}
}

// finishScan 完成扫描任务
func finishScan(wg *sync.WaitGroup) {
	wg.Wait()
	Common.LogWG.Wait()
	close(Common.Results)
	fmt.Printf("[+] 扫描已完成: %v/%v\n", Common.End, Common.Num)
}

// Mutex用于保护共享资源的并发访问
var Mutex = &sync.Mutex{}

// AddScan 添加扫描任务到并发队列
func AddScan(plugin string, info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
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
		ScanFunc(&plugin, &info)

		// 增加已完成任务数
		Mutex.Lock()
		Common.End += 1
		Mutex.Unlock()
	}()
}

// ScanFunc 执行扫描插件
func ScanFunc(name *string, info *Common.HostInfo) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("[!] 扫描错误 %v:%v - %v\n", info.Host, info.Ports, err)
		}
	}()

	// 检查插件是否存在
	plugin, exists := Common.PluginManager[*name]
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
