package Core

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Scan 执行扫描主流程
func Scan(info Common.HostInfo) {
	Common.LogInfo("开始信息扫描")
	Common.ParseScanMode(Common.ScanMode)

	ch := make(chan struct{}, Common.ThreadNum)
	wg := sync.WaitGroup{}

	// 本地信息收集模式
	if Common.LocalScan {
		executeScans([]Common.HostInfo{info}, &ch, &wg)
		finishScan(&wg)
		return
	}

	// 初始化并解析目标
	hosts, err := Common.ParseIP(info.Host, Common.HostsFile, Common.ExcludeHosts)
	if err != nil {
		Common.LogError(fmt.Sprintf("解析主机错误: %v", err))
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

	if len(hosts) > 0 || len(Common.HostPort) > 0 {
		if (Common.DisablePing == false && len(hosts) > 1) || Common.IsICMPScan() {
			hosts = CheckLive(hosts, Common.UsePing)
			Common.LogInfo(fmt.Sprintf("存活主机数量: %d", len(hosts)))
			if Common.IsICMPScan() {
				return
			}
		}

		var alivePorts []string
		if Common.IsWebScan() {
			alivePorts = NoPortScan(hosts, Common.Ports)
		} else if len(hosts) > 0 {
			alivePorts = PortScan(hosts, Common.Ports, Common.Timeout)
			Common.LogInfo(fmt.Sprintf("存活端口数量: %d", len(alivePorts)))
			if Common.IsPortScan() {
				return
			}
		}

		if len(Common.HostPort) > 0 {
			alivePorts = append(alivePorts, Common.HostPort...)
			alivePorts = Common.RemoveDuplicate(alivePorts)
			Common.HostPort = nil
			Common.LogInfo(fmt.Sprintf("存活端口数量: %d", len(alivePorts)))
		}

		targetInfos = prepareTargetInfos(alivePorts, info)
	}

	for _, url := range Common.URLs {
		urlInfo := info
		urlInfo.Url = url
		targetInfos = append(targetInfos, urlInfo)
	}

	if len(targetInfos) > 0 {
		Common.LogInfo("开始漏洞扫描")
		executeScans(targetInfos, ch, wg)
	}
}

// prepareTargetInfos 准备扫描目标信息
func prepareTargetInfos(alivePorts []string, baseInfo Common.HostInfo) []Common.HostInfo {
	var infos []Common.HostInfo
	for _, targetIP := range alivePorts {
		hostParts := strings.Split(targetIP, ":")
		if len(hostParts) != 2 {
			Common.LogError(fmt.Sprintf("无效的目标地址格式: %s", targetIP))
			continue
		}
		info := baseInfo
		info.Host = hostParts[0]
		info.Ports = hostParts[1]
		infos = append(infos, info)
	}
	return infos
}

func executeScans(targets []Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	mode := Common.GetScanMode()
	var pluginsToRun []string
	isSinglePlugin := false

	if plugins := Common.GetPluginsForMode(mode); plugins != nil {
		pluginsToRun = plugins
		Common.LogInfo(fmt.Sprintf("加载插件组: %s", mode))
	} else {
		pluginsToRun = []string{mode}
		isSinglePlugin = true
		Common.LogInfo(fmt.Sprintf("使用单个插件: %s", mode))
	}

	for _, target := range targets {
		targetPort, _ := strconv.Atoi(target.Ports)

		for _, pluginName := range pluginsToRun {
			plugin, exists := Common.PluginManager[pluginName]
			if !exists {
				Common.LogError(fmt.Sprintf("插件 %s 不存在", pluginName))
				continue
			}

			if Common.LocalScan {
				if len(plugin.Ports) == 0 {
					AddScan(pluginName, target, ch, wg)
				}
				continue
			}

			if isSinglePlugin {
				AddScan(pluginName, target, ch, wg)
				continue
			}

			if len(plugin.Ports) > 0 {
				if plugin.HasPort(targetPort) {
					AddScan(pluginName, target, ch, wg)
				}
			} else {
				AddScan(pluginName, target, ch, wg)
			}
		}
	}
}

// finishScan 完成扫描任务
func finishScan(wg *sync.WaitGroup) {
	wg.Wait()
	// 先发送最后的成功消息
	Common.LogSuccess(fmt.Sprintf("扫描已完成: %v/%v", Common.End, Common.Num))
	// 等待日志处理完成后再关闭通道
	Common.LogWG.Wait()
	close(Common.Results)
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
		atomic.AddInt64(&Common.Num, 1)
		Mutex.Unlock()

		// 执行扫描
		ScanFunc(&plugin, &info)

		// 增加已完成任务数
		Mutex.Lock()
		atomic.AddInt64(&Common.End, 1)
		Mutex.Unlock()
	}()
}

// ScanFunc 执行扫描插件
func ScanFunc(name *string, info *Common.HostInfo) {
	defer func() {
		if err := recover(); err != nil {
			Common.LogError(fmt.Sprintf("扫描错误 %v:%v - %v", info.Host, info.Ports, err))
		}
	}()

	plugin, exists := Common.PluginManager[*name]
	if !exists {
		Common.LogInfo(fmt.Sprintf("扫描类型 %v 无对应插件，已跳过", *name))
		return
	}

	if err := plugin.ScanFunc(info); err != nil {
		Common.LogError(fmt.Sprintf("扫描错误 %v:%v - %v", info.Host, info.Ports, err))
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
