package Core

import (
	"fmt"
	"github.com/schollz/progressbar/v3"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
	} else {
		pluginsToRun = []string{mode}
		isSinglePlugin = true
	}
	
	loadedPlugins := make([]string, 0)
	// 先遍历一遍计算实际要执行的任务数
	actualTasks := 0

	// 定义任务结构
	type ScanTask struct {
		pluginName string
		target     Common.HostInfo
	}
	tasks := make([]ScanTask, 0)

	// 第一次遍历：计算任务数和收集要执行的插件
	for _, target := range targets {
		targetPort, _ := strconv.Atoi(target.Ports)

		for _, pluginName := range pluginsToRun {
			plugin, exists := Common.PluginManager[pluginName]
			if !exists {
				continue
			}

			if Common.LocalScan {
				if len(plugin.Ports) == 0 {
					actualTasks++
					loadedPlugins = append(loadedPlugins, pluginName)
					tasks = append(tasks, ScanTask{
						pluginName: pluginName,
						target:     target,
					})
				}
				continue
			}

			if isSinglePlugin {
				actualTasks++
				loadedPlugins = append(loadedPlugins, pluginName)
				tasks = append(tasks, ScanTask{
					pluginName: pluginName,
					target:     target,
				})
				continue
			}

			if len(plugin.Ports) > 0 {
				if plugin.HasPort(targetPort) {
					actualTasks++
					loadedPlugins = append(loadedPlugins, pluginName)
					tasks = append(tasks, ScanTask{
						pluginName: pluginName,
						target:     target,
					})
				}
			} else {
				actualTasks++
				loadedPlugins = append(loadedPlugins, pluginName)
				tasks = append(tasks, ScanTask{
					pluginName: pluginName,
					target:     target,
				})
			}
		}
	}

	// 去重并输出实际加载的插件
	uniquePlugins := make(map[string]struct{})
	for _, p := range loadedPlugins {
		uniquePlugins[p] = struct{}{}
	}

	finalPlugins := make([]string, 0, len(uniquePlugins))
	for p := range uniquePlugins {
		finalPlugins = append(finalPlugins, p)
	}
	sort.Strings(finalPlugins)

	Common.LogInfo(fmt.Sprintf("加载的插件: %s", strings.Join(finalPlugins, ", ")))

	// 在初始化进度条的地方添加判断
	if !Common.NoProgress {
		Common.ProgressBar = progressbar.NewOptions(actualTasks,
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowCount(),
			progressbar.OptionSetWidth(15),
			progressbar.OptionSetDescription("[cyan]扫描进度:[reset]"),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "[green]=[reset]",
				SaucerHead:    "[green]>[reset]",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
			progressbar.OptionThrottle(65*time.Millisecond),
			progressbar.OptionUseANSICodes(true),
			progressbar.OptionSetRenderBlankState(true),
		)
	}

	// 开始执行收集到的所有任务
	for _, task := range tasks {
		AddScan(task.pluginName, task.target, ch, wg)
	}
}

// finishScan 完成扫描任务
func finishScan(wg *sync.WaitGroup) {
	wg.Wait()
	// 确保进度条完成，只在存在进度条时调用
	if Common.ProgressBar != nil {
		Common.ProgressBar.Finish()
		fmt.Println() // 添加一个换行
	}
	Common.LogSuccess(fmt.Sprintf("扫描已完成: %v/%v", Common.End, Common.Num))
}

// Mutex用于保护共享资源的并发访问
var Mutex = &sync.Mutex{}

// AddScan
func AddScan(plugin string, info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	*ch <- struct{}{}
	wg.Add(1)

	go func() {
		defer func() {
			wg.Done()
			<-*ch
		}()

		Mutex.Lock()
		atomic.AddInt64(&Common.Num, 1)
		Mutex.Unlock()

		ScanFunc(&plugin, &info)

		Common.OutputMutex.Lock()
		atomic.AddInt64(&Common.End, 1)
		if Common.ProgressBar != nil {
			// 清除当前行
			fmt.Print("\033[2K\r")
			Common.ProgressBar.Add(1)
		}
		Common.OutputMutex.Unlock()
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
