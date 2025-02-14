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

// 全局变量定义
var (
	LocalScan bool // 本地扫描模式标识
	WebScan   bool // Web扫描模式标识
)

// Scan 执行扫描主流程
// info: 主机信息结构体,包含扫描目标的基本信息
func Scan(info Common.HostInfo) {
	Common.LogInfo("开始信息扫描")

	// 初始化HTTP客户端配置
	lib.Inithttp()

	// 初始化并发控制
	ch := make(chan struct{}, Common.ThreadNum)
	wg := sync.WaitGroup{}

	// 根据扫描模式执行不同的扫描策略
	switch {
	case Common.LocalMode:
		// 本地信息收集模式
		LocalScan = true
		executeLocalScan(info, &ch, &wg)
	case len(Common.URLs) > 0:
		// Web扫描模式
		WebScan = true
		executeWebScan(info, &ch, &wg)
	default:
		// 主机扫描模式
		executeHostScan(info, &ch, &wg)
	}

	// 等待所有扫描任务完成
	finishScan(&wg)
}

// executeLocalScan 执行本地扫描
// info: 主机信息
// ch: 并发控制通道
// wg: 等待组
func executeLocalScan(info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	Common.LogInfo("执行本地信息收集")

	// 获取本地模式支持的插件列表
	validLocalPlugins := getValidPlugins(Common.ModeLocal)

	// 验证扫描模式的合法性
	if err := validateScanMode(validLocalPlugins, Common.ModeLocal); err != nil {
		Common.LogError(err.Error())
		return
	}

	// 输出使用的插件信息
	if Common.ScanMode == Common.ModeLocal {
		Common.LogInfo("使用全部本地插件")
		Common.ParseScanMode(Common.ScanMode)
	} else {
		Common.LogInfo(fmt.Sprintf("使用插件: %s", Common.ScanMode))
	}

	// 执行扫描任务
	executeScans([]Common.HostInfo{info}, ch, wg)
}

// executeWebScan 执行Web扫描
// info: 主机信息
// ch: 并发控制通道
// wg: 等待组
func executeWebScan(info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	Common.LogInfo("开始Web扫描")

	// 获取Web模式支持的插件列表
	validWebPlugins := getValidPlugins(Common.ModeWeb)

	// 验证扫描模式的合法性
	if err := validateScanMode(validWebPlugins, Common.ModeWeb); err != nil {
		Common.LogError(err.Error())
		return
	}

	// 处理目标URL列表
	var targetInfos []Common.HostInfo
	for _, url := range Common.URLs {
		urlInfo := info
		// 确保URL包含协议头
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "http://" + url
		}
		urlInfo.Url = url
		targetInfos = append(targetInfos, urlInfo)
	}

	// 输出使用的插件信息
	if Common.ScanMode == Common.ModeWeb {
		Common.LogInfo("使用全部Web插件")
		Common.ParseScanMode(Common.ScanMode)
	} else {
		Common.LogInfo(fmt.Sprintf("使用插件: %s", Common.ScanMode))
	}

	// 执行扫描任务
	executeScans(targetInfos, ch, wg)
}

// executeHostScan 执行主机扫描
// info: 主机信息
// ch: 并发控制通道
// wg: 等待组
func executeHostScan(info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	// 验证扫描目标
	if info.Host == "" {
		Common.LogError("未指定扫描目标")
		return
	}

	// 解析目标主机
	hosts, err := Common.ParseIP(info.Host, Common.HostsFile, Common.ExcludeHosts)
	if err != nil {
		Common.LogError(fmt.Sprintf("解析主机错误: %v", err))
		return
	}

	Common.LogInfo("开始主机扫描")
	executeScan(hosts, info, ch, wg)
}

// getValidPlugins 获取指定模式下的有效插件列表
// mode: 扫描模式
// 返回: 有效插件映射表
func getValidPlugins(mode string) map[string]bool {
	validPlugins := make(map[string]bool)
	for _, plugin := range Common.PluginGroups[mode] {
		validPlugins[plugin] = true
	}
	return validPlugins
}

// validateScanMode 验证扫描模式的合法性
// validPlugins: 有效插件列表
// mode: 扫描模式
// 返回: 错误信息
func validateScanMode(validPlugins map[string]bool, mode string) error {
	if Common.ScanMode == "" || Common.ScanMode == "All" {
		Common.ScanMode = mode
	} else if _, exists := validPlugins[Common.ScanMode]; !exists {
		return fmt.Errorf("无效的%s插件: %s", mode, Common.ScanMode)
	}
	return nil
}

// executeScan 执行主扫描流程
// hosts: 目标主机列表
// info: 主机信息
// ch: 并发控制通道
// wg: 等待组
func executeScan(hosts []string, info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	var targetInfos []Common.HostInfo

	// 处理主机和端口扫描
	if len(hosts) > 0 || len(Common.HostPort) > 0 {
		// 检查主机存活性
		if shouldPingScan(hosts) {
			hosts = CheckLive(hosts, Common.UsePing)
			Common.LogInfo(fmt.Sprintf("存活主机数量: %d", len(hosts)))
			if Common.IsICMPScan() {
				return
			}
		}

		// 获取存活端口
		alivePorts := getAlivePorts(hosts)
		if len(alivePorts) > 0 {
			targetInfos = prepareTargetInfos(alivePorts, info)
		}
	}

	// 添加URL扫描目标
	targetInfos = appendURLTargets(targetInfos, info)

	// 执行漏洞扫描
	if len(targetInfos) > 0 {
		Common.LogInfo("开始漏洞扫描")
		executeScans(targetInfos, ch, wg)
	}
}

// shouldPingScan 判断是否需要执行ping扫描
// hosts: 目标主机列表
// 返回: 是否需要ping扫描
func shouldPingScan(hosts []string) bool {
	return (Common.DisablePing == false && len(hosts) > 1) || Common.IsICMPScan()
}

// getAlivePorts 获取存活端口列表
// hosts: 目标主机列表
// 返回: 存活端口列表
func getAlivePorts(hosts []string) []string {
	var alivePorts []string

	// 根据扫描模式选择端口扫描方式
	if Common.IsWebScan() {
		alivePorts = NoPortScan(hosts, Common.Ports)
	} else if len(hosts) > 0 {
		alivePorts = PortScan(hosts, Common.Ports, Common.Timeout)
		Common.LogInfo(fmt.Sprintf("存活端口数量: %d", len(alivePorts)))
		if Common.IsPortScan() {
			return nil
		}
	}

	// 合并额外指定的端口
	if len(Common.HostPort) > 0 {
		alivePorts = append(alivePorts, Common.HostPort...)
		alivePorts = Common.RemoveDuplicate(alivePorts)
		Common.HostPort = nil
		Common.LogInfo(fmt.Sprintf("存活端口数量: %d", len(alivePorts)))
	}

	return alivePorts
}

// appendURLTargets 添加URL扫描目标
// targetInfos: 现有目标列表
// baseInfo: 基础主机信息
// 返回: 更新后的目标列表
func appendURLTargets(targetInfos []Common.HostInfo, baseInfo Common.HostInfo) []Common.HostInfo {
	for _, url := range Common.URLs {
		urlInfo := baseInfo
		urlInfo.Url = url
		targetInfos = append(targetInfos, urlInfo)
	}
	return targetInfos
}

// prepareTargetInfos 准备扫描目标信息
// alivePorts: 存活端口列表
// baseInfo: 基础主机信息
// 返回: 目标信息列表
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

// ScanTask 扫描任务结构体
type ScanTask struct {
	pluginName string          // 插件名称
	target     Common.HostInfo // 目标信息
}

// executeScans 执行扫描任务
// targets: 目标列表
// ch: 并发控制通道
// wg: 等待组
func executeScans(targets []Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	mode := Common.GetScanMode()

	// 获取要执行的插件列表
	pluginsToRun, isSinglePlugin := getPluginsToRun(mode)

	var tasks []ScanTask
	actualTasks := 0
	loadedPlugins := make([]string, 0)

	// 收集扫描任务
	for _, target := range targets {
		targetPort, _ := strconv.Atoi(target.Ports)
		for _, pluginName := range pluginsToRun {
			plugin, exists := Common.PluginManager[pluginName]
			if !exists {
				continue
			}
			taskAdded, newTasks := collectScanTasks(plugin, target, targetPort, pluginName, isSinglePlugin)
			if taskAdded {
				actualTasks += len(newTasks)
				loadedPlugins = append(loadedPlugins, pluginName)
				tasks = append(tasks, newTasks...)
			}
		}
	}

	// 处理插件列表
	finalPlugins := getUniquePlugins(loadedPlugins)
	Common.LogInfo(fmt.Sprintf("加载的插件: %s", strings.Join(finalPlugins, ", ")))

	// 初始化进度条
	initializeProgressBar(actualTasks)

	// 执行扫描任务
	for _, task := range tasks {
		AddScan(task.pluginName, task.target, ch, wg)
	}
}

// getPluginsToRun 获取要执行的插件列表
// mode: 扫描模式
// 返回: 插件列表和是否为单插件模式
func getPluginsToRun(mode string) ([]string, bool) {
	var pluginsToRun []string
	isSinglePlugin := false

	if plugins := Common.GetPluginsForMode(mode); plugins != nil {
		pluginsToRun = plugins
	} else {
		pluginsToRun = []string{mode}
		isSinglePlugin = true
	}

	return pluginsToRun, isSinglePlugin
}

// collectScanTasks 收集扫描任务
// plugin: 插件信息
// target: 目标信息
// targetPort: 目标端口
// pluginName: 插件名称
// isSinglePlugin: 是否为单插件模式
// 返回: 是否添加任务和任务列表
func collectScanTasks(plugin Common.ScanPlugin, target Common.HostInfo, targetPort int, pluginName string, isSinglePlugin bool) (bool, []ScanTask) {
	var tasks []ScanTask
	taskAdded := false

	if WebScan || LocalScan || isSinglePlugin || len(plugin.Ports) == 0 || plugin.HasPort(targetPort) {
		taskAdded = true
		tasks = append(tasks, ScanTask{
			pluginName: pluginName,
			target:     target,
		})
	}

	return taskAdded, tasks
}

// getUniquePlugins 获取去重后的插件列表
// loadedPlugins: 已加载的插件列表
// 返回: 去重并排序后的插件列表
func getUniquePlugins(loadedPlugins []string) []string {
	uniquePlugins := make(map[string]struct{})
	for _, p := range loadedPlugins {
		uniquePlugins[p] = struct{}{}
	}

	finalPlugins := make([]string, 0, len(uniquePlugins))
	for p := range uniquePlugins {
		finalPlugins = append(finalPlugins, p)
	}

	sort.Strings(finalPlugins)
	return finalPlugins
}

// initializeProgressBar 初始化进度条
// actualTasks: 实际任务数量
func initializeProgressBar(actualTasks int) {
	if Common.ShowProgress {
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
}

// finishScan 完成扫描任务
// wg: 等待组
func finishScan(wg *sync.WaitGroup) {
	wg.Wait()
	if Common.ProgressBar != nil {
		Common.ProgressBar.Finish()
		fmt.Println()
	}
	Common.LogSuccess(fmt.Sprintf("扫描已完成: %v/%v", Common.End, Common.Num))
}

// Mutex 用于保护共享资源的并发访问
var Mutex = &sync.Mutex{}

// AddScan 添加扫描任务并启动扫描
// plugin: 插件名称
// info: 目标信息
// ch: 并发控制通道
// wg: 等待组
func AddScan(plugin string, info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	*ch <- struct{}{}
	wg.Add(1)

	go func() {
		defer func() {
			wg.Done()
			<-*ch
		}()

		atomic.AddInt64(&Common.Num, 1)
		ScanFunc(&plugin, &info)
		updateScanProgress(&info)
	}()
}

// ScanFunc 执行扫描插件
// name: 插件名称
// info: 目标信息
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

// updateScanProgress 更新扫描进度
// info: 目标信息
func updateScanProgress(info *Common.HostInfo) {
	Common.OutputMutex.Lock()
	atomic.AddInt64(&Common.End, 1)
	if Common.ProgressBar != nil {
		fmt.Print("\033[2K\r")
		Common.ProgressBar.Add(1)
	}
	Common.OutputMutex.Unlock()
}
