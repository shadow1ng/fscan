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

// 定义在文件开头
var (
	LocalScan bool // 本地扫描模式标识
	WebScan   bool // Web扫描模式标识
)

// Scan 执行扫描主流程
func Scan(info Common.HostInfo) {
	Common.LogInfo("开始信息扫描")

	// 初始化HTTP客户端
	lib.Inithttp()

	ch := make(chan struct{}, Common.ThreadNum)
	wg := sync.WaitGroup{}

	// 执行扫描逻辑
	switch {
	case Common.LocalMode:
		executeLocalScan(info, &ch, &wg)
	case len(Common.URLs) > 0:
		executeWebScan(info, &ch, &wg)
	default:
		executeHostScan(info, &ch, &wg)
	}

	// 等待扫描完成
	finishScan(&wg)
}

// 执行本地扫描
func executeLocalScan(info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	Common.LogInfo("执行本地信息收集")

	// 定义本地模式允许的插件
	validLocalPlugins := getValidPlugins(Common.ModeLocal)

	// 校验扫描模式
	if err := validateScanMode(validLocalPlugins, Common.ModeLocal); err != nil {
		Common.LogError(err.Error())
		return
	}

	if Common.ScanMode == Common.ModeLocal {
		Common.LogInfo("使用全部本地插件")
	} else {
		Common.LogInfo(fmt.Sprintf("使用插件: %s", Common.ScanMode))
	}

	// 执行扫描
	executeScans([]Common.HostInfo{info}, ch, wg)
}

// 执行Web扫描
func executeWebScan(info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	Common.LogInfo("开始Web扫描")

	// 从 pluginGroups 获取Web模式允许的插件
	validWebPlugins := getValidPlugins(Common.ModeWeb)

	// 校验扫描模式
	if err := validateScanMode(validWebPlugins, Common.ModeWeb); err != nil {
		Common.LogError(err.Error())
		return
	}

	// 创建目标URL信息
	var targetInfos []Common.HostInfo
	for _, url := range Common.URLs {
		urlInfo := info
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "http://" + url
		}
		urlInfo.Url = url
		targetInfos = append(targetInfos, urlInfo)
	}

	if Common.ScanMode == Common.ModeWeb {
		Common.LogInfo("使用全部Web插件")
	} else {
		Common.LogInfo(fmt.Sprintf("使用插件: %s", Common.ScanMode))
	}

	// 执行扫描
	executeScans(targetInfos, ch, wg)
}

// 执行主机扫描
func executeHostScan(info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	if info.Host == "" {
		Common.LogError("未指定扫描目标")
		return
	}

	hosts, err := Common.ParseIP(info.Host, Common.HostsFile, Common.ExcludeHosts)
	if err != nil {
		Common.LogError(fmt.Sprintf("解析主机错误: %v", err))
		return
	}

	Common.LogInfo("开始主机扫描")
	executeScan(hosts, info, ch, wg)
}

// 获取合法的插件列表
func getValidPlugins(mode string) map[string]bool {
	validPlugins := make(map[string]bool)
	for _, plugin := range Common.PluginGroups[mode] {
		validPlugins[plugin] = true
	}
	return validPlugins
}

// 校验扫描模式是否有效
func validateScanMode(validPlugins map[string]bool, mode string) error {
	if Common.ScanMode == "" || Common.ScanMode == "All" {
		Common.ScanMode = mode
	} else if _, exists := validPlugins[Common.ScanMode]; !exists {
		return fmt.Errorf("无效的%s插件: %s", mode, Common.ScanMode)
	}
	return nil
}

// executeScan 执行主扫描流程
func executeScan(hosts []string, info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	var targetInfos []Common.HostInfo

	// 扫描主机和端口
	if len(hosts) > 0 || len(Common.HostPort) > 0 {
		// 处理活跃主机
		if shouldPingScan(hosts) {
			hosts = CheckLive(hosts, Common.UsePing)
			Common.LogInfo(fmt.Sprintf("存活主机数量: %d", len(hosts)))
			if Common.IsICMPScan() {
				return
			}
		}

		// 处理活跃端口
		alivePorts := getAlivePorts(hosts)
		if len(alivePorts) > 0 {
			targetInfos = prepareTargetInfos(alivePorts, info)
		}
	}

	// 添加 URL 扫描目标
	targetInfos = appendURLTargets(targetInfos, info)

	// 如果有扫描目标，执行漏洞扫描
	if len(targetInfos) > 0 {
		Common.LogInfo("开始漏洞扫描")
		executeScans(targetInfos, ch, wg)
	}
}

// shouldPingScan 判断是否需要进行 ping 扫描
func shouldPingScan(hosts []string) bool {
	return (Common.DisablePing == false && len(hosts) > 1) || Common.IsICMPScan()
}

// getAlivePorts 获取存活端口
func getAlivePorts(hosts []string) []string {
	var alivePorts []string
	if Common.IsWebScan() {
		alivePorts = NoPortScan(hosts, Common.Ports)
	} else if len(hosts) > 0 {
		alivePorts = PortScan(hosts, Common.Ports, Common.Timeout)
		Common.LogInfo(fmt.Sprintf("存活端口数量: %d", len(alivePorts)))
		if Common.IsPortScan() {
			return nil // 结束扫描
		}
	}

	// 合并传入的端口信息
	if len(Common.HostPort) > 0 {
		alivePorts = append(alivePorts, Common.HostPort...)
		alivePorts = Common.RemoveDuplicate(alivePorts)
		Common.HostPort = nil
		Common.LogInfo(fmt.Sprintf("存活端口数量: %d", len(alivePorts)))
	}

	return alivePorts
}

// appendURLTargets 添加 URL 扫描目标
func appendURLTargets(targetInfos []Common.HostInfo, baseInfo Common.HostInfo) []Common.HostInfo {
	for _, url := range Common.URLs {
		urlInfo := baseInfo
		urlInfo.Url = url
		targetInfos = append(targetInfos, urlInfo)
	}
	return targetInfos
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

// 扫描任务结构体定义
type ScanTask struct {
	pluginName string
	target     Common.HostInfo
}

// executeScans 执行扫描任务
func executeScans(targets []Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	mode := Common.GetScanMode()

	// 获取待执行的插件列表
	pluginsToRun, isSinglePlugin := getPluginsToRun(mode)

	var tasks []ScanTask
	actualTasks := 0
	loadedPlugins := make([]string, 0)

	// 遍历目标，收集任务
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

	// 去重并排序插件
	finalPlugins := getUniquePlugins(loadedPlugins)

	// 输出加载的插件信息
	Common.LogInfo(fmt.Sprintf("加载的插件: %s", strings.Join(finalPlugins, ", ")))

	// 初始化进度条
	initializeProgressBar(actualTasks)

	// 执行收集的任务
	for _, task := range tasks {
		AddScan(task.pluginName, task.target, ch, wg)
	}
}

// 获取待执行插件列表
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

// 收集扫描任务
func collectScanTasks(plugin Common.ScanPlugin, target Common.HostInfo, targetPort int, pluginName string, isSinglePlugin bool) (bool, []ScanTask) {
	var tasks []ScanTask
	taskAdded := false

	// Web模式特殊处理
	if WebScan || LocalScan || isSinglePlugin || len(plugin.Ports) == 0 || plugin.HasPort(targetPort) {
		taskAdded = true
		tasks = append(tasks, ScanTask{
			pluginName: pluginName,
			target:     target,
		})
	}

	return taskAdded, tasks
}

// 获取去重后的插件列表
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

// 初始化进度条
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

// AddScan 添加扫描任务并启动扫描
func AddScan(plugin string, info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	*ch <- struct{}{}
	wg.Add(1)

	go func() {
		defer func() {
			wg.Done()
			<-*ch
		}()

		// 使用原子操作更新扫描计数
		atomic.AddInt64(&Common.Num, 1)

		// 执行扫描插件
		ScanFunc(&plugin, &info)

		// 更新扫描结束后的状态
		updateScanProgress(&info)
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

// updateScanProgress 更新扫描进度
func updateScanProgress(info *Common.HostInfo) {
	// 输出互斥锁更新进度条
	Common.OutputMutex.Lock()
	atomic.AddInt64(&Common.End, 1)
	if Common.ProgressBar != nil {
		// 清除当前行并更新进度条
		fmt.Print("\033[2K\r")
		Common.ProgressBar.Add(1)
	}
	Common.OutputMutex.Unlock()
}
