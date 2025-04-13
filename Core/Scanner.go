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

// 全局状态
var (
	LocalScan bool            // 本地扫描模式标识
	WebScan   bool            // Web扫描模式标识
	Mutex     = &sync.Mutex{} // 用于保护共享资源
)

// ScanTask 表示单个扫描任务
type ScanTask struct {
	pluginName string          // 插件名称
	target     Common.HostInfo // 目标信息
}

// 添加一个本地插件集合，用于识别哪些插件是本地信息收集插件
var localPlugins = map[string]bool{
	"localinfo": true,
	"dcinfo":    true,
	"minidump":  true,
}

// -----------------------------------------------------------------------------
// 主扫描流程
// -----------------------------------------------------------------------------

// Scan 执行整体扫描流程的入口函数
func Scan(info Common.HostInfo) {
	Common.LogInfo("开始信息扫描")
	lib.Inithttp()

	// 并发控制初始化
	ch := make(chan struct{}, Common.ThreadNum)
	wg := sync.WaitGroup{}

	// 选择并执行扫描模式
	selectScanMode(info, &ch, &wg)

	// 等待所有扫描完成
	wg.Wait()
	finishScan()
}

// 根据配置选择扫描模式
func selectScanMode(info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	switch {
	case Common.LocalMode:
		LocalScan = true
		executeLocalScan(info, ch, wg)
	case len(Common.URLs) > 0:
		WebScan = true
		executeWebScan(info, ch, wg)
	default:
		executeHostScan(info, ch, wg)
	}
}

// 完成扫描并输出结果
func finishScan() {
	if Common.ProgressBar != nil {
		Common.ProgressBar.Finish()
		fmt.Println()
	}
	Common.LogSuccess(fmt.Sprintf("扫描已完成: %v/%v", Common.End, Common.Num))
}

// -----------------------------------------------------------------------------
// 三种扫描模式实现
// -----------------------------------------------------------------------------

// 执行本地信息收集
func executeLocalScan(info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	Common.LogInfo("执行本地信息收集")

	// 验证插件配置
	if err := validateScanPlugins(); err != nil {
		Common.LogError(err.Error())
		return
	}

	// 输出插件信息
	logPluginInfo()

	// 执行扫描任务
	executeScanTasks([]Common.HostInfo{info}, ch, wg)
}

// 执行Web扫描
func executeWebScan(info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	Common.LogInfo("开始Web扫描")

	// 验证插件配置
	if err := validateScanPlugins(); err != nil {
		Common.LogError(err.Error())
		return
	}

	// 准备URL目标
	targetInfos := prepareURLTargets(info)

	// 输出插件信息
	logPluginInfo()

	// 执行扫描任务
	executeScanTasks(targetInfos, ch, wg)
}

// 执行主机扫描
func executeHostScan(info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	// 验证扫描目标
	if info.Host == "" {
		Common.LogError("未指定扫描目标")
		return
	}

	// 验证插件配置
	if err := validateScanPlugins(); err != nil {
		Common.LogError(err.Error())
		return
	}

	// 解析目标主机
	hosts, err := Common.ParseIP(info.Host, Common.HostsFile, Common.ExcludeHosts)
	if err != nil {
		Common.LogError(fmt.Sprintf("解析主机错误: %v", err))
		return
	}

	Common.LogInfo("开始主机扫描")

	// 输出插件信息
	logPluginInfo()

	// 执行主机扫描
	performHostScan(hosts, info, ch, wg)
}

// -----------------------------------------------------------------------------
// 主机扫描流程详细实现
// -----------------------------------------------------------------------------

// 执行主机扫描的完整流程
func performHostScan(hosts []string, info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	var targetInfos []Common.HostInfo

	// 主机存活性检测和端口扫描
	if len(hosts) > 0 || len(Common.HostPort) > 0 {
		// 主机存活检测
		if shouldPerformLivenessCheck(hosts) {
			hosts = CheckLive(hosts, Common.UsePing)
			Common.LogInfo(fmt.Sprintf("存活主机数量: %d", len(hosts)))
		}

		// 端口扫描
		targetInfos = scanPortsAndPrepareTargets(hosts, info)
	}

	// 添加URL目标
	targetInfos = appendURLTargets(targetInfos, info)

	// 执行漏洞扫描
	if len(targetInfos) > 0 {
		Common.LogInfo("开始漏洞扫描")
		executeScanTasks(targetInfos, ch, wg)
	}
}

// 判断是否需要执行存活性检测
func shouldPerformLivenessCheck(hosts []string) bool {
	return Common.DisablePing == false && len(hosts) > 1
}

// 扫描端口并准备目标信息
func scanPortsAndPrepareTargets(hosts []string, info Common.HostInfo) []Common.HostInfo {
	// 扫描存活端口
	alivePorts := discoverAlivePorts(hosts)
	if len(alivePorts) == 0 {
		return nil
	}

	// 转换为目标信息
	return convertToTargetInfos(alivePorts, info)
}

// 发现存活的端口
func discoverAlivePorts(hosts []string) []string {
	var alivePorts []string

	// 根据扫描模式选择端口扫描方式
	if WebScan || len(Common.URLs) > 0 {
		alivePorts = NoPortScan(hosts, Common.Ports)
	} else if len(hosts) > 0 {
		alivePorts = PortScan(hosts, Common.Ports, Common.Timeout)
		Common.LogInfo(fmt.Sprintf("存活端口数量: %d", len(alivePorts)))
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

// -----------------------------------------------------------------------------
// 插件管理和解析
// -----------------------------------------------------------------------------

// getAllLocalPlugins 返回所有本地插件的名称列表
func getAllLocalPlugins() []string {
	var localPluginList []string
	for plugin := range localPlugins {
		localPluginList = append(localPluginList, plugin)
	}
	sort.Strings(localPluginList)
	return localPluginList
}

// parsePluginList 解析逗号分隔的插件列表
// pluginStr: 逗号分隔的插件字符串，如 "ssh,ftp,telnet"
// 返回: 插件名称的字符串切片
func parsePluginList(pluginStr string) []string {
	if pluginStr == "" {
		return nil
	}

	// 按逗号分割并去除每个插件名称两端的空白
	plugins := strings.Split(pluginStr, ",")
	for i, p := range plugins {
		plugins[i] = strings.TrimSpace(p)
	}

	// 过滤空字符串
	var result []string
	for _, p := range plugins {
		if p != "" {
			result = append(result, p)
		}
	}

	return result
}

// validateScanPlugins 验证扫描插件的有效性
// 返回: 错误信息
func validateScanPlugins() error {
	// 如果未指定扫描模式或使用All模式，则无需验证
	if Common.ScanMode == "" || Common.ScanMode == "All" {
		return nil
	}

	// 解析插件列表
	plugins := parsePluginList(Common.ScanMode)
	if len(plugins) == 0 {
		plugins = []string{Common.ScanMode}
	}

	// 验证每个插件是否有效
	var invalidPlugins []string
	for _, plugin := range plugins {
		if _, exists := Common.PluginManager[plugin]; !exists {
			invalidPlugins = append(invalidPlugins, plugin)
		}
	}

	if len(invalidPlugins) > 0 {
		return fmt.Errorf("无效的插件: %s", strings.Join(invalidPlugins, ", "))
	}

	// 如果是本地模式，验证是否包含非本地插件
	if Common.LocalMode {
		var nonLocalPlugins []string
		for _, plugin := range plugins {
			if !isLocalPlugin(plugin) {
				nonLocalPlugins = append(nonLocalPlugins, plugin)
			}
		}

		if len(nonLocalPlugins) > 0 {
			Common.LogInfo(fmt.Sprintf("本地模式下，以下非本地插件将被忽略: %s", strings.Join(nonLocalPlugins, ", ")))
		}
	}

	return nil
}

// isLocalPlugin 判断插件是否为本地信息收集插件
func isLocalPlugin(pluginName string) bool {
	return localPlugins[pluginName]
}

// getPluginsToRun 获取要执行的插件列表
// 返回: 插件列表和是否为自定义插件模式
func getPluginsToRun() ([]string, bool) {
	// 本地模式处理
	if Common.LocalMode {
		// 在本地模式下只执行本地插件

		// 如果指定了特定插件（单个或多个）
		if Common.ScanMode != "" && Common.ScanMode != "All" {
			requestedPlugins := parsePluginList(Common.ScanMode)
			if len(requestedPlugins) == 0 {
				requestedPlugins = []string{Common.ScanMode}
			}

			// 过滤出本地插件
			var localPluginsToRun []string
			for _, plugin := range requestedPlugins {
				if isLocalPlugin(plugin) {
					localPluginsToRun = append(localPluginsToRun, plugin)
				}
			}

			return localPluginsToRun, true
		}

		// 如果是All模式或未指定，则返回所有本地插件
		return getAllLocalPlugins(), true
	}

	// 非本地模式处理（保持原有行为）
	// 如果指定了插件列表（逗号分隔）
	if Common.ScanMode != "" && Common.ScanMode != "All" {
		plugins := parsePluginList(Common.ScanMode)
		if len(plugins) > 0 {
			return plugins, true
		}
		return []string{Common.ScanMode}, true
	}

	// 默认情况：使用所有非本地插件
	allPlugins := GetAllPlugins()
	filteredPlugins := make([]string, 0, len(allPlugins))

	for _, plugin := range allPlugins {
		if !isLocalPlugin(plugin) {
			filteredPlugins = append(filteredPlugins, plugin)
		}
	}

	return filteredPlugins, false
}

// logPluginInfo 输出插件信息
func logPluginInfo() {
	if Common.LocalMode {
		if Common.ScanMode == "" || Common.ScanMode == "All" {
			Common.LogInfo("本地模式: 使用所有本地信息收集插件")
		} else {
			plugins := parsePluginList(Common.ScanMode)
			if len(plugins) == 0 {
				plugins = []string{Common.ScanMode}
			}

			// 过滤出本地插件
			var localPluginsToRun []string
			for _, plugin := range plugins {
				if isLocalPlugin(plugin) {
					localPluginsToRun = append(localPluginsToRun, plugin)
				}
			}

			if len(localPluginsToRun) > 1 {
				Common.LogInfo(fmt.Sprintf("本地模式: 使用本地插件: %s", strings.Join(localPluginsToRun, ", ")))
			} else if len(localPluginsToRun) == 1 {
				Common.LogInfo(fmt.Sprintf("本地模式: 使用本地插件: %s", localPluginsToRun[0]))
			} else {
				Common.LogInfo("本地模式: 未指定有效的本地插件，将不执行任何扫描")
			}
		}
		return
	}

	// 非本地模式的原有逻辑
	if Common.ScanMode == "" || Common.ScanMode == "All" {
		Common.LogInfo("使用所有可用插件（已排除本地敏感插件）")
	} else {
		plugins := parsePluginList(Common.ScanMode)
		if len(plugins) > 1 {
			Common.LogInfo(fmt.Sprintf("使用插件: %s", strings.Join(plugins, ", ")))
		} else {
			Common.LogInfo(fmt.Sprintf("使用插件: %s", Common.ScanMode))
		}
	}
}

// -----------------------------------------------------------------------------
// 目标准备
// -----------------------------------------------------------------------------

// 准备URL目标列表
func prepareURLTargets(baseInfo Common.HostInfo) []Common.HostInfo {
	var targetInfos []Common.HostInfo

	for _, url := range Common.URLs {
		urlInfo := baseInfo
		// 确保URL包含协议头
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "http://" + url
		}
		urlInfo.Url = url
		targetInfos = append(targetInfos, urlInfo)
	}

	return targetInfos
}

// 将端口列表转换为目标信息
func convertToTargetInfos(ports []string, baseInfo Common.HostInfo) []Common.HostInfo {
	var infos []Common.HostInfo

	for _, targetIP := range ports {
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

// 添加URL扫描目标
func appendURLTargets(targetInfos []Common.HostInfo, baseInfo Common.HostInfo) []Common.HostInfo {
	for _, url := range Common.URLs {
		urlInfo := baseInfo
		urlInfo.Url = url
		targetInfos = append(targetInfos, urlInfo)
	}
	return targetInfos
}

// -----------------------------------------------------------------------------
// 任务执行
// -----------------------------------------------------------------------------

// 执行扫描任务集合
func executeScanTasks(targets []Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	// 获取要执行的插件
	pluginsToRun, isCustomMode := getPluginsToRun()

	// 准备扫描任务
	tasks := prepareScanTasks(targets, pluginsToRun, isCustomMode)

	// 输出扫描计划
	if Common.ShowScanPlan && len(tasks) > 0 {
		logScanPlan(tasks)
	}

	// 初始化进度条
	if len(tasks) > 0 && Common.ShowProgress {
		initProgressBar(len(tasks))
	}

	// 执行所有任务
	for _, task := range tasks {
		scheduleScanTask(task.pluginName, task.target, ch, wg)
	}
}

// logScanPlan 输出扫描计划信息
func logScanPlan(tasks []ScanTask) {
	// 统计每个插件的目标数量
	pluginCounts := make(map[string]int)
	for _, task := range tasks {
		pluginCounts[task.pluginName]++
	}

	// 构建扫描计划信息
	var planInfo strings.Builder
	planInfo.WriteString("扫描计划:\n")

	for plugin, count := range pluginCounts {
		planInfo.WriteString(fmt.Sprintf("  - %s: %d 个目标\n", plugin, count))
	}

	Common.LogInfo(planInfo.String())
}

// 准备扫描任务列表
func prepareScanTasks(targets []Common.HostInfo, pluginsToRun []string, isCustomMode bool) []ScanTask {
	var tasks []ScanTask

	for _, target := range targets {
		targetPort, _ := strconv.Atoi(target.Ports)

		for _, pluginName := range pluginsToRun {
			plugin, exists := Common.PluginManager[pluginName]
			if !exists {
				continue
			}

			// 检查插件是否适用于当前目标
			if isPluginApplicable(plugin, targetPort, isCustomMode, pluginName) {
				tasks = append(tasks, ScanTask{
					pluginName: pluginName,
					target:     target,
				})
			}
		}
	}

	return tasks
}

// isPluginApplicable 判断插件是否适用于目标
func isPluginApplicable(plugin Common.ScanPlugin, targetPort int, isCustomMode bool, pluginName string) bool {
	// 本地模式下，只执行本地插件
	if LocalScan {
		return isLocalPlugin(pluginName)
	}

	// 非本地模式下，本地插件特殊处理
	if isLocalPlugin(pluginName) {
		// 只有在自定义模式下明确指定时才执行本地插件
		return isCustomMode
	}

	// 特殊扫描模式下的处理
	if WebScan || isCustomMode {
		return true
	}

	// 端口匹配检查
	// 无端口限制的插件或端口匹配的插件
	return len(plugin.Ports) == 0 || plugin.HasPort(targetPort)
}

// 初始化进度条
func initProgressBar(totalTasks int) {
	Common.ProgressBar = progressbar.NewOptions(totalTasks,
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

// 调度单个扫描任务
func scheduleScanTask(pluginName string, target Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	*ch <- struct{}{} // 获取并发槽位

	go func() {
		startTime := time.Now()

		defer func() {
			// 捕获并记录任何可能的panic
			if r := recover(); r != nil {
				Common.LogError(fmt.Sprintf("[PANIC] 插件 %s 扫描 %s:%s 时崩溃: %v",
					pluginName, target.Host, target.Ports, r))
			}

			// 完成任务，释放资源
			duration := time.Since(startTime)
			if Common.ShowScanPlan {
				Common.LogInfo(fmt.Sprintf("完成 %s 扫描 %s:%s (耗时: %.2fs)",
					pluginName, target.Host, target.Ports, duration.Seconds()))
			}

			wg.Done()
			<-*ch // 释放并发槽位
		}()

		atomic.AddInt64(&Common.Num, 1)
		executeSingleScan(pluginName, target)
		updateProgress()
	}()
}

// 执行单个扫描
func executeSingleScan(pluginName string, info Common.HostInfo) {
	plugin, exists := Common.PluginManager[pluginName]
	if !exists {
		Common.LogInfo(fmt.Sprintf("扫描类型 %v 无对应插件，已跳过", pluginName))
		return
	}

	if err := plugin.ScanFunc(&info); err != nil {
		Common.LogError(fmt.Sprintf("扫描错误 %v:%v - %v", info.Host, info.Ports, err))
	}
}

// 更新扫描进度
func updateProgress() {
	Common.OutputMutex.Lock()
	defer Common.OutputMutex.Unlock()

	atomic.AddInt64(&Common.End, 1)

	if Common.ProgressBar != nil {
		fmt.Print("\033[2K\r")
		Common.ProgressBar.Add(1)
	}
}
