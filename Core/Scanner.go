package Core

import (
	"fmt"
	"github.com/schollz/progressbar/v3"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ScanTask 表示单个扫描任务
type ScanTask struct {
	pluginName string          // 插件名称
	target     Common.HostInfo // 目标信息
}

// ScanStrategy 定义扫描策略接口
type ScanStrategy interface {
	// 名称和描述
	Name() string
	Description() string

	// 执行扫描的主要方法
	Execute(info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup)

	// 插件管理方法
	GetPlugins() ([]string, bool)
	LogPluginInfo()

	// 任务准备方法
	PrepareTargets(info Common.HostInfo) []Common.HostInfo
	IsPluginApplicable(plugin Common.ScanPlugin, targetPort int, isCustomMode bool) bool
}

// Scanner 扫描器结构体
type Scanner struct {
	strategy ScanStrategy
}

// NewScanner 创建新的扫描器并选择合适的策略
func NewScanner(info Common.HostInfo) *Scanner {
	scanner := &Scanner{}
	scanner.selectStrategy(info)
	return scanner
}

// selectStrategy 根据扫描配置选择适当的扫描策略
func (s *Scanner) selectStrategy(info Common.HostInfo) {
	switch {
	case Common.LocalMode:
		s.strategy = NewLocalScanStrategy()
		Common.LogBase("已选择本地扫描模式")
	case len(Common.URLs) > 0:
		s.strategy = NewWebScanStrategy()
		Common.LogBase("已选择Web扫描模式")
	default:
		s.strategy = NewServiceScanStrategy()
		Common.LogBase("已选择服务扫描模式")
	}
}

// Scan 执行整体扫描流程
func (s *Scanner) Scan(info Common.HostInfo) {
	Common.LogBase("开始信息扫描")
	lib.Inithttp()

	// 并发控制初始化
	ch := make(chan struct{}, Common.ThreadNum)
	wg := sync.WaitGroup{}

	// 执行策略
	s.strategy.Execute(info, &ch, &wg)

	// 等待所有扫描完成
	wg.Wait()
	s.finishScan()
}

// finishScan 完成扫描并输出结果
func (s *Scanner) finishScan() {
	if Common.ProgressBar != nil {
		Common.ProgressBar.Finish()
		fmt.Println()
	}
	Common.LogBase(fmt.Sprintf("扫描已完成: %v/%v", Common.End, Common.Num))
}

// 任务执行通用框架
func ExecuteScanTasks(targets []Common.HostInfo, strategy ScanStrategy, ch *chan struct{}, wg *sync.WaitGroup) {
	// 获取要执行的插件
	pluginsToRun, isCustomMode := strategy.GetPlugins()

	// 准备扫描任务
	tasks := prepareScanTasks(targets, pluginsToRun, isCustomMode, strategy)

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

// 准备扫描任务列表
func prepareScanTasks(targets []Common.HostInfo, pluginsToRun []string, isCustomMode bool, strategy ScanStrategy) []ScanTask {
	var tasks []ScanTask

	for _, target := range targets {
		targetPort := 0
		if target.Ports != "" {
			targetPort, _ = strconv.Atoi(target.Ports)
		}

		for _, pluginName := range pluginsToRun {
			plugin, exists := Common.PluginManager[pluginName]
			if !exists {
				continue
			}

			// 检查插件是否适用于当前目标 (通过策略判断)
			if strategy.IsPluginApplicable(plugin, targetPort, isCustomMode) {
				tasks = append(tasks, ScanTask{
					pluginName: pluginName,
					target:     target,
				})
			}
		}
	}

	return tasks
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

	Common.LogBase(planInfo.String())
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
				Common.LogBase(fmt.Sprintf("完成 %s 扫描 %s:%s (耗时: %.2fs)",
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
		Common.LogBase(fmt.Sprintf("扫描类型 %v 无对应插件，已跳过", pluginName))
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

// 入口函数，向后兼容旧的调用方式
func Scan(info Common.HostInfo) {
	scanner := NewScanner(info)
	scanner.Scan(info)
}
