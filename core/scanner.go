package core

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/common/output"
	"github.com/shadow1ng/fscan/plugins"
	"github.com/shadow1ng/fscan/webscan/lib"
)

// ScanStrategy 定义扫描策略接口
type ScanStrategy interface {
	Execute(ctx context.Context, session *common.ScanSession, info common.HostInfo, ch chan struct{}, wg *sync.WaitGroup)
	GetPlugins(config *common.Config) ([]string, bool)
	IsPluginApplicableByName(pluginName string, targetHost string, targetPort int, isCustomMode bool, config *common.Config) bool
}

// ScanMode 扫描模式类型
type ScanMode int

const (
	ScanModeService ScanMode = iota // 默认：服务扫描
	ScanModeAlive                   // 仅存活检测
	ScanModeLocal                   // 本地插件
	ScanModeWeb                     // Web扫描
)

// strategyInfo 策略信息
type strategyInfo struct {
	factory func() ScanStrategy
	logKey  string
}

var strategyRegistry = map[ScanMode]strategyInfo{
	ScanModeAlive:   {func() ScanStrategy { return NewAliveScanStrategy() }, "scan_mode_alive_selected"},
	ScanModeLocal:   {func() ScanStrategy { return NewLocalScanStrategy() }, "scan_mode_local_selected"},
	ScanModeWeb:     {func() ScanStrategy { return NewWebScanStrategy() }, "scan_mode_web_selected"},
	ScanModeService: {func() ScanStrategy { return NewServiceScanStrategy() }, "scan_mode_service_selected"},
}

// determineScanMode 根据配置和状态确定扫描模式
func determineScanMode(config *common.Config, state *common.State) ScanMode {
	switch {
	case config.AliveOnly || config.Mode == "icmp":
		return ScanModeAlive
	case config.LocalMode:
		return ScanModeLocal
	case len(state.GetURLs()) > 0:
		return ScanModeWeb
	default:
		return ScanModeService
	}
}

// selectStrategy 根据扫描模式选择策略
func selectStrategy(config *common.Config, state *common.State, info common.HostInfo) ScanStrategy {
	mode := determineScanMode(config, state)

	if info, ok := strategyRegistry[mode]; ok {
		return info.factory()
	}

	// 后备：默认服务扫描（理论上不会执行到这里）
	return NewServiceScanStrategy()
}

// RunScan 执行整体扫描流程
func RunScan(ctx context.Context, info common.HostInfo, session *common.ScanSession) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	config := session.Config
	state := session.State

	// 初始化HTTP客户端（静默，无需日志）
	if err := lib.Inithttp(config); err != nil {
		common.LogError(i18n.Tr("http_client_init_failed", err))
		os.Exit(1)
	}

	// 选择策略
	strategy := selectStrategy(config, state, info)

	// 并发控制初始化
	ch := make(chan struct{}, config.ThreadNum)
	wg := sync.WaitGroup{}

	// 执行策略
	strategy.Execute(ctx, session, info, ch, &wg)

	// 等待所有扫描完成
	wg.Wait()

	// 检查是否有活跃的连接需要维持
	if state.IsReverseShellActive() || state.IsSocks5ProxyActive() || state.IsForwardShellActive() {
		if state.IsReverseShellActive() {
			common.LogInfo(i18n.GetText("active_reverse_shell"))
		}
		if state.IsSocks5ProxyActive() {
			common.LogInfo(i18n.GetText("active_socks5_proxy"))
		}
		if state.IsForwardShellActive() {
			common.LogInfo(i18n.GetText("active_forward_shell"))
		}
		common.LogInfo(i18n.GetText("press_ctrl_c_exit"))

		// 优雅等待信号或 context 取消（Web Stop）
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		select {
		case <-sigChan:
			common.LogInfo(i18n.GetText("received_exit_signal"))
		case <-ctx.Done():
		}
		cancel()
		time.Sleep(500 * time.Millisecond)
	}

	// 完成扫描
	finishScan(config, state)
}

// finishScan 完成扫描并输出结果
func finishScan(config *common.Config, state *common.State) {
	// 确保进度条正确完成
	if common.IsProgressActive() {
		common.FinishProgressBar()
	}

	// 输出扫描完成信息
	common.LogInfo(i18n.Tr("scan_task_complete", time.Since(state.GetStartTime()).Round(time.Millisecond), state.GetNum()))

	// 输出性能统计 JSON（如果启用）
	if config.Output.PerfStats {
		fmt.Printf("\n[PERF_STATS_JSON]%s[/PERF_STATS_JSON]\n", state.GetPerfStatsJSON())
	}
}

// ExecuteScanTasks 任务执行通用框架
func ExecuteScanTasks(ctx context.Context, session *common.ScanSession, targets []common.HostInfo, strategy ScanStrategy, ch chan struct{}, wg *sync.WaitGroup) {
	config := session.Config

	// 获取要执行的插件
	pluginsToRun, isCustomMode := strategy.GetPlugins(config)

	// 预计算任务数量用于进度条
	taskCount := countApplicableTasks(targets, pluginsToRun, isCustomMode, strategy, config)

	// 初始化进度条
	if taskCount > 0 && config.Output.ShowProgress {
		description := i18n.GetText("progress_scanning_description")
		common.InitProgressBar(int64(taskCount), description)
	}

	// 流式执行任务，避免预构建大量任务对象
	for _, target := range targets {
		// 检查取消
		select {
		case <-ctx.Done():
			return
		default:
		}

		targetPort := target.Port

		for _, pluginName := range pluginsToRun {
			// 使用Exists检查避免不必要的插件实例创建
			if !plugins.Exists(pluginName) {
				continue
			}

			// 检查插件是否适用于当前目标
			if strategy.IsPluginApplicableByName(pluginName, target.Host, targetPort, isCustomMode, config) {
				executeScanTask(ctx, session, pluginName, target, ch, wg)
			}
		}
	}
}

// countApplicableTasks 计算适用的任务数量
func countApplicableTasks(targets []common.HostInfo, pluginsToRun []string, isCustomMode bool, strategy ScanStrategy, config *common.Config) int {
	count := 0
	for _, target := range targets {
		targetPort := target.Port

		for _, pluginName := range pluginsToRun {
			// 使用Exists检查避免不必要的插件实例创建
			if plugins.Exists(pluginName) &&
				strategy.IsPluginApplicableByName(pluginName, target.Host, targetPort, isCustomMode, config) {
				count++
			}
		}
	}
	return count
}

// longRunningPlugins 长驻插件，不加入 scan WaitGroup，通过 ctx 取消退出
var longRunningPlugins = map[string]bool{
	"forwardshell": true,
	"socks5proxy":  true,
	"reverseshell": true,
}

// executeScanTask 执行单个扫描任务
func executeScanTask(ctx context.Context, session *common.ScanSession, pluginName string, target common.HostInfo, ch chan struct{}, wg *sync.WaitGroup) {
	state := session.State

	// 检查取消
	select {
	case <-ctx.Done():
		return
	default:
	}

	// 长驻插件不进 WaitGroup，通过 ctx 管理生命周期
	if longRunningPlugins[pluginName] {
		go func() {
			plugin := plugins.Get(pluginName)
			if plugin != nil {
				plugin.Scan(ctx, &target, session)
			}
		}()
		return
	}

	wg.Add(1)

	// 获取并发槽位，支持取消
	select {
	case ch <- struct{}{}:
	case <-ctx.Done():
		wg.Done()
		return
	}

	go func() {
		// 开始监控插件任务
		monitor := common.GetConcurrencyMonitor()
		monitor.StartPluginTask()

		defer func() {
			// 捕获并记录任何可能的panic
			if r := recover(); r != nil {
				common.LogError(i18n.Tr("plugin_panic", pluginName, target.Host, target.Port, r))
			}

			// 更新统计和进度（任务真正完成时才更新）
			state.IncrementNum()
			common.UpdateProgressBar(1)

			// 完成任务，释放资源
			monitor.FinishPluginTask()
			wg.Done()
			<-ch // 释放并发槽位
		}()

		plugin := plugins.Get(pluginName)
		if plugin != nil {
			result := plugin.Scan(ctx, &target, session)
			if result != nil {
				if result.Success {
					// 保存成功的扫描结果到文件
					savePluginResult(&target, pluginName, result)
				} else if result.Type == plugins.ResultTypeCredential {
					// 凭据测试完成但未发现弱密码，在error级别输出提示
					common.LogError(i18n.Tr("brute_no_weak_pass", target.Host, target.Port, pluginName))
				} else if result.Error != nil {
					// 其他类型的错误
					common.LogError(i18n.Tr("plugin_scan_error", target.Host, target.Port, result.Error))
				}
			}
		}
	}()
}

// resultSerializer 结果序列化信息
type resultSerializer struct {
	outputType output.ResultType
	getStatus  func(*plugins.Result, *common.HostInfo) string
	fillDetail func(*plugins.Result, *common.HostInfo, map[string]interface{})
}

var resultSerializers = map[plugins.ResultType]resultSerializer{
	plugins.ResultTypeCredential: {
		outputType: output.TypeVuln,
		getStatus: func(r *plugins.Result, _ *common.HostInfo) string {
			return fmt.Sprintf("weak_credential: %s:%s", r.Username, r.Password)
		},
		fillDetail: func(r *plugins.Result, _ *common.HostInfo, d map[string]interface{}) {
			d["service"] = r.Service
			d["username"] = r.Username
			d["password"] = r.Password
			d["type"] = "weak_credential"
		},
	},
	plugins.ResultTypeService: {
		outputType: output.TypeService,
		getStatus: func(r *plugins.Result, _ *common.HostInfo) string {
			if r.Banner != "" {
				return r.Banner
			}
			return r.Service
		},
		fillDetail: func(r *plugins.Result, _ *common.HostInfo, d map[string]interface{}) {
			if r.Banner != "" {
				d["banner"] = r.Banner
			}
			if r.Service != "" {
				d["service"] = r.Service
			}
		},
	},
	plugins.ResultTypeVuln: {
		outputType: output.TypeVuln,
		getStatus: func(r *plugins.Result, _ *common.HostInfo) string {
			// 优先使用VulInfo，为空则回退到Banner
			if r.VulInfo != "" {
				return r.VulInfo
			}
			return r.Banner
		},
		fillDetail: func(r *plugins.Result, _ *common.HostInfo, d map[string]interface{}) {
			// 优先使用VulInfo，为空则回退到Banner
			vuln := r.VulInfo
			if vuln == "" {
				vuln = r.Banner
			}
			d["vulnerability"] = vuln
			d["service"] = r.Service
		},
	},
	plugins.ResultTypeWeb: {
		outputType: output.TypeService,
		getStatus:  func(_ *plugins.Result, _ *common.HostInfo) string { return "web" },
		fillDetail: func(r *plugins.Result, info *common.HostInfo, d map[string]interface{}) {
			d["is_web"] = true
			d["port"] = info.Port
			if r.Output == "" {
				return
			}
			d["url"] = r.Output
			if parsed, err := url.Parse(r.Output); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
				d["protocol"] = parsed.Scheme
			}
		},
	},
}

var defaultSerializer = resultSerializer{
	outputType: output.TypeService,
	getStatus: func(r *plugins.Result, _ *common.HostInfo) string {
		if r.Banner != "" {
			return r.Banner
		}
		if r.Service != "" {
			return r.Service
		}
		return "detected"
	},
	fillDetail: func(_ *plugins.Result, _ *common.HostInfo, _ map[string]interface{}) {},
}

// savePluginResult 保存插件扫描结果
func savePluginResult(info *common.HostInfo, pluginName string, result *plugins.Result) {
	if result == nil || !result.Success || result.Skipped {
		return
	}

	// 获取序列化器
	serializer, ok := resultSerializers[result.Type]
	if !ok {
		serializer = defaultSerializer
	}

	// 构建详情
	details := map[string]interface{}{"plugin": pluginName}
	serializer.fillDetail(result, info, details)

	// 添加通用字段
	addCommonDetails(result, details)

	// 保存结果
	target := info.Target()
	_ = common.SaveResult(&output.ScanResult{
		Time:    time.Now(),
		Type:    serializer.outputType,
		Target:  target,
		Status:  serializer.getStatus(result, info),
		Details: details,
	})
}

// addCommonDetails 添加通用详情字段
func addCommonDetails(result *plugins.Result, details map[string]interface{}) {
	if len(result.Fingerprints) > 0 {
		details["fingerprints"] = result.Fingerprints
	}
	if result.Title != "" {
		details["title"] = result.Title
	}
	if result.Status != 0 {
		details["status"] = result.Status
	}
	if result.Server != "" {
		details["server"] = result.Server
	}
}
