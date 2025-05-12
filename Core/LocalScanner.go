package Core

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"sync"
)

// LocalScanStrategy 本地扫描策略
type LocalScanStrategy struct{}

// NewLocalScanStrategy 创建新的本地扫描策略
func NewLocalScanStrategy() *LocalScanStrategy {
	return &LocalScanStrategy{}
}

// Name 返回策略名称
func (s *LocalScanStrategy) Name() string {
	return "本地扫描"
}

// Description 返回策略描述
func (s *LocalScanStrategy) Description() string {
	return "收集本地系统信息"
}

// Execute 执行本地扫描策略
func (s *LocalScanStrategy) Execute(info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	Common.LogBase("执行本地信息收集")

	// 验证插件配置
	if err := validateScanPlugins(); err != nil {
		Common.LogError(err.Error())
		return
	}

	// 输出插件信息
	s.LogPluginInfo()

	// 准备目标（本地扫描通常只有一个目标，即本机）
	targets := s.PrepareTargets(info)

	// 执行扫描任务
	ExecuteScanTasks(targets, s, ch, wg)
}

// PrepareTargets 准备本地扫描目标
func (s *LocalScanStrategy) PrepareTargets(info Common.HostInfo) []Common.HostInfo {
	// 本地扫描只使用传入的目标信息，不做额外处理
	return []Common.HostInfo{info}
}

// GetPlugins 获取本地扫描插件列表
func (s *LocalScanStrategy) GetPlugins() ([]string, bool) {
	// 如果指定了特定插件且不是"all"
	if Common.ScanMode != "" && Common.ScanMode != "all" {
		requestedPlugins := parsePluginList(Common.ScanMode)
		if len(requestedPlugins) == 0 {
			requestedPlugins = []string{Common.ScanMode}
		}

		// 验证插件是否存在，不做Local类型过滤
		var validPlugins []string
		for _, name := range requestedPlugins {
			if _, exists := Common.PluginManager[name]; exists {
				validPlugins = append(validPlugins, name)
			}
		}

		return validPlugins, true
	}

	// 未指定或使用"all"：获取所有插件，由IsPluginApplicable做类型过滤
	return GetAllPlugins(), false
}

// LogPluginInfo 输出本地扫描插件信息
func (s *LocalScanStrategy) LogPluginInfo() {
	allPlugins, isCustomMode := s.GetPlugins()

	// 如果是自定义模式，直接显示用户指定的插件
	if isCustomMode {
		Common.LogBase(fmt.Sprintf("本地模式: 使用指定插件: %s", strings.Join(allPlugins, ", ")))
		return
	}

	// 在自动模式下，只显示Local类型的插件
	var applicablePlugins []string
	for _, pluginName := range allPlugins {
		plugin, exists := Common.PluginManager[pluginName]
		if exists && plugin.HasType(Common.PluginTypeLocal) {
			applicablePlugins = append(applicablePlugins, pluginName)
		}
	}

	if len(applicablePlugins) > 0 {
		Common.LogBase(fmt.Sprintf("本地模式: 使用本地插件: %s", strings.Join(applicablePlugins, ", ")))
	} else {
		Common.LogBase("本地模式: 未找到可用的本地插件")
	}
}

// IsPluginApplicable 判断插件是否适用于本地扫描
func (s *LocalScanStrategy) IsPluginApplicable(plugin Common.ScanPlugin, targetPort int, isCustomMode bool) bool {
	// 自定义模式下运行所有明确指定的插件
	if isCustomMode {
		return true
	}
	// 非自定义模式下，只运行Local类型插件
	return plugin.HasType(Common.PluginTypeLocal)
}
