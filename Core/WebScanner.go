package Core

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"sync"
)

// WebScanStrategy Web扫描策略
type WebScanStrategy struct{}

// NewWebScanStrategy 创建新的Web扫描策略
func NewWebScanStrategy() *WebScanStrategy {
	return &WebScanStrategy{}
}

// Name 返回策略名称
func (s *WebScanStrategy) Name() string {
	return "Web扫描"
}

// Description 返回策略描述
func (s *WebScanStrategy) Description() string {
	return "扫描Web应用漏洞和信息"
}

// Execute 执行Web扫描策略
func (s *WebScanStrategy) Execute(info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	Common.LogBase("开始Web扫描")

	// 验证插件配置
	if err := validateScanPlugins(); err != nil {
		Common.LogError(err.Error())
		return
	}

	// 准备URL目标
	targets := s.PrepareTargets(info)

	// 输出插件信息
	s.LogPluginInfo()

	// 执行扫描任务
	ExecuteScanTasks(targets, s, ch, wg)
}

// PrepareTargets 准备URL目标列表
func (s *WebScanStrategy) PrepareTargets(baseInfo Common.HostInfo) []Common.HostInfo {
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

// GetPlugins 获取Web扫描插件列表
func (s *WebScanStrategy) GetPlugins() ([]string, bool) {
	// 如果指定了自定义插件并且不是"all"
	if Common.ScanMode != "" && Common.ScanMode != "all" {
		requestedPlugins := parsePluginList(Common.ScanMode)
		if len(requestedPlugins) == 0 {
			requestedPlugins = []string{Common.ScanMode}
		}

		// 验证插件是否存在，不做Web类型过滤
		var validPlugins []string
		for _, name := range requestedPlugins {
			if _, exists := Common.PluginManager[name]; exists {
				validPlugins = append(validPlugins, name)
			}
		}

		if len(validPlugins) > 0 {
			return validPlugins, true
		}
	}

	// 未指定或使用"all"：获取所有插件，由IsPluginApplicable做类型过滤
	return GetAllPlugins(), false
}

// LogPluginInfo 输出Web扫描插件信息
func (s *WebScanStrategy) LogPluginInfo() {
	allPlugins, isCustomMode := s.GetPlugins()

	// 如果是自定义模式，直接显示用户指定的插件
	if isCustomMode {
		Common.LogBase(fmt.Sprintf("Web扫描模式: 使用指定插件: %s", strings.Join(allPlugins, ", ")))
		return
	}

	// 在自动模式下，只显示Web类型的插件
	var applicablePlugins []string
	for _, pluginName := range allPlugins {
		plugin, exists := Common.PluginManager[pluginName]
		if exists && plugin.HasType(Common.PluginTypeWeb) {
			applicablePlugins = append(applicablePlugins, pluginName)
		}
	}

	if len(applicablePlugins) > 0 {
		Common.LogBase(fmt.Sprintf("Web扫描模式: 使用Web插件: %s", strings.Join(applicablePlugins, ", ")))
	} else {
		Common.LogBase("Web扫描模式: 未找到可用的Web插件")
	}
}

// IsPluginApplicable 判断插件是否适用于Web扫描
func (s *WebScanStrategy) IsPluginApplicable(plugin Common.ScanPlugin, targetPort int, isCustomMode bool) bool {
	// 自定义模式下运行所有明确指定的插件
	if isCustomMode {
		return true
	}
	// 非自定义模式下，只运行Web类型插件
	return plugin.HasType(Common.PluginTypeWeb)
}
