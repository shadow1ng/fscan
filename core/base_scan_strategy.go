package core

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// PluginFilterType 插件过滤类型
type PluginFilterType int

const (
	// FilterNone 不过滤
	FilterNone PluginFilterType = iota
	// FilterLocal 仅本地插件
	FilterLocal
	// FilterService 仅服务插件（排除本地）
	FilterService
	// FilterWeb 仅Web插件
	FilterWeb
)

// BaseScanStrategy 扫描策略基础类
type BaseScanStrategy struct {
	strategyName string
	filterType   PluginFilterType
}

// NewBaseScanStrategy 创建基础扫描策略
func NewBaseScanStrategy(name string, filterType PluginFilterType) *BaseScanStrategy {
	return &BaseScanStrategy{
		strategyName: name,
		filterType:   filterType,
	}
}

// GetPlugins 获取插件列表
func (b *BaseScanStrategy) GetPlugins(config *common.Config) ([]string, bool) {
	scanMode := config.Mode
	// 如果指定了特定插件且不是"all"
	if scanMode != "" && scanMode != "all" {
		requestedPlugins := parsePluginList(scanMode)
		if len(requestedPlugins) == 0 {
			requestedPlugins = []string{scanMode}
		}

		// 验证插件是否存在
		var validPlugins []string
		var missingPlugins []string
		for _, name := range requestedPlugins {
			if b.pluginExists(name) {
				validPlugins = append(validPlugins, name)
			} else {
				missingPlugins = append(missingPlugins, name)
			}
		}

		// 警告用户显式指定的插件不存在
		// 注意：使用fmt.Fprintf直接输出到stderr，确保错误消息不会被日志级别过滤
		for _, name := range missingPlugins {
			errMsg := i18n.Tr("scan_plugin_not_found", name)
			fmt.Fprintf(os.Stderr, "[ERROR] %s\n", errMsg)
		}

		return validPlugins, true
	}

	// 未指定或使用"all"：根据策略类型获取对应插件
	return b.getPluginsByFilterType(), false
}

// IsPluginApplicableByName 根据插件名称判断是否适用
func (b *BaseScanStrategy) IsPluginApplicableByName(pluginName string, targetHost string, targetPort int, isCustomMode bool, config *common.Config) bool {
	// 首先检查插件是否存在
	if !b.pluginExists(pluginName) {
		return false
	}

	// 显式指定插件时，尊重调用方选择，不再强制使用插件默认端口过滤。
	if isCustomMode {
		return b.isPluginPassesFilterType(pluginName, isCustomMode, config)
	}

	// 检查端口匹配和过滤器类型
	return b.isPluginApplicableToPortWithHost(pluginName, targetHost, targetPort) && b.isPluginPassesFilterType(pluginName, isCustomMode, config)
}

func (b *BaseScanStrategy) pluginExists(pluginName string) bool {
	return plugins.Exists(pluginName)
}

func (b *BaseScanStrategy) getPluginPorts(pluginName string) []int {
	return plugins.GetPluginPorts(pluginName)
}

func (b *BaseScanStrategy) isWebPlugin(pluginName string) bool {
	return plugins.HasType(pluginName, plugins.PluginTypeWeb)
}

func (b *BaseScanStrategy) isLocalPlugin(pluginName string) bool {
	return plugins.HasType(pluginName, plugins.PluginTypeLocal)
}

func (b *BaseScanStrategy) isUDPPlugin(pluginName string) bool {
	return plugins.IsUDP(pluginName)
}

func (b *BaseScanStrategy) isLocalPluginExplicitlySpecified(pluginName string, config *common.Config) bool {
	return config.LocalPlugin == pluginName
}

// isPluginApplicableToPortWithHost 检查插件是否适用于指定端口
func (b *BaseScanStrategy) isPluginApplicableToPortWithHost(pluginName string, targetHost string, targetPort int) bool {
	if b.isWebPlugin(pluginName) {
		return IsMarkedWebService(targetHost, targetPort)
	}

	pluginPorts := b.getPluginPorts(pluginName)

	// 无端口限制的插件适用于所有端口
	if len(pluginPorts) == 0 {
		return true
	}

	// 有端口限制的插件：检查端口匹配
	if targetPort > 0 {
		for _, port := range pluginPorts {
			if port == targetPort {
				return true
			}
		}
	}

	return false
}

func (b *BaseScanStrategy) isPluginApplicableToPort(pluginName string, targetPort int) bool {
	return b.isPluginApplicableToPortWithHost(pluginName, "", targetPort)
}

// isPluginPassesFilterType 检查插件是否通过过滤器类型检查
func (b *BaseScanStrategy) isPluginPassesFilterType(pluginName string, isCustomMode bool, config *common.Config) bool {
	// UDP 插件有独立分发路径，不参与 TCP 端口匹配流水线
	if b.isUDPPlugin(pluginName) {
		return false
	}

	// 自定义模式下强制运行所有明确指定的插件
	if isCustomMode {
		return true
	}

	// 应用过滤器类型检查
	switch b.filterType {
	case FilterLocal:
		// 本地扫描策略：只允许本地插件且必须通过-local参数明确指定
		if b.isLocalPlugin(pluginName) {
			return b.isLocalPluginExplicitlySpecified(pluginName, config)
		}
		return false
	case FilterService:
		// 服务扫描策略：排除本地插件和UDP插件（UDP有独立分发路径）
		return !b.isLocalPlugin(pluginName) && !b.isUDPPlugin(pluginName)
	case FilterWeb:
		// Web扫描策略：只允许Web插件
		return b.isWebPlugin(pluginName)
	default:
		// 无过滤器：本地插件需要明确指定，其他插件都允许
		if b.isLocalPlugin(pluginName) {
			return b.isLocalPluginExplicitlySpecified(pluginName, config)
		}
		return true
	}
}

// LogPluginInfo 输出插件信息
func (b *BaseScanStrategy) LogPluginInfo(config *common.Config, session *common.ScanSession) {
	allPlugins, isCustomMode := b.GetPlugins(config)

	var prefix string
	switch b.filterType {
	case FilterLocal:
		prefix = i18n.GetText("concurrency_local_plugin")
	case FilterService:
		prefix = i18n.GetText("concurrency_service_plugin")
	case FilterWeb:
		prefix = i18n.GetText("concurrency_web_plugin")
	default:
		prefix = i18n.GetText("concurrency_plugin")
	}

	// 插件信息不再输出，减少干扰
	_ = allPlugins
	_ = isCustomMode
	_ = prefix
	_ = session
}

// formatPluginList 格式化插件列表（超过5个时精简显示）
func formatPluginList(plugins []string) string {
	if len(plugins) <= 5 {
		return strings.Join(plugins, ", ")
	}
	return i18n.Tr("plugin_list_summary", strings.Join(plugins[:5], ", "), len(plugins))
}

// ValidateConfiguration 验证扫描配置
func (b *BaseScanStrategy) ValidateConfiguration() error {
	return nil
}

// LogScanStart 输出扫描开始信息（已精简，仅在非服务扫描模式下显示）
func (b *BaseScanStrategy) LogScanStart(session *common.ScanSession) {
	// 服务扫描模式下不显示（插件信息已足够说明）
	// 仅在本地/Web等特殊模式下显示
	switch b.filterType {
	case FilterLocal:
		session.LogInfo(i18n.GetText("start_local_scan"))
	case FilterWeb:
		session.LogInfo(i18n.GetText("start_web_scan"))
	}
}

// getPluginsByFilterType 根据过滤器类型获取插件列表
func (b *BaseScanStrategy) getPluginsByFilterType() []string {
	allPlugins := plugins.All()
	var filteredPlugins []string

	switch b.filterType {
	case FilterLocal:
		// 本地扫描策略：只返回本地插件
		for _, pluginName := range allPlugins {
			if b.isLocalPlugin(pluginName) {
				filteredPlugins = append(filteredPlugins, pluginName)
			}
		}
	case FilterService:
		// 服务扫描策略：排除本地插件和UDP插件，保留TCP服务插件
		for _, pluginName := range allPlugins {
			if !b.isLocalPlugin(pluginName) && !b.isUDPPlugin(pluginName) {
				filteredPlugins = append(filteredPlugins, pluginName)
			}
		}
	case FilterWeb:
		// Web扫描策略：只返回Web插件
		for _, pluginName := range allPlugins {
			if b.isWebPlugin(pluginName) {
				filteredPlugins = append(filteredPlugins, pluginName)
			}
		}
		// 确保 webtitle 在 webpoc 之前执行，避免指纹识别竞态
		sort.Slice(filteredPlugins, func(i, j int) bool {
			// webtitle 必须在 webpoc 之前
			if filteredPlugins[i] == "webtitle" {
				return true
			}
			if filteredPlugins[j] == "webtitle" {
				return false
			}
			if filteredPlugins[i] == "webpoc" {
				return false
			}
			if filteredPlugins[j] == "webpoc" {
				return true
			}
			// 其他插件保持字母顺序
			return filteredPlugins[i] < filteredPlugins[j]
		})
	default:
		// 无过滤器：返回所有插件
		filteredPlugins = allPlugins
	}

	return filteredPlugins
}

// parsePluginList 解析插件列表字符串
func parsePluginList(pluginStr string) []string {
	if pluginStr == "" {
		return []string{}
	}

	// 支持逗号分隔的插件列表
	plugins := strings.Split(pluginStr, ",")
	result := []string{} // 初始化为空切片而非nil
	for _, plugin := range plugins {
		plugin = strings.TrimSpace(plugin)
		if plugin != "" {
			result = append(result, plugin)
		}
	}
	return result
}
