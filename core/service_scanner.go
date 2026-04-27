package core

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/common/parsers"
)

// ServiceScanStrategy 服务扫描策略
type ServiceScanStrategy struct {
	*BaseScanStrategy
}

// NewServiceScanStrategy 创建新的服务扫描策略
func NewServiceScanStrategy() *ServiceScanStrategy {
	return &ServiceScanStrategy{
		BaseScanStrategy: NewBaseScanStrategy("服务扫描", FilterService),
	}
}

// LogPluginInfo 重写以提供基于端口的插件过滤
func (s *ServiceScanStrategy) LogPluginInfo(config *common.Config) {
	// 需要从命令行参数获取端口信息来进行过滤
	// 如果没有指定端口，使用默认端口进行过滤显示
	ports := common.GetFlagVars().Ports
	if ports == "" || ports == "all" {
		// 默认端口扫描：显示所有插件
		s.BaseScanStrategy.LogPluginInfo(config)
	} else {
		// 指定端口扫描：只显示匹配的插件
		s.showPluginsForSpecifiedPorts(config)
	}
}

// showPluginsForSpecifiedPorts 显示指定端口的匹配插件
func (s *ServiceScanStrategy) showPluginsForSpecifiedPorts(config *common.Config) {
	allPlugins, isCustomMode := s.GetPlugins(config)

	// 解析端口
	ports := s.parsePortList(common.GetFlagVars().Ports)
	if len(ports) == 0 {
		s.BaseScanStrategy.LogPluginInfo(config)
		return
	}

	// 收集所有匹配的插件（去重）
	pluginSet := make(map[string]struct{}, len(allPlugins))
	for _, port := range ports {
		for _, pluginName := range allPlugins {
			if s.pluginExists(pluginName) {
				if s.isPluginApplicableToPort(pluginName, port) && s.isPluginPassesFilterType(pluginName, isCustomMode, config) {
					pluginSet[pluginName] = struct{}{}
				}
			}
		}
	}

	// 转换为列表
	var applicablePlugins []string
	for pluginName := range pluginSet {
		applicablePlugins = append(applicablePlugins, pluginName)
	}

	// 输出结果
	if len(applicablePlugins) > 0 {
		pluginStr := formatPluginList(applicablePlugins)
		if isCustomMode {
			common.LogInfo(i18n.Tr("service_plugin_custom", pluginStr))
		} else {
			common.LogInfo(i18n.Tr("service_plugin_info", pluginStr))
		}
	} else {
		common.LogInfo(i18n.GetText("service_plugin_none"))
	}
}

// parsePortList 解析端口列表
func (s *ServiceScanStrategy) parsePortList(portStr string) []int {
	if portStr == "" || portStr == "all" {
		return []int{}
	}

	ports := []int{} // 初始化为空切片而非nil
	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if port, err := strconv.Atoi(part); err == nil {
			// 验证端口范围 1-65535（与 scanner.go 的 parsePort 保持一致）
			if port >= 1 && port <= 65535 {
				ports = append(ports, port)
			} else {
				common.LogError(i18n.Tr("port_out_of_range", port))
			}
		}
	}
	return ports
}

// Name 返回策略名称
func (s *ServiceScanStrategy) Name() string {
	return i18n.GetText("scan_strategy_service_name")
}

// Description 返回策略描述
func (s *ServiceScanStrategy) Description() string {
	return i18n.GetText("scan_strategy_service_desc")
}

// Execute 执行服务扫描策略
func (s *ServiceScanStrategy) Execute(ctx context.Context, config *common.Config, state *common.State, info common.HostInfo, ch chan struct{}, wg *sync.WaitGroup) {
	// 验证扫描目标（需要同时检查 -h 和 -hf 参数）
	fv := common.GetFlagVars()
	if info.Host == "" && fv.HostsFile == "" {
		common.LogError(i18n.GetText("parse_error_target_empty"))
		return
	}

	// 输出扫描开始信息
	s.LogScanStart()

	// 验证插件配置
	if err := s.ValidateConfiguration(); err != nil {
		common.LogError(err.Error())
		return
	}

	// 输出插件信息（重写以提供端口过滤）
	s.LogPluginInfo(config)

	// 执行主机扫描流程
	s.performHostScan(ctx, config, state, info, ch, wg)
}

// performHostScan 执行主机扫描的完整流程
func (s *ServiceScanStrategy) performHostScan(ctx context.Context, config *common.Config, state *common.State, info common.HostInfo, ch chan struct{}, wg *sync.WaitGroup) {
	// 发现目标主机和端口
	targetInfos, err := s.discoverTargets(info.Host, info, config, state)
	if err != nil {
		common.LogError(err.Error())
		return
	}

	// 执行漏洞扫描
	if len(targetInfos) > 0 {
		ExecuteScanTasks(ctx, config, state, targetInfos, s, ch, wg)
	}
}

// PrepareTargets 准备目标信息
func (s *ServiceScanStrategy) PrepareTargets(info common.HostInfo, config *common.Config, state *common.State) []common.HostInfo {
	// 发现目标主机和端口
	targetInfos, err := s.discoverTargets(info.Host, info, config, state)
	if err != nil {
		common.LogError(err.Error())
		return nil
	}
	return targetInfos
}

// LogVulnerabilityPluginInfo 输出服务扫描插件信息
func (s *ServiceScanStrategy) LogVulnerabilityPluginInfo(targets []common.HostInfo, config *common.Config) {
	allPlugins, isCustomMode := s.GetPlugins(config)

	// 获取实际会被使用的插件列表
	servicePluginSet := make(map[string]struct{}, len(allPlugins))

	for _, pluginName := range allPlugins {
		// 使用统一插件系统检查插件存在性
		if !s.pluginExists(pluginName) {
			continue
		}

		// 检查插件是否通过过滤器类型检查
		if !s.isPluginPassesFilterType(pluginName, isCustomMode, config) {
			continue
		}

		// 检查插件是否适用于任意一个目标
		for _, target := range targets {
			if target.Port == 0 {
				continue
			}

			// 使用 host:port 信息检查插件适用性（Web插件需要host信息）
			if s.isPluginApplicableToPortWithHost(pluginName, target.Host, target.Port) {
				servicePluginSet[pluginName] = struct{}{}
				break // 只要适用于一个目标就添加
			}
		}
	}

	// 转换为切片
	var servicePlugins []string
	for pluginName := range servicePluginSet {
		servicePlugins = append(servicePlugins, pluginName)
	}

	// 输出插件信息
	if len(servicePlugins) > 0 {
		common.LogInfo(i18n.Tr("service_plugin_info", strings.Join(servicePlugins, ", ")))
	} else {
		common.LogInfo(i18n.GetText("scan_no_service_plugins"))
	}
}

// =============================================================================
// 端口发现功能（从 PortDiscoveryService 合并）
// =============================================================================

// discoverTargets 发现目标主机和端口
func (s *ServiceScanStrategy) discoverTargets(hostInput string, baseInfo common.HostInfo, config *common.Config, state *common.State) ([]common.HostInfo, error) {
	// 标准流程：解析目标主机
	fv := common.GetFlagVars()
	hosts, err := parsers.ParseIP(hostInput, fv.HostsFile, fv.ExcludeHosts)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.GetText("parse_target_failed"), err)
	}

	var targetInfos []common.HostInfo

	// 主机存活性检测和端口扫描
	if len(hosts) > 0 || len(state.GetHostPorts()) > 0 {
		// 主机存活检测
		if s.shouldPerformLivenessCheck(hosts, config) {
			hosts = CheckLive(hosts, false, config, state)
			common.LogInfo(i18n.Tr("alive_hosts_count_info", len(hosts)))
		}

		// 端口扫描
		alivePorts := s.discoverAlivePorts(hosts, config, state)
		if len(alivePorts) > 0 {
			targetInfos = s.convertToTargetInfos(alivePorts, baseInfo)
		}
	}

	return targetInfos, nil
}

// shouldPerformLivenessCheck 判断是否需要执行存活性检测
func (s *ServiceScanStrategy) shouldPerformLivenessCheck(hosts []string, config *common.Config) bool {
	return !config.DisablePing && len(hosts) > 1
}

// discoverAlivePorts 发现存活的端口
func (s *ServiceScanStrategy) discoverAlivePorts(hosts []string, config *common.Config, state *common.State) []string {
	var alivePorts []string

	// 如果已经有明确指定的host:port，直接使用（让后续SmartIdentify统一验证和识别）
	hostPorts := state.GetHostPorts()
	if len(hostPorts) > 0 {
		alivePorts = hostPorts
		common.LogInfo(i18n.Tr("alive_ports_count", len(alivePorts)))
		state.ClearHostPorts()
		return alivePorts
	}

	// 根据扫描模式选择端口扫描方式
	if len(hosts) > 0 {
		alivePorts = EnhancedPortScan(hosts, config.Target.Ports, int64(config.Timeout.Seconds()), config, state)
	}

	return alivePorts
}

// convertToTargetInfos 将端口列表转换为目标信息
func (s *ServiceScanStrategy) convertToTargetInfos(ports []string, baseInfo common.HostInfo) []common.HostInfo {
	var infos []common.HostInfo

	for _, targetIP := range ports {
		hostParts := strings.Split(targetIP, ":")
		if len(hostParts) != 2 {
			common.LogError(i18n.Tr("invalid_target_format", targetIP))
			continue
		}

		// 去除空格并过滤空值
		host := strings.TrimSpace(hostParts[0])
		portStr := strings.TrimSpace(hostParts[1])
		if host == "" || portStr == "" {
			common.LogError(i18n.Tr("invalid_target_format", targetIP))
			continue
		}

		// 验证端口范围（与scanner.go中parsePort保持一致）
		port, err := strconv.Atoi(portStr)
		if err != nil {
			common.LogError(i18n.Tr("host_port_invalid", host, portStr))
			continue
		}
		if port < 1 || port > 65535 {
			common.LogError(i18n.Tr("host_port_out_of_range", host, port))
			continue
		}

		info := baseInfo
		info.Host = host
		info.Port = port
		// 深拷贝Info避免多个target共享slice底层数组
		if len(baseInfo.Info) > 0 {
			info.Info = append([]string(nil), baseInfo.Info...)
		}
		infos = append(infos, info)
	}

	return infos
}

