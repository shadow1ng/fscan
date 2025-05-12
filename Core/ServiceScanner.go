package Core

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"sync"
)

// ServiceScanStrategy 服务扫描策略
type ServiceScanStrategy struct{}

// NewServiceScanStrategy 创建新的服务扫描策略
func NewServiceScanStrategy() *ServiceScanStrategy {
	return &ServiceScanStrategy{}
}

// Name 返回策略名称
func (s *ServiceScanStrategy) Name() string {
	return "服务扫描"
}

// Description 返回策略描述
func (s *ServiceScanStrategy) Description() string {
	return "扫描主机服务和漏洞"
}

// Execute 执行服务扫描策略
func (s *ServiceScanStrategy) Execute(info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
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

	Common.LogBase("开始主机扫描")

	// 输出插件信息
	s.LogPluginInfo()

	// 执行主机扫描流程
	s.performHostScan(hosts, info, ch, wg)
}

// performHostScan 执行主机扫描的完整流程
func (s *ServiceScanStrategy) performHostScan(hosts []string, info Common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	var targetInfos []Common.HostInfo

	// 主机存活性检测和端口扫描
	if len(hosts) > 0 || len(Common.HostPort) > 0 {
		// 主机存活检测
		if s.shouldPerformLivenessCheck(hosts) {
			hosts = CheckLive(hosts, Common.UsePing)
			Common.LogBase(fmt.Sprintf("存活主机数量: %d", len(hosts)))
		}

		// 端口扫描
		alivePorts := s.discoverAlivePorts(hosts)
		if len(alivePorts) > 0 {
			targetInfos = s.convertToTargetInfos(alivePorts, info)
		}
	}

	// 执行漏洞扫描
	if len(targetInfos) > 0 {
		Common.LogBase("开始漏洞扫描")
		ExecuteScanTasks(targetInfos, s, ch, wg)
	}
}

// shouldPerformLivenessCheck 判断是否需要执行存活性检测
func (s *ServiceScanStrategy) shouldPerformLivenessCheck(hosts []string) bool {
	return Common.DisablePing == false && len(hosts) > 1
}

// discoverAlivePorts 发现存活的端口
func (s *ServiceScanStrategy) discoverAlivePorts(hosts []string) []string {
	var alivePorts []string

	// 根据扫描模式选择端口扫描方式
	if len(hosts) > 0 {
		alivePorts = EnhancedPortScan(hosts, Common.Ports, Common.Timeout)
		Common.LogBase(fmt.Sprintf("存活端口数量: %d", len(alivePorts)))
	}

	// 合并额外指定的端口
	if len(Common.HostPort) > 0 {
		alivePorts = append(alivePorts, Common.HostPort...)
		alivePorts = Common.RemoveDuplicate(alivePorts)
		Common.HostPort = nil
		Common.LogBase(fmt.Sprintf("存活端口数量: %d", len(alivePorts)))
	}

	return alivePorts
}

// PrepareTargets 准备目标信息
func (s *ServiceScanStrategy) PrepareTargets(info Common.HostInfo) []Common.HostInfo {
	// 解析目标主机
	hosts, err := Common.ParseIP(info.Host, Common.HostsFile, Common.ExcludeHosts)
	if err != nil {
		Common.LogError(fmt.Sprintf("解析主机错误: %v", err))
		return nil
	}

	var targetInfos []Common.HostInfo

	// 主机存活性检测和端口扫描
	if len(hosts) > 0 || len(Common.HostPort) > 0 {
		// 主机存活检测
		if s.shouldPerformLivenessCheck(hosts) {
			hosts = CheckLive(hosts, Common.UsePing)
		}

		// 端口扫描
		alivePorts := s.discoverAlivePorts(hosts)
		if len(alivePorts) > 0 {
			targetInfos = s.convertToTargetInfos(alivePorts, info)
		}
	}

	return targetInfos
}

// convertToTargetInfos 将端口列表转换为目标信息
func (s *ServiceScanStrategy) convertToTargetInfos(ports []string, baseInfo Common.HostInfo) []Common.HostInfo {
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

// GetPlugins 获取服务扫描插件列表
func (s *ServiceScanStrategy) GetPlugins() ([]string, bool) {
	// 如果指定了插件列表且不是"all"
	if Common.ScanMode != "" && Common.ScanMode != "all" {
		plugins := parsePluginList(Common.ScanMode)
		if len(plugins) > 0 {
			return plugins, true
		}
		return []string{Common.ScanMode}, true
	}

	// 未指定或使用"all"：获取所有插件，由IsPluginApplicable做类型过滤
	return GetAllPlugins(), false
}

// LogPluginInfo 输出服务扫描插件信息
func (s *ServiceScanStrategy) LogPluginInfo() {
	allPlugins, isCustomMode := s.GetPlugins()

	// 如果是自定义模式，直接显示用户指定的插件
	if isCustomMode {
		Common.LogBase(fmt.Sprintf("使用指定插件: %s", strings.Join(allPlugins, ", ")))
		return
	}

	// 在自动模式下，过滤掉本地插件，只显示服务类型插件
	var applicablePlugins []string
	for _, pluginName := range allPlugins {
		plugin, exists := Common.PluginManager[pluginName]
		if exists && !plugin.HasType(Common.PluginTypeLocal) {
			applicablePlugins = append(applicablePlugins, pluginName)
		}
	}

	if len(applicablePlugins) > 0 {
		Common.LogBase(fmt.Sprintf("使用服务插件: %s", strings.Join(applicablePlugins, ", ")))
	} else {
		Common.LogBase("未找到可用的服务插件")
	}
}

// IsPluginApplicable 判断插件是否适用于服务扫描
func (s *ServiceScanStrategy) IsPluginApplicable(plugin Common.ScanPlugin, targetPort int, isCustomMode bool) bool {
	// 自定义模式下运行所有明确指定的插件
	if isCustomMode {
		return true
	}

	// 非自定义模式下，排除本地插件
	if plugin.HasType(Common.PluginTypeLocal) {
		return false
	}

	// 检查端口是否匹配
	if len(plugin.Ports) > 0 && targetPort > 0 {
		return plugin.HasPort(targetPort)
	}

	// 无端口限制的插件或适用于服务扫描的插件
	return len(plugin.Ports) == 0 || plugin.HasType(Common.PluginTypeService)
}
