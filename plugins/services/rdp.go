//go:build plugin_rdp || !plugin_selective

package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/mylib/grdp/glog"
	"github.com/shadow1ng/fscan/mylib/grdp/login"
	"github.com/shadow1ng/fscan/mylib/grdp/protocol/x224"
	"github.com/shadow1ng/fscan/plugins"
)

// RDPPlugin RDP远程桌面服务扫描插件 - 真实RDP认证和系统指纹识别
type RDPPlugin struct {
	plugins.BasePlugin
}

// NewRDPPlugin 创建RDP插件
func NewRDPPlugin() *RDPPlugin {
	return &RDPPlugin{
		BasePlugin: plugins.NewBasePlugin("rdp"),
	}
}

// Scan 执行RDP扫描 - 系统指纹识别 + 真实暴力破解
func (p *RDPPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	target := info.Target()

	// 配置grdp日志级别
	login.LogLever = glog.NONE // 静默模式，避免干扰输出

	// 配置代理
	if config.Network.Socks5Proxy != "" {
		login.Socks5Proxy = config.Network.Socks5Proxy
	}

	// 生成测试凭据（提前生成，用于判断是否为单一凭据测试）
	credentials := GenerateCredentials("rdp", config)

	// 判断是否为单一凭据测试模式（只有1个凭据时跳过指纹识别）
	isSingleCredentialTest := len(credentials) == 1

	var osInfo map[string]any

	// ============================================
	// 第一阶段：系统指纹识别（无需密码）
	// 单一凭据测试时跳过此阶段，减少连接次数
	// ============================================
	if !isSingleCredentialTest {
		osInfo = p.probeOSInfo(target, config, state)
		if len(osInfo) > 0 {
			p.logOSInfo(target, osInfo)
		}
	}

	// ============================================
	// 第二阶段：暴力破解
	// ============================================
	if config.DisableBrute {
		// 禁用暴力破解，仅返回服务识别结果
		if osInfo == nil {
			osInfo = p.probeOSInfo(target, config, state)
			if len(osInfo) > 0 {
				p.logOSInfo(target, osInfo)
			}
		}
		banner := p.buildBanner(osInfo)
		common.LogSuccess(i18n.Tr("rdp_service", target, banner))
		return &ScanResult{
			Success: true,
				Type:     plugins.ResultTypeService,
			Service: "rdp",
			Banner:  banner,
		}
	}
	if len(credentials) == 0 {
		credentials = []Credential{
			{Username: "administrator", Password: ""},
			{Username: "administrator", Password: "administrator"},
			{Username: "administrator", Password: "password"},
			{Username: "administrator", Password: "123456"},
			{Username: "admin", Password: "admin"},
			{Username: "admin", Password: "123456"},
			{Username: "user", Password: "user"},
			{Username: "test", Password: "test"},
		}
	}

	// 获取域名
	domain := config.Credentials.Domain
	if domain == "" {
		// 尝试从OSInfo中提取域名
		if osInfo != nil {
			if val, ok := osInfo["NetBIOSDomainName"].(string); ok && val != "" {
				domain = val
			}
		}
	}

	// 逐个测试凭据
	for _, cred := range credentials {
		// 检查Context是否被取消
		select {
		case <-ctx.Done():
			return &ScanResult{
				Success: false,
				Service: "rdp",
				Error:   ctx.Err(),
			}
		default:
		}

		// 真实RDP认证
		success, err := p.rdpCrack(target, domain, cred.Username, cred.Password, config, state)
		if success {
			displayDomain := domain
			if displayDomain == "" {
				displayDomain = "WORKGROUP"
			}

			result := fmt.Sprintf("RDP %s %s\\%s %s", target, displayDomain, cred.Username, cred.Password)
			common.LogVuln(result)

			return &ScanResult{
				Success:  true,
					Type:     plugins.ResultTypeCredential,
				Service:  "rdp",
				Username: cred.Username,
				Password: cred.Password,
				Banner:   p.buildBanner(osInfo),
			}
		}

		// 记录失败（仅调试时）
		if err != nil && strings.Contains(err.Error(), "dial err") {
			// 端口未开放，直接返回
			return &ScanResult{
				Success: false,
				Service: "rdp",
				Error:   fmt.Errorf("RDP端口未开放"),
			}
		}
	}

	// 所有凭据都失败
	return &ScanResult{
		Success: false,
		Service: "rdp",
		Error:   fmt.Errorf("RDP认证失败"),
	}
}

// rdpCrack 使用NLA认证验证凭据，不建立完整会话，不会挤掉已登录用户
func (p *RDPPlugin) rdpCrack(host, domain, user, password string, config *common.Config, state *common.State) (bool, error) {
	timeout := int64(config.Timeout.Seconds())

	// 使用NLA仅验证模式：只验证凭据，不建立RDP会话
	// 这样不会挤掉目标机器上已登录的用户
	success, err := login.NlaAuth(host, domain, user, password, timeout)
	if success {
		state.IncrementTCPSuccessPacketCount()
		return true, nil
	}

	if err != nil && strings.Contains(err.Error(), "dial err") {
		state.IncrementTCPFailedPacketCount()
		return false, err
	}

	state.IncrementTCPFailedPacketCount()
	return false, err
}

// probeOSInfo 通过NLA协商获取系统信息（无需密码）
func (p *RDPPlugin) probeOSInfo(host string, config *common.Config, state *common.State) map[string]any {
	timeout := int64(config.Timeout.Seconds())
	client := login.NewClient(host, glog.NONE)

	// 使用 PROTOCOL_HYBRID 协议探测系统信息
	// NLA握手阶段会返回系统信息，无需完整认证
	osInfo := client.ProbeOSInfo(host, "", "", "", timeout, x224.PROTOCOL_HYBRID)

	if len(osInfo) > 0 {
		state.IncrementTCPSuccessPacketCount()
	} else {
		state.IncrementTCPFailedPacketCount()
	}

	return osInfo
}

// logOSInfo 输出系统信息
func (p *RDPPlugin) logOSInfo(target string, osInfo map[string]any) {
	var parts []string

	// 提取关键信息
	hostname := p.extractStringField(osInfo, "NetBIOSComputerName")
	dnsDomain := p.extractStringField(osInfo, "DNSDomainName")
	fqdn := p.extractStringField(osInfo, "FQDN")
	netbiosDomain := p.extractStringField(osInfo, "NetBIOSDomainName")
	productVersion := p.extractStringField(osInfo, "ProductVersion")
	osVersion := p.extractStringField(osInfo, "OsVerion")

	// 检查是否获取到有效信息
	if hostname == "" && dnsDomain == "" && fqdn == "" && netbiosDomain == "" && productVersion == "" && osVersion == "" {
		return
	}

	// 构造输出
	if osVersion != "" {
		parts = append(parts, fmt.Sprintf("OS:%s", osVersion))
	}
	if productVersion != "" {
		parts = append(parts, fmt.Sprintf("Build:Windows %s", productVersion))
	}
	if hostname != "" {
		parts = append(parts, fmt.Sprintf("Hostname:%s", hostname))
	}
	if dnsDomain != "" {
		parts = append(parts, fmt.Sprintf("DNSDomain:%s", dnsDomain))
	}
	if fqdn != "" {
		parts = append(parts, fmt.Sprintf("FQDN:%s", fqdn))
	}
	if netbiosDomain != "" {
		parts = append(parts, fmt.Sprintf("NetBIOSDomain:%s", netbiosDomain))
	}

	if len(parts) > 0 {
		info := fmt.Sprintf("RDP %s [%s]", target, strings.Join(parts, ", "))
		common.LogSuccess(info)
	}
}

// buildBanner 构建服务识别Banner
func (p *RDPPlugin) buildBanner(osInfo map[string]any) string {
	if len(osInfo) == 0 {
		return "RDP远程桌面服务"
	}

	osVersion := p.extractStringField(osInfo, "OsVerion")
	hostname := p.extractStringField(osInfo, "NetBIOSComputerName")

	if osVersion != "" && hostname != "" {
		return fmt.Sprintf("RDP (%s, %s)", osVersion, hostname)
	} else if osVersion != "" {
		return fmt.Sprintf("RDP (%s)", osVersion)
	} else if hostname != "" {
		return fmt.Sprintf("RDP (Hostname:%s)", hostname)
	}

	return "RDP远程桌面服务"
}

// extractStringField 安全提取字符串字段
func (p *RDPPlugin) extractStringField(osInfo map[string]any, key string) string {
	if value, exists := osInfo[key]; exists {
		if strValue, ok := value.(string); ok {
			return strValue
		}
	}
	return ""
}

// init 自动注册插件
func init() {
	// 使用高效注册方式：直接传递端口信息，避免实例创建
	RegisterPluginWithPorts("rdp", func() Plugin {
		return NewRDPPlugin()
	}, []int{3389})
}
