//go:build plugin_smb || !plugin_selective

package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// SmbPlugin 统一SMB检测插件
// 融合了原有的 smb, smb2, smbinfo, smbghost 四个插件
type SmbPlugin struct {
	plugins.BasePlugin
}

func NewSmbPlugin() *SmbPlugin {
	return &SmbPlugin{
		BasePlugin: plugins.NewBasePlugin("smb"),
	}
}

func (p *SmbPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *plugins.Result {
	config := session.Config
	state := session.State
	target := info.Target()

	// 检查端口
	if info.Port != 445 && info.Port != 139 {
		return &ScanResult{
			Success: false,
			Service: "smb",
			Error:   fmt.Errorf("SMB插件仅支持139和445端口"),
		}
	}

	// 1. 协议探测和信息收集
	smbTarget, err := probeTarget(ctx, info.Host, info.Port, config.Timeout, session)
	if err != nil {
		return &ScanResult{
			Success: false,
			Service: "smb",
			Error:   fmt.Errorf("SMB协议探测失败: %w", err),
		}
	}

	// 输出信息收集结果
	p.logSMBInfo(target, smbTarget)

	// 2. 漏洞检测 (仅SMBv2+且端口445)
	if smbTarget.Protocol == SMBProtocol2 && info.Port == 445 {
		if checkSMBGhost(ctx, info.Host, config.Timeout, session) {
			smbTarget.Vulnerable = &SMBVuln{CVE20200796: true}
			common.LogVuln(i18n.Tr("smbghost_vuln", target))
		}
	}

	// 如果禁用暴力破解，只返回信息收集结果
	if config.DisableBrute {
		return p.buildInfoResult(smbTarget)
	}

	// 3. 根据协议版本选择认证器
	auth := p.getAuthenticator(smbTarget.Protocol)

	// 4. 未授权访问检测
	if result := p.testUnauthorizedAccess(ctx, info, auth, config, state, session); result != nil && result.Success {
		var successMsg string
		if config.Credentials.Domain != "" {
			successMsg = fmt.Sprintf("SMB %s 未授权访问 - %s\\%s:%s", target, config.Credentials.Domain, result.Username, result.Password)
		} else {
			successMsg = fmt.Sprintf("SMB %s 未授权访问 - %s:%s", target, result.Username, result.Password)
		}
		common.LogVuln(successMsg)
		return result
	}

	// 5. 弱密码检测
	credentials := plugins.GenerateCredentials("smb", config)
	if len(credentials) == 0 {
		return p.buildInfoResult(smbTarget)
	}

	creds := make([]Credential, len(credentials))
	for i, c := range credentials {
		creds[i] = Credential{Username: c.Username, Password: c.Password}
	}

	authFn := p.createAuthFunc(info, auth, session)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, creds, authFn, "smb", testConfig)

	if result.Success {
		var successMsg string
		if config.Credentials.Domain != "" {
			successMsg = fmt.Sprintf("SMB %s %s\\%s:%s", target, config.Credentials.Domain, result.Username, result.Password)
		} else {
			successMsg = fmt.Sprintf("SMB %s %s:%s", target, result.Username, result.Password)
		}
		common.LogVuln(successMsg)
	}

	return result
}

// getAuthenticator 根据协议版本返回认证器
func (p *SmbPlugin) getAuthenticator(protocol SMBProtocol) SMBAuthenticator {
	if protocol == SMBProtocol1 {
		return &SMB1Authenticator{}
	}
	return &SMB2Authenticator{}
}

// createAuthFunc 创建认证函数
func (p *SmbPlugin) createAuthFunc(info *common.HostInfo, auth SMBAuthenticator, session *common.ScanSession) AuthFunc {
	config := session.Config
	return func(ctx context.Context, cred Credential) *AuthResult {
		result, _ := auth.Authenticate(ctx, info.Host, info.Port, cred, config.Credentials.Domain, config.Timeout, session)
		return result
	}
}

// testUnauthorizedAccess 测试未授权访问
func (p *SmbPlugin) testUnauthorizedAccess(ctx context.Context, info *common.HostInfo, auth SMBAuthenticator, config *common.Config, state *common.State, session *common.ScanSession) *ScanResult {
	target := info.Target()

	unauthorizedCreds := []Credential{
		{Username: "", Password: ""},
		{Username: "guest", Password: ""},
		{Username: "anonymous", Password: ""},
	}

	for _, cred := range unauthorizedCreds {
		shareInfo, err := auth.ListShares(ctx, info.Host, info.Port, cred, config.Credentials.Domain, config.Timeout, session)
		if err == nil && len(shareInfo) > 0 {
			var output strings.Builder
			displayUser := cred.Username
			if displayUser == "" {
				displayUser = "<empty>"
			}
			output.WriteString(fmt.Sprintf("SMB %s 匿名访问 - %s:%s", target, displayUser, cred.Password))
			for _, share := range shareInfo {
				output.WriteString(fmt.Sprintf("\n%s", share))
			}

			common.LogSuccess(output.String())

			return &ScanResult{
				Success:  true,
				Type:     plugins.ResultTypeCredential,
				Service:  "smb",
				Username: cred.Username,
				Password: cred.Password,
				Banner:   "SMB匿名访问",
			}
		}
	}

	return nil
}

// logSMBInfo 输出SMB信息
func (p *SmbPlugin) logSMBInfo(target string, info *SMBTarget) {
	msg := fmt.Sprintf("SMBInfo %s", target)
	if info.OSVersion != "" {
		msg += fmt.Sprintf(" [%s]", info.OSVersion)
	}
	if info.ComputerName != "" {
		msg += fmt.Sprintf(" %s", info.ComputerName)
	}
	msg += fmt.Sprintf(" %s", info.Protocol.String())
	common.LogSuccess(msg)
}

// buildInfoResult 构建信息收集结果
func (p *SmbPlugin) buildInfoResult(info *SMBTarget) *ScanResult {
	result := &ScanResult{
		Success: true,
		Type:    plugins.ResultTypeService,
		Service: "smb",
		Banner:  info.Summary(),
	}

	// 如果发现漏洞，标记为漏洞类型
	if info.Vulnerable != nil && info.Vulnerable.CVE20200796 {
		result.Type = plugins.ResultTypeVuln
		result.Banner = fmt.Sprintf("%s CVE-2020-0796", info.Summary())
	}

	return result
}

func init() {
	RegisterPluginWithPorts("smb", func() Plugin {
		return NewSmbPlugin()
	}, []int{139, 445})
}
