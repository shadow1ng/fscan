//go:build plugin_oracle || !plugin_selective

package services

import (
	"context"
	"fmt"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// OraclePlugin Oracle扫描插件
type OraclePlugin struct {
	plugins.BasePlugin
}

func NewOraclePlugin() *OraclePlugin {
	return &OraclePlugin{
		BasePlugin: plugins.NewBasePlugin("oracle"),
	}
}

func (p *OraclePlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	target := info.Target()

	if config.DisableBrute {
		return p.identifyService(ctx, info, session)
	}

	// 先测试未授权访问
	if result := p.testUnauthorizedAccess(ctx, info, session); result != nil && result.Success {
		session.LogSuccess(i18n.Tr("oracle_service", target, result.Banner))
		return result
	}

	credentials := GenerateCredentials("oracle", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "oracle",
			Error:   fmt.Errorf("%s", i18n.GetText("service_no_credentials")),
		}
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "oracle", testConfig)

	if result.Success {
		session.LogVuln(i18n.Tr("oracle_credential", target, result.Username, result.Password))
	}

	return result
}

// createAuthFunc 创建Oracle认证函数
func (p *OraclePlugin) createAuthFunc(info *common.HostInfo, config *common.Config, state *common.State) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doOracleAuth(ctx, info, cred, config, state)
	}
}

// doOracleAuth 执行Oracle认证
func (p *OraclePlugin) doOracleAuth(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) *AuthResult {
	target := info.Target()
	serviceNames := []string{"ORCL", "XE", "XEPDB1", target}

	for _, serviceName := range serviceNames {
		connectCtx, cancel := context.WithTimeout(ctx, config.ModuleTimeout())
		err := oracleRawAuth(connectCtx, info.Host, info.Port, serviceName, cred.Username, cred.Password, config.ModuleTimeout())
		if err != nil {
			cancel()
			errorType := classifyOracleErrorType(err)
			if errorType == ErrorTypeAuth {
				return &AuthResult{
					Success:   false,
					ErrorType: errorType,
					Error:     err,
				}
			}
			continue
		}

		cancel()
		state.IncrementTCPSuccessPacketCount()

		return &AuthResult{
			Success:   true,
			ErrorType: ErrorTypeUnknown,
			Error:     nil,
		}
	}

	state.IncrementTCPFailedPacketCount()
	return &AuthResult{
		Success:   false,
		ErrorType: ErrorTypeNetwork,
		Error:     fmt.Errorf("%s", i18n.GetText("oracle_connect_failed")),
	}
}

// classifyOracleErrorType Oracle错误分类
func classifyOracleErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	oracleAuthErrors := []string{
		"invalid username/password",
		"logon denied",
		"ora-01017",
		"ora-01045",
		"ora-28000",
		"ora-28001",
		"authentication failed",
		"permission denied",
		"access denied",
	}

	oracleNetworkErrors := append(CommonNetworkErrors,
		"tns-12541", "tns-12514", "tns-12505",
		"ora-12170", "ora-12154", "ora-12537",
		"ora-03135", "ora-03113",
	)

	return ClassifyError(err, oracleAuthErrors, oracleNetworkErrors)
}

// testUnauthorizedAccess 测试Oracle未授权访问
func (p *OraclePlugin) testUnauthorizedAccess(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	target := info.Target()

	defaultAccounts := []Credential{
		{Username: "scott", Password: "tiger"},
		{Username: "sys", Password: "sys"},
		{Username: "system", Password: "manager"},
	}

	for _, cred := range defaultAccounts {
		result := p.doOracleAuth(ctx, info, cred, config, state)
		if result.Success {
			if result.Conn != nil {
				_ = result.Conn.Close()
			}
			session.LogVuln(i18n.Tr("oracle_default_account", target, cred.Username, cred.Password))
			return &ScanResult{
				Type:     plugins.ResultTypeVuln,
				Success:  true,
				Service:  "oracle",
				Username: cred.Username,
				Password: cred.Password,
				Banner:   i18n.GetText("oracle_default_account_banner"),
			}
		}
	}

	return nil
}

func (p *OraclePlugin) identifyService(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	target := info.Target()

	conn, err := session.DialTCP(ctx, "tcp", target, session.Config.ModuleTimeout())
	if err != nil {
		return &ScanResult{
			Success: false,
			Service: "oracle",
			Error:   err,
		}
	}
	_ = conn.Close()

	banner := "Oracle"
	session.LogSuccess(i18n.Tr("oracle_service", target, banner))

	return &ScanResult{
		Type:    plugins.ResultTypeService,
		Success: true,
		Service: "oracle",
		Banner:  banner,
	}
}

func init() {
	RegisterPluginWithPorts("oracle", func() Plugin {
		return NewOraclePlugin()
	}, []int{1521, 1522, 1525})
}
