//go:build plugin_mssql || !plugin_selective

package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// MSSQLPlugin MSSQL扫描插件
type MSSQLPlugin struct {
	plugins.BasePlugin
}

func NewMSSQLPlugin() *MSSQLPlugin {
	return &MSSQLPlugin{
		BasePlugin: plugins.NewBasePlugin("mssql"),
	}
}

func (p *MSSQLPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	if config.DisableBrute {
		return p.identifyService(ctx, info, session)
	}

	target := info.Target()

	credentials := GenerateCredentials("mssql", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "mssql",
			Error:   fmt.Errorf("%s", i18n.GetText("service_no_credentials")),
		}
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "mssql", testConfig)

	if result.Success {
		session.LogVuln(i18n.Tr("mssql_credential", target, result.Username, result.Password))
	}

	return result
}

// createAuthFunc 创建MSSQL认证函数
func (p *MSSQLPlugin) createAuthFunc(info *common.HostInfo, config *common.Config, state *common.State) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doMSSQLAuth(ctx, info, cred, config, state)
	}
}

// doMSSQLAuth 执行MSSQL认证
func (p *MSSQLPlugin) doMSSQLAuth(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) *AuthResult {
	authCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	_, err := mssqlRawLogin(authCtx, info.Host, info.Port, cred.Username, cred.Password, config.Timeout)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{
			Success:   false,
			ErrorType: classifyMSSQLErrorType(err),
			Error:     err,
		}
	}

	state.IncrementTCPSuccessPacketCount()

	return &AuthResult{
		Success:   true,
		ErrorType: ErrorTypeUnknown,
		Error:     nil,
	}
}

// classifyMSSQLErrorType MSSQL错误分类
func classifyMSSQLErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	mssqlAuthErrors := []string{
		"login failed",
		"password incorrect",
		"authentication failed",
		"invalid credentials",
		"access denied",
		"invalid login",
		"invalid user",
		"invalid password",
		"bad login",
		"authentication failure",
		"login error",
		"credential",
		"user login failed",
		"logon failure",
		"account locked",
		"user not found",
		"invalid account",
	}

	mssqlNetworkErrors := append(CommonNetworkErrors,
		"dial tcp",
		"connection closed",
		"eof",
		"network error",
		"context deadline exceeded",
		"server closed the connection",
		"connection lost",
	)

	return ClassifyError(err, mssqlAuthErrors, mssqlNetworkErrors)
}

func (p *MSSQLPlugin) identifyService(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	target := info.Target()

	identifyCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	result, err := mssqlRawLogin(identifyCtx, info.Host, info.Port, "invalid", "invalid", config.Timeout)

	if err != nil {
		state.IncrementTCPFailedPacketCount()
	} else {
		state.IncrementTCPSuccessPacketCount()
	}

	var banner string
	errLower := ""
	if err != nil {
		errLower = strings.ToLower(err.Error())
	}

	if err == nil || (result != nil && result.isMSSQL()) ||
		(strings.Contains(errLower, "login failed") ||
			strings.Contains(errLower, "mssql") ||
			strings.Contains(errLower, "sql server")) {
		banner = "MSSQL"
	} else {
		return &ScanResult{
			Success: false,
			Service: "mssql",
			Error:   fmt.Errorf("%s", i18n.Tr("service_not_identified", "MSSQL")),
		}
	}

	session.LogSuccess(i18n.Tr("mssql_service", target, banner))

	return &ScanResult{
		Type:    plugins.ResultTypeService,
		Success: true,
		Service: "mssql",
		Banner:  banner,
	}
}

func init() {
	RegisterPluginWithPorts("mssql", func() Plugin {
		return NewMSSQLPlugin()
	}, []int{1433, 1434})
}
