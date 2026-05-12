//go:build plugin_mssql || !plugin_selective

package services

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/denisenkom/go-mssqldb" // MSSQL driver
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
		return p.identifyService(ctx, info, config, state)
	}

	target := info.Target()

	credentials := GenerateCredentials("mssql", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "mssql",
			Error:   fmt.Errorf("没有可用的测试凭据"),
		}
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "mssql", testConfig)

	if result.Success {
		common.LogVuln(i18n.Tr("mssql_credential", target, result.Username, result.Password))
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
	connStr := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%d;database=master;encrypt=disable;connection timeout=%d",
		info.Host, cred.Username, cred.Password, info.Port, int64(config.Timeout.Seconds()))

	db, err := sql.Open("mssql", connStr)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{
			Success:   false,
			ErrorType: classifyMSSQLErrorType(err),
			Error:     err,
		}
	}

	db.SetConnMaxLifetime(config.Timeout)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	pingCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	err = db.PingContext(pingCtx)
	if err != nil {
		_ = db.Close()
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
		Conn:      &SQLDBWrapper{db},
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

func (p *MSSQLPlugin) identifyService(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()

	connStr := fmt.Sprintf("server=%s;user id=invalid;password=invalid;port=%d;database=master;encrypt=disable;connection timeout=%d",
		info.Host, info.Port, int64(config.Timeout.Seconds()))

	db, err := sql.Open("mssql", connStr)
	if err != nil {
		return &ScanResult{
			Success: false,
			Service: "mssql",
			Error:   err,
		}
	}
	defer func() { _ = db.Close() }()

	pingCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	err = db.PingContext(pingCtx)

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

	if err != nil && (strings.Contains(errLower, "login failed") ||
		strings.Contains(errLower, "mssql") ||
		strings.Contains(errLower, "sql server")) {
		banner = "MSSQL"
	} else if err == nil {
		banner = "MSSQL"
	} else {
		return &ScanResult{
			Success: false,
			Service: "mssql",
			Error:   fmt.Errorf("无法识别为MSSQL服务"),
		}
	}

	common.LogSuccess(i18n.Tr("mssql_service", target, banner))

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
