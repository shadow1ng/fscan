//go:build plugin_postgresql || !plugin_selective

package services

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// PostgreSQLPlugin PostgreSQL扫描插件
type PostgreSQLPlugin struct {
	plugins.BasePlugin
}

func NewPostgreSQLPlugin() *PostgreSQLPlugin {
	return &PostgreSQLPlugin{
		BasePlugin: plugins.NewBasePlugin("postgresql"),
	}
}

func (p *PostgreSQLPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	target := info.Target()

	if config.DisableBrute {
		return p.identifyService(ctx, info, config, state)
	}

	// 先测试未授权访问
	if result := p.testUnauthorizedAccess(ctx, info, config, state); result != nil && result.Success {
		common.LogVuln(i18n.Tr("postgresql_vuln", target, result.VulInfo))
		return result
	}

	credentials := GenerateCredentials("postgresql", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "postgresql",
			Error:   fmt.Errorf("没有可用的测试凭据"),
		}
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "postgresql", testConfig)

	if result.Success {
		common.LogVuln(i18n.Tr("postgresql_credential", target, result.Username, result.Password))
	}

	return result
}

// createAuthFunc 创建PostgreSQL认证函数
func (p *PostgreSQLPlugin) createAuthFunc(info *common.HostInfo, config *common.Config, state *common.State) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doPostgreSQLAuth(ctx, info, cred, config, state)
	}
}

// doPostgreSQLAuth 执行PostgreSQL认证
func (p *PostgreSQLPlugin) doPostgreSQLAuth(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) *AuthResult {
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable&connect_timeout=%d",
		cred.Username, cred.Password, info.Host, info.Port, int64(config.Timeout.Seconds()))

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{
			Success:   false,
			ErrorType: classifyPostgreSQLErrorType(err),
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
			ErrorType: classifyPostgreSQLErrorType(err),
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

// classifyPostgreSQLErrorType PostgreSQL错误分类
func classifyPostgreSQLErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	pgAuthErrors := []string{
		"authentication failed",
		"password authentication failed",
		"role does not exist",
		"invalid authorization",
		"permission denied",
		"unauthorized",
		"invalid credentials",
		"access denied",
		"pq: password authentication failed",
		"pq: role",
		"pq: invalid authorization specification",
		"pq: permission denied",
		"pq: authentication failed",
		"pq: FATAL: password authentication failed",
		"pq: FATAL: role",
	}

	pgNetworkErrors := append(CommonNetworkErrors,
		"dial tcp",
		"connection closed",
		"eof",
		"network error",
		"context deadline exceeded",
		"pq: server closed the connection unexpectedly",
	)

	return ClassifyError(err, pgAuthErrors, pgNetworkErrors)
}

// testUnauthorizedAccess 测试PostgreSQL未授权访问
func (p *PostgreSQLPlugin) testUnauthorizedAccess(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	connStr := fmt.Sprintf("postgres://postgres@%s:%d/postgres?sslmode=disable&connect_timeout=%d",
		info.Host, info.Port, int64(config.Timeout.Seconds()))

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil
	}
	defer func() { _ = db.Close() }()

	db.SetConnMaxLifetime(config.Timeout)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	pingCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	err = db.PingContext(pingCtx)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return nil
	}

	state.IncrementTCPSuccessPacketCount()

	queryCtx, queryCancel := context.WithTimeout(ctx, config.Timeout)
	defer queryCancel()

	var version string
	err = db.QueryRowContext(queryCtx, "SELECT version()").Scan(&version)
	if err != nil {
		return &ScanResult{
			Type:    plugins.ResultTypeVuln,
			Success: true,
			Service: "postgresql",
			VulInfo: "未授权访问(trust认证)",
		}
	}

	vulInfo := fmt.Sprintf("未授权访问(trust认证) - %s", version)
	if len(vulInfo) > 100 {
		vulInfo = vulInfo[:100] + "..."
	}

	return &ScanResult{
		Type:    plugins.ResultTypeVuln,
		Success: true,
		Service: "postgresql",
		VulInfo: vulInfo,
	}
}

func (p *PostgreSQLPlugin) identifyService(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()

	connStr := fmt.Sprintf("postgres://invalid:invalid@%s:%d/postgres?sslmode=disable&connect_timeout=%d",
		info.Host, info.Port, int64(config.Timeout.Seconds()))

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return &ScanResult{
			Success: false,
			Service: "postgresql",
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
	if err != nil {
		errMsg := strings.ToLower(err.Error())
		if strings.Contains(errMsg, "postgres") ||
			strings.Contains(errMsg, "authentication") ||
			strings.Contains(errMsg, "database") ||
			strings.Contains(errMsg, "password") ||
			strings.Contains(errMsg, "role") ||
			strings.Contains(errMsg, "user") ||
			strings.Contains(errMsg, "pq:") {
			banner = "PostgreSQL"
		} else {
			return &ScanResult{
				Success: false,
				Service: "postgresql",
				Error:   fmt.Errorf("无法识别为PostgreSQL服务"),
			}
		}
	} else {
		banner = "PostgreSQL"
	}

	common.LogSuccess(i18n.Tr("postgresql_service", target, banner))

	return &ScanResult{
		Type:    plugins.ResultTypeService,
		Success: true,
		Service: "postgresql",
		Banner:  banner,
	}
}

func init() {
	RegisterPluginWithPorts("postgresql", func() Plugin {
		return NewPostgreSQLPlugin()
	}, []int{5432, 5433, 5434})
}
