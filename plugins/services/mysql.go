//go:build plugin_mysql || !plugin_selective

package services

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

type nullWriter struct{}

func (nullWriter) Write(p []byte) (int, error) { return len(p), nil }

func init() {
	// 禁用mysql驱动的错误日志（如unexpected EOF）
	_ = mysql.SetLogger(log.New(&nullWriter{}, "", 0))
}

// MySQLPlugin MySQL数据库扫描插件
type MySQLPlugin struct {
	plugins.BasePlugin
}

func NewMySQLPlugin() *MySQLPlugin {
	return &MySQLPlugin{
		BasePlugin: plugins.NewBasePlugin("mysql"),
	}
}

func (p *MySQLPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	if config.DisableBrute {
		return p.identifyService(ctx, info, session)
	}

	credentials := GenerateCredentials("mysql", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "mysql",
			Error:   fmt.Errorf("没有可用的测试凭据"),
		}
	}

	target := info.Target()

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "mysql", testConfig)

	if result.Success {
		common.LogVuln(i18n.Tr("mysql_credential", target, result.Username, result.Password))
	}

	return result
}

// createAuthFunc 创建MySQL认证函数
func (p *MySQLPlugin) createAuthFunc(info *common.HostInfo, config *common.Config, state *common.State) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doMySQLAuth(ctx, info, cred, config, state)
	}
}

// doMySQLAuth 执行MySQL认证
func (p *MySQLPlugin) doMySQLAuth(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) *AuthResult {
	connStr := fmt.Sprintf("%s:%s@tcp(%s:%d)/information_schema?charset=utf8&timeout=%ds",
		cred.Username, cred.Password, info.Host, info.Port, int64(config.Timeout.Seconds()))

	db, err := sql.Open("mysql", connStr)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{
			Success:   false,
			ErrorType: classifyMySQLErrorType(err),
			Error:     err,
		}
	}

	db.SetConnMaxLifetime(config.Timeout)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	err = db.PingContext(ctx)
	if err != nil {
		_ = db.Close()
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{
			Success:   false,
			ErrorType: classifyMySQLErrorType(err),
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

// classifyMySQLErrorType MySQL错误分类
func classifyMySQLErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	mysqlAuthErrors := []string{
		"access denied for user",
		"unknown database",
		"host is not allowed",
		"authentication failed",
		"permission denied",
		"user does not exist",
	}

	mysqlNetworkErrors := append(CommonNetworkErrors,
		"too many connections",
		"can't connect to mysql server",
		"lost connection to mysql server",
		"mysql server has gone away",
	)

	return ClassifyError(err, mysqlAuthErrors, mysqlNetworkErrors)
}

func (p *MySQLPlugin) identifyService(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	target := info.Target()

	conn, err := session.DialTCP(ctx, "tcp", target, session.Config.Timeout)
	if err != nil {
		return &ScanResult{
			Success: false,
			Service: "mysql",
			Error:   err,
		}
	}
	defer func() { _ = conn.Close() }()

	if banner := p.readMySQLBanner(conn, session.Config); banner != "" {
		common.LogSuccess(i18n.Tr("mysql_service", target, banner))
		return &ScanResult{
			Type:    plugins.ResultTypeService,
			Success: true,
			Service: "mysql",
			Banner:  banner,
		}
	}

	return &ScanResult{
		Success: false,
		Service: "mysql",
		Error:   fmt.Errorf("无法识别为MySQL服务"),
	}
}

func (p *MySQLPlugin) readMySQLBanner(conn net.Conn, config *common.Config) string {
	_ = conn.SetReadDeadline(time.Now().Add(config.Timeout))

	handshake := make([]byte, 256)
	n, err := conn.Read(handshake)
	if err != nil || n < 10 {
		return ""
	}

	if handshake[4] != 10 {
		return ""
	}

	versionStart := 5
	versionEnd := versionStart
	for versionEnd < n && handshake[versionEnd] != 0 {
		versionEnd++
	}

	if versionEnd <= versionStart {
		return ""
	}

	versionStr := string(handshake[versionStart:versionEnd])
	return fmt.Sprintf("MySQL %s", versionStr)
}

func init() {
	RegisterPluginWithPorts("mysql", func() Plugin {
		return NewMySQLPlugin()
	}, []int{3306, 3307, 33060})
}
