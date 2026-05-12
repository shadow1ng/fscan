//go:build plugin_cassandra || !plugin_selective

package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/gocql/gocql"
	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// CassandraPlugin Cassandra扫描插件
type CassandraPlugin struct {
	plugins.BasePlugin
}

func NewCassandraPlugin() *CassandraPlugin {
	return &CassandraPlugin{
		BasePlugin: plugins.NewBasePlugin("cassandra"),
	}
}

func (p *CassandraPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	target := info.Target()

	if config.DisableBrute {
		return p.identifyService(ctx, info, config, state)
	}

	// 先尝试无认证连接
	if result := p.tryNoAuthConnection(ctx, info, config, state); result != nil && result.Success {
		return result
	}

	credentials := GenerateCredentials("cassandra", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "cassandra",
			Error:   fmt.Errorf("没有可用的测试凭据"),
		}
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "cassandra", testConfig)

	if result.Success {
		common.LogVuln(i18n.Tr("cassandra_credential", target, result.Username, result.Password))
	}

	return result
}

// createAuthFunc 创建Cassandra认证函数
func (p *CassandraPlugin) createAuthFunc(info *common.HostInfo, config *common.Config, state *common.State) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doCassandraAuth(ctx, info, cred, config, state)
	}
}

// doCassandraAuth 执行Cassandra认证
func (p *CassandraPlugin) doCassandraAuth(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) *AuthResult {
	cluster := gocql.NewCluster(info.Host)
	cluster.Port = info.Port
	cluster.Timeout = config.Timeout
	cluster.ConnectTimeout = config.Timeout

	if cred.Username != "" || cred.Password != "" {
		cluster.Authenticator = gocql.PasswordAuthenticator{
			Username: cred.Username,
			Password: cred.Password,
		}
	}

	session, err := cluster.CreateSession()
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{
			Success:   false,
			ErrorType: classifyCassandraErrorType(err),
			Error:     err,
		}
	}
	state.IncrementTCPSuccessPacketCount()

	var dummy string
	err = session.Query("SELECT cluster_name FROM system.local").WithContext(ctx).Scan(&dummy)
	if err != nil {
		session.Close()
		return &AuthResult{
			Success:   false,
			ErrorType: classifyCassandraErrorType(err),
			Error:     err,
		}
	}

	return &AuthResult{
		Success:   true,
		Conn:      &cassandraSessionWrapper{session},
		ErrorType: ErrorTypeUnknown,
		Error:     nil,
	}
}

// cassandraSessionWrapper 包装 gocql.Session 以实现 io.Closer
type cassandraSessionWrapper struct {
	*gocql.Session
}

func (w *cassandraSessionWrapper) Close() error {
	w.Session.Close()
	return nil
}

// classifyCassandraErrorType Cassandra错误分类
func classifyCassandraErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	cassandraAuthErrors := []string{
		"authentication failed",
		"bad credentials",
		"invalid credentials",
		"username and/or password are incorrect",
		"unauthorized",
		"access denied",
	}

	return ClassifyError(err, cassandraAuthErrors, CommonNetworkErrors)
}

// tryNoAuthConnection 尝试无认证连接
func (p *CassandraPlugin) tryNoAuthConnection(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()

	cluster := gocql.NewCluster(info.Host)
	cluster.Port = info.Port
	cluster.Timeout = config.Timeout
	cluster.ConnectTimeout = config.Timeout

	session, err := cluster.CreateSession()
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return nil
	}
	state.IncrementTCPSuccessPacketCount()

	var dummy string
	err = session.Query("SELECT cluster_name FROM system.local").WithContext(ctx).Scan(&dummy)
	if err != nil {
		session.Close()
		return nil
	}

	session.Close()
	common.LogVuln(i18n.Tr("cassandra_unauth", target))
	return &ScanResult{
		Type:    plugins.ResultTypeService,
		Success: true,
		Service: "cassandra",
		Banner:  fmt.Sprintf("Cassandra (无认证, 集群: %s)", dummy),
	}
}

func (p *CassandraPlugin) identifyService(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()

	cluster := gocql.NewCluster(info.Host)
	cluster.Port = info.Port
	cluster.Timeout = config.Timeout
	cluster.ConnectTimeout = config.Timeout

	session, err := cluster.CreateSession()
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		if strings.Contains(strings.ToLower(err.Error()), "authentication") {
			banner := "Cassandra (需要认证)"
			common.LogSuccess(i18n.Tr("cassandra_service", target, banner))
			return &ScanResult{
				Type:    plugins.ResultTypeService,
				Success: true,
				Service: "cassandra",
				Banner:  banner,
			}
		}
		return &ScanResult{
			Success: false,
			Service: "cassandra",
			Error:   err,
		}
	}
	state.IncrementTCPSuccessPacketCount()
	session.Close()

	banner := "Cassandra"
	common.LogSuccess(i18n.Tr("cassandra_service", target, banner))
	return &ScanResult{
		Type:    plugins.ResultTypeService,
		Success: true,
		Service: "cassandra",
		Banner:  banner,
	}
}

func init() {
	RegisterPluginWithPorts("cassandra", func() Plugin {
		return NewCassandraPlugin()
	}, []int{9042, 9160, 7000, 7001})
}
