//go:build plugin_ldap || !plugin_selective

package services

import (
	"context"
	"fmt"

	ldaplib "github.com/go-ldap/ldap/v3"
	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// LDAPPlugin LDAP扫描插件
type LDAPPlugin struct {
	plugins.BasePlugin
}

func NewLDAPPlugin() *LDAPPlugin {
	return &LDAPPlugin{
		BasePlugin: plugins.NewBasePlugin("ldap"),
	}
}

func (p *LDAPPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	if config.DisableBrute {
		return p.identifyService(ctx, info, config, state)
	}

	target := info.Target()

	// Hash 认证优先：检查是否配置了 Hash 和 Domain
	if len(config.Credentials.HashValues) > 0 && config.Credentials.Domain != "" {
		result := p.tryHashAuth(ctx, info, config, state)
		if result != nil && result.Success {
			return result
		}
	}

	credentials := GenerateCredentials("ldap", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "ldap",
			Error:   fmt.Errorf("没有可用的测试凭据"),
		}
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfig(config)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "ldap", testConfig)

	if result.Success {
		common.LogVuln(i18n.Tr("ldap_credential", target, result.Username, result.Password))
	}

	return result
}

// createAuthFunc 创建LDAP认证函数
func (p *LDAPPlugin) createAuthFunc(info *common.HostInfo, config *common.Config, state *common.State) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doLDAPAuth(ctx, info, cred, config, state)
	}
}

// doLDAPAuth 执行LDAP认证
func (p *LDAPPlugin) doLDAPAuth(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) *AuthResult {
	conn, err := p.connectLDAP(ctx, info, config)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{
			Success:   false,
			ErrorType: classifyLDAPErrorType(err),
			Error:     err,
		}
	}
	state.IncrementTCPSuccessPacketCount()

	// 尝试多种DN格式进行绑定测试
	dnFormats := []string{
		fmt.Sprintf("cn=%s,dc=example,dc=com", cred.Username),
		fmt.Sprintf("uid=%s,dc=example,dc=com", cred.Username),
		fmt.Sprintf("cn=%s,ou=users,dc=example,dc=com", cred.Username),
		cred.Username,
	}

	for _, dn := range dnFormats {
		if bindErr := conn.Bind(dn, cred.Password); bindErr == nil {
			return &AuthResult{
				Success:   true,
				Conn:      &ldapConnWrapper{conn},
				ErrorType: ErrorTypeUnknown,
				Error:     nil,
			}
		}
	}

	_ = conn.Close()
	return &AuthResult{
		Success:   false,
		ErrorType: ErrorTypeAuth,
		Error:     fmt.Errorf("所有DN格式都失败"),
	}
}

// ldapConnWrapper 包装 ldap.Conn 以实现 io.Closer
type ldapConnWrapper struct {
	*ldaplib.Conn
}

func (w *ldapConnWrapper) Close() error {
	return w.Conn.Close()
}

// tryHashAuth 尝试 NTLM Hash 认证
func (p *LDAPPlugin) tryHashAuth(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()
	domain := config.Credentials.Domain
	users := config.Credentials.Userdict["ldap"]

	// 如果没有用户名，使用默认用户名
	if len(users) == 0 {
		users = []string{"administrator", "admin"}
	}

	for _, user := range users {
		for _, hash := range config.Credentials.HashValues {
			select {
			case <-ctx.Done():
				return &ScanResult{
					Success: false,
					Service: "ldap",
					Error:   ctx.Err(),
				}
			default:
			}

			result := p.doNTLMHashAuth(ctx, info, domain, user, hash, config, state)
			if result.Success {
				// 截断 hash 用于显示
				displayHash := hash
				if len(hash) > 16 {
					displayHash = hash[:16] + "..."
				}
				common.LogVuln(i18n.Tr("ldap_hash_credential", target, domain, user, displayHash))
				return &ScanResult{
					Type:     plugins.ResultTypeVuln,
					Success:  true,
					Service:  "ldap",
					Username: user,
					Password: hash, // 使用 Password 字段存储 hash
				}
			}
		}
	}

	return nil
}

// doNTLMHashAuth 执行单次 NTLM Hash 认证
func (p *LDAPPlugin) doNTLMHashAuth(ctx context.Context, info *common.HostInfo, domain, username, hash string, config *common.Config, state *common.State) *AuthResult {
	conn, err := p.connectLDAP(ctx, info, config)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{
			Success:   false,
			ErrorType: classifyLDAPErrorType(err),
			Error:     err,
		}
	}
	state.IncrementTCPSuccessPacketCount()

	if err := conn.NTLMBindWithHash(domain, username, hash); err == nil {
		return &AuthResult{
			Success:   true,
			Conn:      &ldapConnWrapper{conn},
			ErrorType: ErrorTypeUnknown,
			Error:     nil,
		}
	}

	_ = conn.Close()
	return &AuthResult{
		Success:   false,
		ErrorType: ErrorTypeAuth,
		Error:     fmt.Errorf("NTLM hash authentication failed"),
	}
}

// connectLDAP 连接LDAP服务器
func (p *LDAPPlugin) connectLDAP(ctx context.Context, info *common.HostInfo, config *common.Config) (*ldaplib.Conn, error) {
	target := info.Target()

	type result struct {
		conn *ldaplib.Conn
		err  error
	}
	resultChan := make(chan result, 1)

	go func() {
		tcpConn, err := common.WrapperTcpWithTimeout("tcp", target, config.Timeout)
		if err != nil {
			resultChan <- result{nil, err}
			return
		}

		var conn *ldaplib.Conn
		if info.Port == 636 {
			conn = ldaplib.NewConn(tcpConn, true)
		} else {
			conn = ldaplib.NewConn(tcpConn, false)
		}
		conn.Start()

		resultChan <- result{conn, nil}
	}()

	select {
	case res := <-resultChan:
		return res.conn, res.err
	case <-ctx.Done():
		// context 被取消，启动清理协程等待并关闭可能创建的连接
		go func() {
			res := <-resultChan
			if res.conn != nil {
				_ = res.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// classifyLDAPErrorType LDAP错误分类
func classifyLDAPErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	ldapAuthErrors := []string{
		"invalid credentials",
		"authentication failed",
		"bind failed",
		"ldap result code",
		"invalid dn",
		"access denied",
	}

	ldapNetworkErrors := append(CommonNetworkErrors,
		"ldap: connection lost",
		"ldap: connection error",
	)

	return ClassifyError(err, ldapAuthErrors, ldapNetworkErrors)
}

func (p *LDAPPlugin) identifyService(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()

	conn, err := p.connectLDAP(ctx, info, config)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &ScanResult{
			Success: false,
			Service: "ldap",
			Error:   err,
		}
	}
	state.IncrementTCPSuccessPacketCount()
	defer func() { _ = conn.Close() }()

	banner := "LDAP"
	common.LogSuccess(i18n.Tr("ldap_service", target, banner))

	return &ScanResult{
		Type:    plugins.ResultTypeService,
		Success: true,
		Service: "ldap",
		Banner:  banner,
	}
}

func init() {
	RegisterPluginWithPorts("ldap", func() Plugin {
		return NewLDAPPlugin()
	}, []int{389, 636, 3268, 3269})
}
