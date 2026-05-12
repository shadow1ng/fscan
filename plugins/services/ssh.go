//go:build plugin_ssh || !plugin_selective

package services

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
	"golang.org/x/crypto/ssh"
)

// 预编译正则表达式
var sshBannerRegex = regexp.MustCompile(`SSH-([0-9.]+)-(.+)`)

// SSHPlugin SSH扫描插件
type SSHPlugin struct {
	plugins.BasePlugin
}

// NewSSHPlugin 创建SSH插件
func NewSSHPlugin() *SSHPlugin {
	return &SSHPlugin{
		BasePlugin: plugins.NewBasePlugin("ssh"),
	}
}

// Scan 执行SSH扫描
func (p *SSHPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	target := info.Target()

	// 如果指定了SSH密钥，优先使用密钥认证
	if config.Credentials.SSHKeyPath != "" {
		if result := p.scanWithKey(ctx, info, session); result != nil && result.Success {
			common.LogVuln(i18n.Tr("ssh_key_auth_success", target, result.Username)) //nolint:govet
			return result
		}
	}

	// 如果禁用暴力破解，只做服务识别
	if config.DisableBrute {
		return p.identifyService(ctx, info, session)
	}

	// 生成测试凭据
	credentials := GenerateCredentials("ssh", config)
	if len(credentials) == 0 {
		credentials = []Credential{
			{Username: "root", Password: ""},
			{Username: "root", Password: "root"},
			{Username: "root", Password: "toor"},
			{Username: "admin", Password: "admin"},
			{Username: "admin", Password: ""},
		}
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, session)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "ssh", testConfig)

	// 记录成功
	if result.Success {
		common.LogVuln(i18n.Tr("ssh_pwd_auth_success", target, result.Username, result.Password)) //nolint:govet
	}

	return result
}

// createAuthFunc 创建SSH认证函数
func (p *SSHPlugin) createAuthFunc(info *common.HostInfo, session *common.ScanSession) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doSSHAuth(ctx, info, cred, session)
	}
}

// doSSHAuth 执行SSH认证
func (p *SSHPlugin) doSSHAuth(ctx context.Context, info *common.HostInfo, cred Credential, session *common.ScanSession) *AuthResult {
	config := session.Config
	target := info.Target()

	// 创建SSH配置
	sshConfig := &ssh.ClientConfig{
		User:    cred.Username,
		Timeout: config.Timeout,
		//nolint:gosec // G106: 扫描工具需要忽略主机密钥验证以连接未知主机
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// 设置认证方法
	if len(cred.KeyData) > 0 {
		signer, err := ssh.ParsePrivateKey(cred.KeyData)
		if err != nil {
			return &AuthResult{
				Success:   false,
				ErrorType: ErrorTypeAuth,
				Error:     err,
			}
		}
		sshConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		sshConfig.Auth = []ssh.AuthMethod{ssh.Password(cred.Password)}
	}

	// 建立TCP连接
	conn, err := session.DialTCP(ctx, "tcp", target, config.Timeout)
	if err != nil {
		return &AuthResult{
			Success:   false,
			ErrorType: classifySSHErrorType(err),
			Error:     err,
		}
	}

	// 在TCP连接上创建SSH客户端
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, target, sshConfig)
	if err != nil {
		_ = conn.Close()
		return &AuthResult{
			Success:   false,
			ErrorType: classifySSHErrorType(err),
			Error:     err,
		}
	}

	// 创建SSH客户端
	client := ssh.NewClient(sshConn, chans, reqs)

	return &AuthResult{
		Success:   true,
		Conn:      &sshClientWrapper{client},
		ErrorType: ErrorTypeUnknown,
		Error:     nil,
	}
}

// sshClientWrapper 包装 ssh.Client 以实现 io.Closer
type sshClientWrapper struct {
	*ssh.Client
}

func (w *sshClientWrapper) Close() error {
	return w.Client.Close()
}

// classifySSHErrorType SSH错误分类
func classifySSHErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	// SSH 特有的认证错误（密码错误）
	sshAuthErrors := append(CommonAuthErrors,
		"unable to authenticate",
		"no supported methods remain",
	)

	// SSH 特有的网络/临时错误（需要重试）
	sshNetworkErrors := append(CommonNetworkErrors,
		"handshake failed",           // 握手失败，可能是服务端限流
		"ssh: disconnect",            // SSH 主动断开
		"connection closed",          // 连接被关闭
		"max startups",               // SSH MaxStartups 限制
		"too many authentication",    // 认证次数过多
	)

	return ClassifyError(err, sshAuthErrors, sshNetworkErrors)
}

// scanWithKey 使用SSH私钥扫描
func (p *SSHPlugin) scanWithKey(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	keyData, err := os.ReadFile(config.Credentials.SSHKeyPath)
	if err != nil {
		common.LogError(i18n.Tr("ssh_key_read_failed", err)) //nolint:govet
		return nil
	}

	usernames := config.Credentials.Userdict["ssh"]
	if len(usernames) == 0 {
		usernames = []string{"root", "admin", "ubuntu", "centos", "user", "git", "www-data"}
	}

	// 逐个测试用户名
	for _, username := range usernames {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		cred := Credential{
			Username: username,
			KeyData:  keyData,
		}

		result := p.doSSHAuth(ctx, info, cred, session)
		if result.Success {
			if result.Conn != nil {
				_ = result.Conn.Close()
			}
			return &ScanResult{
				Type:     plugins.ResultTypeCredential,
				Success:  true,
				Service:  "ssh",
				Username: username,
			}
		}
	}

	return nil
}

// identifyService 服务识别
func (p *SSHPlugin) identifyService(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	target := info.Target()

	conn, err := session.DialTCP(ctx, "tcp", target, session.Config.Timeout)
	if err != nil {
		return &ScanResult{
			Success: false,
			Service: "ssh",
			Error:   err,
		}
	}
	defer func() { _ = conn.Close() }()

	if banner := p.readSSHBanner(conn, session.Config); banner != "" {
		common.LogSuccess(i18n.Tr("ssh_service_identified", target, banner)) //nolint:govet
		return &ScanResult{
			Type:    plugins.ResultTypeService,
			Success: true,
			Service: "ssh",
			Banner:  banner,
		}
	}

	return &ScanResult{
		Success: false,
		Service: "ssh",
		Error:   fmt.Errorf("无法识别为SSH服务"),
	}
}

// readSSHBanner 读取SSH服务器Banner
func (p *SSHPlugin) readSSHBanner(conn net.Conn, config *common.Config) string {
	_ = conn.SetReadDeadline(time.Now().Add(config.Timeout))

	banner := make([]byte, 256)
	n, err := conn.Read(banner)
	if err != nil || n < 4 {
		return ""
	}

	bannerStr := strings.TrimSpace(string(banner[:n]))

	if strings.HasPrefix(bannerStr, "SSH-") {
		if matched := sshBannerRegex.FindStringSubmatch(bannerStr); len(matched) >= 3 {
			return fmt.Sprintf("SSH %s (%s)", matched[1], matched[2])
		}
		return fmt.Sprintf("SSH服务: %s", bannerStr)
	}

	return ""
}

// init 自动注册插件
func init() {
	RegisterPluginWithPorts("ssh", func() Plugin {
		return NewSSHPlugin()
	}, []int{22, 2222, 2200, 22222})
}

// 确保实现了 io.Closer 接口
var _ io.Closer = (*sshClientWrapper)(nil)
