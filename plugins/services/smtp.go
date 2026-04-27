//go:build plugin_smtp || !plugin_selective

package services

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// SMTPPlugin SMTP扫描插件
type SMTPPlugin struct {
	plugins.BasePlugin
}

func NewSMTPPlugin() *SMTPPlugin {
	return &SMTPPlugin{
		BasePlugin: plugins.NewBasePlugin("smtp"),
	}
}

func (p *SMTPPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	target := info.Target()

	if config.DisableBrute {
		return p.identifyService(ctx, info, config, state)
	}

	// 检测未授权访问
	if result := p.testUnauthorizedAccess(ctx, info, config, state); result != nil && result.Success {
		common.LogSuccess(i18n.Tr("smtp_service", target, result.Banner))
		return result
	}

	// 生成密码字典
	credentials := plugins.GenerateCredentials("smtp", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "smtp",
			Error:   fmt.Errorf("没有可用的测试凭据"),
		}
	}

	// 转换凭据类型
	creds := make([]Credential, len(credentials))
	for i, c := range credentials {
		creds[i] = Credential{Username: c.Username, Password: c.Password}
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfig(config)

	result := TestCredentialsConcurrently(ctx, creds, authFn, "smtp", testConfig)

	if result.Success {
		common.LogVuln(i18n.Tr("smtp_credential", target, result.Username, result.Password))
	}

	return result
}

// createAuthFunc 创建SMTP认证函数
func (p *SMTPPlugin) createAuthFunc(info *common.HostInfo, config *common.Config, state *common.State) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doSMTPAuth(ctx, info, cred, config, state)
	}
}

// doSMTPAuth 执行SMTP认证
func (p *SMTPPlugin) doSMTPAuth(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) *AuthResult {
	target := info.Target()
	timeout := config.Timeout

	resultChan := make(chan *AuthResult, 1)

	go func() {
		conn, err := common.WrapperTcpWithTimeout("tcp", target, timeout)
		if err != nil {
			state.IncrementTCPFailedPacketCount()
			resultChan <- &AuthResult{
				Success:   false,
				ErrorType: classifySMTPErrorType(err),
				Error:     err,
			}
			return
		}

		_ = conn.SetDeadline(time.Now().Add(timeout))

		client, err := smtp.NewClient(conn, info.Host)
		if err != nil {
			_ = conn.Close()
			state.IncrementTCPFailedPacketCount()
			resultChan <- &AuthResult{
				Success:   false,
				ErrorType: classifySMTPErrorType(err),
				Error:     err,
			}
			return
		}

		if cred.Username != "" {
			auth := smtp.PlainAuth("", cred.Username, cred.Password, info.Host)
			if err := client.Auth(auth); err != nil {
				_ = client.Close()
				state.IncrementTCPFailedPacketCount()
				resultChan <- &AuthResult{
					Success:   false,
					ErrorType: classifySMTPErrorType(err),
					Error:     err,
				}
				return
			}
		}

		if err := client.Mail("test@test.com"); err != nil {
			_ = client.Close()
			state.IncrementTCPFailedPacketCount()
			resultChan <- &AuthResult{
				Success:   false,
				ErrorType: classifySMTPErrorType(err),
				Error:     err,
			}
			return
		}

		state.IncrementTCPSuccessPacketCount()
		resultChan <- &AuthResult{
			Success:   true,
			Conn:      &smtpClientWrapper{client},
			ErrorType: ErrorTypeUnknown,
			Error:     nil,
		}
	}()

	select {
	case result := <-resultChan:
		return result
	case <-ctx.Done():
		// context 被取消，启动清理协程等待并关闭可能创建的连接
		go func() {
			result := <-resultChan
			if result != nil && result.Conn != nil {
				_ = result.Conn.Close()
			}
		}()
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeNetwork,
			Error:     ctx.Err(),
		}
	}
}

// smtpClientWrapper 包装SMTP客户端以实现io.Closer
type smtpClientWrapper struct {
	client *smtp.Client
}

func (w *smtpClientWrapper) Close() error {
	return w.client.Close()
}

// classifySMTPErrorType SMTP错误分类
func classifySMTPErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	smtpAuthErrors := []string{
		"authentication failed",
		"authentication failure",
		"auth failed",
		"login failed",
		"invalid credentials",
		"invalid username or password",
		"username or password incorrect",
		"password incorrect",
		"access denied",
		"permission denied",
		"unauthorized",
		"not authorized",
		"authentication required",
		"535 authentication failed",
		"535 incorrect authentication",
		"535 invalid credentials",
		"535 authentication credentials invalid",
		"534 authentication mechanism is too weak",
		"530 authentication required",
		"530 must authenticate",
		"451 authentication aborted",
		"bad username or password",
		"invalid user",
		"user unknown",
		"mailbox unavailable",
		"relay access denied",
		"relay not permitted",
	}

	return ClassifyError(err, smtpAuthErrors, CommonNetworkErrors)
}

// testUnauthorizedAccess 测试SMTP未授权访问
func (p *SMTPPlugin) testUnauthorizedAccess(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	// 测试匿名访问
	if result := p.testAnonymousAccess(ctx, info, config, state); result != nil {
		return result
	}

	// 测试开放中继
	if result := p.testOpenRelay(ctx, info, config, state); result != nil {
		return result
	}

	// 测试VRFY命令
	if result := p.testVRFYCommand(ctx, info, config, state); result != nil {
		return result
	}

	// 测试EXPN命令
	if result := p.testEXPNCommand(ctx, info, config, state); result != nil {
		return result
	}

	return nil
}

// testAnonymousAccess 测试匿名邮件发送
func (p *SMTPPlugin) testAnonymousAccess(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()

	resultChan := make(chan *ScanResult, 1)

	go func() {
		conn, err := common.WrapperTcpWithTimeout("tcp", target, config.Timeout)
		if err != nil {
			state.IncrementTCPFailedPacketCount()
			resultChan <- nil
			return
		}
		defer func() { _ = conn.Close() }()

		client, err := smtp.NewClient(conn, info.Host)
		if err != nil {
			resultChan <- nil
			return
		}
		defer func() { _ = client.Quit() }()

		if err := client.Hello("fscan.test"); err != nil {
			resultChan <- nil
			return
		}

		if err := client.Mail("anonymous@test.com"); err != nil {
			resultChan <- nil
			return
		}

		if err := client.Rcpt("test@local.domain"); err != nil {
			resultChan <- nil
			return
		}

		state.IncrementTCPSuccessPacketCount()
		resultChan <- &ScanResult{
			Success: true,
			Type:    plugins.ResultTypeVuln,
			Service: "smtp",
			Banner:  "未授权访问 - 允许匿名邮件发送",
		}
	}()

	select {
	case result := <-resultChan:
		return result
	case <-ctx.Done():
		return nil
	}
}

// testOpenRelay 测试开放中继
func (p *SMTPPlugin) testOpenRelay(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()

	resultChan := make(chan *ScanResult, 1)

	go func() {
		conn, err := common.WrapperTcpWithTimeout("tcp", target, config.Timeout)
		if err != nil {
			state.IncrementTCPFailedPacketCount()
			resultChan <- nil
			return
		}
		defer func() { _ = conn.Close() }()

		client, err := smtp.NewClient(conn, info.Host)
		if err != nil {
			resultChan <- nil
			return
		}
		defer func() { _ = client.Quit() }()

		if err := client.Hello("fscan.test"); err != nil {
			resultChan <- nil
			return
		}

		if err := client.Mail("test@fscan.test"); err != nil {
			resultChan <- nil
			return
		}

		if err := client.Rcpt("external@example.com"); err != nil {
			resultChan <- nil
			return
		}

		state.IncrementTCPSuccessPacketCount()
		resultChan <- &ScanResult{
			Success: true,
			Type:    plugins.ResultTypeVuln,
			Service: "smtp",
			Banner:  "未授权访问 - 开放中继",
		}
	}()

	select {
	case result := <-resultChan:
		return result
	case <-ctx.Done():
		return nil
	}
}

// testVRFYCommand 测试VRFY命令用户枚举
func (p *SMTPPlugin) testVRFYCommand(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()

	resultChan := make(chan *ScanResult, 1)

	go func() {
		conn, err := common.WrapperTcpWithTimeout("tcp", target, config.Timeout)
		if err != nil {
			state.IncrementTCPFailedPacketCount()
			resultChan <- nil
			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(config.Timeout))

		if _, heloWriteErr := fmt.Fprintf(conn, "HELO fscan.test\r\n"); heloWriteErr != nil {
			resultChan <- nil
			return
		}

		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			resultChan <- nil
			return
		}
		response := string(buffer[:n])

		if !strings.HasPrefix(response, "250") {
			resultChan <- nil
			return
		}

		testUsers := []string{"admin", "root", "test", "user", "postmaster", "administrator"}

		for _, user := range testUsers {
			if _, err := fmt.Fprintf(conn, "VRFY %s\r\n", user); err != nil {
				continue
			}

			n, err := conn.Read(buffer)
			if err != nil {
				continue
			}

			vrfyResponse := strings.TrimSpace(string(buffer[:n]))

			if strings.HasPrefix(vrfyResponse, "250") {
				state.IncrementTCPSuccessPacketCount()
				resultChan <- &ScanResult{
					Success: true,
					Type:    plugins.ResultTypeVuln,
					Service: "smtp",
					Banner:  fmt.Sprintf("未授权访问 - VRFY命令枚举用户(%s)", user),
				}
				return
			}
		}

		resultChan <- nil
	}()

	select {
	case result := <-resultChan:
		return result
	case <-ctx.Done():
		return nil
	}
}

// testEXPNCommand 测试EXPN命令邮件列表枚举
func (p *SMTPPlugin) testEXPNCommand(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()

	resultChan := make(chan *ScanResult, 1)

	go func() {
		conn, err := common.WrapperTcpWithTimeout("tcp", target, config.Timeout)
		if err != nil {
			state.IncrementTCPFailedPacketCount()
			resultChan <- nil
			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(config.Timeout))

		if _, heloWriteErr := fmt.Fprintf(conn, "HELO fscan.test\r\n"); heloWriteErr != nil {
			resultChan <- nil
			return
		}

		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			resultChan <- nil
			return
		}

		response := string(buffer[:n])
		if !strings.HasPrefix(response, "250") {
			resultChan <- nil
			return
		}

		testLists := []string{"all", "staff", "users", "admin", "everyone", "postmaster"}

		for _, list := range testLists {
			if _, err := fmt.Fprintf(conn, "EXPN %s\r\n", list); err != nil {
				continue
			}

			n, err := conn.Read(buffer)
			if err != nil {
				continue
			}

			expnResponse := strings.TrimSpace(string(buffer[:n]))

			if strings.HasPrefix(expnResponse, "250") {
				state.IncrementTCPSuccessPacketCount()
				resultChan <- &ScanResult{
					Success: true,
					Type:    plugins.ResultTypeVuln,
					Service: "smtp",
					Banner:  fmt.Sprintf("未授权访问 - EXPN命令枚举邮件列表(%s)", list),
				}
				return
			}
		}

		resultChan <- nil
	}()

	select {
	case result := <-resultChan:
		return result
	case <-ctx.Done():
		return nil
	}
}

// getServerInfo 获取SMTP服务器信息
func (p *SMTPPlugin) getServerInfo(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) string {
	target := info.Target()

	resultChan := make(chan string, 1)

	go func() {
		conn, err := common.SafeTCPDial(target, config.Timeout)
		if err != nil {
			state.IncrementTCPFailedPacketCount()
			resultChan <- ""
			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetReadDeadline(time.Now().Add(config.Timeout))
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			resultChan <- ""
			return
		}

		state.IncrementTCPSuccessPacketCount()
		welcome := strings.TrimSpace(string(buffer[:n]))

		if strings.HasPrefix(welcome, "220") {
			serverInfo := strings.TrimPrefix(welcome, "220 ")
			resultChan <- serverInfo
			return
		}

		resultChan <- welcome
	}()

	select {
	case result := <-resultChan:
		return result
	case <-ctx.Done():
		return ""
	}
}

// identifyService SMTP服务识别
func (p *SMTPPlugin) identifyService(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()

	serverInfo := p.getServerInfo(ctx, info, config, state)
	var banner string

	if serverInfo != "" {
		banner = fmt.Sprintf("SMTP邮件服务 (%s)", serverInfo)
	} else {
		conn, err := common.SafeTCPDial(target, config.Timeout)
		if err != nil {
			state.IncrementTCPFailedPacketCount()
			return &ScanResult{
				Success: false,
				Service: "smtp",
				Error:   err,
			}
		}
		defer func() { _ = conn.Close() }()
		state.IncrementTCPSuccessPacketCount()
		banner = "SMTP邮件服务"
	}

	common.LogSuccess(i18n.Tr("smtp_service", target, banner))

	return &ScanResult{
		Success: true,
		Type:    plugins.ResultTypeService,
		Service: "smtp",
		Banner:  banner,
	}
}

func init() {
	RegisterPluginWithPorts("smtp", func() Plugin {
		return NewSMTPPlugin()
	}, []int{25, 465, 587, 2525})
}
