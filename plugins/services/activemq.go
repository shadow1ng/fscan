//go:build plugin_activemq || !plugin_selective

package services

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// ActiveMQPlugin ActiveMQ扫描插件
type ActiveMQPlugin struct {
	plugins.BasePlugin
}

func NewActiveMQPlugin() *ActiveMQPlugin {
	return &ActiveMQPlugin{
		BasePlugin: plugins.NewBasePlugin("activemq"),
	}
}

func (p *ActiveMQPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	target := info.Target()

	if config.DisableBrute {
		return p.identifyService(ctx, info, config, state)
	}

	// 生成测试凭据
	credentials := GenerateCredentials("activemq", config)
	if len(credentials) == 0 {
		// ActiveMQ默认凭据
		credentials = []Credential{
			{Username: "admin", Password: "admin"},
			{Username: "admin", Password: ""},
			{Username: "admin", Password: "password"},
			{Username: "activemq", Password: "activemq"},
			{Username: "activemq", Password: "admin"},
			{Username: "user", Password: "user"},
			{Username: "guest", Password: "guest"},
		}
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfig(config)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "activemq", testConfig)

	if result.Success {
		common.LogVuln(i18n.Tr("activemq_credential", target, result.Username, result.Password))
	}

	return result
}

// createAuthFunc 创建ActiveMQ认证函数
func (p *ActiveMQPlugin) createAuthFunc(info *common.HostInfo, config *common.Config, state *common.State) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doActiveMQAuth(ctx, info, cred, config, state)
	}
}

// doActiveMQAuth 执行ActiveMQ认证
func (p *ActiveMQPlugin) doActiveMQAuth(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) *AuthResult {
	target := info.Target()
	timeout := config.Timeout

	resultChan := make(chan *AuthResult, 1)

	go func() {
		conn, err := common.WrapperTcpWithTimeout("tcp", target, timeout)
		if err != nil {
			state.IncrementTCPFailedPacketCount()
			resultChan <- &AuthResult{
				Success:   false,
				ErrorType: classifyActiveMQErrorType(err),
				Error:     err,
			}
			return
		}

		success, err := p.authenticateSTOMP(conn, cred.Username, cred.Password, config)
		if success {
			state.IncrementTCPSuccessPacketCount()
			resultChan <- &AuthResult{
				Success:   true,
				Conn:      &activeMQConnWrapper{conn},
				ErrorType: ErrorTypeUnknown,
				Error:     nil,
			}
			return
		}

		_ = conn.Close()
		state.IncrementTCPFailedPacketCount()
		resultChan <- &AuthResult{
			Success:   false,
			ErrorType: classifyActiveMQErrorType(err),
			Error:     err,
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

// activeMQConnWrapper 包装ActiveMQ连接以实现io.Closer
type activeMQConnWrapper struct {
	conn net.Conn
}

func (w *activeMQConnWrapper) Close() error {
	return w.conn.Close()
}

// classifyActiveMQErrorType ActiveMQ错误分类
func classifyActiveMQErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	activeMQAuthErrors := []string{
		"authentication failed",
		"access denied",
		"invalid credentials",
		"login failed",
		"unauthorized",
		"403 forbidden",
		"security exception",
		"invalid user",
		"invalid password",
		"login incorrect",
	}

	return ClassifyError(err, activeMQAuthErrors, CommonNetworkErrors)
}

// authenticateSTOMP 使用STOMP协议认证ActiveMQ
func (p *ActiveMQPlugin) authenticateSTOMP(conn net.Conn, username, password string, config *common.Config) (bool, error) {
	timeout := config.Timeout

	stompConnect := fmt.Sprintf("CONNECT\naccept-version:1.0,1.1,1.2\nhost:/\nlogin:%s\npasscode:%s\n\n\x00",
		username, password)

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(stompConnect)); err != nil {
		return false, fmt.Errorf("STOMP请求发送失败: %w", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return false, fmt.Errorf("STOMP响应读取失败: %w", err)
	}
	if n == 0 {
		return false, fmt.Errorf("STOMP无响应数据")
	}

	responseStr := string(response[:n])

	if strings.Contains(responseStr, "CONNECTED") {
		return true, nil
	} else if strings.Contains(responseStr, "ERROR") {
		errorMsg := "STOMP认证错误"
		if strings.Contains(responseStr, "Authentication failed") {
			errorMsg = "Authentication failed"
		} else if strings.Contains(responseStr, "Access denied") {
			errorMsg = "Access denied"
		} else if strings.Contains(responseStr, "Invalid credentials") {
			errorMsg = "Invalid credentials"
		}
		return false, fmt.Errorf("%s", errorMsg)
	}

	return false, fmt.Errorf("STOMP未知响应格式")
}

// identifyService ActiveMQ服务识别
func (p *ActiveMQPlugin) identifyService(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()
	timeout := config.Timeout

	conn, err := common.WrapperTcpWithTimeout("tcp", target, timeout)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &ScanResult{
			Success: false,
			Service: "activemq",
			Error:   err,
		}
	}
	defer func() { _ = conn.Close() }()

	stompConnect := "CONNECT\naccept-version:1.0,1.1,1.2\nhost:/\n\n\x00"

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, writeErr := conn.Write([]byte(stompConnect)); writeErr != nil {
		state.IncrementTCPFailedPacketCount()
		return &ScanResult{
			Success: false,
			Service: "activemq",
			Error:   fmt.Errorf("无法发送STOMP请求: %w", writeErr),
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &ScanResult{
			Success: false,
			Service: "activemq",
			Error:   fmt.Errorf("无法读取响应: %w", err),
		}
	}
	if n == 0 {
		return &ScanResult{
			Success: false,
			Service: "activemq",
			Error:   fmt.Errorf("无响应数据"),
		}
	}

	state.IncrementTCPSuccessPacketCount()
	responseStr := string(response[:n])

	if common.ContainsAny(responseStr, "CONNECTED", "ERROR") {
		banner := "ActiveMQ STOMP"
		if strings.Contains(responseStr, "server:") {
			lines := strings.Split(responseStr, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "server:") {
					banner = strings.TrimSpace(strings.TrimPrefix(line, "server:"))
					break
				}
			}
		}

		common.LogSuccess(i18n.Tr("activemq_service", target, banner))

		return &ScanResult{
			Success: true,
			Type:    plugins.ResultTypeService,
			Service: "activemq",
			Banner:  banner,
		}
	}

	return &ScanResult{
		Success: false,
		Service: "activemq",
		Error:   fmt.Errorf("无法识别为ActiveMQ STOMP服务"),
	}
}

func init() {
	RegisterPluginWithPorts("activemq", func() Plugin {
		return NewActiveMQPlugin()
	}, []int{61613, 61614, 61616, 61617, 61618, 8161})
}
