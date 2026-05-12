//go:build plugin_rabbitmq || !plugin_selective

package services

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// RabbitMQPlugin RabbitMQ扫描插件
type RabbitMQPlugin struct {
	plugins.BasePlugin
}

func NewRabbitMQPlugin() *RabbitMQPlugin {
	return &RabbitMQPlugin{
		BasePlugin: plugins.NewBasePlugin("rabbitmq"),
	}
}

func (p *RabbitMQPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	target := info.Target()

	if config.DisableBrute {
		return p.identifyService(ctx, info, session)
	}

	// 先检测未授权访问
	if result := p.testUnauthorizedAccess(ctx, info, config, state); result != nil && result.Success {
		common.LogSuccess(i18n.Tr("rabbitmq_service", target, result.Banner))
		return result
	}

	credentials := GenerateCredentials("rabbitmq", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "rabbitmq",
			Error:   fmt.Errorf("没有可用的测试凭据"),
		}
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "rabbitmq", testConfig)

	if result.Success {
		common.LogVuln(i18n.Tr("rabbitmq_credential", target, result.Username, result.Password))
	}

	return result
}

// createAuthFunc 创建RabbitMQ认证函数
func (p *RabbitMQPlugin) createAuthFunc(info *common.HostInfo, config *common.Config, state *common.State) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doRabbitMQAuth(ctx, info, cred, config, state)
	}
}

// doRabbitMQAuth 执行RabbitMQ认证
func (p *RabbitMQPlugin) doRabbitMQAuth(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) *AuthResult {
	// 对于AMQP端口，使用HTTP管理接口
	port := info.Port
	if port == 5672 || port == 5671 {
		port = 15672
		if info.Port == 5671 {
			port = 15671
		}
	}

	baseURL := fmt.Sprintf("http://%s:%d", info.Host, port)
	client := &http.Client{Timeout: config.Timeout}

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/overview", nil)
	if err != nil {
		return &AuthResult{
			Success:   false,
			ErrorType: classifyRabbitMQErrorType(err),
			Error:     err,
		}
	}

	req.SetBasicAuth(cred.Username, cred.Password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{
			Success:   false,
			ErrorType: classifyRabbitMQErrorType(err),
			Error:     err,
		}
	}
	state.IncrementTCPSuccessPacketCount()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == 200 {
		return &AuthResult{
			Success:   true,
			Conn:      &rabbitMQConnWrapper{},
			ErrorType: ErrorTypeUnknown,
			Error:     nil,
		}
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeAuth,
			Error:     fmt.Errorf("认证失败，状态码: %d", resp.StatusCode),
		}
	}

	return &AuthResult{
		Success:   false,
		ErrorType: ErrorTypeUnknown,
		Error:     fmt.Errorf("意外响应状态码: %d", resp.StatusCode),
	}
}

// rabbitMQConnWrapper RabbitMQ连接包装器
type rabbitMQConnWrapper struct{}

func (w *rabbitMQConnWrapper) Close() error {
	return nil
}

// classifyRabbitMQErrorType RabbitMQ错误分类
func classifyRabbitMQErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	rabbitMQAuthErrors := []string{
		"authentication failed",
		"access denied",
		"unauthorized",
		"401 unauthorized",
		"403 forbidden",
	}

	return ClassifyError(err, rabbitMQAuthErrors, CommonNetworkErrors)
}

// testUnauthorizedAccess 测试RabbitMQ未授权访问
func (p *RabbitMQPlugin) testUnauthorizedAccess(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	port := info.Port
	if port == 5672 || port == 5671 {
		port = 15672
	}

	baseURL := fmt.Sprintf("http://%s:%d", info.Host, port)
	client := &http.Client{Timeout: config.Timeout}

	// 测试无认证访问
	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/overview", nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
	} else {
		state.IncrementTCPSuccessPacketCount()
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode == 200 {
			return &ScanResult{
				Type:    plugins.ResultTypeVuln,
				Success: true,
				Service: "rabbitmq",
				Banner:  "未授权访问",
			}
		}
	}

	// 测试guest默认用户
	guestReq, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/overview", nil)
	if err == nil {
		guestReq.SetBasicAuth("guest", "guest")
		guestResp, guestErr := client.Do(guestReq)
		if guestErr == nil {
			defer func() { _ = guestResp.Body.Close() }()
			if guestResp.StatusCode == 200 {
				return &ScanResult{
					Type:    plugins.ResultTypeVuln,
					Success: true,
					Service: "rabbitmq",
					Banner:  "未授权访问 - guest默认密码",
				}
			}
		}
	}

	return nil
}

// testAMQPProtocol 检测AMQP协议
func (p *RabbitMQPlugin) testAMQPProtocol(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	target := info.Target()

	conn, err := session.DialTCP(ctx, "tcp", target, session.Config.Timeout)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(session.Config.Timeout))

	// 发送AMQP协议头
	amqpHeader := []byte{0x41, 0x4d, 0x51, 0x50, 0x00, 0x00, 0x09, 0x01}
	_, err = conn.Write(amqpHeader)
	if err != nil {
		return nil
	}

	buffer := make([]byte, 32)
	n, err := conn.Read(buffer)
	if err != nil || n < 4 {
		return nil
	}

	if string(buffer[:4]) == "AMQP" || (n >= 8 && buffer[0] == 0x01) {
		banner := "RabbitMQ AMQP"
		common.LogSuccess(i18n.Tr("rabbitmq_service", target, banner))
		return &ScanResult{
			Type:    plugins.ResultTypeService,
			Success: true,
			Service: "rabbitmq",
			Banner:  banner,
		}
	}

	return nil
}

func (p *RabbitMQPlugin) identifyService(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	// 对于AMQP端口，检测AMQP协议
	if info.Port == 5672 || info.Port == 5671 {
		if result := p.testAMQPProtocol(ctx, info, session); result != nil && result.Success {
			return result
		}
	}

	// 检测HTTP管理界面
	return p.testManagementInterface(ctx, info, session)
}

func (p *RabbitMQPlugin) testManagementInterface(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	target := info.Target()
	baseURL := fmt.Sprintf("http://%s:%d", info.Host, info.Port)

	client := &http.Client{Timeout: config.Timeout}

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	if err != nil {
		return &ScanResult{
			Success: false,
			Service: "rabbitmq",
			Error:   err,
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &ScanResult{
			Success: false,
			Service: "rabbitmq",
			Error:   err,
		}
	}
	state.IncrementTCPSuccessPacketCount()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == 200 || resp.StatusCode == 401 {
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(strings.ToLower(string(body)), "rabbitmq") {
			banner := "RabbitMQ Management"
			common.LogSuccess(i18n.Tr("rabbitmq_detected", target, banner))
			return &ScanResult{
				Type:    plugins.ResultTypeService,
				Success: true,
				Service: "rabbitmq",
				Banner:  banner,
			}
		}
	}

	return &ScanResult{
		Success: false,
		Service: "rabbitmq",
		Error:   fmt.Errorf("无法识别为RabbitMQ服务"),
	}
}

func init() {
	RegisterPluginWithPorts("rabbitmq", func() Plugin {
		return NewRabbitMQPlugin()
	}, []int{5672, 15672, 5671})
}
