//go:build plugin_kafka || !plugin_selective

package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/IBM/sarama"
	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// KafkaPlugin Kafka扫描插件
type KafkaPlugin struct {
	plugins.BasePlugin
}

func NewKafkaPlugin() *KafkaPlugin {
	return &KafkaPlugin{
		BasePlugin: plugins.NewBasePlugin("kafka"),
	}
}

func (p *KafkaPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	if config.DisableBrute {
		return p.identifyService(ctx, info, config, state)
	}

	target := info.Target()

	credentials := GenerateCredentials("kafka", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "kafka",
			Error:   fmt.Errorf("没有可用的测试凭据"),
		}
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "kafka", testConfig)

	if result.Success {
		common.LogVuln(i18n.Tr("kafka_credential", target, result.Username, result.Password))
	}

	return result
}

// createAuthFunc 创建Kafka认证函数
func (p *KafkaPlugin) createAuthFunc(info *common.HostInfo, config *common.Config, state *common.State) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doKafkaAuth(ctx, info, cred, config, state)
	}
}

// doKafkaAuth 执行Kafka认证
func (p *KafkaPlugin) doKafkaAuth(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) *AuthResult {
	target := info.Target()

	kafkaConfig := sarama.NewConfig()
	kafkaConfig.Net.DialTimeout = config.Timeout
	kafkaConfig.Net.ReadTimeout = config.Timeout
	kafkaConfig.Net.WriteTimeout = config.Timeout
	kafkaConfig.Version = sarama.V2_0_0_0

	if cred.Username != "" || cred.Password != "" {
		kafkaConfig.Net.SASL.Enable = true
		kafkaConfig.Net.SASL.Mechanism = sarama.SASLTypePlaintext
		kafkaConfig.Net.SASL.User = cred.Username
		kafkaConfig.Net.SASL.Password = cred.Password
		kafkaConfig.Net.SASL.Handshake = true
	}

	type kafkaResult struct {
		client sarama.Client
		err    error
	}

	resultChan := make(chan kafkaResult, 1)
	go func() {
		client, err := sarama.NewClient([]string{target}, kafkaConfig)
		resultChan <- kafkaResult{client: client, err: err}
	}()

	select {
	case result := <-resultChan:
		if result.err != nil {
			state.IncrementTCPFailedPacketCount()
			return &AuthResult{
				Success:   false,
				ErrorType: classifyKafkaErrorType(result.err),
				Error:     result.err,
			}
		}
		state.IncrementTCPSuccessPacketCount()
		return &AuthResult{
			Success:   true,
			Conn:      &kafkaClientWrapper{result.client},
			ErrorType: ErrorTypeUnknown,
			Error:     nil,
		}
	case <-ctx.Done():
		// context 被取消，启动清理协程等待并关闭可能创建的 client
		go func() {
			result := <-resultChan
			if result.client != nil {
				_ = result.client.Close()
			}
		}()
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeNetwork,
			Error:     ctx.Err(),
		}
	}
}

// kafkaClientWrapper 包装 sarama.Client 以实现 io.Closer
type kafkaClientWrapper struct {
	sarama.Client
}

func (w *kafkaClientWrapper) Close() error {
	return w.Client.Close()
}

// classifyKafkaErrorType Kafka错误分类
func classifyKafkaErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	kafkaAuthErrors := []string{
		"sasl authentication failed",
		"authentication failed",
		"invalid credentials",
		"unauthorized",
		"sasl/plain authentication failed",
	}

	kafkaNetworkErrors := append(CommonNetworkErrors,
		"kafka: client has run out of available brokers",
		"broker not available",
		"no available brokers",
	)

	return ClassifyError(err, kafkaAuthErrors, kafkaNetworkErrors)
}

func (p *KafkaPlugin) identifyService(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()

	// 尝试无认证连接
	emptyCred := Credential{Username: "", Password: ""}
	result := p.doKafkaAuth(ctx, info, emptyCred, config, state)
	if result.Success && result.Conn != nil {
		_ = result.Conn.Close()
		banner := "Kafka (无认证)"
		common.LogSuccess(i18n.Tr("kafka_service", target, banner))
		return &ScanResult{
			Type:    plugins.ResultTypeService,
			Success: true,
			Service: "kafka",
			Banner:  banner,
		}
	}

	// 尝试检测协议
	kafkaConfig := sarama.NewConfig()
	kafkaConfig.Net.DialTimeout = config.Timeout
	kafkaConfig.Version = sarama.V2_0_0_0

	client, err := sarama.NewClient([]string{target}, kafkaConfig)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		if p.isKafkaProtocolError(err) {
			banner := "Kafka (需要认证)"
			common.LogSuccess(i18n.Tr("kafka_service", target, banner))
			return &ScanResult{
				Type:    plugins.ResultTypeService,
				Success: true,
				Service: "kafka",
				Banner:  banner,
			}
		}
		return &ScanResult{
			Success: false,
			Service: "kafka",
			Error:   fmt.Errorf("无法识别为Kafka服务"),
		}
	}
	state.IncrementTCPSuccessPacketCount()
	_ = client.Close()

	banner := "Kafka"
	common.LogSuccess(i18n.Tr("kafka_service", target, banner))
	return &ScanResult{
		Type:    plugins.ResultTypeService,
		Success: true,
		Service: "kafka",
		Banner:  banner,
	}
}

func (p *KafkaPlugin) isKafkaProtocolError(err error) bool {
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "sasl") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "kafka") ||
		strings.Contains(errStr, "broker")
}

func init() {
	RegisterPluginWithPorts("kafka", func() Plugin {
		return NewKafkaPlugin()
	}, []int{9092, 9093, 9094})
}
