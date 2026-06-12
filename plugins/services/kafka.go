//go:build plugin_kafka || !plugin_selective

package services

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// KafkaPlugin Kafka扫描插件（纯 raw TCP 实现，无重型依赖）
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
		return p.identifyService(ctx, info, session)
	}

	target := info.Target()

	credentials := GenerateCredentials("kafka", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "kafka",
			Error:   fmt.Errorf("%s", i18n.GetText("service_no_credentials")),
		}
	}

	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "kafka", testConfig)

	if result.Success {
		session.LogVuln(i18n.Tr("kafka_credential", target, result.Username, result.Password))
	}

	return result
}

func (p *KafkaPlugin) createAuthFunc(info *common.HostInfo, config *common.Config, state *common.State) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doKafkaAuth(ctx, info, cred, config, state)
	}
}

// ── raw TCP Kafka 实现 ──────────────────────────────────────────

func (p *KafkaPlugin) doKafkaAuth(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) *AuthResult {
	target := info.Target()
	timeout := config.Timeout

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{
			Success:   false,
			ErrorType: classifyKafkaErrorType(err),
			Error:     err,
		}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Step 1: ApiVersions 握手 (api_key=18, api_version=0)
	if err := kafkaSend(conn, 18, 0, nil); err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{Success: false, ErrorType: ErrorTypeNetwork, Error: err}
	}
	_, err = kafkaRecv(conn)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{Success: false, ErrorType: ErrorTypeNetwork, Error: err}
	}

	// Step 2: SASL/PLAIN 认证 (如果需要)
	if cred.Username != "" || cred.Password != "" {
		// SaslHandshake: mechanism=PLAIN (api_key=17, api_version=0)
		body := kafkaString("PLAIN")
		if err := kafkaSend(conn, 17, 0, body); err != nil {
			state.IncrementTCPFailedPacketCount()
			return &AuthResult{Success: false, ErrorType: ErrorTypeNetwork, Error: err}
		}
		resp, err := kafkaRecv(conn)
		if err != nil {
			state.IncrementTCPFailedPacketCount()
			return &AuthResult{Success: false, ErrorType: classifyKafkaErrorType(err), Error: err}
		}
		// SaslHandshake 响应: [4B error_code] + [mechanisms array]
		if len(resp) >= 2 {
			code := int16(binary.BigEndian.Uint16(resp[:2]))
			if code != 0 {
				return &AuthResult{Success: false, ErrorType: ErrorTypeAuth, Error: fmt.Errorf("SASL handshake error: %d", code)}
			}
		}

		// SaslAuthenticate: PLAIN token = \x00user\x00pass (api_key=36, api_version=0)
		token := []byte("\x00" + cred.Username + "\x00" + cred.Password)
		authBody := kafkaBytes(token)
		if err := kafkaSend(conn, 36, 0, authBody); err != nil {
			state.IncrementTCPFailedPacketCount()
			return &AuthResult{Success: false, ErrorType: ErrorTypeNetwork, Error: err}
		}
		resp, err = kafkaRecv(conn)
		if err != nil {
			state.IncrementTCPFailedPacketCount()
			return &AuthResult{Success: false, ErrorType: classifyKafkaErrorType(err), Error: err}
		}
		if len(resp) >= 2 {
			code := int16(binary.BigEndian.Uint16(resp[:2]))
			if code != 0 {
				return &AuthResult{Success: false, ErrorType: ErrorTypeAuth, Error: fmt.Errorf("SASL authenticate error: %d", code)}
			}
		}
	}

	// Step 3: Metadata 请求验证连接 (api_key=3, api_version=0)
	// body: [topics_array] -> empty array = request all topics
	metaBody := []byte{0x00, 0x00, 0x00, 0x00} // empty topics array + allow_auto_topic_creation=false
	if err := kafkaSend(conn, 3, 0, metaBody); err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{Success: false, ErrorType: ErrorTypeNetwork, Error: err}
	}
	_, err = kafkaRecv(conn)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{Success: false, ErrorType: ErrorTypeNetwork, Error: err}
	}

	state.IncrementTCPSuccessPacketCount()
	return &AuthResult{Success: true, ErrorType: ErrorTypeUnknown, Error: nil}
}

// ── Kafka 协议编解码 ────────────────────────────────────────────

var kafkaCorrelationID int32

func nextKafkaCorrelationID() int32 {
	return atomic.AddInt32(&kafkaCorrelationID, 1) - 1
}

func kafkaSend(conn net.Conn, apiKey, apiVersion int16, body []byte) error {
	corrID := nextKafkaCorrelationID()

	// 请求格式: [4B len] [2B api_key] [2B api_version] [4B corr_id] [2B client_id_len] [client_id] [body]
	clientID := "fscan"
	totalLen := 2 + 2 + 4 + 2 + len(clientID) + len(body)
	buf := make([]byte, 4+totalLen)
	binary.BigEndian.PutUint32(buf[0:4], uint32(totalLen))
	binary.BigEndian.PutUint16(buf[4:6], uint16(apiKey))
	binary.BigEndian.PutUint16(buf[6:8], uint16(apiVersion))
	binary.BigEndian.PutUint32(buf[8:12], uint32(corrID))
	binary.BigEndian.PutUint16(buf[12:14], uint16(len(clientID)))
	copy(buf[14:], clientID)
	copy(buf[14+len(clientID):], body)

	_, err := conn.Write(buf)
	return err
}

func kafkaRecv(conn net.Conn) ([]byte, error) {
	// 读取 4 字节长度
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	msgLen := int(binary.BigEndian.Uint32(lenBuf))
	// 读取消息体
	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}
	// 跳过 correlation_id (4B)，返回 body
	if len(msg) >= 4 {
		return msg[4:], nil
	}
	return msg, nil
}

func kafkaString(s string) []byte {
	b := []byte(s)
	buf := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(buf, uint16(len(b)))
	copy(buf[2:], b)
	return buf
}

func kafkaBytes(b []byte) []byte {
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	return buf
}

// ── 错误分类 ────────────────────────────────────────────────────

func classifyKafkaErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}
	kafkaAuthErrors := []string{
		"sasl authentication failed",
		"authentication failed",
		"invalid credentials",
		"unauthorized",
	}
	kafkaNetworkErrors := append(CommonNetworkErrors,
		"broker not available",
		"no available brokers",
	)
	return ClassifyError(err, kafkaAuthErrors, kafkaNetworkErrors)
}

// ── 服务识别 ────────────────────────────────────────────────────

func (p *KafkaPlugin) identifyService(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	target := info.Target()
	timeout := config.Timeout

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &ScanResult{
			Success: false,
			Service: "kafka",
			Error:   fmt.Errorf("%s", i18n.Tr("service_not_identified", "Kafka")),
		}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := kafkaSend(conn, 18, 0, nil); err != nil {
		state.IncrementTCPFailedPacketCount()
		return &ScanResult{Success: false, Service: "kafka", Error: err}
	}
	_, err = kafkaRecv(conn)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		if p.isKafkaError(err) {
			banner := i18n.GetText("kafka_auth_required")
			session.LogSuccess(i18n.Tr("kafka_service", target, banner))
			return &ScanResult{Type: plugins.ResultTypeService, Success: true, Service: "kafka", Banner: banner}
		}
		return &ScanResult{Success: false, Service: "kafka", Error: fmt.Errorf("%s", i18n.Tr("service_not_identified", "Kafka"))}
	}
	state.IncrementTCPSuccessPacketCount()

	banner := "Kafka"
	session.LogSuccess(i18n.Tr("kafka_service", target, banner))
	return &ScanResult{Type: plugins.ResultTypeService, Success: true, Service: "kafka", Banner: banner}
}

func (p *KafkaPlugin) isKafkaError(err error) bool {
	if err == nil {
		return false
	}
	// 连接成功后读不到数据 -> 需要认证的 Kafka
	return true
}

func init() {
	RegisterPluginWithPorts("kafka", func() Plugin {
		return NewKafkaPlugin()
	}, []int{9092, 9093, 9094})
}
