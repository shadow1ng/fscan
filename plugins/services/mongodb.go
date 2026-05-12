//go:build plugin_mongodb || !plugin_selective

package services

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// MongoDBPlugin MongoDB扫描插件
type MongoDBPlugin struct {
	plugins.BasePlugin
}

func NewMongoDBPlugin() *MongoDBPlugin {
	return &MongoDBPlugin{
		BasePlugin: plugins.NewBasePlugin("mongodb"),
	}
}

func (p *MongoDBPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	target := info.Target()

	if config.DisableBrute {
		return p.identifyService(ctx, info, session)
	}

	// 首先检测未授权访问
	isUnauth, err := p.mongodbUnauth(ctx, info, session)
	if err != nil {
		return &ScanResult{
			Success: false,
			Service: "mongodb",
			Error:   err,
		}
	}

	if isUnauth {
		common.LogVuln(i18n.Tr("mongodb_unauth", target))
		return &ScanResult{
			Type:    plugins.ResultTypeVuln,
			Success: true,
			Service: "mongodb",
			VulInfo: "未授权访问",
		}
	}

	// 如果需要认证，使用并发方式尝试常见凭据
	credentials := GenerateCredentials("mongodb", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "mongodb",
			Error:   fmt.Errorf("没有可用的测试凭据"),
		}
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "mongodb", testConfig)

	if result.Success {
		common.LogVuln(i18n.Tr("mongodb_credential", target, result.Username, result.Password))
	}

	return result
}

// createAuthFunc 创建MongoDB认证函数
func (p *MongoDBPlugin) createAuthFunc(info *common.HostInfo, config *common.Config, state *common.State) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doMongoDBAuth(ctx, info, cred, config, state)
	}
}

// doMongoDBAuth 执行MongoDB认证
func (p *MongoDBPlugin) doMongoDBAuth(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) *AuthResult {
	var uri string
	timeout := config.Timeout

	if cred.Username != "" && cred.Password != "" {
		uri = fmt.Sprintf("mongodb://%s:%s@%s:%d/?connectTimeoutMS=%d&serverSelectionTimeoutMS=%d",
			cred.Username, cred.Password, info.Host, info.Port, timeout.Milliseconds(), timeout.Milliseconds())
	} else if cred.Username != "" {
		uri = fmt.Sprintf("mongodb://%s:@%s:%d/?connectTimeoutMS=%d&serverSelectionTimeoutMS=%d",
			cred.Username, info.Host, info.Port, timeout.Milliseconds(), timeout.Milliseconds())
	} else {
		uri = fmt.Sprintf("mongodb://%s:%d/?connectTimeoutMS=%d&serverSelectionTimeoutMS=%d",
			info.Host, info.Port, timeout.Milliseconds(), timeout.Milliseconds())
	}

	clientOptions := options.Client().ApplyURI(uri)

	authCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	client, err := mongo.Connect(authCtx, clientOptions)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{
			Success:   false,
			ErrorType: classifyMongoDBErrorType(err),
			Error:     err,
		}
	}
	state.IncrementTCPSuccessPacketCount()

	err = client.Ping(authCtx, nil)
	if err != nil {
		_ = client.Disconnect(authCtx)
		return &AuthResult{
			Success:   false,
			ErrorType: classifyMongoDBErrorType(err),
			Error:     err,
		}
	}

	return &AuthResult{
		Success:   true,
		Conn:      &mongoClientWrapper{client, ctx},
		ErrorType: ErrorTypeUnknown,
		Error:     nil,
	}
}

// mongoClientWrapper 包装 mongo.Client 以实现 io.Closer
type mongoClientWrapper struct {
	*mongo.Client
	ctx context.Context
}

func (w *mongoClientWrapper) Close() error {
	return w.Disconnect(w.ctx)
}

// classifyMongoDBErrorType MongoDB错误分类
func classifyMongoDBErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	mongoAuthErrors := []string{
		"authentication failed",
		"auth mechanism",
		"unauthorized",
		"scram",
		"credential",
		"invalid username",
		"invalid password",
		"login failed",
		"access denied",
		"authentication mechanism",
		"sasl",
		"mongo auth",
		"bad auth",
		"wrong credentials",
	}

	mongoNetworkErrors := append(CommonNetworkErrors,
		"dial tcp",
		"connection closed",
		"eof",
		"server selection timeout",
		"connection pool closed",
		"no reachable servers",
		"topology",
		"network error",
	)

	return ClassifyError(err, mongoAuthErrors, mongoNetworkErrors)
}

func (p *MongoDBPlugin) identifyService(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	target := info.Target()

	isUnauth, err := p.mongodbUnauth(ctx, info, session)
	if err != nil {
		return &ScanResult{
			Success: false,
			Service: "mongodb",
			Error:   err,
		}
	}

	if isUnauth {
		common.LogVuln(i18n.Tr("mongodb_unauth", target))
		return &ScanResult{
			Type:    plugins.ResultTypeVuln,
			Success: true,
			Service: "mongodb",
			VulInfo: "未授权访问",
		}
	}

	common.LogSuccess(i18n.Tr("mongodb_auth_required", target))
	return &ScanResult{
		Type:    plugins.ResultTypeService,
		Success: true,
		Service: "mongodb",
		Banner:  "需要认证",
	}
}

// mongodbUnauth 检测MongoDB未授权访问
func (p *MongoDBPlugin) mongodbUnauth(ctx context.Context, info *common.HostInfo, session *common.ScanSession) (bool, error) {
	msgPacket := p.createOpMsgPacket()
	queryPacket := p.createOpQueryPacket()
	realhost := fmt.Sprintf("%s:%d", info.Host, info.Port)

	reply, err := p.checkMongoAuth(ctx, realhost, msgPacket, session)
	if err != nil {
		reply, err = p.checkMongoAuth(ctx, realhost, queryPacket, session)
		if err != nil {
			return false, err
		}
	}

	if strings.Contains(reply, "totalLinesWritten") {
		return true, nil
	}

	if len(reply) > 0 {
		return false, nil
	}

	return false, fmt.Errorf("无法识别为MongoDB服务")
}

// checkMongoAuth 检查MongoDB认证状态
func (p *MongoDBPlugin) checkMongoAuth(ctx context.Context, address string, packet []byte, session *common.ScanSession) (string, error) {
	conn, err := session.DialTCP(ctx, "tcp", address, session.Config.Timeout)
	if err != nil {
		return "", fmt.Errorf("连接失败: %w", err)
	}
	defer func() { _ = conn.Close() }()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	if deadlineErr := conn.SetDeadline(time.Now().Add(session.Config.Timeout)); deadlineErr != nil {
		return "", fmt.Errorf("设置超时失败: %w", deadlineErr)
	}

	if _, writeErr := conn.Write(packet); writeErr != nil {
		return "", fmt.Errorf("发送查询失败: %w", writeErr)
	}

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	reply := make([]byte, 2048)
	count, err := conn.Read(reply)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("读取响应失败: %w", err)
	}

	if count == 0 {
		return "", fmt.Errorf("收到空响应")
	}

	return string(reply[:count]), nil
}

// createOpMsgPacket 创建OP_MSG查询包
func (p *MongoDBPlugin) createOpMsgPacket() []byte {
	return []byte{
		0x69, 0x00, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xdd, 0x07, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00,
		0x00, 0x02, 0x67, 0x65, 0x74, 0x4c, 0x6f, 0x67,
		0x00, 0x10, 0x00, 0x00, 0x00, 0x73, 0x74, 0x61,
		0x72, 0x74, 0x75, 0x70, 0x57, 0x61, 0x72, 0x6e,
		0x69, 0x6e, 0x67, 0x73, 0x00, 0x02, 0x24, 0x64,
		0x62, 0x00, 0x06, 0x00, 0x00, 0x00, 0x61, 0x64,
		0x6d, 0x69, 0x6e, 0x00, 0x03, 0x6c, 0x73, 0x69,
		0x64, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x05, 0x69,
		0x64, 0x00, 0x10, 0x00, 0x00, 0x00, 0x04, 0x6e,
		0x81, 0xf8, 0x8e, 0x37, 0x7b, 0x4c, 0x97, 0x84,
		0x4e, 0x90, 0x62, 0x5a, 0x54, 0x3c, 0x93, 0x00, 0x00,
	}
}

// createOpQueryPacket 创建OP_QUERY查询包
func (p *MongoDBPlugin) createOpQueryPacket() []byte {
	return []byte{
		0x48, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69,
		0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x21,
		0x00, 0x00, 0x00, 0x02, 0x67, 0x65, 0x74, 0x4c,
		0x6f, 0x67, 0x00, 0x10, 0x00, 0x00, 0x00, 0x73,
		0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x57, 0x61,
		0x72, 0x6e, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x00,
	}
}

func init() {
	RegisterPluginWithPorts("mongodb", func() Plugin {
		return NewMongoDBPlugin()
	}, []int{27017, 27018, 27019})
}
