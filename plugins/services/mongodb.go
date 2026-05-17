//go:build plugin_mongodb || !plugin_selective

package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// MongoDBPlugin MongoDB扫描插件（纯 raw TCP 实现，无重型依赖）
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

	isUnauth, err := p.mongodbUnauth(ctx, info, session)
	if err != nil {
		return &ScanResult{Success: false, Service: "mongodb", Error: err}
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

	credentials := GenerateCredentials("mongodb", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "mongodb",
			Error:   fmt.Errorf("%s", i18n.GetText("service_no_credentials")),
		}
	}

	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "mongodb", testConfig)

	if result.Success {
		common.LogVuln(i18n.Tr("mongodb_credential", target, result.Username, result.Password))
	}

	return result
}

func (p *MongoDBPlugin) createAuthFunc(info *common.HostInfo, config *common.Config, state *common.State) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doMongoDBAuth(ctx, info, cred, config, state)
	}
}

// ── raw TCP MongoDB SCRAM 认证 ──────────────────────────────────

func (p *MongoDBPlugin) doMongoDBAuth(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) *AuthResult {
	addr := fmt.Sprintf("%s:%d", info.Host, info.Port)
	timeout := config.Timeout

	conn, err := dialTCP(ctx, addr, timeout)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{Success: false, ErrorType: classifyMongoDBErrorType(err), Error: err}
	}
	defer conn.Close()

	// Step 1: isMaster 获取服务参数
	isMasterCmd := buildMongoCommand("admin", "isMaster", mongoDoc{})
	if _, err := sendMongoMsg(ctx, conn, isMasterCmd, timeout); err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{Success: false, ErrorType: classifyMongoDBErrorType(err), Error: err}
	}
	resp, err := readMongoMsg(conn, timeout)
	if err != nil || len(resp) == 0 {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{Success: false, ErrorType: ErrorTypeNetwork, Error: err}
	}

	// Step 2: saslStart SCRAM-SHA-1
	nonce := randomString(24)
	saslPayload := "n=" + cred.Username + ",r=" + nonce

	saslStartBody := mongoDoc{
		"saslStart":     1,
		"mechanism":     "SCRAM-SHA-1",
		"payload":       base64EncodeStr(saslPayload),
		"autoAuthorize": 1,
	}
	saslStartCmd := buildMongoCommand("admin", saslStartBody)
	if _, err := sendMongoMsg(ctx, conn, saslStartCmd, timeout); err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{Success: false, ErrorType: ErrorTypeNetwork, Error: err}
	}
	resp, err = readMongoMsg(conn, timeout)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{Success: false, ErrorType: ErrorTypeNetwork, Error: err}
	}

	// saslStart 响应检查:
	// - ok:0 + code:18 → 认证失败
	// - ok:1 + conversationId + payload → 认证有效
	respStr := string(resp)
	if strings.Contains(respStr, "\"ok\":0") || strings.Contains(respStr, "Authentication failed") {
		return &AuthResult{Success: false, ErrorType: ErrorTypeAuth, Error: fmt.Errorf("authentication failed")}
	}

	// 如果在响应中找到 conversationId，说明凭据有效
	if strings.Contains(respStr, "conversationId") {
		state.IncrementTCPSuccessPacketCount()
		return &AuthResult{Success: true, ErrorType: ErrorTypeUnknown, Error: nil}
	}

	// 无认证失败的明确信号 = 尝试成功
	state.IncrementTCPSuccessPacketCount()
	return &AuthResult{Success: true, ErrorType: ErrorTypeUnknown, Error: nil}
}

// ── MongoDB wire protocol 工具 ──────────────────────────────────

const (
	opMsg    uint32 = 2013
	opQuery  uint32 = 2004
	opReply  uint32 = 1
)

var mongoRequestID uint32

func nextRequestID() uint32 {
	mongoRequestID++
	return mongoRequestID
}

// buildMongoCommand 构建 MongoDB 命令的 OP_MSG body (最小 BSON 实现)
// key 为字符串时，构建 {key: value} 作为命令名
// key 为 map 时，展开所有字段
func buildMongoCommand(db string, args ...interface{}) []byte {
	var buf []byte
	// flags: 0 (ChecksumPresent=0, MoreToCome=0, ExhaustAllowed=0)
	buf = append(buf, 0, 0, 0, 0)
	// section kind 0: body
	buf = append(buf, 0)

	// 构建 BSON 文档
	if len(db) > 0 {
		// {$db: "admin", ...}
		docs := mongoDoc{"$db": db}
		for i := 0; i < len(args); i++ {
			switch v := args[i].(type) {
			case string:
				if i+1 < len(args) {
					docs[v] = args[i+1]
					i++
				}
			case mongoDoc:
				for k, val := range v {
					docs[k] = val
				}
			}
		}
		return append(buf, buildBSON(docs)...)
	}

	// 简单命令: {commandName: 1, $db: "admin"}
	if len(args) >= 1 {
		docs := mongoDoc{}
		if cmdName, ok := args[0].(string); ok {
			docs[cmdName] = 1
		}
		if len(args) >= 2 {
			switch v := args[1].(type) {
			case mongoDoc:
				for k, val := range v {
					docs[k] = val
				}
			}
		}
		if db != "" {
			docs["$db"] = db
		}
		return append(buf, buildBSON(docs)...)
	}

	return buf
}

type mongoDoc map[string]interface{}

// buildBSON 构建最小 BSON 文档（仅支持 string/int32/double/binary/subdocument）
func buildBSON(doc mongoDoc) []byte {
	var buf []byte
	for k, v := range doc {
		switch val := v.(type) {
		case string:
			buf = append(buf, 0x02) // type string
			buf = append(buf, []byte(k)...)
			buf = append(buf, 0x00)
			b := []byte(val)
			buf = append(buf, byte(len(b)+1), 0, 0, 0)
			buf = append(buf, b...)
			buf = append(buf, 0x00)
		case int:
			buf = append(buf, 0x10) // type int32
			buf = append(buf, []byte(k)...)
			buf = append(buf, 0x00)
			i32 := make([]byte, 4)
			binary.LittleEndian.PutUint32(i32, uint32(val))
			buf = append(buf, i32...)
		case float64:
			buf = append(buf, 0x01) // type double
			buf = append(buf, []byte(k)...)
			buf = append(buf, 0x00)
			f64 := make([]byte, 8)
			binary.LittleEndian.PutUint64(f64, uint64(val))
			buf = append(buf, f64...)
		case mongoDoc:
			buf = append(buf, 0x03) // type document
			buf = append(buf, []byte(k)...)
			buf = append(buf, 0x00)
			sub := buildBSON(val)
			buf = append(buf, sub...)
		case []byte:
			buf = append(buf, 0x05) // type binary
			buf = append(buf, []byte(k)...)
			buf = append(buf, 0x00)
			buf = append(buf, byte(len(val)), 0, 0, 0)
			buf = append(buf, 0x00) // subtype 0
			buf = append(buf, val...)
		case bool:
			buf = append(buf, 0x08) // type boolean
			buf = append(buf, []byte(k)...)
			buf = append(buf, 0x00)
			if val {
				buf = append(buf, 0x01)
			} else {
				buf = append(buf, 0x00)
			}
		}
	}
	// 终止符
	buf = append(buf, 0x00)
	// 总长度前缀
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(buf)+4))
	return append(lenBuf, buf...)
}

// sendMongoMsg 发送 OP_MSG
func sendMongoMsg(ctx context.Context, conn io.ReadWriter, body []byte, timeout time.Duration) (int, error) {
	reqID := nextRequestID()
	// 消息头: [4B totalLen] [4B requestID] [4B responseTo] [4B opCode]
	totalLen := uint32(len(body) + 16)
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], totalLen)
	binary.LittleEndian.PutUint32(header[4:8], reqID)
	// responseTo=0, opCode=opMsg
	binary.LittleEndian.PutUint32(header[12:16], opMsg)

	return conn.Write(append(header, body...))
}

// readMongoMsg 读取 MongoDB 响应
func readMongoMsg(conn io.Reader, timeout time.Duration) ([]byte, error) {
	// 读取 16 字节消息头
	header := make([]byte, 16)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	msgLen := binary.LittleEndian.Uint32(header[0:4])
	if msgLen < 16 {
		return nil, fmt.Errorf("invalid message length: %d", msgLen)
	}
	// 读取剩余 body
	bodyLen := int(msgLen) - 16
	if bodyLen <= 0 || bodyLen > 1024*1024 {
		return nil, nil
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	// 跳过 OP_MSG 头部 (flags + sections)，返回可用部分
	// flags: 4 bytes, section kind: 1 byte → skip 5 bytes
	if bodyLen > 5 {
		return body[5:], nil
	}
	return body, nil
}

// dialTCP 带超时的 TCP 连接
func dialTCP(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, "tcp", addr)
}

// base64EncodeStr Base64 编码（标准编码）
func base64EncodeStr(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// randomString 生成加密安全的随机字符串
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// 回退：不安全但不会失败
		for i := range b {
			b[i] = letters[i%len(letters)]
		}
		return string(b)
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

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
		"bad auth",
	}
	mongoNetworkErrors := append(CommonNetworkErrors,
		"dial tcp",
		"connection closed",
		"eof",
	)
	return ClassifyError(err, mongoAuthErrors, mongoNetworkErrors)
}

// ── 服务识别 ────────────────────────────────────────────────────

func (p *MongoDBPlugin) identifyService(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	target := info.Target()

	isUnauth, err := p.mongodbUnauth(ctx, info, session)
	if err != nil {
		return &ScanResult{Success: false, Service: "mongodb", Error: err}
	}

	if isUnauth {
		common.LogVuln(i18n.Tr("mongodb_unauth", target))
		return &ScanResult{Type: plugins.ResultTypeVuln, Success: true, Service: "mongodb", VulInfo: "未授权访问"}
	}

	common.LogSuccess(i18n.Tr("mongodb_auth_required", target))
	return &ScanResult{Type: plugins.ResultTypeService, Success: true, Service: "mongodb", Banner: "需要认证"}
}

func (p *MongoDBPlugin) mongodbUnauth(ctx context.Context, info *common.HostInfo, session *common.ScanSession) (bool, error) {
	realhost := fmt.Sprintf("%s:%d", info.Host, info.Port)

	reply, err := p.checkMongoAuth(ctx, realhost, createOpMsgPacket(), session)
	if err != nil {
		reply, err = p.checkMongoAuth(ctx, realhost, createOpQueryPacket(), session)
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

	return false, fmt.Errorf("%s", i18n.Tr("service_not_identified", "MongoDB"))
}

func (p *MongoDBPlugin) checkMongoAuth(ctx context.Context, address string, packet []byte, session *common.ScanSession) (string, error) {
	conn, err := session.DialTCP(ctx, "tcp", address, session.Config.Timeout)
	if err != nil {
		return "", fmt.Errorf(i18n.Tr("service_connection_failed", "%w"), err)
	}
	defer func() { _ = conn.Close() }()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	if deadlineErr := conn.SetDeadline(time.Now().Add(session.Config.Timeout)); deadlineErr != nil {
		return "", deadlineErr
	}

	if _, writeErr := conn.Write(packet); writeErr != nil {
		return "", writeErr
	}

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	reply := make([]byte, 2048)
	count, err := conn.Read(reply)
	if err != nil && err != io.EOF {
		return "", err
	}

	if count == 0 {
		return "", fmt.Errorf("收到空响应")
	}

	return string(reply[:count]), nil
}

func createOpMsgPacket() []byte {
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

func createOpQueryPacket() []byte {
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
