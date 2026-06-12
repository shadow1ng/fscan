//go:build plugin_cassandra || !plugin_selective

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

// CassandraPlugin Cassandra扫描插件（纯 raw TCP CQL 协议实现）
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
		return p.identifyService(ctx, info, session)
	}

	// 先尝试无认证连接
	if result := p.tryNoAuthConnection(ctx, info, session); result != nil && result.Success {
		return result
	}

	credentials := GenerateCredentials("cassandra", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "cassandra",
			Error:   fmt.Errorf("%s", i18n.GetText("service_no_credentials")),
		}
	}

	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "cassandra", testConfig)

	if result.Success {
		session.LogVuln(i18n.Tr("cassandra_credential", target, result.Username, result.Password))
	}

	return result
}

func (p *CassandraPlugin) createAuthFunc(info *common.HostInfo, config *common.Config, state *common.State) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doCassandraAuth(ctx, info, cred, config, state)
	}
}

// ── raw TCP Cassandra CQL 协议 ──────────────────────────────────

// CQL frame 格式 (v4):
//
//	[1B version|flags] [2B stream] [1B opcode] [4B length] [body]
const (
	cqlVersion      = 0x84 // version=4, direction=request
	cqlOpStartup    = 0x01
	cqlOpAuthRsp    = 0x0f
	cqlOpQuery      = 0x07
	cqlOpResult     = 0x08
	cqlOpReady      = 0x02
	cqlOpAuthOk     = 0x10
	cqlOpAuthChl    = 0x0e
	cqlOpError      = 0x00
	maxCQLFrameBody = 1024 * 1024
)

func (p *CassandraPlugin) doCassandraAuth(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) *AuthResult {
	addr := info.Target()
	timeout := config.Timeout

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{Success: false, ErrorType: classifyCassandraErrorType(err), Error: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Step 1: STARTUP (CQL_VERSION=3.0.0)
	startupBody := cqlStringMap(map[string]string{"CQL_VERSION": "3.0.0"})
	if err := cqlSend(conn, cqlOpStartup, startupBody); err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{Success: false, ErrorType: ErrorTypeNetwork, Error: err}
	}

	// Step 2: 读取响应
	opcode, body, err := cqlRecv(conn)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{Success: false, ErrorType: ErrorTypeNetwork, Error: err}
	}

	// READY → 已就绪，发送测试查询
	// AUTHENTICATE → 需要认证
	// ERROR → 错误
	if opcode == cqlOpError {
		return &AuthResult{Success: false, ErrorType: ErrorTypeAuth, Error: fmt.Errorf("cassandra error: %s", string(body))}
	}

	// Step 3: 如果需要认证
	if opcode == cqlOpAuthChl {
		if cred.Username == "" && cred.Password == "" {
			return &AuthResult{Success: false, ErrorType: ErrorTypeAuth, Error: fmt.Errorf("authentication required")}
		}
		// SASL PLAIN: \x00username\x00password
		saslToken := []byte("\x00" + cred.Username + "\x00" + cred.Password)
		if err := cqlSend(conn, cqlOpAuthRsp, saslToken); err != nil {
			state.IncrementTCPFailedPacketCount()
			return &AuthResult{Success: false, ErrorType: ErrorTypeNetwork, Error: err}
		}
		opcode, body, err = cqlRecv(conn)
		if err != nil {
			state.IncrementTCPFailedPacketCount()
			return &AuthResult{Success: false, ErrorType: ErrorTypeNetwork, Error: err}
		}
		// AUTH_SUCCESS → 认证成功
		// ERROR → 认证失败
		if opcode == cqlOpError {
			return &AuthResult{Success: false, ErrorType: ErrorTypeAuth, Error: fmt.Errorf("authentication failed: %s", string(body))}
		}
		if opcode != cqlOpAuthOk && opcode != cqlOpReady {
			return &AuthResult{Success: false, ErrorType: ErrorTypeAuth, Error: fmt.Errorf("unexpected opcode: %d", opcode)}
		}
	}

	// Step 4: 发送测试查询
	queryBody := cqlLongString("SELECT cluster_name FROM system.local")
	// 添加 consistency level (ONE=1)
	queryBody = append(queryBody, 0x00, 0x01) // flags=0, consistency=ONE
	if err := cqlSend(conn, cqlOpQuery, queryBody); err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{Success: false, ErrorType: ErrorTypeNetwork, Error: err}
	}
	opcode, body, err = cqlRecv(conn)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{Success: false, ErrorType: ErrorTypeNetwork, Error: err}
	}
	if err := validateCQLQueryResponse(opcode, body); err != nil {
		return &AuthResult{Success: false, ErrorType: ErrorTypeAuth, Error: err}
	}

	state.IncrementTCPSuccessPacketCount()
	return &AuthResult{Success: true, ErrorType: ErrorTypeUnknown, Error: nil}
}

// ── CQL wire protocol 工具 ──────────────────────────────────────

var cqlStreamID uint32

func nextCQLStreamID() uint16 {
	return uint16((atomic.AddUint32(&cqlStreamID, 1) - 1) & 0x7fff)
}

func cqlSend(conn net.Conn, opcode byte, body []byte) error {
	id := nextCQLStreamID()

	// frame: [1B version|flags] [2B stream] [1B opcode] [4B length] [body]
	header := make([]byte, 8)
	header[0] = cqlVersion
	binary.BigEndian.PutUint16(header[1:3], id)
	header[3] = opcode
	binary.BigEndian.PutUint32(header[4:8], uint32(len(body)))

	buf := append(header, body...)
	_, err := conn.Write(buf)
	return err
}

func cqlRecv(conn io.Reader) (byte, []byte, error) {
	// 读取 9 字节头部（响应也有额外标志字节）
	header := make([]byte, 9)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	opcode := header[4]
	bodyLen := int(binary.BigEndian.Uint32(header[5:9]))
	if bodyLen == 0 {
		return opcode, []byte{}, nil
	}
	if bodyLen > maxCQLFrameBody {
		return opcode, nil, fmt.Errorf("cassandra frame too large: %d", bodyLen)
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return opcode, nil, err
	}
	return opcode, body, nil
}

func validateCQLQueryResponse(opcode byte, body []byte) error {
	if opcode == cqlOpError {
		return fmt.Errorf("cassandra query failed: %s", string(body))
	}
	if opcode != cqlOpResult {
		return fmt.Errorf("unexpected query opcode: %d", opcode)
	}
	return nil
}

// cqlStringMap CQL string map 编码: [2B count] [pairs: [2B len] [str]]
func cqlStringMap(m map[string]string) []byte {
	var buf []byte
	buf = append(buf, 0x00, byte(len(m))) // count as short
	for k, v := range m {
		buf = append(buf, cqlShortString(k)...)
		buf = append(buf, cqlShortString(v)...)
	}
	return buf
}

func cqlShortString(s string) []byte {
	b := []byte(s)
	buf := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(buf, uint16(len(b)))
	copy(buf[2:], b)
	return buf
}

func cqlLongString(s string) []byte {
	b := []byte(s)
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	return buf
}

// ── 错误分类 ────────────────────────────────────────────────────

func classifyCassandraErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}
	cassandraAuthErrors := []string{
		"authentication failed",
		"bad credentials",
		"invalid credentials",
		"unauthorized",
	}
	return ClassifyError(err, cassandraAuthErrors, CommonNetworkErrors)
}

// ── 无认证 + 服务识别 ──────────────────────────────────────────

func (p *CassandraPlugin) tryNoAuthConnection(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	target := info.Target()
	addr := info.Target()
	timeout := config.Timeout

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// STARTUP
	if err := cqlSend(conn, cqlOpStartup, cqlStringMap(map[string]string{"CQL_VERSION": "3.0.0"})); err != nil {
		state.IncrementTCPFailedPacketCount()
		return nil
	}
	opcode, body, err := cqlRecv(conn)
	if err != nil || opcode != cqlOpReady {
		return nil
	}

	// QUERY test
	queryBody := append(cqlLongString("SELECT cluster_name FROM system.local"), 0x00, 0x01)
	if err := cqlSend(conn, cqlOpQuery, queryBody); err != nil {
		return nil
	}
	opcode, body, err = cqlRecv(conn)
	if err != nil {
		return nil
	}
	if err := validateCQLQueryResponse(opcode, body); err != nil {
		return nil
	}

	state.IncrementTCPSuccessPacketCount()
	dummy := extractClusterName(body)

	session.LogVuln(i18n.Tr("cassandra_unauth", target))
	return &ScanResult{
		Type:    plugins.ResultTypeService,
		Success: true,
		Service: "cassandra",
		Banner:  i18n.Tr("cassandra_no_auth_cluster", dummy),
	}
}

func (p *CassandraPlugin) identifyService(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	target := info.Target()
	addr := info.Target()
	timeout := config.Timeout

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &ScanResult{Success: false, Service: "cassandra", Error: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := cqlSend(conn, cqlOpStartup, cqlStringMap(map[string]string{"CQL_VERSION": "3.0.0"})); err != nil {
		state.IncrementTCPFailedPacketCount()
		return &ScanResult{Success: false, Service: "cassandra", Error: err}
	}
	opcode, _, err := cqlRecv(conn)
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &ScanResult{Success: false, Service: "cassandra", Error: err}
	}

	state.IncrementTCPSuccessPacketCount()

	if opcode == cqlOpAuthChl {
		banner := i18n.GetText("cassandra_auth_required")
		session.LogSuccess(i18n.Tr("cassandra_service", target, banner))
		return &ScanResult{Type: plugins.ResultTypeService, Success: true, Service: "cassandra", Banner: banner}
	}

	banner := "Cassandra"
	session.LogSuccess(i18n.Tr("cassandra_service", target, banner))
	return &ScanResult{Type: plugins.ResultTypeService, Success: true, Service: "cassandra", Banner: banner}
}

// extractClusterName 从 CQL ROWS result body 提取 cluster_name
func extractClusterName(body []byte) string {
	s := string(body)
	// 简单查找可打印的 UTF8 字符串作为 cluster_name 候选
	if len(s) > 3 {
		// CQL ROWS result: [4B rows_count] [rows data...]
		// cluster_name 通常以可读字符串形式出现在响应中
		for i := 0; i < len(s)-2; i++ {
			if s[i] >= 0x20 && s[i] < 0x7f {
				// 提取连续可打印字符串
				j := i
				for j < len(s) && s[j] >= 0x20 && s[j] < 0x7f {
					j++
				}
				if j-i >= 3 && j-i <= 64 {
					return s[i:j]
				}
				i = j
			}
		}
	}
	return "unknown"
}

func init() {
	RegisterPluginWithPorts("cassandra", func() Plugin {
		return NewCassandraPlugin()
	}, []int{9042, 9160, 7000, 7001})
}
