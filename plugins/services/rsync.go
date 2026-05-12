//go:build (plugin_rsync || !plugin_selective) && go1.21

package services

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
	"go.ciq.dev/go-rsync/rsync"
)

// RsyncPlugin Rsync扫描插件
type RsyncPlugin struct {
	plugins.BasePlugin
}

func NewRsyncPlugin() *RsyncPlugin {
	return &RsyncPlugin{
		BasePlugin: plugins.NewBasePlugin("rsync"),
	}
}

func (p *RsyncPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	target := info.Target()

	if config.DisableBrute {
		return p.identifyService(ctx, info, session)
	}

	var findings []string

	// 检测未授权访问
	if result := p.testUnauthorizedAccess(ctx, info, session); result != nil && result.Success {
		common.LogSuccess(i18n.Tr("rsync_service", target, result.Banner))
		findings = append(findings, result.Banner)
	}

	// 生成密码字典
	credentials := plugins.GenerateCredentials("rsync", config)
	if len(credentials) == 0 {
		if len(findings) > 0 {
			return &ScanResult{
				Success: true,
				Type:    plugins.ResultTypeService,
				Service: "rsync",
				Banner:  findings[0],
			}
		}
		return &ScanResult{
			Success: false,
			Service: "rsync",
			Error:   fmt.Errorf("没有可用的测试凭据"),
		}
	}

	// 转换凭据类型
	creds := make([]Credential, len(credentials))
	for i, c := range credentials {
		creds[i] = Credential{Username: c.Username, Password: c.Password}
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, session)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, creds, authFn, "rsync", testConfig)

	if result.Success {
		common.LogVuln(i18n.Tr("rsync_credential", target, result.Username, result.Password))
		return result
	}

	// 如果暴力破解失败但有未授权访问发现，返回该结果
	if len(findings) > 0 {
		return &ScanResult{
			Success: true,
			Type:    plugins.ResultTypeService,
			Service: "rsync",
			Banner:  findings[0],
		}
	}

	return &ScanResult{
		Success: false,
		Service: "rsync",
	}
}

// createAuthFunc 创建Rsync认证函数
func (p *RsyncPlugin) createAuthFunc(info *common.HostInfo, session *common.ScanSession) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doRsyncAuth(ctx, info, cred, session)
	}
}

// doRsyncAuth 执行Rsync认证
func (p *RsyncPlugin) doRsyncAuth(ctx context.Context, info *common.HostInfo, cred Credential, session *common.ScanSession) *AuthResult {
	// 先获取可用模块列表
	conn := p.connectToRsync(ctx, info, session)
	if conn == nil {
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeNetwork,
			Error:     fmt.Errorf("无法连接到Rsync服务"),
		}
	}
	modules := p.getModules(conn, session.Config)
	_ = conn.Close()

	if len(modules) == 0 {
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeUnknown,
			Error:     fmt.Errorf("无法获取模块列表"),
		}
	}

	// 提取第一个模块名
	firstModuleLine := modules[0]
	firstModule := strings.Fields(firstModuleLine)[0]

	// 使用 go-rsync 库进行认证测试
	address := fmt.Sprintf("%s:%d", info.Host, info.Port)
	dummyFS := &dummyStorage{}

	_, err := rsync.SocketClient(
		dummyFS,
		address,
		firstModule,
		"/",
		rsync.WithClientAuth(cred.Username, cred.Password),
	)

	if err != nil {
		errMsg := err.Error()
		if common.ContainsAny(errMsg, "auth", "password") {
			return &AuthResult{
				Success:   false,
				ErrorType: ErrorTypeAuth,
				Error:     err,
			}
		}
		return &AuthResult{
			Success:   false,
			ErrorType: classifyRsyncErrorType(err),
			Error:     err,
		}
	}

	return &AuthResult{
		Success:   true,
		Conn:      &rsyncConnWrapper{},
		ErrorType: ErrorTypeUnknown,
		Error:     nil,
	}
}

// rsyncConnWrapper 包装Rsync连接以实现io.Closer
type rsyncConnWrapper struct{}

func (w *rsyncConnWrapper) Close() error {
	return nil
}

// dummyStorage 空的 FS 实现，用于认证测试
type dummyStorage struct{}

func (d *dummyStorage) Put(fileName string, content io.Reader, fileSize int64, metadata rsync.FileMetadata) (written int64, err error) {
	return 0, fmt.Errorf("not implemented")
}

func (d *dummyStorage) Delete(fileName string, mode rsync.FileMode) error {
	return fmt.Errorf("not implemented")
}

func (d *dummyStorage) List() (rsync.FileList, error) {
	return nil, fmt.Errorf("not implemented")
}

// classifyRsyncErrorType Rsync错误分类
func classifyRsyncErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	rsyncAuthErrors := []string{
		"auth",
		"password",
		"authentication failed",
		"access denied",
		"unauthorized",
		"invalid credentials",
	}

	return ClassifyError(err, rsyncAuthErrors, CommonNetworkErrors)
}

// testUnauthorizedAccess 测试未授权访问
func (p *RsyncPlugin) testUnauthorizedAccess(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	conn := p.connectToRsync(ctx, info, session)
	if conn == nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	modules := p.getModules(conn, session.Config)

	if len(modules) > 0 {
		banner := fmt.Sprintf("未授权访问 - 可用模块: %s", strings.Join(modules, ", "))
		return &ScanResult{
			Success: true,
			Type:    plugins.ResultTypeService,
			Service: "rsync",
			Banner:  banner,
		}
	}

	return nil
}

// connectToRsync 连接到Rsync服务
func (p *RsyncPlugin) connectToRsync(ctx context.Context, info *common.HostInfo, session *common.ScanSession) net.Conn {
	target := info.Target()
	timeout := session.Config.Timeout

	connChan := make(chan net.Conn, 1)

	go func() {
		conn, err := session.DialTCP(ctx, "tcp", target, timeout)
		if err != nil {
			connChan <- nil
			return
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		connChan <- conn
	}()

	select {
	case conn := <-connChan:
		return conn
	case <-ctx.Done():
		go func() {
			conn := <-connChan
			if conn != nil {
				_ = conn.Close()
			}
		}()
		return nil
	}
}

// getModules 获取Rsync模块列表
func (p *RsyncPlugin) getModules(conn net.Conn, config *common.Config) []string {
	timeout := config.Timeout

	// 读取服务器版本
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	versionBuf := make([]byte, 256)
	n, err := conn.Read(versionBuf)
	if err != nil {
		return nil
	}
	_ = string(versionBuf[:n])

	// 回复客户端版本
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("@RSYNCD: 31.0\n")); err != nil {
		return nil
	}

	// 发送模块列表请求
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("\n")); err != nil {
		return nil
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	scanner := bufio.NewScanner(conn)

	var modules []string
	hasError := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "@RSYNCD: EXIT") {
			break
		}

		if strings.HasPrefix(line, "@RSYNCD:") {
			continue
		}

		if strings.HasPrefix(line, "@ERROR:") {
			hasError = true
			break
		}

		modules = append(modules, line)
	}

	if hasError {
		return nil
	}

	return modules
}

// identifyService Rsync服务识别
func (p *RsyncPlugin) identifyService(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	target := info.Target()

	conn := p.connectToRsync(ctx, info, session)
	if conn == nil {
		return &ScanResult{
			Success: false,
			Service: "rsync",
			Error:   fmt.Errorf("无法连接到Rsync服务"),
		}
	}
	defer func() { _ = conn.Close() }()

	timeout := session.Config.Timeout

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("\n")); err != nil {
		return &ScanResult{
			Success: false,
			Service: "rsync",
			Error:   err,
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return &ScanResult{
			Success: false,
			Service: "rsync",
			Error:   err,
		}
	}

	responseStr := string(response[:n])

	var banner string

	if strings.Contains(responseStr, "@RSYNCD") {
		lines := strings.Split(responseStr, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "@RSYNCD:") {
				banner = fmt.Sprintf("Rsync服务 (%s)", strings.TrimSpace(line))
				break
			}
		}
		if banner == "" {
			banner = "Rsync文件同步服务"
		}
	} else {
		return &ScanResult{
			Success: false,
			Service: "rsync",
			Error:   fmt.Errorf("无法识别为Rsync服务"),
		}
	}

	common.LogSuccess(i18n.Tr("rsync_service", target, banner))

	return &ScanResult{
		Success: true,
		Type:    plugins.ResultTypeService,
		Service: "rsync",
		Banner:  banner,
	}
}

func init() {
	RegisterPluginWithPorts("rsync", func() Plugin {
		return NewRsyncPlugin()
	}, []int{873})
}
