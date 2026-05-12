//go:build plugin_ftp || !plugin_selective

package services

import (
	"context"
	"fmt"
	"strings"

	ftplib "github.com/jlaffaye/ftp"
	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// FTPPlugin FTP扫描插件
type FTPPlugin struct {
	plugins.BasePlugin
}

func NewFTPPlugin() *FTPPlugin {
	return &FTPPlugin{
		BasePlugin: plugins.NewBasePlugin("ftp"),
	}
}

func (p *FTPPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	if config.DisableBrute {
		return p.identifyService(info, config, state)
	}

	target := info.Target()

	// 优先检测匿名访问
	if result := p.testAnonymousAccess(ctx, info, config, state); result != nil && result.Success {
		return result
	}

	credentials := GenerateCredentials("ftp", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "ftp",
			Error:   fmt.Errorf("没有可用的测试凭据"),
		}
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "ftp", testConfig)

	if result.Success {
		// 成功后重新连接获取文件列表
		fileList := p.getFileListAfterAuth(info, result.Username, result.Password, config, state)
		var output strings.Builder
		output.WriteString(fmt.Sprintf("FTP %s %s:%s", target, result.Username, result.Password))
		if len(fileList) > 0 {
			for _, file := range fileList {
				output.WriteString(fmt.Sprintf("\n   [->] %s", file))
			}
		}
		common.LogVuln(output.String())
	}

	return result
}

// createAuthFunc 创建FTP认证函数
func (p *FTPPlugin) createAuthFunc(info *common.HostInfo, config *common.Config, state *common.State) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doFTPAuth(ctx, info, cred, config, state)
	}
}

// doFTPAuth 执行FTP认证
func (p *FTPPlugin) doFTPAuth(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) *AuthResult {
	target := info.Target()

	conn, err := ftplib.Dial(target, ftplib.DialWithTimeout(config.Timeout))
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &AuthResult{
			Success:   false,
			ErrorType: classifyFTPErrorType(err),
			Error:     err,
		}
	}
	state.IncrementTCPSuccessPacketCount()

	err = conn.Login(cred.Username, cred.Password)
	if err != nil {
		_ = conn.Quit()
		return &AuthResult{
			Success:   false,
			ErrorType: classifyFTPErrorType(err),
			Error:     err,
		}
	}

	return &AuthResult{
		Success:   true,
		Conn:      &ftpConnWrapper{conn},
		ErrorType: ErrorTypeUnknown,
		Error:     nil,
	}
}

// ftpConnWrapper 包装 ftplib.ServerConn 以实现 io.Closer
type ftpConnWrapper struct {
	*ftplib.ServerConn
}

func (w *ftpConnWrapper) Close() error {
	return w.Quit()
}

// classifyFTPErrorType FTP错误分类
func classifyFTPErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	ftpAuthErrors := []string{
		"530 login incorrect",
		"530 not logged in",
		"530 user cannot log in",
		"530 authentication failed",
		"authentication failed",
		"permission denied",
		"access denied",
		"invalid credentials",
		"bad password",
		"login incorrect",
	}

	ftpNetworkErrors := append(CommonNetworkErrors,
		"421 there are too many connections",
	)

	return ClassifyError(err, ftpAuthErrors, ftpNetworkErrors)
}

func (p *FTPPlugin) identifyService(info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()

	conn, err := ftplib.Dial(target, ftplib.DialWithTimeout(config.Timeout))
	if err != nil {
		state.IncrementTCPFailedPacketCount()
		return &ScanResult{
			Success: false,
			Service: "ftp",
			Error:   err,
		}
	}
	state.IncrementTCPSuccessPacketCount()
	defer func() { _ = conn.Quit() }()

	banner := "FTP"
	common.LogSuccess(i18n.Tr("ftp_service", target, banner))
	return &ScanResult{
		Type:    plugins.ResultTypeService,
		Success: true,
		Service: "ftp",
		Banner:  banner,
	}
}

// testAnonymousAccess 测试FTP匿名访问
func (p *FTPPlugin) testAnonymousAccess(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()

	anonymousCreds := []Credential{
		{Username: "anonymous", Password: "anonymous"},
		{Username: "anonymous", Password: ""},
		{Username: "ftp", Password: "ftp"},
	}

	for _, cred := range anonymousCreds {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		result := p.doFTPAuth(ctx, info, cred, config, state)
		if result.Success && result.Conn != nil {
			// 获取文件列表
			ftpConn, ok := result.Conn.(*ftpConnWrapper)
			if !ok {
				_ = result.Conn.Close()
				return nil
			}
			fileList := p.listFTPFiles(ftpConn.ServerConn)
			_ = result.Conn.Close()

			var output strings.Builder
			output.WriteString(fmt.Sprintf("FTP %s 匿名访问 - %s:%s", target, cred.Username, cred.Password))
			if len(fileList) > 0 {
				for _, file := range fileList {
					output.WriteString(fmt.Sprintf("\n   [->] %s", file))
				}
			}
			common.LogVuln(output.String())

			return &ScanResult{
				Type:     plugins.ResultTypeCredential,
				Success:  true,
				Service:  "ftp",
				Username: cred.Username,
				Password: cred.Password,
				Banner:   "FTP匿名访问",
			}
		}
	}

	return nil
}

// getFileListAfterAuth 认证成功后获取文件列表
func (p *FTPPlugin) getFileListAfterAuth(info *common.HostInfo, username, password string, config *common.Config, state *common.State) []string {
	target := info.Target()

	conn, err := ftplib.Dial(target, ftplib.DialWithTimeout(config.Timeout))
	if err != nil {
		return nil
	}

	err = conn.Login(username, password)
	if err != nil {
		_ = conn.Quit()
		return nil
	}

	fileList := p.listFTPFiles(conn)
	_ = conn.Quit()
	return fileList
}

// listFTPFiles 列出FTP文件列表（前6个）
func (p *FTPPlugin) listFTPFiles(conn *ftplib.ServerConn) []string {
	files := []string{}

	entries, err := conn.List(".")
	if err != nil {
		return files
	}

	maxFiles := 6
	for i, entry := range entries {
		if i >= maxFiles {
			break
		}

		fileName := entry.Name
		if len(fileName) > 50 {
			fileName = fileName[:50] + "..."
		}
		files = append(files, fileName)
	}

	return files
}

func init() {
	RegisterPluginWithPorts("ftp", func() Plugin {
		return NewFTPPlugin()
	}, []int{21, 2121, 990})
}
