//go:build plugin_vnc || !plugin_selective

package services

import (
	"context"
	"strings"
	"time"

	vnc "github.com/mitchellh/go-vnc"
	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// VNCPlugin VNC扫描插件
type VNCPlugin struct {
	plugins.BasePlugin
}

func NewVNCPlugin() *VNCPlugin {
	return &VNCPlugin{
		BasePlugin: plugins.NewBasePlugin("vnc"),
	}
}

func (p *VNCPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	target := info.Target()

	// 检查未授权访问
	if result := p.testUnauthAccess(ctx, info, session); result != nil && result.Success {
		common.LogVuln(i18n.Tr("vnc_unauth", target))
		return result
	}

	// 生成密码列表
	var credentials []Credential
	if config.Credentials.Passwords != nil {
		for _, pass := range config.Credentials.Passwords {
			credentials = append(credentials, Credential{Username: "", Password: pass})
		}
	} else {
		defaultPasswords := []string{"123456", "password", "admin", "root", "vnc"}
		for _, pass := range defaultPasswords {
			credentials = append(credentials, Credential{Username: "", Password: pass})
		}
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, session)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "vnc", testConfig)

	if result.Success {
		common.LogVuln(i18n.Tr("vnc_credential", target, result.Password))
	}

	return result
}

// createAuthFunc 创建VNC认证函数
func (p *VNCPlugin) createAuthFunc(info *common.HostInfo, session *common.ScanSession) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doVNCAuth(ctx, info, cred, session)
	}
}

// doVNCAuth 执行VNC认证
func (p *VNCPlugin) doVNCAuth(ctx context.Context, info *common.HostInfo, cred Credential, session *common.ScanSession) *AuthResult {
	target := info.Target()

	resultChan := make(chan *AuthResult, 1)

	go func() {
		conn, err := session.DialTCP(ctx, "tcp", target, session.Config.Timeout)
		if err != nil {
			resultChan <- &AuthResult{
				Success:   false,
				ErrorType: classifyVNCErrorType(err),
				Error:     err,
			}
			return
		}

		_ = conn.SetDeadline(time.Now().Add(session.Config.Timeout))

		vncConfig := &vnc.ClientConfig{
			Auth: []vnc.ClientAuth{
				&vnc.PasswordAuth{Password: cred.Password},
			},
		}

		client, err := vnc.Client(conn, vncConfig)
		if err != nil {
			_ = conn.Close()
			resultChan <- &AuthResult{
				Success:   false,
				ErrorType: classifyVNCErrorType(err),
				Error:     err,
			}
			return
		}

		resultChan <- &AuthResult{
			Success:   true,
			Conn:      &vncClientWrapper{client, conn},
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

// vncClientWrapper 包装VNC连接以实现io.Closer
type vncClientWrapper struct {
	*vnc.ClientConn
	conn interface{ Close() error }
}

func (w *vncClientWrapper) Close() error {
	_ = w.ClientConn.Close()
	return w.conn.Close()
}

// classifyVNCErrorType VNC错误分类
func classifyVNCErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	errStr := strings.ToLower(err.Error())

	vncAuthErrors := []string{
		"authentication failed",
		"auth failed",
		"password",
		"unauthorized",
		"access denied",
	}

	for _, keyword := range vncAuthErrors {
		if strings.Contains(errStr, keyword) {
			return ErrorTypeAuth
		}
	}

	if strings.Contains(errStr, "too many authentication failures") {
		return ErrorTypeNetwork
	}

	return ClassifyError(err, nil, CommonNetworkErrors)
}

func (p *VNCPlugin) testUnauthAccess(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	cred := Credential{Username: "", Password: ""}
	result := p.doVNCAuth(ctx, info, cred, session)

	if result.Success {
		if result.Conn != nil {
			_ = result.Conn.Close()
		}
		return &ScanResult{
			Type:    plugins.ResultTypeVuln,
			Success: true,
			Service: "vnc",
			Banner:  "未授权访问",
		}
	}

	return nil
}

func init() {
	RegisterPluginWithPorts("vnc", func() Plugin {
		return NewVNCPlugin()
	}, []int{5900, 5901, 5902, 5903, 5904, 5905})
}
