//go:build plugin_imap || !plugin_selective

package services

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

type IMAPPlugin struct {
	plugins.BasePlugin
}

func NewIMAPPlugin() *IMAPPlugin {
	return &IMAPPlugin{BasePlugin: plugins.NewBasePlugin("imap")}
}

func (p *IMAPPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	addr := info.Target()
	conn, err := session.DialTCP(ctx, "tcp", addr, timeout)
	if err != nil {
		return &ScanResult{Success: false, Service: "imap"}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(banner, "OK") {
		return &ScanResult{Success: false, Service: "imap"}
	}
	banner = strings.TrimSpace(banner)

	serviceResult := &ScanResult{
		Success: true,
		Type:    plugins.ResultTypeService,
		Service: "imap",
		Banner:  banner,
	}

	if config.DisableBrute {
		return serviceResult
	}

	credentials := GenerateCredentials("imap", config)
	if len(credentials) == 0 {
		return serviceResult
	}

	for _, cred := range credentials {
		select {
		case <-ctx.Done():
			return serviceResult
		default:
		}

		if result := p.tryLogin(ctx, info, cred, timeout, session); result != nil {
			return result
		}
	}

	return serviceResult
}

func (p *IMAPPlugin) tryLogin(ctx context.Context, info *common.HostInfo, cred plugins.Credential, timeout time.Duration, session *common.ScanSession) *ScanResult {
	addr := info.Target()
	conn, err := session.DialTCP(ctx, "tcp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		return nil
	}

	loginCmd := fmt.Sprintf("a001 LOGIN %s %s\r\n", cred.Username, cred.Password)
	if _, err := conn.Write([]byte(loginCmd)); err != nil {
		return nil
	}

	response, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}

	if strings.Contains(response, "a001 OK") {
		_, _ = conn.Write([]byte("a002 LOGOUT\r\n"))
		return &ScanResult{
			Success:  true,
			Type:     plugins.ResultTypeCredential,
			Service:  "imap",
			Username: cred.Username,
			Password: cred.Password,
		}
	}
	return nil
}

func init() {
	RegisterPluginWithPorts("imap", func() Plugin {
		return NewIMAPPlugin()
	}, []int{143, 993})
}
