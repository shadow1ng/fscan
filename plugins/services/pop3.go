//go:build plugin_pop3 || !plugin_selective

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

type POP3Plugin struct {
	plugins.BasePlugin
}

func NewPOP3Plugin() *POP3Plugin {
	return &POP3Plugin{BasePlugin: plugins.NewBasePlugin("pop3")}
}

func (p *POP3Plugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	timeout := config.ModuleTimeout()
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	addr := info.Target()
	conn, err := session.DialTCP(ctx, "tcp", addr, timeout)
	if err != nil {
		return &ScanResult{Success: false, Service: "pop3"}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(banner, "+OK") {
		return &ScanResult{Success: false, Service: "pop3"}
	}
	banner = strings.TrimSpace(banner)

	serviceResult := &ScanResult{
		Success: true,
		Type:    plugins.ResultTypeService,
		Service: "pop3",
		Banner:  banner,
	}

	if config.DisableBrute {
		return serviceResult
	}

	credentials := GenerateCredentials("pop3", config)
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

func (p *POP3Plugin) tryLogin(ctx context.Context, info *common.HostInfo, cred plugins.Credential, timeout time.Duration, session *common.ScanSession) *ScanResult {
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
	if err := rejectLineBreaks(cred.Username, cred.Password); err != nil {
		return nil
	}

	if _, err := fmt.Fprintf(conn, "USER %s\r\n", cred.Username); err != nil {
		return nil
	}
	resp, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(resp, "+OK") {
		return nil
	}

	if _, err := fmt.Fprintf(conn, "PASS %s\r\n", cred.Password); err != nil {
		return nil
	}
	resp, err = reader.ReadString('\n')
	if err != nil {
		return nil
	}

	if strings.HasPrefix(resp, "+OK") {
		_, _ = conn.Write([]byte("QUIT\r\n"))
		return &ScanResult{
			Success:  true,
			Type:     plugins.ResultTypeCredential,
			Service:  "pop3",
			Username: cred.Username,
			Password: cred.Password,
		}
	}
	return nil
}

func init() {
	RegisterPluginWithPorts("pop3", func() Plugin {
		return NewPOP3Plugin()
	}, []int{110, 995})
}
