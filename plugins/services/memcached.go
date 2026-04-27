//go:build plugin_memcached || !plugin_selective

package services

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// MemcachedPlugin Memcached扫描插件
type MemcachedPlugin struct {
	plugins.BasePlugin
}

func NewMemcachedPlugin() *MemcachedPlugin {
	return &MemcachedPlugin{
		BasePlugin: plugins.NewBasePlugin("memcached"),
	}
}

func (p *MemcachedPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	target := info.Target()

	if config.DisableBrute {
		return p.identifyService(ctx, info, session)
	}

	// 检测未授权访问
	if result := p.testUnauthorizedAccess(ctx, info, session); result != nil && result.Success {
		common.LogVuln(i18n.Tr("memcached_unauth", target))
		return result
	}

	// Memcached通常不需要认证，如果上面检测失败则服务可能不可用
	return &ScanResult{
		Success: false,
		Service: "memcached",
		Error:   fmt.Errorf("无法访问Memcached服务"),
	}
}

// testUnauthorizedAccess 测试Memcached未授权访问
func (p *MemcachedPlugin) testUnauthorizedAccess(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	conn := p.connectToMemcached(ctx, info, session)
	if conn == nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	if p.testBasicCommand(conn, session.Config) {
		return &ScanResult{
			Type:    plugins.ResultTypeVuln,
			Success: true,
			Service: "memcached",
			Banner:  "未授权访问",
		}
	}

	return nil
}

func (p *MemcachedPlugin) connectToMemcached(ctx context.Context, info *common.HostInfo, session *common.ScanSession) net.Conn {
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

func (p *MemcachedPlugin) testBasicCommand(conn net.Conn, config *common.Config) bool {
	_ = conn.SetWriteDeadline(time.Now().Add(config.Timeout))
	if _, err := conn.Write([]byte("version\r\n")); err != nil {
		return false
	}

	_ = conn.SetReadDeadline(time.Now().Add(config.Timeout))
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return false
	}

	responseStr := string(response[:n])
	return common.ContainsAny(responseStr, "VERSION", "memcached")
}

func (p *MemcachedPlugin) identifyService(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	target := info.Target()

	conn := p.connectToMemcached(ctx, info, session)
	if conn == nil {
		return &ScanResult{
			Success: false,
			Service: "memcached",
			Error:   fmt.Errorf("无法连接到Memcached服务"),
		}
	}
	defer func() { _ = conn.Close() }()

	if p.testBasicCommand(conn, session.Config) {
		banner := "Memcached"
		common.LogSuccess(i18n.Tr("memcached_service", target, banner))
		return &ScanResult{
			Type:    plugins.ResultTypeService,
			Success: true,
			Service: "memcached",
			Banner:  banner,
		}
	}

	return &ScanResult{
		Success: false,
		Service: "memcached",
		Error:   fmt.Errorf("无法识别为Memcached服务"),
	}
}

func init() {
	RegisterPluginWithPorts("memcached", func() Plugin {
		return NewMemcachedPlugin()
	}, []int{11211, 11212, 11213})
}
