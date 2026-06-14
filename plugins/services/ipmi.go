//go:build plugin_ipmi || !plugin_selective

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

type IPMIPlugin struct {
	plugins.BasePlugin
}

func NewIPMIPlugin() *IPMIPlugin {
	return &IPMIPlugin{BasePlugin: plugins.NewBasePlugin("ipmi")}
}

func (p *IPMIPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	timeout := session.Config.ModuleTimeout()
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	target := info.Target()

	if result := p.rmcpPing(ctx, target, timeout, session); result != nil {
		return result
	}
	return &ScanResult{Success: false, Service: "ipmi"}
}

func (p *IPMIPlugin) rmcpPing(ctx context.Context, target string, timeout time.Duration, session *common.ScanSession) *ScanResult {
	ping := []byte{
		0x06, 0x00, 0xff, 0x06,
		0x00, 0x00, 0x11, 0xbe,
		0x80, 0x00, 0x00, 0x00,
	}

	buf, n := udpProbe(ctx, session, target, timeout, ping, 512)
	if buf == nil || n < 12 {
		return nil
	}

	if buf[0] != 0x06 || buf[3] != 0x06 {
		return nil
	}
	if n >= 9 && buf[8] != 0x40 {
		return nil
	}

	banner := "IPMI/RMCP service detected"
	if n >= 16 {
		banner = fmt.Sprintf("IPMI/RMCP detected (supported entities: 0x%02x)", buf[15])
		if buf[15]&0x80 != 0 {
			banner += " [IPMI supported]"
		}
	}

	return &ScanResult{
		Success: true,
		Type:    plugins.ResultTypeVuln,
		Service: "ipmi",
		VulInfo: "IPMI Service Exposed (hash dump possible with rakp)",
		Banner:  banner,
	}
}

func init() {
	RegisterUDPPluginWithPorts("ipmi", func() Plugin {
		return NewIPMIPlugin()
	}, []int{623})
}
