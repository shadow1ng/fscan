//go:build plugin_dns || !plugin_selective

package services

import (
	"context"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

type DNSPlugin struct {
	plugins.BasePlugin
}

func NewDNSPlugin() *DNSPlugin {
	return &DNSPlugin{BasePlugin: plugins.NewBasePlugin("dns")}
}

func (p *DNSPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	timeout := session.Config.ModuleTimeout()
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	target := info.Target()
	queryID := randomUint16()
	query := buildDNSRootNSQuery(queryID)

	data, n := udpProbe(ctx, session, target, timeout, query, 1500)
	if data == nil || n < 12 {
		return &ScanResult{Success: false, Service: "dns"}
	}

	banner, ok := parseDNSResponse(data[:n], queryID)
	if !ok {
		return &ScanResult{Success: false, Service: "dns"}
	}

	return &ScanResult{
		Success: true,
		Type:    plugins.ResultTypeService,
		Service: "dns",
		Banner:  banner,
	}
}

func init() {
	RegisterUDPPluginWithPorts("dns", func() Plugin {
		return NewDNSPlugin()
	}, []int{53})
}
