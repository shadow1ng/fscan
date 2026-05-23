//go:build plugin_dns || !plugin_selective

package services

import (
	"context"
	"fmt"
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
	timeout := session.Config.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	target := fmt.Sprintf("%s:%d", info.Host, info.Port)
	queryID := randomUint16()
	query := buildDNSRootNSQuery(queryID)

	conn, err := session.DialUDP(ctx, target, timeout)
	if err != nil {
		return &ScanResult{Success: false, Service: "dns"}
	}
	defer conn.Close()

	if _, err := conn.Write(query); err != nil {
		return &ScanResult{Success: false, Service: "dns"}
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return &ScanResult{Success: false, Service: "dns"}
	}

	banner, ok := parseDNSResponse(buf[:n], queryID)
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
