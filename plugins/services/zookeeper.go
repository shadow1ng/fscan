//go:build plugin_zookeeper || !plugin_selective

package services

import (
	"context"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

type ZooKeeperPlugin struct {
	plugins.BasePlugin
}

func NewZooKeeperPlugin() *ZooKeeperPlugin {
	return &ZooKeeperPlugin{BasePlugin: plugins.NewBasePlugin("zookeeper")}
}

func (p *ZooKeeperPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	timeout := session.Config.ModuleTimeout()
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	addr := info.Target()
	conn, err := session.DialTCP(ctx, "tcp", addr, timeout)
	if err != nil {
		return &ScanResult{Success: false, Service: "zookeeper"}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("ruok")); err != nil {
		return &ScanResult{Success: false, Service: "zookeeper"}
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return &ScanResult{Success: false, Service: "zookeeper"}
	}

	banner, ok := parseZooKeeperResponse(buf[:n])
	if !ok {
		return &ScanResult{Success: false, Service: "zookeeper"}
	}

	return &ScanResult{
		Success: true,
		Type:    plugins.ResultTypeService,
		Service: "zookeeper",
		Banner:  banner,
	}
}

func parseZooKeeperResponse(data []byte) (string, bool) {
	resp := strings.TrimSpace(string(data))
	if resp == "imok" {
		return "ZooKeeper ruok=imok", true
	}
	lower := strings.ToLower(resp)
	if strings.Contains(lower, "zookeeper") || strings.Contains(lower, "zk_version") ||
		strings.Contains(lower, "mode:") || strings.Contains(lower, "not in the whitelist") {
		return truncateRunes(resp, 200), true
	}
	return "", false
}

func init() {
	RegisterPluginWithPorts("zookeeper", func() Plugin {
		return NewZooKeeperPlugin()
	}, []int{2181})
}
