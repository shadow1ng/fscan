//go:build plugin_tftp || !plugin_selective

package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

type TFTPPlugin struct {
	plugins.BasePlugin
}

func NewTFTPPlugin() *TFTPPlugin {
	return &TFTPPlugin{BasePlugin: plugins.NewBasePlugin("tftp")}
}

func (p *TFTPPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	timeout := session.Config.ModuleTimeout()
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	target := info.Target()
	data, n := udpProbe(ctx, session, target, timeout, buildTFTPReadRequest("probe"), 516)
	if data == nil || n < 4 {
		return &ScanResult{Success: false, Service: "tftp"}
	}

	banner, ok := parseTFTPResponse(data[:n])
	if !ok {
		return &ScanResult{Success: false, Service: "tftp"}
	}

	return &ScanResult{
		Success: true,
		Type:    plugins.ResultTypeService,
		Service: "tftp",
		Banner:  banner,
	}
}

func buildTFTPReadRequest(filename string) []byte {
	req := []byte{0x00, 0x01}
	req = append(req, filename...)
	req = append(req, 0x00)
	req = append(req, "octet"...)
	req = append(req, 0x00)
	return req
}

func parseTFTPResponse(data []byte) (string, bool) {
	if len(data) < 4 || data[0] != 0x00 {
		return "", false
	}

	opcode := data[1]
	switch opcode {
	case 0x03:
		return "TFTP DATA response", true
	case 0x05:
		msg := strings.TrimRight(string(data[4:]), "\x00")
		msg = truncateRunes(msg, 160)
		if msg == "" {
			msg = "error response"
		}
		return fmt.Sprintf("TFTP %s", msg), true
	default:
		return "", false
	}
}

func init() {
	RegisterUDPPluginWithPorts("tftp", func() Plugin {
		return NewTFTPPlugin()
	}, []int{69})
}
