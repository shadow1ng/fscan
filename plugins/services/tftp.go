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
	timeout := session.Config.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	target := fmt.Sprintf("%s:%d", info.Host, info.Port)
	conn, err := session.DialUDP(ctx, target, timeout)
	if err != nil {
		return &ScanResult{Success: false, Service: "tftp"}
	}
	defer conn.Close()

	if _, err := conn.Write(buildTFTPReadRequest("probe")); err != nil {
		return &ScanResult{Success: false, Service: "tftp"}
	}

	buf := make([]byte, 516)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return &ScanResult{Success: false, Service: "tftp"}
	}

	banner, ok := parseTFTPResponse(buf[:n])
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
		if len(msg) > 160 {
			msg = msg[:160]
		}
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
