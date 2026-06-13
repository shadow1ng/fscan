//go:build plugin_bacnet || !plugin_selective

package services

import (
	"context"
	"encoding/binary"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

var bacnetWhoIs = []byte{0x81, 0x0a, 0x00, 0x0c, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08}

type BACnetPlugin struct {
	plugins.BasePlugin
}

func NewBACnetPlugin() *BACnetPlugin {
	return &BACnetPlugin{BasePlugin: plugins.NewBasePlugin("bacnet")}
}

func (p *BACnetPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	timeout := session.Config.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	target := info.Target()
	conn, err := session.DialUDP(ctx, target, timeout)
	if err != nil {
		return &ScanResult{Success: false, Service: "bacnet"}
	}
	defer conn.Close()

	if dl, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = dl.SetReadDeadline(time.Now().Add(timeout))
	}

	if _, err := conn.Write(bacnetWhoIs); err != nil {
		return &ScanResult{Success: false, Service: "bacnet"}
	}

	buf := make([]byte, 1476)
	n, err := conn.Read(buf)
	if err != nil {
		return &ScanResult{Success: false, Service: "bacnet"}
	}

	banner, ok := parseBACnetResponse(buf[:n])
	if !ok {
		return &ScanResult{Success: false, Service: "bacnet"}
	}

	return &ScanResult{
		Success: true,
		Type:    plugins.ResultTypeService,
		Service: "bacnet",
		Banner:  banner,
	}
}

func parseBACnetResponse(data []byte) (string, bool) {
	if len(data) < 6 || data[0] != 0x81 {
		return "", false
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length != len(data) {
		return "", false
	}
	for i := 4; i+1 < len(data); i++ {
		if data[i] == 0x10 && data[i+1] == 0x00 {
			return "BACnet I-Am response", true
		}
	}
	return "", false
}

func init() {
	RegisterUDPPluginWithPorts("bacnet", func() Plugin {
		return NewBACnetPlugin()
	}, []int{47808})
}
