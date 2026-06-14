//go:build plugin_modbus || !plugin_selective

package services

import (
	"context"
	"encoding/binary"
	"io"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

type ModbusPlugin struct {
	plugins.BasePlugin
}

func NewModbusPlugin() *ModbusPlugin {
	return &ModbusPlugin{BasePlugin: plugins.NewBasePlugin("modbus")}
}

func (p *ModbusPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	timeout := session.Config.ModuleTimeout()
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	addr := info.Target()
	conn, err := session.DialTCP(ctx, "tcp", addr, timeout)
	if err != nil {
		return &ScanResult{Success: false, Service: "modbus"}
	}
	defer conn.Close()

	txID := randomUint16()
	req := buildModbusDeviceIDRequest(txID)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req); err != nil {
		return &ScanResult{Success: false, Service: "modbus"}
	}

	header := make([]byte, 7)
	if _, err := io.ReadFull(conn, header); err != nil {
		return &ScanResult{Success: false, Service: "modbus"}
	}
	length := int(binary.BigEndian.Uint16(header[4:6]))
	if length < 2 || length > 260 {
		return &ScanResult{Success: false, Service: "modbus"}
	}
	body := make([]byte, length-1)
	if _, err := io.ReadFull(conn, body); err != nil {
		return &ScanResult{Success: false, Service: "modbus"}
	}

	banner, ok := parseModbusResponse(header, body, txID)
	if !ok {
		return &ScanResult{Success: false, Service: "modbus"}
	}

	return &ScanResult{
		Success: true,
		Type:    plugins.ResultTypeService,
		Service: "modbus",
		Banner:  banner,
	}
}

func buildModbusDeviceIDRequest(txID uint16) []byte {
	req := make([]byte, 11)
	binary.BigEndian.PutUint16(req[0:2], txID)
	binary.BigEndian.PutUint16(req[2:4], 0)
	binary.BigEndian.PutUint16(req[4:6], 5)
	req[6] = 0xff
	req[7] = 0x2b
	req[8] = 0x0e
	req[9] = 0x01
	req[10] = 0x00
	return req
}

func parseModbusResponse(header, body []byte, txID uint16) (string, bool) {
	if len(header) < 7 || len(body) < 1 {
		return "", false
	}
	if binary.BigEndian.Uint16(header[0:2]) != txID || binary.BigEndian.Uint16(header[2:4]) != 0 {
		return "", false
	}
	switch body[0] {
	case 0x2b:
		return "Modbus TCP device identification response", true
	case 0xab:
		return "Modbus TCP exception response", true
	default:
		return "", false
	}
}

func init() {
	RegisterPluginWithPorts("modbus", func() Plugin {
		return NewModbusPlugin()
	}, []int{502})
}
