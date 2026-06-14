//go:build plugin_rmi || !plugin_selective

package services

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

// Java RMI protocol magic: "JRMI" + version 2 + StreamProtocol
var rmiHandshake = []byte{0x4a, 0x52, 0x4d, 0x49, 0x00, 0x02, 0x4b}

type RMIPlugin struct {
	plugins.BasePlugin
}

func NewRMIPlugin() *RMIPlugin {
	return &RMIPlugin{BasePlugin: plugins.NewBasePlugin("rmi")}
}

func (p *RMIPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	timeout := session.Config.ModuleTimeout()
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	addr := info.Target()
	conn, err := session.DialTCP(ctx, "tcp", addr, timeout)
	if err != nil {
		return &ScanResult{Success: false, Service: "rmi"}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(rmiHandshake); err != nil {
		return &ScanResult{Success: false, Service: "rmi"}
	}

	// RMI server responds with ProtocolAck (0x4e) followed by endpoint info.
	// Read at least 1 byte for the ack; io.ReadFull guarantees it.
	ack := make([]byte, 1)
	if _, err := io.ReadFull(conn, ack); err != nil {
		return &ScanResult{Success: false, Service: "rmi"}
	}
	if ack[0] != 0x4e {
		return &ScanResult{Success: false, Service: "rmi"}
	}

	endpoint := readRMIEndpoint(conn)

	return &ScanResult{
		Success: true,
		Type:    plugins.ResultTypeVuln,
		Service: "rmi",
		VulInfo: "Java RMI/JMX Service Exposed",
		Banner:  endpoint,
	}
}

func parseRMIEndpoint(data []byte) string {
	if len(data) < 4 {
		return "Java RMI"
	}
	// Skip 2 bytes (host length big-endian)
	hostLen := int(data[0])<<8 | int(data[1])
	if hostLen <= 0 || hostLen+2 > len(data) {
		return "Java RMI"
	}
	host := string(data[2 : 2+hostLen])
	offset := 2 + hostLen
	if offset+4 > len(data) {
		return fmt.Sprintf("Java RMI endpoint=%s", host)
	}
	port := int(data[offset])<<24 | int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
	return fmt.Sprintf("Java RMI endpoint=%s:%d", host, port)
}

func readRMIEndpoint(conn interface {
	Read([]byte) (int, error)
}) string {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "Java RMI"
	}
	hostLen := int(header[0])<<8 | int(header[1])
	if hostLen <= 0 || hostLen > 249 {
		return "Java RMI"
	}
	payload := make([]byte, hostLen+4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return "Java RMI"
	}
	data := append(header, payload...)
	return parseRMIEndpoint(data)
}

func init() {
	RegisterPluginWithPorts("rmi", func() Plugin {
		return NewRMIPlugin()
	}, []int{1099, 1098, 9999, 4444})
}
