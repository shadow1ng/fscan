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
	timeout := session.Config.Timeout
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
	conn, err := session.DialUDP(ctx, target, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// ASF Presence Ping: RMCP header + ASF message
	ping := []byte{
		0x06,                   // RMCP version 1.0
		0x00,                   // reserved
		0xff,                   // sequence number (no ack)
		0x06,                   // class = ASF
		0x00, 0x00, 0x11, 0xbe, // IANA enterprise = ASF (4542)
		0x80, // message type = Presence Ping
		0x00, // message tag
		0x00, // reserved
		0x00, // data length = 0
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(ping); err != nil {
		return nil
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return nil
	}

	// Validate RMCP response
	if buf[0] != 0x06 || buf[3] != 0x06 {
		return nil
	}
	// Check ASF Presence Pong (message type = 0x40)
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

	// Try to get channel auth capabilities for more info
	if authInfo := p.getChannelAuth(conn); authInfo != "" {
		banner += " " + authInfo
	}

	return &ScanResult{
		Success: true,
		Type:    plugins.ResultTypeVuln,
		Service: "ipmi",
		VulInfo: "IPMI Service Exposed (hash dump possible with rakp)",
		Banner:  banner,
	}
}

func (p *IPMIPlugin) getChannelAuth(conn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	SetDeadline(time.Time) error
}) string {
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// IPMI Get Channel Authentication Capabilities
	// RMCP header + IPMI session wrapper + message
	pkt := []byte{
		0x06, 0x00, 0xff, 0x07, // RMCP: version, reserved, seq=0xff, class=IPMI
		0x00, 0x00, 0x00, 0x00, // auth type = none
		0x00, 0x00, 0x00, 0x00, // session seq
		0x00, 0x00, 0x00, 0x00, // session id
		0x09, // message length
		0x20, // target = BMC
		0x18, // netFn=App(6) << 2 | lun=0
		0xc8, // checksum
		0x81, // source
		0x00, // seq
		0x38, // cmd = Get Channel Auth Capabilities
		0x8e, // channel=14 (current), IPMI v2.0
		0x04, // privilege = Administrator
		0xb5, // checksum
	}

	if _, err := conn.Write(pkt); err != nil {
		return ""
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 30 {
		return ""
	}

	// Parse auth capabilities from response
	if n >= 27 {
		authTypes := buf[22]
		var methods []string
		if authTypes&0x01 != 0 {
			methods = append(methods, "none")
		}
		if authTypes&0x02 != 0 {
			methods = append(methods, "md2")
		}
		if authTypes&0x04 != 0 {
			methods = append(methods, "md5")
		}
		if authTypes&0x10 != 0 {
			methods = append(methods, "password")
		}
		if authTypes&0x20 != 0 {
			methods = append(methods, "oem")
		}
		if len(methods) > 0 {
			return fmt.Sprintf("[auth: %v]", methods)
		}
	}
	return ""
}

func init() {
	RegisterUDPPluginWithPorts("ipmi", func() Plugin {
		return NewIPMIPlugin()
	}, []int{623})
}
