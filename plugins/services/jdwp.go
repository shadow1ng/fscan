//go:build plugin_jdwp || !plugin_selective

package services

import (
	"bytes"
	"context"
	"io"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

var jdwpHandshake = []byte("JDWP-Handshake")

type JDWPPlugin struct {
	plugins.BasePlugin
}

func NewJDWPPlugin() *JDWPPlugin {
	return &JDWPPlugin{BasePlugin: plugins.NewBasePlugin("jdwp")}
}

func (p *JDWPPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	timeout := session.Config.ModuleTimeout()
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	addr := info.Target()
	conn, err := session.DialTCP(ctx, "tcp", addr, timeout)
	if err != nil {
		return &ScanResult{Success: false, Service: "jdwp"}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(jdwpHandshake); err != nil {
		return &ScanResult{Success: false, Service: "jdwp"}
	}

	buf := make([]byte, len(jdwpHandshake))
	if _, err := io.ReadFull(conn, buf); err != nil || !bytes.Equal(buf, jdwpHandshake) {
		return &ScanResult{Success: false, Service: "jdwp"}
	}

	version := p.getVersion(conn, timeout)

	return &ScanResult{
		Success: true,
		Type:    plugins.ResultTypeVuln,
		Service: "jdwp",
		VulInfo: "JDWP Remote Debug Port Exposed",
		Banner:  version,
	}
}

func (p *JDWPPlugin) getVersion(conn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	SetDeadline(time.Time) error
}, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// JDWP Version command: length=11, id=1, flags=0, commandSet=1, command=1
	pkt := []byte{
		0x00, 0x00, 0x00, 0x0b, // length = 11
		0x00, 0x00, 0x00, 0x01, // id = 1
		0x00, // flags = 0 (request)
		0x01, // commandSet = 1 (VirtualMachine)
		0x01, // command = 1 (Version)
	}
	if _, err := conn.Write(pkt); err != nil {
		return ""
	}

	header := make([]byte, 11)
	if _, err := io.ReadFull(conn, header); err != nil {
		return ""
	}
	replyLen := int(header[0])<<24 | int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if replyLen <= 11 || replyLen > 4096 {
		return ""
	}

	body := make([]byte, replyLen-11)
	if _, err := io.ReadFull(conn, body); err != nil {
		return ""
	}

	return parseJDWPVersionString(body)
}

func parseJDWPVersionString(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	strLen := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if strLen <= 0 || strLen > len(data)-4 {
		return ""
	}
	s := string(data[4 : 4+strLen])
	return truncateRunes(s, 200)
}

func init() {
	RegisterPluginWithPorts("jdwp", func() Plugin {
		return NewJDWPPlugin()
	}, []int{5005, 8000, 8787, 5050})
}
