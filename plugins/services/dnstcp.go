//go:build plugin_dnstcp || !plugin_selective

package services

import (
	"context"
	"encoding/binary"
	"io"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

type DNSTCPPlugin struct {
	plugins.BasePlugin
}

func NewDNSTCPPlugin() *DNSTCPPlugin {
	return &DNSTCPPlugin{BasePlugin: plugins.NewBasePlugin("dnstcp")}
}

func (p *DNSTCPPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	timeout := session.Config.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	addr := info.Target()
	conn, err := session.DialTCP(ctx, "tcp", addr, timeout)
	if err != nil {
		return &ScanResult{Success: false, Service: "dns"}
	}
	defer conn.Close()

	queryID := randomUint16()
	query := buildDNSRootNSQuery(queryID)
	frame := make([]byte, 2, len(query)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	frame = append(frame, query...)

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(frame); err != nil {
		return &ScanResult{Success: false, Service: "dns"}
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return &ScanResult{Success: false, Service: "dns"}
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen < 12 || respLen > 4096 {
		return &ScanResult{Success: false, Service: "dns"}
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return &ScanResult{Success: false, Service: "dns"}
	}

	banner, ok := parseDNSResponse(resp, queryID)
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
	RegisterPluginWithPorts("dnstcp", func() Plugin {
		return NewDNSTCPPlugin()
	}, []int{53})
}
