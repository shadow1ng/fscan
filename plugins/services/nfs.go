//go:build plugin_nfs || !plugin_selective

package services

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

type NFSPlugin struct {
	plugins.BasePlugin
}

func NewNFSPlugin() *NFSPlugin {
	return &NFSPlugin{BasePlugin: plugins.NewBasePlugin("nfs")}
}

func (p *NFSPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	timeout := session.Config.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	addr := info.Target()
	conn, err := session.DialTCP(ctx, "tcp", addr, timeout)
	if err != nil {
		return &ScanResult{Success: false, Service: "nfs"}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// NFS NULL call (program=100003, version=3, procedure=0) to confirm NFS service
	if err := p.rpcNullCall(conn, 100003, 3); err != nil {
		// Try v4 on a fresh connection
		conn.Close()
		c, dialErr := session.DialTCP(ctx, "tcp", addr, timeout)
		if dialErr != nil {
			return &ScanResult{Success: false, Service: "nfs"}
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(timeout))
		if err := p.rpcNullCall(c, 100003, 4); err != nil {
			return &ScanResult{Success: false, Service: "nfs"}
		}
	}

	// NFS confirmed. Try MOUNT EXPORT on a separate connection (port 2049 may also host mountd).
	var exports []string
	mountConn, err := session.DialTCP(ctx, "tcp", addr, timeout)
	if err == nil {
		_ = mountConn.SetDeadline(time.Now().Add(timeout))
		exports, _ = p.getExports(mountConn)
		mountConn.Close()
	}

	if len(exports) > 0 {
		return &ScanResult{
			Success: true,
			Type:    plugins.ResultTypeVuln,
			Service: "nfs",
			VulInfo: fmt.Sprintf("NFS Exported Shares: %v", exports),
			Banner:  fmt.Sprintf("NFS exports: %v", exports),
		}
	}

	return &ScanResult{
		Success: true,
		Type:    plugins.ResultTypeService,
		Service: "nfs",
		Banner:  "NFS service detected",
	}
}

func (p *NFSPlugin) rpcNullCall(conn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
}, program, version uint32) error {
	xid := uint32(0x12340000 + program)
	rpcCall := p.buildRPCCall(xid, program, version, 0, nil)
	rpcFragment := p.wrapRPCFragment(rpcCall)

	if _, err := conn.Write(rpcFragment); err != nil {
		return err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 28 {
		return fmt.Errorf("short response")
	}

	reply := buf[4:n]
	replyXID := binary.BigEndian.Uint32(reply[0:4])
	if replyXID != xid {
		return fmt.Errorf("xid mismatch")
	}
	msgType := binary.BigEndian.Uint32(reply[4:8])
	if msgType != 1 {
		return fmt.Errorf("not a reply")
	}
	return nil
}

func (p *NFSPlugin) getExports(conn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
}) ([]string, error) {
	// Sun RPC call: program=MOUNT(100005), version=3, procedure=EXPORT(5)
	xid := uint32(0x12345678)
	rpcCall := p.buildRPCCall(xid, 100005, 3, 5, nil)
	rpcFragment := p.wrapRPCFragment(rpcCall)

	if _, err := conn.Write(rpcFragment); err != nil {
		return nil, err
	}

	// Read fragment header (4 bytes) + response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 28 {
		return nil, fmt.Errorf("short response: %d bytes", n)
	}

	// Skip fragment header (4 bytes), parse RPC reply
	reply := buf[4:n]
	if len(reply) < 24 {
		return nil, fmt.Errorf("invalid reply")
	}

	replyXID := binary.BigEndian.Uint32(reply[0:4])
	if replyXID != xid {
		return nil, fmt.Errorf("xid mismatch")
	}
	msgType := binary.BigEndian.Uint32(reply[4:8])
	if msgType != 1 { // REPLY
		return nil, fmt.Errorf("not a reply")
	}
	replyStatus := binary.BigEndian.Uint32(reply[8:12])
	if replyStatus != 0 { // MSG_ACCEPTED
		return nil, fmt.Errorf("reply rejected")
	}

	// Skip auth verifier
	offset := 12
	if offset+8 > len(reply) {
		return nil, fmt.Errorf("truncated")
	}
	// verifier flavor + length
	verifierLen := binary.BigEndian.Uint32(reply[offset+4 : offset+8])
	offset += 8 + int(verifierLen)

	// Accept status
	if offset+4 > len(reply) {
		return nil, fmt.Errorf("truncated")
	}
	acceptStatus := binary.BigEndian.Uint32(reply[offset : offset+4])
	if acceptStatus != 0 { // SUCCESS
		return nil, fmt.Errorf("accept status: %d", acceptStatus)
	}
	offset += 4

	return p.parseExportList(reply[offset:]), nil
}

func (p *NFSPlugin) parseExportList(data []byte) []string {
	var exports []string
	offset := 0
	for offset+4 <= len(data) {
		valueFollows := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		if valueFollows == 0 {
			break
		}
		if offset+4 > len(data) {
			break
		}
		strLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		if int(strLen) > len(data)-offset {
			break
		}
		exports = append(exports, string(data[offset:offset+int(strLen)]))
		offset += int(strLen)
		// Align to 4 bytes
		if pad := (4 - strLen%4) % 4; pad > 0 {
			offset += int(pad)
		}
		// Skip group list
		for offset+4 <= len(data) {
			groupFollows := binary.BigEndian.Uint32(data[offset : offset+4])
			offset += 4
			if groupFollows == 0 {
				break
			}
			if offset+4 > len(data) {
				break
			}
			groupLen := binary.BigEndian.Uint32(data[offset : offset+4])
			offset += 4 + int(groupLen)
			if pad := (4 - groupLen%4) % 4; pad > 0 {
				offset += int(pad)
			}
		}
	}
	return exports
}

func (p *NFSPlugin) buildRPCCall(xid, program, version, procedure uint32, data []byte) []byte {
	authNone := []byte{0, 0, 0, 0, 0, 0, 0, 0} // AUTH_NONE flavor=0, len=0

	buf := make([]byte, 0, 40+len(data))
	buf = binary.BigEndian.AppendUint32(buf, xid)
	buf = binary.BigEndian.AppendUint32(buf, 0) // CALL
	buf = binary.BigEndian.AppendUint32(buf, 2) // RPC version
	buf = binary.BigEndian.AppendUint32(buf, program)
	buf = binary.BigEndian.AppendUint32(buf, version)
	buf = binary.BigEndian.AppendUint32(buf, procedure)
	buf = append(buf, authNone...) // credentials
	buf = append(buf, authNone...) // verifier
	buf = append(buf, data...)
	return buf
}

func (p *NFSPlugin) wrapRPCFragment(data []byte) []byte {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data))|0x80000000) // last fragment
	return append(header, data...)
}

func init() {
	RegisterPluginWithPorts("nfs", func() Plugin {
		return NewNFSPlugin()
	}, []int{2049})
}
