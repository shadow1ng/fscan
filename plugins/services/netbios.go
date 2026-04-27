//go:build plugin_netbios || !plugin_selective

package services

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

// NetBIOSPlugin NetBIOS名称服务扫描插件 - 收集Windows主机名和域信息
type NetBIOSPlugin struct {
	plugins.BasePlugin
}

// NewNetBIOSPlugin 创建NetBIOS插件
func NewNetBIOSPlugin() *NetBIOSPlugin {
	return &NetBIOSPlugin{
		BasePlugin: plugins.NewBasePlugin("netbios"),
	}
}

// GetPorts 实现Plugin接口

// Scan 执行NetBIOS扫描 - 收集Windows主机和域信息
func (p *NetBIOSPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	state := session.State
	target := info.Target()

	// 检查端口类型
	if info.Port != 137 && info.Port != 139 {
		return &ScanResult{
			Success: false,
			Service: "netbios",
			Error:   fmt.Errorf("NetBIOS插件仅支持137和139端口"),
		}
	}

	var netbiosInfo *NetBIOSInfo
	var err error

	if info.Port == 137 {
		// UDP端口137 - NetBIOS名称服务
		netbiosInfo, err = p.queryNetBIOSNames(info.Host, config, state)
	} else {
		// TCP端口139 - NetBIOS会话服务
		netbiosInfo, err = p.queryNetBIOSSession(ctx, info.Host, session)
	}

	if err != nil {
		return &ScanResult{
			Success: false,
			Service: "netbios",
			Error:   err,
		}
	}

	if !netbiosInfo.Valid {
		return &ScanResult{
			Success: false,
			Service: "netbios",
			Error:   fmt.Errorf("未发现有效的NetBIOS信息"),
		}
	}

	// 记录NetBIOS发现信息
	msg := fmt.Sprintf("NetBios %s", target)
	if netbiosInfo.Summary() != "" {
		msg += fmt.Sprintf(" %s", netbiosInfo.Summary())
	}
	common.LogSuccess(msg)

	return &ScanResult{
		Success: true,
			Type:     plugins.ResultTypeService,
		Service: "netbios",
		Banner:  netbiosInfo.Summary(),
	}
}

// NetBIOSInfo NetBIOS信息结构
type NetBIOSInfo struct {
	Valid               bool
	ComputerName        string
	DomainName          string
	WorkstationService  string
	ServerService       string
	DomainControllers   string
	OSVersion           string
	NetBIOSComputerName string
	NetBIOSDomainName   string
}

// Summary 返回NetBIOS信息摘要
func (ni *NetBIOSInfo) Summary() string {
	if !ni.Valid {
		return ""
	}

	var parts []string

	// 优先使用完整的计算机名
	if ni.ComputerName != "" {
		if ni.DomainName != "" && !strings.Contains(ni.ComputerName, ".") {
			parts = append(parts, fmt.Sprintf("%s\\%s", ni.DomainName, ni.ComputerName))
		} else {
			parts = append(parts, ni.ComputerName)
		}
	} else {
		// 使用服务名称
		var name string
		if ni.ServerService != "" {
			name = ni.ServerService
		} else if ni.WorkstationService != "" {
			name = ni.WorkstationService
		} else if ni.NetBIOSComputerName != "" {
			name = ni.NetBIOSComputerName
		}

		if name != "" {
			if ni.DomainName != "" {
				parts = append(parts, fmt.Sprintf("%s\\%s", ni.DomainName, name))
			} else if ni.NetBIOSDomainName != "" {
				parts = append(parts, fmt.Sprintf("%s\\%s", ni.NetBIOSDomainName, name))
			} else {
				parts = append(parts, name)
			}
		}
	}

	// 添加域控制器标识
	if ni.DomainControllers != "" {
		if len(parts) > 0 {
			parts[0] = fmt.Sprintf("DC:%s", parts[0])
		}
	}

	// 添加操作系统信息
	if ni.OSVersion != "" {
		parts = append(parts, ni.OSVersion)
	}

	return strings.Join(parts, " ")
}

// queryNetBIOSNames 查询NetBIOS名称服务(UDP 137)
func (p *NetBIOSPlugin) queryNetBIOSNames(host string, config *common.Config, state *common.State) (*NetBIOSInfo, error) {
	// NetBIOS名称查询数据包
	queryPacket := []byte{
		0x66, 0x66, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01,
	}

	target := fmt.Sprintf("%s:137", host)

	conn, err := net.DialTimeout("udp", target, config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("连接NetBIOS名称服务失败: %w", err)
	}
	state.IncrementUDPPacketCount()
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(config.Timeout))

	_, err = conn.Write(queryPacket)
	if err != nil {
		return nil, fmt.Errorf("发送NetBIOS查询失败: %w", err)
	}

	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("读取NetBIOS响应失败: %w", err)
	}

	return p.parseNetBIOSNames(response[:n])
}

// queryNetBIOSSession 查询NetBIOS会话服务(TCP 139)
func (p *NetBIOSPlugin) queryNetBIOSSession(ctx context.Context, host string, session *common.ScanSession) (*NetBIOSInfo, error) {
	target := fmt.Sprintf("%s:139", host)

	conn, err := session.DialTCP(ctx, "tcp", target, session.Config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("连接NetBIOS会话服务失败: %w", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(session.Config.Timeout))

	// 发送SMB协商数据包
	smbNegotiate1 := []byte{
		0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F,
		0x52, 0x4B, 0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D, 0x20, 0x31, 0x2E, 0x30, 0x00, 0x02,
		0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x57, 0x69, 0x6E, 0x64, 0x6F,
		0x77, 0x73, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x57, 0x6F, 0x72, 0x6B, 0x67, 0x72, 0x6F, 0x75, 0x70,
		0x73, 0x20, 0x33, 0x2E, 0x31, 0x61, 0x00, 0x02, 0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30,
		0x32, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x32, 0x2E, 0x31, 0x00, 0x02, 0x4E, 0x54,
		0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
	}

	_, err = conn.Write(smbNegotiate1)
	if err != nil {
		return nil, fmt.Errorf("发送SMB协商1失败: %w", err)
	}

	response1 := make([]byte, 1024)
	_, err = conn.Read(response1)
	if err != nil {
		return nil, fmt.Errorf("读取SMB协商1响应失败: %w", err)
	}

	// 发送Session Setup请求
	smbSessionSetup := []byte{
		0x00, 0x00, 0x01, 0x0A, 0xFF, 0x53, 0x4D, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
		0x00, 0x00, 0x40, 0x00, 0x0C, 0xFF, 0x00, 0x0A, 0x01, 0x04, 0x41, 0x32, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x00, 0x00, 0xA0, 0xCF, 0x00, 0x60,
		0x48, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x3E, 0x30, 0x3C, 0xA0, 0x0E, 0x30,
		0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A, 0xA2, 0x2A, 0x04,
		0x28, 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x82, 0x08,
		0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x05, 0x02, 0xCE, 0x0E, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00,
		0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00,
		0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00, 0x33, 0x00,
		0x20, 0x00, 0x33, 0x00, 0x37, 0x00, 0x39, 0x00, 0x30, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00,
		0x72, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x20, 0x00, 0x50, 0x00, 0x61, 0x00,
		0x63, 0x00, 0x6B, 0x00, 0x20, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x00, 0x69, 0x00,
		0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00,
		0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00,
		0x33, 0x00, 0x20, 0x00, 0x35, 0x00, 0x2E, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	_, err = conn.Write(smbSessionSetup)
	if err != nil {
		return nil, fmt.Errorf("发送SMB Session Setup失败: %w", err)
	}

	response2 := make([]byte, 2048)
	n, err := conn.Read(response2)
	if err != nil {
		return nil, fmt.Errorf("读取SMB Session Setup响应失败: %w", err)
	}

	return p.parseNetBIOSSession(response2[:n])
}

// parseNetBIOSNames 解析NetBIOS名称查询响应
func (p *NetBIOSPlugin) parseNetBIOSNames(data []byte) (*NetBIOSInfo, error) {
	info := &NetBIOSInfo{Valid: false}

	if len(data) < 57 {
		return info, fmt.Errorf("NetBIOS响应数据过短")
	}

	// 获取名称记录数量
	numNames := int(data[56])
	if numNames == 0 {
		return info, fmt.Errorf("没有NetBIOS名称记录")
	}

	nameData := data[57:]

	// 服务类型映射
	uniqueNames := map[byte]string{
		0x00: "WorkstationService",
		0x03: "Messenger Service",
		0x06: "RAS Server Service",
		0x1F: "NetDDE Service",
		0x20: "ServerService",
		0x21: "RAS Client Service",
		0x1D: "Master Browser",
		0x1B: "Domain Master Browser",
	}

	groupNames := map[byte]string{
		0x00: "DomainName",
		0x1C: "DomainControllers",
		0x1E: "Browser Service Elections",
	}

	info.Valid = true

	// 解析每个名称记录
	for i := 0; i < numNames && len(nameData) >= 18*(i+1); i++ {
		offset := 18 * i
		name := strings.TrimSpace(string(nameData[offset : offset+15]))
		flagByte := nameData[offset+15]

		if len(nameData) >= 18*(i+1) {
			nameFlags := nameData[offset+16]

			if nameFlags >= 128 {
				// 组名称
				if service, exists := groupNames[flagByte]; exists {
					switch service {
					case "DomainName":
						info.DomainName = name
					case "DomainControllers":
						info.DomainControllers = name
					}
				}
			} else {
				// 唯一名称
				if service, exists := uniqueNames[flagByte]; exists {
					switch service {
					case "WorkstationService":
						info.WorkstationService = name
					case "ServerService":
						info.ServerService = name
					}
				}
			}
		}
	}

	return info, nil
}

// parseNetBIOSSession 解析NetBIOS会话响应
func (p *NetBIOSPlugin) parseNetBIOSSession(data []byte) (*NetBIOSInfo, error) {
	info := &NetBIOSInfo{Valid: false}

	if len(data) < 47 {
		return info, fmt.Errorf("SMB响应数据过短")
	}

	info.Valid = true

	// 解析OS版本信息
	blobLength := int(data[43]) + int(data[44])*256
	if len(data) >= 48+blobLength {
		osVersion := data[47+blobLength:]
		osText := p.cleanOSString(osVersion)
		if osText != "" {
			info.OSVersion = osText
		}
	}

	// 查找NTLM数据
	ntlmStart := bytes.Index(data, []byte("NTLMSSP"))
	if ntlmStart != -1 && len(data) > ntlmStart+45 {
		p.parseNTLMInfo(data[ntlmStart:], info)
	}

	return info, nil
}

// parseNTLMInfo 解析NTLM信息
func (p *NetBIOSPlugin) parseNTLMInfo(data []byte, info *NetBIOSInfo) {
	if len(data) < 45 {
		return
	}

	// 获取Target Info偏移和长度
	targetInfoLength := int(data[40]) + int(data[41])*256
	targetInfoOffset := int(data[44])

	if targetInfoOffset+targetInfoLength > len(data) {
		return
	}

	// 解析AV_PAIR结构
	targetInfo := data[targetInfoOffset : targetInfoOffset+targetInfoLength]
	offset := 0

	for offset+4 <= len(targetInfo) {
		avId := int(targetInfo[offset]) + int(targetInfo[offset+1])*256
		avLen := int(targetInfo[offset+2]) + int(targetInfo[offset+3])*256

		if avId == 0x0000 || offset+4+avLen > len(targetInfo) {
			break
		}

		value := p.parseUnicodeString(targetInfo[offset+4 : offset+4+avLen])

		switch avId {
		case 0x0001: // NetBIOS computer name
			info.NetBIOSComputerName = value
		case 0x0002: // NetBIOS domain name
			info.NetBIOSDomainName = value
		case 0x0003: // DNS computer name
			if info.ComputerName == "" {
				info.ComputerName = value
			}
		case 0x0004: // DNS domain name
			if info.DomainName == "" {
				info.DomainName = value
			}
		}

		offset += 4 + avLen
	}
}

// cleanOSString 清理操作系统字符串
func (p *NetBIOSPlugin) cleanOSString(data []byte) string {
	// 移除NULL字节并分割
	cleaned := bytes.ReplaceAll(data, []byte{0x00, 0x00}, []byte{124})
	cleaned = bytes.ReplaceAll(cleaned, []byte{0x00}, []byte{})

	if len(cleaned) == 0 {
		return ""
	}

	// 移除最后的分隔符
	if cleaned[len(cleaned)-1] == 124 {
		cleaned = cleaned[:len(cleaned)-1]
	}

	osText := string(cleaned)
	parts := strings.Split(osText, "|")
	if len(parts) > 0 {
		return parts[0]
	}

	return ""
}

// parseUnicodeString 解析Unicode字符串
func (p *NetBIOSPlugin) parseUnicodeString(data []byte) string {
	if len(data)%2 != 0 {
		return ""
	}

	var result []rune
	for i := 0; i < len(data); i += 2 {
		if i+1 >= len(data) {
			break
		}
		// UTF-16LE编码
		char := uint16(data[i]) | uint16(data[i+1])<<8
		if char == 0 {
			break
		}
		result = append(result, rune(char))
	}

	return string(result)
}

// init 自动注册插件
func init() {
	// 使用高效注册方式：直接传递端口信息，避免实例创建
	RegisterPluginWithPorts("netbios", func() Plugin {
		return NewNetBIOSPlugin()
	}, []int{137, 139})
}
