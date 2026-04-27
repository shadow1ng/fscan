//go:build plugin_findnet || !plugin_selective

package services

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/plugins"
)

// 预编译正则表达式
var validHostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$`)

// FindNetPlugin Windows网络发现插件 - 通过RPC端点映射服务收集网络信息
type FindNetPlugin struct {
	plugins.BasePlugin
}

// NewFindNetPlugin 创建FindNet插件
func NewFindNetPlugin() *FindNetPlugin {
	return &FindNetPlugin{
		BasePlugin: plugins.NewBasePlugin("findnet"),
	}
}

// GetPorts 实现Plugin接口

// Scan 执行FindNet扫描 - Windows网络信息收集
func (p *FindNetPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	target := info.Target()

	// 检查是否为RPC端口
	if info.Port != 135 {
		return &ScanResult{
			Success: false,
			Service: "findnet",
			Error:   fmt.Errorf("FindNet插件仅支持RPC端口135"),
		}
	}

	conn, err := session.DialTCP(ctx, "tcp", target, config.Timeout)
	if err != nil {
		return &ScanResult{
			Success: false,
			Service: "findnet",
			Error:   fmt.Errorf("连接RPC端口失败: %w", err),
		}
	}
	defer func() { _ = conn.Close() }()

	// 设置超时
	_ = conn.SetDeadline(time.Now().Add(config.Timeout))

	// 执行RPC网络发现
	networkInfo, err := p.performNetworkDiscovery(conn)
	if err != nil {
		return &ScanResult{
			Success: false,
			Service: "findnet",
			Error:   err,
		}
	}

	// 记录发现的网络信息 (一次性输出，避免被其他日志打断)
	if networkInfo.Valid {
		var lines []string
		// 主机名行
		if networkInfo.Hostname != "" {
			lines = append(lines, fmt.Sprintf("NetInfo %s [%s]", target, networkInfo.Hostname))
		}
		// 每个IP单独一行
		for _, ip := range networkInfo.IPv4Addrs {
			lines = append(lines, fmt.Sprintf("NetInfo %s   -> %s", target, ip))
		}
		// 一次性输出所有行
		if len(lines) > 0 {
			common.LogSuccess(strings.Join(lines, "\n"))
		}
	}

	return &ScanResult{
		Success: networkInfo.Valid,
		Service: "findnet",
		Banner:  networkInfo.Summary(),
	}
}

// NetworkInfo 网络信息结构
type NetworkInfo struct {
	Valid     bool
	Hostname  string
	IPv4Addrs []string
	IPv6Addrs []string
}

// Summary 返回网络信息摘要
func (ni *NetworkInfo) Summary() string {
	if !ni.Valid {
		return "网络发现失败"
	}

	var parts []string
	if ni.Hostname != "" {
		parts = append(parts, fmt.Sprintf("主机名: %s", ni.Hostname))
	}
	if len(ni.IPv4Addrs) > 0 {
		parts = append(parts, fmt.Sprintf("IPv4: %d个", len(ni.IPv4Addrs)))
	}
	if len(ni.IPv6Addrs) > 0 {
		parts = append(parts, fmt.Sprintf("IPv6: %d个", len(ni.IPv6Addrs)))
	}

	if len(parts) == 0 {
		return "网络信息收集完成"
	}
	return strings.Join(parts, ", ")
}


// RPC数据包定义
var (
	rpcBuffer1, _ = hex.DecodeString("05000b03100000004800000001000000b810b810000000000100000000000100c4fefc9960521b10bbcb00aa0021347a00000000045d888aeb1cc9119fe808002b10486002000000")
	rpcBuffer2, _ = hex.DecodeString("050000031000000018000000010000000000000000000500")
	rpcBuffer3, _ = hex.DecodeString("0900ffff0000")
)

// performNetworkDiscovery 执行RPC网络发现
func (p *FindNetPlugin) performNetworkDiscovery(conn net.Conn) (*NetworkInfo, error) {
	// 发送第一个RPC请求
	if _, err := conn.Write(rpcBuffer1); err != nil {
		return nil, fmt.Errorf("发送RPC请求1失败: %w", err)
	}

	// 读取响应
	reply := make([]byte, 4096)
	if _, err := conn.Read(reply); err != nil {
		return nil, fmt.Errorf("读取RPC响应1失败: %w", err)
	}

	// 发送第二个RPC请求
	if _, err := conn.Write(rpcBuffer2); err != nil {
		return nil, fmt.Errorf("发送RPC请求2失败: %w", err)
	}

	// 读取网络信息响应
	n, err := conn.Read(reply)
	if err != nil || n < 42 {
		return nil, fmt.Errorf("读取RPC响应2失败: %w", err)
	}

	// 解析响应数据
	responseData := reply[42:]

	// 查找响应结束标记
	for i := 0; i < len(responseData)-5; i++ {
		if bytes.Equal(responseData[i:i+6], rpcBuffer3) {
			if i >= 4 {
				responseData = responseData[:i-4]
			}
			break
		}
	}

	// 解析网络信息
	return p.parseNetworkInfo(responseData), nil
}

// parseNetworkInfo 解析RPC响应中的网络信息
func (p *FindNetPlugin) parseNetworkInfo(data []byte) *NetworkInfo {
	info := &NetworkInfo{
		Valid:     false,
		IPv4Addrs: []string{},
		IPv6Addrs: []string{},
	}

	encodedStr := hex.EncodeToString(data)

	// 解析主机名
	var hostName string
	for i := 0; i < len(encodedStr)-4; i += 4 {
		if encodedStr[i:i+4] == "0000" {
			break
		}
		hostName += encodedStr[i : i+4]
	}

	if hostName != "" {
		name := p.hexUnicodeToString(hostName)
		if p.isValidHostname(name) {
			info.Hostname = name
			info.Valid = true
		}
	}

	// 用于去重的地址集合
	seenAddresses := make(map[string]struct{})

	// 解析网络信息
	netInfo := strings.ReplaceAll(encodedStr, "0700", "")
	segments := strings.Split(netInfo, "000000")

	// 处理每个网络地址段
	for _, segment := range segments {
		if len(segment) == 0 {
			continue
		}

		if len(segment)%2 != 0 {
			segment = segment + "0"
		}

		addrBytes, err := hex.DecodeString(segment)
		if err != nil {
			continue
		}

		addr := p.cleanAndValidateAddress(addrBytes)
		if _, exists := seenAddresses[addr]; addr != "" && !exists {
			seenAddresses[addr] = struct{}{}
			info.Valid = true

			if strings.Contains(addr, ":") {
				info.IPv6Addrs = append(info.IPv6Addrs, addr)
			} else if net.ParseIP(addr) != nil {
				info.IPv4Addrs = append(info.IPv4Addrs, addr)
			}
		}
	}

	return info
}

// hexUnicodeToString 将十六进制Unicode字符串转换为普通字符串
func (p *FindNetPlugin) hexUnicodeToString(src string) string {
	if len(src)%4 != 0 {
		src += strings.Repeat("0", 4-len(src)%4)
	}

	var result strings.Builder
	for i := 0; i < len(src); i += 4 {
		if i+4 > len(src) {
			break
		}

		charCode, err := strconv.ParseInt(src[i+2:i+4]+src[i:i+2], 16, 32)
		if err != nil {
			continue
		}

		if unicode.IsPrint(rune(charCode)) {
			result.WriteRune(rune(charCode))
		}
	}

	return result.String()
}

// isValidHostname 检查是否为有效主机名
func (p *FindNetPlugin) isValidHostname(name string) bool {
	if len(name) == 0 || len(name) > 255 {
		return false
	}
	return validHostnameRegex.MatchString(name)
}

// isValidNetworkAddress 检查是否为有效网络地址
func (p *FindNetPlugin) isValidNetworkAddress(addr string) bool {
	// 检查是否为IPv4或IPv6
	if ip := net.ParseIP(addr); ip != nil {
		return true
	}

	// 检查是否为有效主机名
	return p.isValidHostname(addr)
}

// cleanAndValidateAddress 清理并验证地址
func (p *FindNetPlugin) cleanAndValidateAddress(data []byte) string {
	// 转换为字符串并清理不可打印字符
	addr := strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, string(data))

	// 移除前后空白
	addr = strings.TrimSpace(addr)

	if p.isValidNetworkAddress(addr) {
		return addr
	}
	return ""
}

// init 自动注册插件
func init() {
	// 使用高效注册方式：直接传递端口信息，避免实例创建
	RegisterPluginWithPorts("findnet", func() Plugin {
		return NewFindNetPlugin()
	}, []int{135})
}
