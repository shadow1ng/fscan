package Plugins

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var (
	bufferV1, _ = hex.DecodeString("05000b03100000004800000001000000b810b810000000000100000000000100c4fefc9960521b10bbcb00aa0021347a00000000045d888aeb1cc9119fe808002b10486002000000")
	bufferV2, _ = hex.DecodeString("050000031000000018000000010000000000000000000500")
	bufferV3, _ = hex.DecodeString("0900ffff0000")
)

func Findnet(info *Common.HostInfo) error {
	return FindnetScan(info)
}

func FindnetScan(info *Common.HostInfo) error {
	target := fmt.Sprintf("%s:%v", info.Host, 135)
	conn, err := Common.WrapperTcpWithTimeout("tcp", target, time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		return fmt.Errorf("[-] 连接RPC端口失败: %v", err)
	}
	defer conn.Close()

	if err = conn.SetDeadline(time.Now().Add(time.Duration(Common.Timeout) * time.Second)); err != nil {
		return fmt.Errorf("[-] 设置超时失败: %v", err)
	}

	if _, err = conn.Write(bufferV1); err != nil {
		return fmt.Errorf("[-] 发送RPC请求1失败: %v", err)
	}

	reply := make([]byte, 4096)
	if _, err = conn.Read(reply); err != nil {
		return fmt.Errorf("[-] 读取RPC响应1失败: %v", err)
	}

	if _, err = conn.Write(bufferV2); err != nil {
		return fmt.Errorf("[-] 发送RPC请求2失败: %v", err)
	}

	n, err := conn.Read(reply)
	if err != nil || n < 42 {
		return fmt.Errorf("[-] 读取RPC响应2失败: %v", err)
	}

	text := reply[42:]
	found := false
	for i := 0; i < len(text)-5; i++ {
		if bytes.Equal(text[i:i+6], bufferV3) {
			text = text[:i-4]
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("[-] 未找到有效的响应标记")
	}

	return read(text, info.Host)
}

func HexUnicodeStringToString(src string) string {
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

func isValidHostname(name string) bool {
	if len(name) == 0 || len(name) > 255 {
		return false
	}

	validHostname := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$`)
	return validHostname.MatchString(name)
}

func isValidNetworkAddress(addr string) bool {
	// 检查是否为IPv4或IPv6
	if ip := net.ParseIP(addr); ip != nil {
		return true
	}

	// 检查是否为有效主机名
	return isValidHostname(addr)
}

func cleanAndValidateAddress(data []byte) string {
	// 转换为字符串并清理不可打印字符
	addr := strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, string(data))

	// 移除前后空白
	addr = strings.TrimSpace(addr)

	if isValidNetworkAddress(addr) {
		return addr
	}
	return ""
}

func read(text []byte, host string) error {
	encodedStr := hex.EncodeToString(text)

	// 解析主机名
	var hostName string
	for i := 0; i < len(encodedStr)-4; i += 4 {
		if encodedStr[i:i+4] == "0000" {
			break
		}
		hostName += encodedStr[i : i+4]
	}

	name := HexUnicodeStringToString(hostName)
	if !isValidHostname(name) {
		name = ""
	}

	// 构建基础结果
	result := fmt.Sprintf("[*] NetInfo 扫描结果")
	result += fmt.Sprintf("\n[*] 目标主机: %s", host)
	if name != "" {
		result += fmt.Sprintf("\n[*] 主机名: %s", name)
	}
	result += "\n[*] 发现的网络接口:"

	// 用于分类存储地址
	var ipv4Addrs []string
	var ipv6Addrs []string
	seenAddresses := make(map[string]bool)

	// 解析网络信息
	netInfo := strings.Replace(encodedStr, "0700", "", -1)
	segments := strings.Split(netInfo, "000000")

	// 处理每个网络地址
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

		addr := cleanAndValidateAddress(addrBytes)
		if addr != "" && !seenAddresses[addr] {
			seenAddresses[addr] = true

			// 分类IPv4和IPv6地址
			if strings.Contains(addr, ":") {
				ipv6Addrs = append(ipv6Addrs, addr)
			} else if net.ParseIP(addr) != nil {
				ipv4Addrs = append(ipv4Addrs, addr)
			}
		}
	}

	// 输出IPv4地址
	if len(ipv4Addrs) > 0 {
		result += "\n   [+] IPv4地址:"
		for _, addr := range ipv4Addrs {
			result += fmt.Sprintf("\n      └─ %s", addr)
		}
	}

	// 输出IPv6地址
	if len(ipv6Addrs) > 0 {
		result += "\n   [+] IPv6地址:"
		for _, addr := range ipv6Addrs {
			result += fmt.Sprintf("\n      └─ %s", addr)
		}
	}

	Common.LogSuccess(result)
	return nil
}
