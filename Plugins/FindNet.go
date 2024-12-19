package Plugins

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"strconv"
	"strings"
	"time"
)

var (
	// RPC请求数据包
	bufferV1, _ = hex.DecodeString("05000b03100000004800000001000000b810b810000000000100000000000100c4fefc9960521b10bbcb00aa0021347a00000000045d888aeb1cc9119fe808002b10486002000000")
	bufferV2, _ = hex.DecodeString("050000031000000018000000010000000000000000000500")
	bufferV3, _ = hex.DecodeString("0900ffff0000")
)

// Findnet 探测Windows网络主机信息的入口函数
func Findnet(info *Common.HostInfo) error {
	return FindnetScan(info)
}

// FindnetScan 通过RPC协议扫描网络主机信息
func FindnetScan(info *Common.HostInfo) error {
	// 连接目标RPC端口
	target := fmt.Sprintf("%s:%v", info.Host, 135)
	conn, err := Common.WrapperTcpWithTimeout("tcp", target, time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		return fmt.Errorf("[-] 连接RPC端口失败: %v", err)
	}
	defer conn.Close()

	// 设置连接超时
	if err = conn.SetDeadline(time.Now().Add(time.Duration(Common.Timeout) * time.Second)); err != nil {
		return fmt.Errorf("[-] 设置超时失败: %v", err)
	}

	// 发送第一个RPC请求
	if _, err = conn.Write(bufferV1); err != nil {
		return fmt.Errorf("[-] 发送RPC请求1失败: %v", err)
	}

	// 读取响应
	reply := make([]byte, 4096)
	if _, err = conn.Read(reply); err != nil {
		return fmt.Errorf("[-] 读取RPC响应1失败: %v", err)
	}

	// 发送第二个RPC请求
	if _, err = conn.Write(bufferV2); err != nil {
		return fmt.Errorf("[-] 发送RPC请求2失败: %v", err)
	}

	// 读取并检查响应
	n, err := conn.Read(reply)
	if err != nil || n < 42 {
		return fmt.Errorf("[-] 读取RPC响应2失败: %v", err)
	}

	// 解析响应数据
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
		fmt.Println("[+] FindNet扫描模块结束...")
		return fmt.Errorf("[-] 未找到有效的响应标记")
	}

	// 解析主机信息
	return read(text, info.Host)
}

// HexUnicodeStringToString 将16进制Unicode字符串转换为可读字符串
func HexUnicodeStringToString(src string) string {
	// 确保输入长度是4的倍数
	if len(src)%4 != 0 {
		src += src[:len(src)-len(src)%4]
	}

	// 转换为标准Unicode格式
	var sText string
	for i := 0; i < len(src); i += 4 {
		sText += "\\u" + src[i+2:i+4] + src[i:i+2] // 调整字节顺序
	}

	// 解析每个Unicode字符
	unicodeChars := strings.Split(sText, "\\u")
	var result string

	for _, char := range unicodeChars {
		// 跳过空字符
		if len(char) < 1 {
			continue
		}

		// 将16进制转换为整数
		codePoint, err := strconv.ParseInt(char, 16, 32)
		if err != nil {
			return ""
		}

		// 转换为实际字符
		result += fmt.Sprintf("%c", codePoint)
	}

	return result
}

// read 解析并显示主机网络信息
func read(text []byte, host string) error {
	// 将原始数据转换为16进制字符串
	encodedStr := hex.EncodeToString(text)

	// 解析主机名
	var hostName string
	for i := 0; i < len(encodedStr)-4; i += 4 {
		if encodedStr[i:i+4] == "0000" {
			break
		}
		hostName += encodedStr[i : i+4]
	}

	// 转换主机名为可读字符串
	name := HexUnicodeStringToString(hostName)

	// 解析网络信息
	netInfo := strings.Replace(encodedStr, "0700", "", -1)
	hosts := strings.Split(netInfo, "000000")
	hosts = hosts[1:] // 跳过第一个空元素

	// 构造输出结果
	result := fmt.Sprintf("[*] NetInfo\n[*] %s", host)
	if name != "" {
		result += fmt.Sprintf("\n   [->] %s", name)
	}

	// 解析每个网络主机信息
	for _, h := range hosts {
		// 移除填充字节
		h = strings.Replace(h, "00", "", -1)

		// 解码主机信息
		hostInfo, err := hex.DecodeString(h)
		if err != nil {
			return fmt.Errorf("[-] 解码主机信息失败: %v", err)
		}
		result += fmt.Sprintf("\n   [->] %s", string(hostInfo))
	}

	// 输出结果
	Common.LogSuccess(result)
	return nil
}
