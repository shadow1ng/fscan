//go:build plugin_ms17010 || !plugin_selective

package services

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"scanner/common"
	"scanner/common/i18n"
	"scanner/plugins"
)

// MS17010Plugin MS17-010漏洞检测插件（仅检测，不含利用功能）
type MS17010Plugin struct {
	plugins.BasePlugin
}

// NewMS17010Plugin 创建MS17010插件
func NewMS17010Plugin() *MS17010Plugin {
	return &MS17010Plugin{
		BasePlugin: plugins.NewBasePlugin("ms17010"),
	}
}

// Scan 执行MS17-010扫描
func (p *MS17010Plugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	target := info.Target()

	// 检查端口
	if info.Port != 445 {
		return &ScanResult{
			Success: false,
			Service: "ms17010",
			Error:   fmt.Errorf("%s", i18n.GetText("ms17010_port_only")),
		}
	}

	// 执行MS17010漏洞检测
	vulnerable, osVersion, hasBackdoor, err := p.checkMS17010Vulnerability(ctx, info.Host, session)
	if err != nil {
		return &ScanResult{
			Success: false,
			Service: "ms17010",
			Error:   err,
		}
	}

	if vulnerable {
		msg := fmt.Sprintf("MS17-010 %s", target)
		if osVersion != "" {
			msg += fmt.Sprintf(" [%s]", osVersion)
		}
		session.LogVuln(msg)
		if hasBackdoor {
			session.LogVuln(fmt.Sprintf("MS17-010 %s has DOUBLEPULSAR SMB IMPLANT", target))
		}

		return &ScanResult{
			Success: true,
			Type:    plugins.ResultTypeVuln,
			Service: "ms17010",
			Banner:  i18n.Tr("ms17010_vuln_banner", osVersion),
		}
	}

	return &ScanResult{
		Success: false,
		Service: "ms17010",
		Error:   fmt.Errorf("%s", i18n.GetText("ms17010_not_vulnerable")),
	}
}

// SMB握手数据加解密工具函数

// AES解密函数
func aesDecrypt(crypted string, key string) (string, error) {
	cryptedBytes, err := base64.StdEncoding.DecodeString(crypted)
	if err != nil {
		return "", fmt.Errorf("%s: %w", i18n.GetText("ms17010_base64_decode_failed"), err)
	}

	keyBytes := []byte(key)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("%s: %w", i18n.GetText("ms17010_aes_cipher_failed"), err)
	}

	if len(cryptedBytes) < aes.BlockSize {
		return "", fmt.Errorf("%s", i18n.GetText("ms17010_ciphertext_too_short"))
	}

	mode := cipher.NewCBCDecrypter(block, keyBytes[:aes.BlockSize])
	mode.CryptBlocks(cryptedBytes, cryptedBytes)

	// 移除PKCS7填充
	padding := int(cryptedBytes[len(cryptedBytes)-1])
	if padding > len(cryptedBytes) || padding > aes.BlockSize {
		return "", fmt.Errorf("%s", i18n.GetText("ms17010_invalid_padding"))
	}

	for i := len(cryptedBytes) - padding; i < len(cryptedBytes); i++ {
		if cryptedBytes[i] != byte(padding) {
			return "", fmt.Errorf("%s", i18n.GetText("ms17010_padding_check_failed"))
		}
	}

	return string(cryptedBytes[:len(cryptedBytes)-padding]), nil
}

// AES解密密钥
var defaultKey = "0123456789abcdef"

// SMB协议检测请求数据（仅用于漏洞检测，不含利用载荷）
var (
	negotiateProtocolRequestEnc  = "G8o+kd/4y8chPCaObKK8L9+tJVFBb7ntWH/EXJ74635V3UTXA4TFOc6uabZfuLr0Xisnk7OsKJZ2Xdd3l8HNLdMOYZXAX5ZXnMC4qI+1d/MXA2TmidXeqGt8d9UEF5VesQlhP051GGBSldkJkVrP/fzn4gvLXcwgAYee3Zi2opAvuM6ScXrMkcbx200ThnOOEx98/7ArteornbRiXQjnr6dkJEUDTS43AW6Jl3OK2876Yaz5iYBx+DW5WjiLcMR+b58NJRxm4FlVpusZjBpzEs4XOEqglk6QIWfWbFZYgdNLy3WaFkkgDjmB1+6LhpYSOaTsh4EM0rwZq2Z4Lr8TE5WcPkb/JNsWNbibKlwtNtp94fIYvAWgxt5mn/oXpfUD"
	sessionSetupRequestEnc       = "52HeCQEbsSwiSXg98sdD64qyRou0jARlvfQi1ekDHS77Nk/8dYftNXlFahLEYWIxYYJ8u53db9OaDfAvOEkuox+p+Ic1VL70r9Q5HuL+NMyeyeN5T5el07X5cT66oBDJnScs1XdvM6CBRtj1kUs2h40Z5Vj9EGzGk99SFXjSqbtGfKFBp0DhL5wPQKsoiXYLKKh9NQiOhOMWHYy/C+Iwhf3Qr8d1Wbs2vgEzaWZqIJ3BM3z+dhRBszQoQftszC16TUhGQc48XPFHN74VRxXgVe6xNQwqrWEpA4hcQeF1+QqRVHxuN+PFR7qwEcU1JbnTNISaSrqEe8GtRo1r2rs7+lOFmbe4qqyUMgHhZ6Pwu1bkhrocMUUzWQBogAvXwFb8"
	treeConnectRequestEnc        = "+b/lRcmLzH0c0BYhiTaYNvTVdYz1OdYYDKhzGn/3T3P4b6pAR8D+xPdlb7O4D4A9KMyeIBphDPmEtFy44rtto2dadFoit350nghebxbYA0pTCWIBd1kN0BGMEidRDBwLOpZE6Qpph/DlziDjjfXUz955dr0cigc9ETHD/+f3fELKsopTPkbCsudgCs48mlbXcL13GVG5cGwKzRuP4ezcdKbYzq1DX2I7RNeBtw/vAlYh6etKLv7s+YyZ/r8m0fBY9A57j+XrsmZAyTWbhPJkCg=="
	transNamedPipeRequestEnc     = "k/RGiUQ/tw1yiqioUIqirzGC1SxTAmQmtnfKd1qiLish7FQYxvE+h4/p7RKgWemIWRXDf2XSJ3K0LUIX0vv1gx2eb4NatU7Qosnrhebz3gUo7u25P5BZH1QKdagzPqtitVjASpxIjB3uNWtYMrXGkkuAm8QEitberc+mP0vnzZ8Nv/xiiGBko8O4P/wCKaN2KZVDLbv2jrN8V/1zY6fvWA=="
	trans2SessionSetupRequestEnc = "JqNw6PUKcWOYFisUoUCyD24wnML2Yd8kumx9hJnFWbhM2TQkRvKHsOMWzPVfggRrLl8sLQFqzk8bv8Rpox3uS61l480Mv7HdBPeBeBeFudZMntXBUa4pWUH8D9EXCjoUqgAdvw6kGbPOOKUq3WmNb0GDCZapqQwyUKKMHmNIUMVMAOyVfKeEMJA6LViGwyvHVMNZ1XWLr0xafKfEuz4qoHiDyVWomGjJt8DQd6+jgLk="

	// SMB协议解密后的请求数据
	negotiateProtocolRequest  []byte
	sessionSetupRequest       []byte
	treeConnectRequest        []byte
	transNamedPipeRequest     []byte
	trans2SessionSetupRequest []byte
)

// 初始化解密SMB协议数据
func init() {
	var err error

	// 解密协议请求
	decrypted, err := aesDecrypt(negotiateProtocolRequestEnc, defaultKey)
	if err != nil {
		common.LogError(i18n.Tr("ms17010_protocol_decrypt_error", err))
		return
	}
	negotiateProtocolRequest, err = hex.DecodeString(decrypted)
	if err != nil {
		common.LogError(i18n.Tr("ms17010_protocol_decode_error", err))
		return
	}

	// 解密会话请求
	decrypted, err = aesDecrypt(sessionSetupRequestEnc, defaultKey)
	if err != nil {
		common.LogError(i18n.Tr("ms17010_session_decrypt_error", err))
		return
	}
	sessionSetupRequest, err = hex.DecodeString(decrypted)
	if err != nil {
		common.LogError(i18n.Tr("ms17010_session_decode_error", err))
		return
	}

	// 解密连接请求
	decrypted, err = aesDecrypt(treeConnectRequestEnc, defaultKey)
	if err != nil {
		common.LogError(i18n.Tr("ms17010_connect_decrypt_error", err))
		return
	}
	treeConnectRequest, err = hex.DecodeString(decrypted)
	if err != nil {
		common.LogError(i18n.Tr("ms17010_connect_decode_error", err))
		return
	}

	// 解密管道请求
	decrypted, err = aesDecrypt(transNamedPipeRequestEnc, defaultKey)
	if err != nil {
		common.LogError(i18n.Tr("ms17010_pipe_decrypt_error", err))
		return
	}
	transNamedPipeRequest, err = hex.DecodeString(decrypted)
	if err != nil {
		common.LogError(i18n.Tr("ms17010_pipe_decode_error", err))
		return
	}

	decrypted, err = aesDecrypt(trans2SessionSetupRequestEnc, defaultKey)
	if err != nil {
		common.LogError(i18n.Tr("ms17010_pipe_decrypt_error", err))
		return
	}
	trans2SessionSetupRequest, err = hex.DecodeString(decrypted)
	if err != nil {
		common.LogError(i18n.Tr("ms17010_pipe_decode_error", err))
		return
	}
}

// checkMS17010Vulnerability 检测MS17-010漏洞（SMBv1协议握手+特征匹配）
func (p *MS17010Plugin) checkMS17010Vulnerability(ctx context.Context, ip string, session *common.ScanSession) (bool, string, bool, error) {
	return p.checkMS17010VulnerabilityAt(ctx, net.JoinHostPort(ip, "445"), session)
}

func (p *MS17010Plugin) checkMS17010VulnerabilityAt(ctx context.Context, address string, session *common.ScanSession) (bool, string, bool, error) {
	conn, err := session.DialTCP(ctx, "tcp", address, session.Config.ModuleTimeout())
	if err != nil {
		return false, "", false, fmt.Errorf("%s: %w", i18n.GetText("ms17010_connection_error"), err)
	}
	defer func() { _ = conn.Close() }()

	if err = conn.SetDeadline(time.Now().Add(session.Config.ModuleTimeout())); err != nil {
		return false, "", false, fmt.Errorf("%s: %w", i18n.GetText("ms17010_set_timeout_error"), err)
	}

	// SMB协议协商
	if _, err = conn.Write(negotiateProtocolRequest); err != nil {
		return false, "", false, fmt.Errorf("%s: %w", i18n.GetText("ms17010_send_protocol_error"), err)
	}

	reply := make([]byte, 1024)
	n, readErr := conn.Read(reply)
	if readErr != nil || n < 36 {
		// 连接被关闭或响应不完整，通常表示目标不支持SMBv1
		return false, "", false, fmt.Errorf("%s", i18n.GetText("ms17010_smbv1_unsupported"))
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		return false, "", false, fmt.Errorf("%s", i18n.GetText("ms17010_smbv1_rejected"))
	}

	// 建立会话
	if _, err = conn.Write(sessionSetupRequest); err != nil {
		return false, "", false, fmt.Errorf("%s: %w", i18n.GetText("ms17010_send_session_error"), err)
	}

	n, readErr = conn.Read(reply)
	if readErr != nil || n < 36 {
		return false, "", false, fmt.Errorf("%s", i18n.GetText("ms17010_session_failed"))
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		return false, "", false, fmt.Errorf("%s", i18n.GetText("ms17010_session_rejected"))
	}

	// 提取系统信息
	var osVersion string
	sessionSetupResponse := reply[36:n]
	if len(sessionSetupResponse) > 0 && sessionSetupResponse[0] != 0 && len(sessionSetupResponse) >= 10 {
		byteCount := binary.LittleEndian.Uint16(sessionSetupResponse[7:9])
		if n == int(byteCount)+45 {
			for i := 10; i < len(sessionSetupResponse)-1; i++ {
				if sessionSetupResponse[i] == 0 && sessionSetupResponse[i+1] == 0 {
					osVersion = string(sessionSetupResponse[10:i])
					osVersion = strings.ReplaceAll(osVersion, string([]byte{0x00}), "")
					break
				}
			}
		}
	}

	// 树连接请求
	userID := reply[32:34]
	treeConnect := append([]byte(nil), treeConnectRequest...)
	treeConnect[32] = userID[0]
	treeConnect[33] = userID[1]

	if _, err = conn.Write(treeConnect); err != nil {
		return false, osVersion, false, fmt.Errorf("%s: %w", i18n.GetText("ms17010_send_tree_error"), err)
	}

	n, readErr = conn.Read(reply)
	if readErr != nil || n < 36 {
		if readErr != nil {
			return false, osVersion, false, fmt.Errorf("%s: %w", i18n.GetText("ms17010_read_tree_error"), readErr)
		}
		return false, osVersion, false, fmt.Errorf("%s", i18n.GetText("ms17010_tree_response_incomplete"))
	}

	// 命名管道请求
	treeID := reply[28:30]
	transNamedPipe := append([]byte(nil), transNamedPipeRequest...)
	transNamedPipe[28] = treeID[0]
	transNamedPipe[29] = treeID[1]
	transNamedPipe[32] = userID[0]
	transNamedPipe[33] = userID[1]

	if _, err = conn.Write(transNamedPipe); err != nil {
		return false, osVersion, false, fmt.Errorf("%s: %w", i18n.GetText("ms17010_send_pipe_error"), err)
	}

	n, readErr = conn.Read(reply)
	if readErr != nil || n < 36 {
		if readErr != nil {
			return false, osVersion, false, fmt.Errorf("%s: %w", i18n.GetText("ms17010_read_pipe_error"), readErr)
		}
		return false, osVersion, false, fmt.Errorf("%s", i18n.GetText("ms17010_pipe_response_incomplete"))
	}

	// 漏洞检测 - 关键检查点
	if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 {
		trans2SessionSetup := append([]byte(nil), trans2SessionSetupRequest...)
		trans2SessionSetup[28] = treeID[0]
		trans2SessionSetup[29] = treeID[1]
		trans2SessionSetup[32] = userID[0]
		trans2SessionSetup[33] = userID[1]

		if _, err = conn.Write(trans2SessionSetup); err != nil {
			return true, osVersion, false, nil
		}
		n, readErr = conn.Read(reply)
		if readErr != nil || n < 36 {
			return true, osVersion, false, nil
		}

		return true, osVersion, reply[34] == 0x51, nil
	}

	return false, osVersion, false, nil
}

// init 自动注册插件
func init() {
	// 使用高效注册方式：直接传递端口信息，避免实例创建
	RegisterPluginWithPorts("ms17010", func() Plugin {
		return NewMS17010Plugin()
	}, []int{445})
}
