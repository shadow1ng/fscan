package Plugins

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"os"
	"strings"
	"time"
)

var (
	// SMB协议加密的请求数据
	negotiateProtocolRequest_enc  = "G8o+kd/4y8chPCaObKK8L9+tJVFBb7ntWH/EXJ74635V3UTXA4TFOc6uabZfuLr0Xisnk7OsKJZ2Xdd3l8HNLdMOYZXAX5ZXnMC4qI+1d/MXA2TmidXeqGt8d9UEF5VesQlhP051GGBSldkJkVrP/fzn4gvLXcwgAYee3Zi2opAvuM6ScXrMkcbx200ThnOOEx98/7ArteornbRiXQjnr6dkJEUDTS43AW6Jl3OK2876Yaz5iYBx+DW5WjiLcMR+b58NJRxm4FlVpusZjBpzEs4XOEqglk6QIWfWbFZYgdNLy3WaFkkgDjmB1+6LhpYSOaTsh4EM0rwZq2Z4Lr8TE5WcPkb/JNsWNbibKlwtNtp94fIYvAWgxt5mn/oXpfUD"
	sessionSetupRequest_enc       = "52HeCQEbsSwiSXg98sdD64qyRou0jARlvfQi1ekDHS77Nk/8dYftNXlFahLEYWIxYYJ8u53db9OaDfAvOEkuox+p+Ic1VL70r9Q5HuL+NMyeyeN5T5el07X5cT66oBDJnScs1XdvM6CBRtj1kUs2h40Z5Vj9EGzGk99SFXjSqbtGfKFBp0DhL5wPQKsoiXYLKKh9NQiOhOMWHYy/C+Iwhf3Qr8d1Wbs2vgEzaWZqIJ3BM3z+dhRBszQoQftszC16TUhGQc48XPFHN74VRxXgVe6xNQwqrWEpA4hcQeF1+QqRVHxuN+PFR7qwEcU1JbnTNISaSrqEe8GtRo1r2rs7+lOFmbe4qqyUMgHhZ6Pwu1bkhrocMUUzWQBogAvXwFb8"
	treeConnectRequest_enc        = "+b/lRcmLzH0c0BYhiTaYNvTVdYz1OdYYDKhzGn/3T3P4b6pAR8D+xPdlb7O4D4A9KMyeIBphDPmEtFy44rtto2dadFoit350nghebxbYA0pTCWIBd1kN0BGMEidRDBwLOpZE6Qpph/DlziDjjfXUz955dr0cigc9ETHD/+f3fELKsopTPkbCsudgCs48mlbXcL13GVG5cGwKzRuP4ezcdKbYzq1DX2I7RNeBtw/vAlYh6etKLv7s+YyZ/r8m0fBY9A57j+XrsmZAyTWbhPJkCg=="
	transNamedPipeRequest_enc     = "k/RGiUQ/tw1yiqioUIqirzGC1SxTAmQmtnfKd1qiLish7FQYxvE+h4/p7RKgWemIWRXDf2XSJ3K0LUIX0vv1gx2eb4NatU7Qosnrhebz3gUo7u25P5BZH1QKdagzPqtitVjASpxIjB3uNWtYMrXGkkuAm8QEitberc+mP0vnzZ8Nv/xiiGBko8O4P/wCKaN2KZVDLbv2jrN8V/1zY6fvWA=="
	trans2SessionSetupRequest_enc = "JqNw6PUKcWOYFisUoUCyD24wnML2Yd8kumx9hJnFWbhM2TQkRvKHsOMWzPVfggRrLl8sLQFqzk8bv8Rpox3uS61l480Mv7HdBPeBeBeFudZMntXBUa4pWUH8D9EXCjoUqgAdvw6kGbPOOKUq3WmNb0GDCZapqQwyUKKMHmNIUMVMAOyVfKeEMJA6LViGwyvHVMNZ1XWLr0xafKfEuz4qoHiDyVWomGjJt8DQd6+jgLk="

	// SMB协议解密后的请求数据
	negotiateProtocolRequest  []byte
	sessionSetupRequest       []byte
	treeConnectRequest        []byte
	transNamedPipeRequest     []byte
	trans2SessionSetupRequest []byte
)

func init() {
	var err error

	// 解密协议请求
	decrypted, err := AesDecrypt(negotiateProtocolRequest_enc, key)
	if err != nil {
		Common.LogError(fmt.Sprintf("协议请求解密错误: %v", err))
		os.Exit(1)
	}
	negotiateProtocolRequest, err = hex.DecodeString(decrypted)
	if err != nil {
		Common.LogError(fmt.Sprintf("协议请求解码错误: %v", err))
		os.Exit(1)
	}

	// 解密会话请求
	decrypted, err = AesDecrypt(sessionSetupRequest_enc, key)
	if err != nil {
		Common.LogError(fmt.Sprintf("会话请求解密错误: %v", err))
		os.Exit(1)
	}
	sessionSetupRequest, err = hex.DecodeString(decrypted)
	if err != nil {
		Common.LogError(fmt.Sprintf("会话请求解码错误: %v", err))
		os.Exit(1)
	}

	// 解密连接请求
	decrypted, err = AesDecrypt(treeConnectRequest_enc, key)
	if err != nil {
		Common.LogError(fmt.Sprintf("连接请求解密错误: %v", err))
		os.Exit(1)
	}
	treeConnectRequest, err = hex.DecodeString(decrypted)
	if err != nil {
		Common.LogError(fmt.Sprintf("连接请求解码错误: %v", err))
		os.Exit(1)
	}

	// 解密管道请求
	decrypted, err = AesDecrypt(transNamedPipeRequest_enc, key)
	if err != nil {
		Common.LogError(fmt.Sprintf("管道请求解密错误: %v", err))
		os.Exit(1)
	}
	transNamedPipeRequest, err = hex.DecodeString(decrypted)
	if err != nil {
		Common.LogError(fmt.Sprintf("管道请求解码错误: %v", err))
		os.Exit(1)
	}

	// 解密会话设置请求
	decrypted, err = AesDecrypt(trans2SessionSetupRequest_enc, key)
	if err != nil {
		Common.LogError(fmt.Sprintf("会话设置解密错误: %v", err))
		os.Exit(1)
	}
	trans2SessionSetupRequest, err = hex.DecodeString(decrypted)
	if err != nil {
		Common.LogError(fmt.Sprintf("会话设置解码错误: %v", err))
		os.Exit(1)
	}
}

// MS17010 扫描入口函数
func MS17010(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	err := MS17010Scan(info)
	if err != nil {
		Common.LogError(fmt.Sprintf("%s:%s - %v", info.Host, info.Ports, err))
	}
	return err
}

func MS17010Scan(info *Common.HostInfo) error {
	ip := info.Host

	// 连接目标
	conn, err := Common.WrapperTcpWithTimeout("tcp", ip+":445", time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		return fmt.Errorf("连接错误: %v", err)
	}
	defer conn.Close()

	if err = conn.SetDeadline(time.Now().Add(time.Duration(Common.Timeout) * time.Second)); err != nil {
		return fmt.Errorf("设置超时错误: %v", err)
	}

	// SMB协议协商
	if _, err = conn.Write(negotiateProtocolRequest); err != nil {
		return fmt.Errorf("发送协议请求错误: %v", err)
	}

	reply := make([]byte, 1024)
	if n, err := conn.Read(reply); err != nil || n < 36 {
		if err != nil {
			return fmt.Errorf("读取协议响应错误: %v", err)
		}
		return fmt.Errorf("协议响应不完整")
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		return fmt.Errorf("协议协商被拒绝")
	}

	// 建立会话
	if _, err = conn.Write(sessionSetupRequest); err != nil {
		return fmt.Errorf("发送会话请求错误: %v", err)
	}

	n, err := conn.Read(reply)
	if err != nil || n < 36 {
		if err != nil {
			return fmt.Errorf("读取会话响应错误: %v", err)
		}
		return fmt.Errorf("会话响应不完整")
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		return fmt.Errorf("会话建立失败")
	}

	// 提取系统信息
	var os string
	sessionSetupResponse := reply[36:n]
	if wordCount := sessionSetupResponse[0]; wordCount != 0 {
		byteCount := binary.LittleEndian.Uint16(sessionSetupResponse[7:9])
		if n != int(byteCount)+45 {
			Common.LogError(fmt.Sprintf("无效会话响应 %s:445", ip))
		} else {
			for i := 10; i < len(sessionSetupResponse)-1; i++ {
				if sessionSetupResponse[i] == 0 && sessionSetupResponse[i+1] == 0 {
					os = string(sessionSetupResponse[10:i])
					os = strings.Replace(os, string([]byte{0x00}), "", -1)
					break
				}
			}
		}
	}

	// 树连接请求
	userID := reply[32:34]
	treeConnectRequest[32] = userID[0]
	treeConnectRequest[33] = userID[1]

	if _, err = conn.Write(treeConnectRequest); err != nil {
		return fmt.Errorf("发送树连接请求错误: %v", err)
	}

	if n, err := conn.Read(reply); err != nil || n < 36 {
		if err != nil {
			return fmt.Errorf("读取树连接响应错误: %v", err)
		}
		return fmt.Errorf("树连接响应不完整")
	}

	// 命名管道请求
	treeID := reply[28:30]
	transNamedPipeRequest[28] = treeID[0]
	transNamedPipeRequest[29] = treeID[1]
	transNamedPipeRequest[32] = userID[0]
	transNamedPipeRequest[33] = userID[1]

	if _, err = conn.Write(transNamedPipeRequest); err != nil {
		return fmt.Errorf("发送管道请求错误: %v", err)
	}

	if n, err := conn.Read(reply); err != nil || n < 36 {
		if err != nil {
			return fmt.Errorf("读取管道响应错误: %v", err)
		}
		return fmt.Errorf("管道响应不完整")
	}

	// 漏洞检测部分添加 Output
	if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 {
		// 构造基本详情
		details := map[string]interface{}{
			"port":          "445",
			"vulnerability": "MS17-010",
		}
		if os != "" {
			details["os"] = os
			Common.LogSuccess(fmt.Sprintf("发现漏洞 %s [%s] MS17-010", ip, os))
		} else {
			Common.LogSuccess(fmt.Sprintf("发现漏洞 %s MS17-010", ip))
		}

		// 保存 MS17-010 漏洞结果
		result := &Common.ScanResult{
			Time:    time.Now(),
			Type:    Common.VULN,
			Target:  ip,
			Status:  "vulnerable",
			Details: details,
		}
		Common.SaveResult(result)

		// DOUBLEPULSAR 后门检测
		trans2SessionSetupRequest[28] = treeID[0]
		trans2SessionSetupRequest[29] = treeID[1]
		trans2SessionSetupRequest[32] = userID[0]
		trans2SessionSetupRequest[33] = userID[1]

		if _, err = conn.Write(trans2SessionSetupRequest); err != nil {
			return fmt.Errorf("发送后门检测请求错误: %v", err)
		}

		if n, err := conn.Read(reply); err != nil || n < 36 {
			if err != nil {
				return fmt.Errorf("读取后门检测响应错误: %v", err)
			}
			return fmt.Errorf("后门检测响应不完整")
		}

		if reply[34] == 0x51 {
			Common.LogSuccess(fmt.Sprintf("发现后门 %s DOUBLEPULSAR", ip))

			// 保存 DOUBLEPULSAR 后门结果
			backdoorResult := &Common.ScanResult{
				Time:   time.Now(),
				Type:   Common.VULN,
				Target: ip,
				Status: "backdoor",
				Details: map[string]interface{}{
					"port": "445",
					"type": "DOUBLEPULSAR",
					"os":   os,
				},
			}
			Common.SaveResult(backdoorResult)
		}

		// Shellcode 利用部分保持不变
		if Common.Shellcode != "" {
			defer MS17010EXP(info)
		}
	} else if os != "" {
		Common.LogBase(fmt.Sprintf("系统信息 %s [%s]", ip, os))

		// 保存系统信息
		sysResult := &Common.ScanResult{
			Time:   time.Now(),
			Type:   Common.SERVICE,
			Target: ip,
			Status: "identified",
			Details: map[string]interface{}{
				"port":    "445",
				"service": "smb",
				"os":      os,
			},
		}
		Common.SaveResult(sysResult)
	}

	return nil
}
