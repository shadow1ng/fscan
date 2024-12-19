package Plugins

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"log"
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
		log.Fatalf("解密协议请求失败: %v", err)
	}
	negotiateProtocolRequest, err = hex.DecodeString(decrypted)
	if err != nil {
		log.Fatalf("解码协议请求失败: %v", err)
	}

	// 解密会话请求
	decrypted, err = AesDecrypt(sessionSetupRequest_enc, key)
	if err != nil {
		log.Fatalf("解密会话请求失败: %v", err)
	}
	sessionSetupRequest, err = hex.DecodeString(decrypted)
	if err != nil {
		log.Fatalf("解码会话请求失败: %v", err)
	}

	// 解密连接请求
	decrypted, err = AesDecrypt(treeConnectRequest_enc, key)
	if err != nil {
		log.Fatalf("解密连接请求失败: %v", err)
	}
	treeConnectRequest, err = hex.DecodeString(decrypted)
	if err != nil {
		log.Fatalf("解码连接请求失败: %v", err)
	}

	// 解密管道请求
	decrypted, err = AesDecrypt(transNamedPipeRequest_enc, key)
	if err != nil {
		log.Fatalf("解密管道请求失败: %v", err)
	}
	transNamedPipeRequest, err = hex.DecodeString(decrypted)
	if err != nil {
		log.Fatalf("解码管道请求失败: %v", err)
	}

	// 解密会话设置请求
	decrypted, err = AesDecrypt(trans2SessionSetupRequest_enc, key)
	if err != nil {
		log.Fatalf("解密会话设置请求失败: %v", err)
	}
	trans2SessionSetupRequest, err = hex.DecodeString(decrypted)
	if err != nil {
		log.Fatalf("解码会话设置请求失败: %v", err)
	}
}

// MS17010 扫描入口函数
func MS17010(info *Common.HostInfo) error {
	// 暴力破解模式下跳过扫描
	if Common.IsBrute {
		return nil
	}
	fmt.Println("[+] MS17010扫描模块开始...")

	// 执行MS17-010漏洞扫描
	err := MS17010Scan(info)
	if err != nil {
		Common.LogError(fmt.Sprintf("[-] MS17010 %v %v", info.Host, err))
	}
	fmt.Println("[+] MS17010扫描模块结束...")
	return err
}

// MS17010Scan 执行MS17-010漏洞扫描
func MS17010Scan(info *Common.HostInfo) error {
	ip := info.Host

	// 连接目标445端口
	conn, err := Common.WrapperTcpWithTimeout("tcp", ip+":445", time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	// 设置连接超时
	if err = conn.SetDeadline(time.Now().Add(time.Duration(Common.Timeout) * time.Second)); err != nil {
		return err
	}

	// 发送SMB协议协商请求
	if _, err = conn.Write(negotiateProtocolRequest); err != nil {
		return err
	}

	// 读取响应
	reply := make([]byte, 1024)
	if n, err := conn.Read(reply); err != nil || n < 36 {
		return err
	}

	// 检查协议响应状态
	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		return err
	}

	// 发送会话建立请求
	if _, err = conn.Write(sessionSetupRequest); err != nil {
		return err
	}

	// 读取响应
	n, err := conn.Read(reply)
	if err != nil || n < 36 {
		return err
	}

	// 检查会话响应状态
	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		return errors.New("无法确定目标是否存在漏洞")
	}

	// 提取操作系统信息
	var os string
	sessionSetupResponse := reply[36:n]
	if wordCount := sessionSetupResponse[0]; wordCount != 0 {
		byteCount := binary.LittleEndian.Uint16(sessionSetupResponse[7:9])
		if n != int(byteCount)+45 {
			fmt.Printf("[-] %s:445 MS17010无效的会话响应\n", ip)
		} else {
			// 查找Unicode字符串结束标记(两个连续的0字节)
			for i := 10; i < len(sessionSetupResponse)-1; i++ {
				if sessionSetupResponse[i] == 0 && sessionSetupResponse[i+1] == 0 {
					os = string(sessionSetupResponse[10:i])
					os = strings.Replace(os, string([]byte{0x00}), "", -1)
					break
				}
			}
		}
	}

	// 获取用户ID
	userID := reply[32:34]
	treeConnectRequest[32] = userID[0]
	treeConnectRequest[33] = userID[1]

	// 发送树连接请求
	if _, err = conn.Write(treeConnectRequest); err != nil {
		return err
	}

	if n, err := conn.Read(reply); err != nil || n < 36 {
		return err
	}

	// 获取树ID并设置后续请求
	treeID := reply[28:30]
	transNamedPipeRequest[28] = treeID[0]
	transNamedPipeRequest[29] = treeID[1]
	transNamedPipeRequest[32] = userID[0]
	transNamedPipeRequest[33] = userID[1]

	// 发送命名管道请求
	if _, err = conn.Write(transNamedPipeRequest); err != nil {
		return err
	}

	if n, err := conn.Read(reply); err != nil || n < 36 {
		return err
	}

	// 检查漏洞状态
	if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 {
		// 目标存在MS17-010漏洞
		Common.LogSuccess(fmt.Sprintf("[+] MS17-010 %s\t(%s)", ip, os))

		// 如果指定了shellcode,执行漏洞利用
		defer func() {
			if Common.SC != "" {
				MS17010EXP(info)
			}
		}()

		// 检测DOUBLEPULSAR后门
		trans2SessionSetupRequest[28] = treeID[0]
		trans2SessionSetupRequest[29] = treeID[1]
		trans2SessionSetupRequest[32] = userID[0]
		trans2SessionSetupRequest[33] = userID[1]

		if _, err = conn.Write(trans2SessionSetupRequest); err != nil {
			return err
		}

		if n, err := conn.Read(reply); err != nil || n < 36 {
			return err
		}

		if reply[34] == 0x51 {
			Common.LogSuccess(fmt.Sprintf("[+] MS17-010 %s 存在DOUBLEPULSAR后门", ip))
		}
	} else {
		// 未检测到漏洞,仅输出系统信息
		Common.LogSuccess(fmt.Sprintf("[*] OsInfo %s\t(%s)", ip, os))
	}

	return err
}
