package Plugins

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"regexp"
	"strings"
	"time"
)

// TelnetScan 执行Telnet服务扫描和密码爆破
func TelnetScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))
	totalUsers := len(Common.Userdict["telnet"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// 遍历所有用户名密码组合
	for _, user := range Common.Userdict["telnet"] {
		for _, pass := range Common.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			Common.LogDebug(fmt.Sprintf("[%d/%d] 尝试: %s:%s", tried, total, user, pass))

			// 重试循环
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retryCount+1, user, pass))
				}

				done := make(chan struct {
					success bool
					noAuth  bool
					err     error
				}, 1)

				go func(user, pass string) {
					flag, err := telnetConn(info, user, pass)
					select {
					case done <- struct {
						success bool
						noAuth  bool
						err     error
					}{err == nil, flag, err}:
					default:
					}
				}(user, pass)

				var err error
				select {
				case result := <-done:
					err = result.err
					if result.noAuth {
						// 无需认证
						msg := fmt.Sprintf("Telnet服务 %s 无需认证", target)
						Common.LogSuccess(msg)

						// 保存结果
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":    info.Ports,
								"service": "telnet",
								"type":    "unauthorized-access",
							},
						}
						Common.SaveResult(vulnResult)
						return nil

					} else if result.success {
						// 成功爆破
						msg := fmt.Sprintf("Telnet服务 %s 用户名:%v 密码:%v", target, user, pass)
						Common.LogSuccess(msg)

						// 保存结果
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":     info.Ports,
								"service":  "telnet",
								"type":     "weak-password",
								"username": user,
								"password": pass,
							},
						}
						Common.SaveResult(vulnResult)
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("连接超时")
				}

				if err != nil {
					errlog := fmt.Sprintf("Telnet连接失败 %s 用户名:%v 密码:%v 错误:%v",
						target, user, pass, err)
					Common.LogError(errlog)

					if retryErr := Common.CheckErrs(err); retryErr != nil {
						if retryCount == maxRetries-1 {
							continue
						}
						continue
					}
				}
				break
			}
		}
	}

	Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", tried))
	return tmperr
}

// telnetConn 尝试建立Telnet连接并进行身份验证
func telnetConn(info *Common.HostInfo, user, pass string) (flag bool, err error) {
	client := NewTelnet(info.Host, info.Ports)

	if err = client.Connect(); err != nil {
		return false, err
	}
	defer client.Close()

	client.UserName = user
	client.Password = pass
	client.ServerType = client.MakeServerType()

	if client.ServerType == UnauthorizedAccess {
		return true, nil
	}

	err = client.Login()
	return false, err
}

const (
	// 写入操作后的延迟时间
	TIME_DELAY_AFTER_WRITE = 300 * time.Millisecond

	// Telnet基础控制字符
	IAC  = byte(255) // 解释为命令(Interpret As Command)
	DONT = byte(254) // 请求对方停止执行某选项
	DO   = byte(253) // 请求对方执行某选项
	WONT = byte(252) // 拒绝执行某选项
	WILL = byte(251) // 同意执行某选项

	// 子协商相关控制字符
	SB = byte(250) // 子协商开始(Subnegotiation Begin)
	SE = byte(240) // 子协商结束(Subnegotiation End)

	// 特殊功能字符
	NULL  = byte(0)   // 空字符
	EOF   = byte(236) // 文档结束
	SUSP  = byte(237) // 暂停进程
	ABORT = byte(238) // 停止进程
	REOR  = byte(239) // 记录结束

	// 控制操作字符
	NOP = byte(241) // 无操作
	DM  = byte(242) // 数据标记
	BRK = byte(243) // 中断
	IP  = byte(244) // 中断进程
	AO  = byte(245) // 终止输出
	AYT = byte(246) // 在线确认
	EC  = byte(247) // 擦除字符
	EL  = byte(248) // 擦除行
	GA  = byte(249) // 继续进行

	// Telnet协议选项代码 (来自arpa/telnet.h)
	BINARY = byte(0) // 8位数据通道
	ECHO   = byte(1) // 回显
	RCP    = byte(2) // 准备重新连接
	SGA    = byte(3) // 禁止继续
	NAMS   = byte(4) // 近似消息大小
	STATUS = byte(5) // 状态查询
	TM     = byte(6) // 时间标记
	RCTE   = byte(7) // 远程控制传输和回显

	// 输出协商选项
	NAOL   = byte(8)  // 输出行宽度协商
	NAOP   = byte(9)  // 输出页面大小协商
	NAOCRD = byte(10) // 回车处理协商
	NAOHTS = byte(11) // 水平制表符停止协商
	NAOHTD = byte(12) // 水平制表符处理协商
	NAOFFD = byte(13) // 换页符处理协商
	NAOVTS = byte(14) // 垂直制表符停止协商
	NAOVTD = byte(15) // 垂直制表符处理协商
	NAOLFD = byte(16) // 换行符处理协商

	// 扩展功能选项
	XASCII       = byte(17) // 扩展ASCII字符集
	LOGOUT       = byte(18) // 强制登出
	BM           = byte(19) // 字节宏
	DET          = byte(20) // 数据输入终端
	SUPDUP       = byte(21) // SUPDUP协议
	SUPDUPOUTPUT = byte(22) // SUPDUP输出
	SNDLOC       = byte(23) // 发送位置

	// 终端相关选项
	TTYPE        = byte(24) // 终端类型
	EOR          = byte(25) // 记录结束
	TUID         = byte(26) // TACACS用户识别
	OUTMRK       = byte(27) // 输出标记
	TTYLOC       = byte(28) // 终端位置编号
	VT3270REGIME = byte(29) // 3270体制

	// 通信控制选项
	X3PAD    = byte(30) // X.3 PAD
	NAWS     = byte(31) // 窗口大小
	TSPEED   = byte(32) // 终端速度
	LFLOW    = byte(33) // 远程流控制
	LINEMODE = byte(34) // 行模式选项

	// 环境与认证选项
	XDISPLOC       = byte(35) // X显示位置
	OLD_ENVIRON    = byte(36) // 旧环境变量
	AUTHENTICATION = byte(37) // 认证
	ENCRYPT        = byte(38) // 加密选项
	NEW_ENVIRON    = byte(39) // 新环境变量

	// IANA分配的额外选项
	// http://www.iana.org/assignments/telnet-options
	TN3270E             = byte(40) // TN3270E
	XAUTH               = byte(41) // XAUTH
	CHARSET             = byte(42) // 字符集
	RSP                 = byte(43) // 远程串行端口
	COM_PORT_OPTION     = byte(44) // COM端口控制
	SUPPRESS_LOCAL_ECHO = byte(45) // 禁止本地回显
	TLS                 = byte(46) // 启动TLS
	KERMIT              = byte(47) // KERMIT协议
	SEND_URL            = byte(48) // 发送URL
	FORWARD_X           = byte(49) // X转发

	// 特殊用途选项
	PRAGMA_LOGON     = byte(138) // PRAGMA登录
	SSPI_LOGON       = byte(139) // SSPI登录
	PRAGMA_HEARTBEAT = byte(140) // PRAGMA心跳
	EXOPL            = byte(255) // 扩展选项列表
	NOOPT            = byte(0)   // 无选项
)

// 服务器类型常量定义
const (
	Closed              = iota // 连接关闭
	UnauthorizedAccess         // 无需认证
	OnlyPassword               // 仅需密码
	UsernameAndPassword        // 需要用户名和密码
)

// TelnetClient Telnet客户端结构体
type TelnetClient struct {
	IPAddr       string   // 服务器IP地址
	Port         string   // 服务器端口
	UserName     string   // 用户名
	Password     string   // 密码
	conn         net.Conn // 网络连接
	LastResponse string   // 最近一次响应内容
	ServerType   int      // 服务器类型
}

// NewTelnet 创建新的Telnet客户端实例
func NewTelnet(addr, port string) *TelnetClient {
	return &TelnetClient{
		IPAddr:       addr,
		Port:         port,
		UserName:     "",
		Password:     "",
		conn:         nil,
		LastResponse: "",
		ServerType:   Closed,
	}
}

// Connect 建立Telnet连接
func (c *TelnetClient) Connect() error {
	// 建立TCP连接,超时时间5秒
	conn, err := net.DialTimeout("tcp", c.Netloc(), 5*time.Second)
	if err != nil {
		return err
	}
	c.conn = conn

	// 启动后台goroutine处理服务器响应
	go func() {
		for {
			// 读取服务器响应
			buf, err := c.read()
			if err != nil {
				// 处理连接关闭和EOF情况
				if strings.Contains(err.Error(), "closed") ||
					strings.Contains(err.Error(), "EOF") {
					break
				}
				break
			}

			// 处理响应数据
			displayBuf, commandList := c.SerializationResponse(buf)

			if len(commandList) > 0 {
				// 有命令需要回复
				replyBuf := c.MakeReplyFromList(commandList)
				c.LastResponse += string(displayBuf)
				_ = c.write(replyBuf)
			} else {
				// 仅保存显示内容
				c.LastResponse += string(displayBuf)
			}
		}
	}()

	// 等待连接初始化完成
	time.Sleep(time.Second * 3)
	return nil
}

// WriteContext 写入数据到Telnet连接
func (c *TelnetClient) WriteContext(s string) {
	// 写入字符串并添加回车及空字符
	_ = c.write([]byte(s + "\x0d\x00"))
}

// ReadContext 读取Telnet连接返回的内容
func (c *TelnetClient) ReadContext() string {
	// 读取完成后清空缓存
	defer func() { c.Clear() }()

	// 等待响应
	if c.LastResponse == "" {
		time.Sleep(time.Second)
	}

	// 处理特殊字符
	c.LastResponse = strings.ReplaceAll(c.LastResponse, "\x0d\x00", "")
	c.LastResponse = strings.ReplaceAll(c.LastResponse, "\x0d\x0a", "\n")

	return c.LastResponse
}

// Netloc 获取网络地址字符串
func (c *TelnetClient) Netloc() string {
	return fmt.Sprintf("%s:%s", c.IPAddr, c.Port)
}

// Close 关闭Telnet连接
func (c *TelnetClient) Close() {
	c.conn.Close()
}

// SerializationResponse 解析Telnet响应数据
func (c *TelnetClient) SerializationResponse(responseBuf []byte) (displayBuf []byte, commandList [][]byte) {
	for {
		// 查找IAC命令标记
		index := bytes.IndexByte(responseBuf, IAC)
		if index == -1 || len(responseBuf)-index < 2 {
			displayBuf = append(displayBuf, responseBuf...)
			break
		}

		// 获取选项字符
		ch := responseBuf[index+1]

		// 处理连续的IAC
		if ch == IAC {
			displayBuf = append(displayBuf, responseBuf[:index]...)
			responseBuf = responseBuf[index+1:]
			continue
		}

		// 处理DO/DONT/WILL/WONT命令
		if ch == DO || ch == DONT || ch == WILL || ch == WONT {
			commandBuf := responseBuf[index : index+3]
			commandList = append(commandList, commandBuf)
			displayBuf = append(displayBuf, responseBuf[:index]...)
			responseBuf = responseBuf[index+3:]
			continue
		}

		// 处理子协商命令
		if ch == SB {
			displayBuf = append(displayBuf, responseBuf[:index]...)
			seIndex := bytes.IndexByte(responseBuf, SE)
			commandList = append(commandList, responseBuf[index:seIndex])
			responseBuf = responseBuf[seIndex+1:]
			continue
		}

		break
	}

	return displayBuf, commandList
}

// MakeReplyFromList 处理命令列表并生成回复
func (c *TelnetClient) MakeReplyFromList(list [][]byte) []byte {
	var reply []byte
	for _, command := range list {
		reply = append(reply, c.MakeReply(command)...)
	}
	return reply
}

// MakeReply 根据命令生成对应的回复
func (c *TelnetClient) MakeReply(command []byte) []byte {
	// 命令至少需要3字节
	if len(command) < 3 {
		return []byte{}
	}

	verb := command[1]   // 动作类型
	option := command[2] // 选项码

	// 处理回显(ECHO)和抑制继续进行(SGA)选项
	if option == ECHO || option == SGA {
		switch verb {
		case DO:
			return []byte{IAC, WILL, option}
		case DONT:
			return []byte{IAC, WONT, option}
		case WILL:
			return []byte{IAC, DO, option}
		case WONT:
			return []byte{IAC, DONT, option}
		case SB:
			// 处理子协商命令
			// 命令格式: IAC + SB + option + modifier + IAC + SE
			if len(command) >= 4 {
				modifier := command[3]
				if modifier == ECHO {
					return []byte{IAC, SB, option, BINARY, IAC, SE}
				}
			}
		}
	} else {
		// 处理其他选项 - 拒绝所有请求
		switch verb {
		case DO, DONT:
			return []byte{IAC, WONT, option}
		case WILL, WONT:
			return []byte{IAC, DONT, option}
		}
	}

	return []byte{}
}

// read 从Telnet连接读取数据
func (c *TelnetClient) read() ([]byte, error) {
	var buf [2048]byte
	n, err := c.conn.Read(buf[0:])
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// write 向Telnet连接写入数据
func (c *TelnetClient) write(buf []byte) error {
	// 设置写入超时
	_ = c.conn.SetWriteDeadline(time.Now().Add(time.Second * 3))

	_, err := c.conn.Write(buf)
	if err != nil {
		return err
	}
	return nil
}

// Login 根据服务器类型执行登录
func (c *TelnetClient) Login() error {
	switch c.ServerType {
	case Closed:
		return errors.New("service is disabled")
	case UnauthorizedAccess:
		return nil
	case OnlyPassword:
		return c.loginForOnlyPassword()
	case UsernameAndPassword:
		return c.loginForUsernameAndPassword()
	default:
		return errors.New("unknown server type")
	}
}

// MakeServerType 通过分析服务器响应判断服务器类型
func (c *TelnetClient) MakeServerType() int {
	responseString := c.ReadContext()
	response := strings.Split(responseString, "\n")
	lastLine := strings.ToLower(response[len(response)-1])

	// 检查是否需要用户名和密码
	if containsAny(lastLine, []string{"user", "name", "login", "account", "用户名", "登录"}) {
		return UsernameAndPassword
	}

	// 检查是否只需要密码
	if strings.Contains(lastLine, "pass") {
		return OnlyPassword
	}

	// 检查是否无需认证的情况
	if isNoAuthRequired(lastLine) || c.isLoginSucceed(responseString) {
		return UnauthorizedAccess
	}

	return Closed
}

// 辅助函数:检查字符串是否包含任意给定子串
func containsAny(s string, substrings []string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// 辅助函数:检查是否无需认证
func isNoAuthRequired(line string) bool {
	patterns := []string{
		`^/ #.*`,
		`^<[A-Za-z0-9_]+>`,
		`^#`,
	}

	for _, pattern := range patterns {
		if regexp.MustCompile(pattern).MatchString(line) {
			return true
		}
	}
	return false
}

// loginForOnlyPassword 处理只需密码的登录
func (c *TelnetClient) loginForOnlyPassword() error {
	c.Clear() // 清空之前的响应

	// 发送密码并等待响应
	c.WriteContext(c.Password)
	time.Sleep(time.Second * 3)

	// 验证登录结果
	responseString := c.ReadContext()
	if c.isLoginFailed(responseString) {
		return errors.New("login failed")
	}
	if c.isLoginSucceed(responseString) {
		return nil
	}

	return errors.New("login failed")
}

// loginForUsernameAndPassword 处理需要用户名和密码的登录
func (c *TelnetClient) loginForUsernameAndPassword() error {
	// 发送用户名
	c.WriteContext(c.UserName)
	time.Sleep(time.Second * 3)
	c.Clear()

	// 发送密码
	c.WriteContext(c.Password)
	time.Sleep(time.Second * 5)

	// 验证登录结果
	responseString := c.ReadContext()
	if c.isLoginFailed(responseString) {
		return errors.New("login failed")
	}
	if c.isLoginSucceed(responseString) {
		return nil
	}

	return errors.New("login failed")
}

// Clear 清空最近一次响应
func (c *TelnetClient) Clear() {
	c.LastResponse = ""
}

// 登录失败的关键词列表
var loginFailedString = []string{
	"wrong",
	"invalid",
	"fail",
	"incorrect",
	"error",
}

// isLoginFailed 检查是否登录失败
func (c *TelnetClient) isLoginFailed(responseString string) bool {
	responseString = strings.ToLower(responseString)

	// 空响应视为失败
	if responseString == "" {
		return true
	}

	// 检查失败关键词
	for _, str := range loginFailedString {
		if strings.Contains(responseString, str) {
			return true
		}
	}

	// 检查是否仍在要求输入凭证
	patterns := []string{
		"(?is).*pass(word)?:$",
		"(?is).*user(name)?:$",
		"(?is).*login:$",
	}
	for _, pattern := range patterns {
		if regexp.MustCompile(pattern).MatchString(responseString) {
			return true
		}
	}

	return false
}

// isLoginSucceed 检查是否登录成功
func (c *TelnetClient) isLoginSucceed(responseString string) bool {
	// 获取最后一行响应
	lines := strings.Split(responseString, "\n")
	lastLine := lines[len(lines)-1]

	// 检查命令提示符
	if regexp.MustCompile("^[#$].*").MatchString(lastLine) ||
		regexp.MustCompile("^<[a-zA-Z0-9_]+>.*").MatchString(lastLine) {
		return true
	}

	// 检查last login信息
	if regexp.MustCompile("(?:s)last login").MatchString(responseString) {
		return true
	}

	// 发送测试命令验证
	c.Clear()
	c.WriteContext("?")
	time.Sleep(time.Second * 3)
	responseString = c.ReadContext()

	// 检查响应长度
	if strings.Count(responseString, "\n") > 6 || len([]rune(responseString)) > 100 {
		return true
	}

	return false
}
