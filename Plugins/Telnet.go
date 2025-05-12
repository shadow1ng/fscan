package Plugins

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// TelnetCredential 表示一个Telnet凭据
type TelnetCredential struct {
	Username string
	Password string
}

// TelnetScanResult 表示Telnet扫描结果
type TelnetScanResult struct {
	Success    bool
	Error      error
	Credential TelnetCredential
	NoAuth     bool
}

// TelnetScan 执行Telnet服务扫描和密码爆破
func TelnetScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 构建凭据列表
	var credentials []TelnetCredential
	for _, user := range Common.Userdict["telnet"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, TelnetCredential{
				Username: user,
				Password: actualPass,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["telnet"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	result := concurrentTelnetScan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 记录成功结果
		saveTelnetResult(info, target, result)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("Telnet扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)))
		return nil
	}
}

// concurrentTelnetScan 并发扫描Telnet服务
func concurrentTelnetScan(ctx context.Context, info *Common.HostInfo, credentials []TelnetCredential, timeoutSeconds int64, maxRetries int) *TelnetScanResult {
	// 使用ModuleThreadNum控制并发数
	maxConcurrent := Common.ModuleThreadNum
	if maxConcurrent <= 0 {
		maxConcurrent = 10 // 默认值
	}
	if maxConcurrent > len(credentials) {
		maxConcurrent = len(credentials)
	}

	// 创建工作池
	var wg sync.WaitGroup
	resultChan := make(chan *TelnetScanResult, 1)
	workChan := make(chan TelnetCredential, maxConcurrent)
	scanCtx, scanCancel := context.WithCancel(ctx)
	defer scanCancel()

	// 启动工作协程
	for i := 0; i < maxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for credential := range workChan {
				select {
				case <-scanCtx.Done():
					return
				default:
					result := tryTelnetCredential(scanCtx, info, credential, timeoutSeconds, maxRetries)
					if result.Success || result.NoAuth {
						select {
						case resultChan <- result:
							scanCancel() // 找到有效凭据或无需认证，取消其他工作
						default:
						}
						return
					}
				}
			}
		}()
	}

	// 发送工作
	go func() {
		for i, cred := range credentials {
			select {
			case <-scanCtx.Done():
				break
			default:
				Common.LogDebug(fmt.Sprintf("[%d/%d] 尝试: %s:%s", i+1, len(credentials), cred.Username, cred.Password))
				workChan <- cred
			}
		}
		close(workChan)
	}()

	// 等待结果或完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 获取结果，考虑全局超时
	select {
	case result, ok := <-resultChan:
		if ok && result != nil && (result.Success || result.NoAuth) {
			return result
		}
		return nil
	case <-ctx.Done():
		Common.LogDebug("Telnet并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryTelnetCredential 尝试单个Telnet凭据
func tryTelnetCredential(ctx context.Context, info *Common.HostInfo, credential TelnetCredential, timeoutSeconds int64, maxRetries int) *TelnetScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &TelnetScanResult{
				Success:    false,
				Error:      fmt.Errorf("全局超时"),
				Credential: credential,
			}
		default:
			if retry > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retry+1, credential.Username, credential.Password))
				time.Sleep(500 * time.Millisecond) // 重试前等待
			}

			// 创建结果通道
			resultChan := make(chan struct {
				success bool
				noAuth  bool
				err     error
			}, 1)

			// 设置单个连接超时
			connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
			go func() {
				defer cancel()
				noAuth, err := telnetConnWithContext(connCtx, info, credential.Username, credential.Password)
				select {
				case <-connCtx.Done():
					// 连接已超时或取消
				case resultChan <- struct {
					success bool
					noAuth  bool
					err     error
				}{err == nil, noAuth, err}:
				}
			}()

			// 等待结果或超时
			var success bool
			var noAuth bool
			var err error

			select {
			case result := <-resultChan:
				success = result.success
				noAuth = result.noAuth
				err = result.err
			case <-connCtx.Done():
				if ctx.Err() != nil {
					// 全局超时
					return &TelnetScanResult{
						Success:    false,
						Error:      ctx.Err(),
						Credential: credential,
					}
				}
				// 单个连接超时
				err = fmt.Errorf("连接超时")
			}

			if noAuth {
				return &TelnetScanResult{
					Success:    false,
					NoAuth:     true,
					Credential: credential,
				}
			}

			if success {
				return &TelnetScanResult{
					Success:    true,
					Credential: credential,
				}
			}

			lastErr = err
			if err != nil {
				// 检查是否需要重试
				if retryErr := Common.CheckErrs(err); retryErr == nil {
					break // 不需要重试的错误
				}
			}
		}
	}

	return &TelnetScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// telnetConnWithContext 带上下文的Telnet连接尝试
func telnetConnWithContext(ctx context.Context, info *Common.HostInfo, user, pass string) (bool, error) {
	// 创建TCP连接(使用上下文控制)
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%s", info.Host, info.Ports))
	if err != nil {
		return false, err
	}

	client := &TelnetClient{
		IPAddr:   info.Host,
		Port:     info.Ports,
		UserName: user,
		Password: pass,
		conn:     conn,
	}

	// 设置连接关闭
	defer client.Close()

	// 检查上下文是否已取消
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	// 初始化连接
	client.init()

	client.ServerType = client.MakeServerType()

	if client.ServerType == UnauthorizedAccess {
		return true, nil
	}

	err = client.Login()
	return false, err
}

// saveTelnetResult 保存Telnet扫描结果
func saveTelnetResult(info *Common.HostInfo, target string, result *TelnetScanResult) {
	var successMsg string
	var details map[string]interface{}

	if result.NoAuth {
		successMsg = fmt.Sprintf("Telnet服务 %s 无需认证", target)
		details = map[string]interface{}{
			"port":    info.Ports,
			"service": "telnet",
			"type":    "unauthorized-access",
		}
	} else {
		successMsg = fmt.Sprintf("Telnet服务 %s 用户名:%v 密码:%v",
			target, result.Credential.Username, result.Credential.Password)
		details = map[string]interface{}{
			"port":     info.Ports,
			"service":  "telnet",
			"type":     "weak-password",
			"username": result.Credential.Username,
			"password": result.Credential.Password,
		}
	}

	Common.LogSuccess(successMsg)

	// 保存结果
	vulnResult := &Common.ScanResult{
		Time:    time.Now(),
		Type:    Common.VULN,
		Target:  info.Host,
		Status:  "vulnerable",
		Details: details,
	}
	Common.SaveResult(vulnResult)
}

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

// init 初始化Telnet连接
func (c *TelnetClient) init() {
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
	time.Sleep(time.Second * 2)
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
	if c.conn != nil {
		c.conn.Close()
	}
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
			if seIndex != -1 && seIndex > index {
				commandList = append(commandList, responseBuf[index:seIndex+1])
				responseBuf = responseBuf[seIndex+1:]
				continue
			}
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
	// 设置读取超时为2秒
	_ = c.conn.SetReadDeadline(time.Now().Add(time.Second * 2))
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
	// 写入后短暂延迟，让服务器有时间处理
	time.Sleep(TIME_DELAY_AFTER_WRITE)
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
		return c.LogBaserOnlyPassword()
	case UsernameAndPassword:
		return c.LogBaserUsernameAndPassword()
	default:
		return errors.New("unknown server type")
	}
}

// MakeServerType 通过分析服务器响应判断服务器类型
func (c *TelnetClient) MakeServerType() int {
	responseString := c.ReadContext()

	// 空响应情况
	if responseString == "" {
		return Closed
	}

	response := strings.Split(responseString, "\n")
	if len(response) == 0 {
		return Closed
	}

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

// LogBaserOnlyPassword 处理只需密码的登录
func (c *TelnetClient) LogBaserOnlyPassword() error {
	c.Clear() // 清空之前的响应

	// 发送密码并等待响应
	c.WriteContext(c.Password)
	time.Sleep(time.Second * 2)

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

// LogBaserUsernameAndPassword 处理需要用户名和密码的登录
func (c *TelnetClient) LogBaserUsernameAndPassword() error {
	// 发送用户名
	c.WriteContext(c.UserName)
	time.Sleep(time.Second * 2)
	c.Clear()

	// 发送密码
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
	// 空响应视为失败
	if responseString == "" {
		return false
	}

	// 获取最后一行响应
	lines := strings.Split(responseString, "\n")
	if len(lines) == 0 {
		return false
	}

	lastLine := lines[len(lines)-1]

	// 检查命令提示符
	if regexp.MustCompile("^[#$>].*").MatchString(lastLine) ||
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
	time.Sleep(time.Second * 2)
	responseString = c.ReadContext()

	// 检查响应长度
	if strings.Count(responseString, "\n") > 6 || len([]rune(responseString)) > 100 {
		return true
	}

	return false
}

// Telnet协议常量定义
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

	// Telnet选项代码
	BINARY = byte(0) // 8位数据通道
	ECHO   = byte(1) // 回显
	SGA    = byte(3) // 禁止继续

	// 服务器类型常量定义
	Closed              = iota // 连接关闭
	UnauthorizedAccess         // 无需认证
	OnlyPassword               // 仅需密码
	UsernameAndPassword        // 需要用户名和密码
)
