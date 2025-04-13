package Plugins

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// IMAPCredential 表示一个IMAP凭据
type IMAPCredential struct {
	Username string
	Password string
}

// IMAPScanResult 表示IMAP扫描结果
type IMAPScanResult struct {
	Success    bool
	Error      error
	Credential IMAPCredential
}

// IMAPScan 主扫描函数
func IMAPScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 构建凭据列表
	var credentials []IMAPCredential
	for _, user := range Common.Userdict["imap"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, IMAPCredential{
				Username: user,
				Password: actualPass,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["imap"]), len(Common.Passwords), len(credentials)))

	// 并发扫描
	result := concurrentIMAPScan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 记录成功结果
		saveIMAPResult(info, target, result.Credential)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("IMAP扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)))
		return nil
	}
}

// concurrentIMAPScan 并发扫描IMAP服务
func concurrentIMAPScan(ctx context.Context, info *Common.HostInfo, credentials []IMAPCredential, timeoutSeconds int64, maxRetries int) *IMAPScanResult {
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
	resultChan := make(chan *IMAPScanResult, 1)
	workChan := make(chan IMAPCredential, maxConcurrent)
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
					result := tryIMAPCredential(scanCtx, info, credential, timeoutSeconds, maxRetries)
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
		if ok && result != nil && result.Success {
			return result
		}
		return nil
	case <-ctx.Done():
		Common.LogDebug("IMAP并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryIMAPCredential 尝试单个IMAP凭据
func tryIMAPCredential(ctx context.Context, info *Common.HostInfo, credential IMAPCredential, timeoutSeconds int64, maxRetries int) *IMAPScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &IMAPScanResult{
				Success:    false,
				Error:      fmt.Errorf("全局超时"),
				Credential: credential,
			}
		default:
			if retry > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retry+1, credential.Username, credential.Password))
				time.Sleep(500 * time.Millisecond) // 重试前等待
			}

			// 创建单个连接超时的上下文
			connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
			success, err := IMAPConn(connCtx, info, credential.Username, credential.Password)
			cancel()

			if success {
				return &IMAPScanResult{
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

	return &IMAPScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// IMAPConn 连接测试函数
func IMAPConn(ctx context.Context, info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second
	addr := fmt.Sprintf("%s:%s", host, port)

	// 创建结果通道
	resultChan := make(chan struct {
		success bool
		err     error
	}, 1)

	// 在协程中尝试连接
	go func() {
		// 先尝试普通连接
		dialer := &net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			flag, authErr := tryIMAPAuth(conn, user, pass, timeout)
			conn.Close()
			if authErr == nil {
				select {
				case <-ctx.Done():
				case resultChan <- struct {
					success bool
					err     error
				}{flag, nil}:
				}
				return
			}
		}

		// 如果普通连接失败或认证失败，尝试TLS连接
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		tlsConn, tlsErr := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if tlsErr != nil {
			select {
			case <-ctx.Done():
			case resultChan <- struct {
				success bool
				err     error
			}{false, fmt.Errorf("连接失败: %v", tlsErr)}:
			}
			return
		}
		defer tlsConn.Close()

		flag, authErr := tryIMAPAuth(tlsConn, user, pass, timeout)
		select {
		case <-ctx.Done():
		case resultChan <- struct {
			success bool
			err     error
		}{flag, authErr}:
		}
	}()

	// 等待结果或上下文取消
	select {
	case result := <-resultChan:
		return result.success, result.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// tryIMAPAuth 尝试IMAP认证
func tryIMAPAuth(conn net.Conn, user string, pass string, timeout time.Duration) (bool, error) {
	conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	_, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("读取欢迎消息失败: %v", err)
	}

	loginCmd := fmt.Sprintf("a001 LOGIN \"%s\" \"%s\"\r\n", user, pass)
	_, err = conn.Write([]byte(loginCmd))
	if err != nil {
		return false, fmt.Errorf("发送登录命令失败: %v", err)
	}

	for {
		conn.SetDeadline(time.Now().Add(timeout))
		response, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return false, fmt.Errorf("认证失败")
			}
			return false, fmt.Errorf("读取响应失败: %v", err)
		}

		if strings.Contains(response, "a001 OK") {
			return true, nil
		}

		if strings.Contains(response, "a001 NO") || strings.Contains(response, "a001 BAD") {
			return false, fmt.Errorf("认证失败")
		}
	}
}

// saveIMAPResult 保存IMAP扫描结果
func saveIMAPResult(info *Common.HostInfo, target string, credential IMAPCredential) {
	successMsg := fmt.Sprintf("IMAP服务 %s 爆破成功 用户名: %v 密码: %v",
		target, credential.Username, credential.Password)
	Common.LogSuccess(successMsg)

	// 保存结果
	vulnResult := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.VULN,
		Target: info.Host,
		Status: "vulnerable",
		Details: map[string]interface{}{
			"port":     info.Ports,
			"service":  "imap",
			"username": credential.Username,
			"password": credential.Password,
			"type":     "weak-password",
		},
	}
	Common.SaveResult(vulnResult)
}
