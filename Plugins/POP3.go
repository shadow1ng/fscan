package Plugins

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"sync"
	"time"
)

// POP3Credential 表示一个POP3凭据
type POP3Credential struct {
	Username string
	Password string
}

// POP3ScanResult 表示POP3扫描结果
type POP3ScanResult struct {
	Success    bool
	Error      error
	Credential POP3Credential
	IsTLS      bool
}

func POP3Scan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 构建凭据列表
	var credentials []POP3Credential
	for _, user := range Common.Userdict["pop3"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, POP3Credential{
				Username: user,
				Password: actualPass,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["pop3"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描，但需要限制速率
	result := concurrentPOP3Scan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 记录成功结果
		savePOP3Result(info, target, result)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("POP3扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)))
		return nil
	}
}

// concurrentPOP3Scan 并发扫描POP3服务（包含速率限制）
func concurrentPOP3Scan(ctx context.Context, info *Common.HostInfo, credentials []POP3Credential, timeoutSeconds int64, maxRetries int) *POP3ScanResult {
	// 不使用ModuleThreadNum控制并发数，必须单线程
	maxConcurrent := 1
	if maxConcurrent <= 0 {
		maxConcurrent = 1 // POP3默认并发更低
	}
	if maxConcurrent > len(credentials) {
		maxConcurrent = len(credentials)
	}

	// 创建工作池
	var wg sync.WaitGroup
	resultChan := make(chan *POP3ScanResult, 1)

	// 创建限速通道，控制请求频率
	// 每次发送前需要从中获取令牌，确保请求间隔
	rateLimiter := make(chan struct{}, maxConcurrent)

	// 初始填充令牌
	for i := 0; i < maxConcurrent; i++ {
		rateLimiter <- struct{}{}
	}

	// 使用动态的请求间隔
	requestInterval := 1500 * time.Millisecond // 默认间隔1.5秒

	scanCtx, scanCancel := context.WithCancel(ctx)
	defer scanCancel()

	// 创建任务队列
	taskQueue := make(chan POP3Credential, len(credentials))
	for _, cred := range credentials {
		taskQueue <- cred
	}
	close(taskQueue)

	// 记录已处理的凭据数
	var processedCount int32
	processedCountMutex := &sync.Mutex{}

	// 启动工作协程
	for i := 0; i < maxConcurrent; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for credential := range taskQueue {
				select {
				case <-scanCtx.Done():
					return
				case <-rateLimiter:
					// 获取令牌，可以发送请求
					processedCountMutex.Lock()
					processedCount++
					currentCount := processedCount
					processedCountMutex.Unlock()

					Common.LogDebug(fmt.Sprintf("[%d/%d] 工作线程 %d 尝试: %s:%s",
						currentCount, len(credentials), workerID, credential.Username, credential.Password))

					result := tryPOP3Credential(scanCtx, info, credential, timeoutSeconds, maxRetries)

					// 尝试完成后添加延迟，然后归还令牌
					time.Sleep(requestInterval)

					// 未被取消的情况下归还令牌
					select {
					case <-scanCtx.Done():
						// 如果已经取消，不再归还令牌
					default:
						rateLimiter <- struct{}{}
					}

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
		}(i)
	}

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
		Common.LogDebug("POP3并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryPOP3Credential 尝试单个POP3凭据
func tryPOP3Credential(ctx context.Context, info *Common.HostInfo, credential POP3Credential, timeoutSeconds int64, maxRetries int) *POP3ScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &POP3ScanResult{
				Success:    false,
				Error:      fmt.Errorf("全局超时"),
				Credential: credential,
			}
		default:
			if retry > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retry+1, credential.Username, credential.Password))
				// 重试间隔时间增加，避免触发服务器限制
				retryDelay := time.Duration(retry*2000) * time.Millisecond
				time.Sleep(retryDelay)
			}

			// 创建连接超时上下文
			connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
			success, isTLS, err := POP3Conn(connCtx, info, credential.Username, credential.Password)
			cancel()

			if success {
				return &POP3ScanResult{
					Success:    true,
					Credential: credential,
					IsTLS:      isTLS,
				}
			}

			lastErr = err
			if err != nil {
				// 处理特定错误情况
				if strings.Contains(strings.ToLower(err.Error()), "too many connections") ||
					strings.Contains(strings.ToLower(err.Error()), "connection refused") ||
					strings.Contains(strings.ToLower(err.Error()), "timeout") {
					// 服务器可能限制连接，增加等待时间
					waitTime := time.Duration((retry+1)*3000) * time.Millisecond
					Common.LogDebug(fmt.Sprintf("服务器可能限制连接，等待 %v 后重试", waitTime))
					time.Sleep(waitTime)
					continue
				}

				// 检查是否需要重试
				if retryErr := Common.CheckErrs(err); retryErr == nil {
					break // 不需要重试的错误
				}
			}
		}
	}

	return &POP3ScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// POP3Conn 尝试POP3连接
func POP3Conn(ctx context.Context, info *Common.HostInfo, user string, pass string) (success bool, isTLS bool, err error) {
	timeout := time.Duration(Common.Timeout) * time.Second
	addr := fmt.Sprintf("%s:%s", info.Host, info.Ports)

	// 创建结果通道
	resultChan := make(chan struct {
		success bool
		isTLS   bool
		err     error
	}, 1)

	// 在协程中尝试连接，支持取消
	go func() {
		// 首先尝试普通连接
		dialer := &net.Dialer{
			Timeout: timeout,
			// 增加KeepAlive设置，可能有助于处理一些服务器的限制
			KeepAlive: 30 * time.Second,
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			flag, authErr := tryPOP3Auth(conn, user, pass, timeout)
			conn.Close()
			if authErr == nil && flag {
				select {
				case <-ctx.Done():
				case resultChan <- struct {
					success bool
					isTLS   bool
					err     error
				}{flag, false, nil}:
				}
				return
			}
		}

		// 如果普通连接失败，尝试TLS连接
		select {
		case <-ctx.Done():
			return
		default:
		}

		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		tlsConn, tlsErr := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if tlsErr != nil {
			select {
			case <-ctx.Done():
			case resultChan <- struct {
				success bool
				isTLS   bool
				err     error
			}{false, false, fmt.Errorf("连接失败: %v", tlsErr)}:
			}
			return
		}
		defer tlsConn.Close()

		flag, authErr := tryPOP3Auth(tlsConn, user, pass, timeout)
		select {
		case <-ctx.Done():
		case resultChan <- struct {
			success bool
			isTLS   bool
			err     error
		}{flag, true, authErr}:
		}
	}()

	// 等待结果或上下文取消
	select {
	case result := <-resultChan:
		return result.success, result.isTLS, result.err
	case <-ctx.Done():
		return false, false, ctx.Err()
	}
}

// tryPOP3Auth 尝试POP3认证
func tryPOP3Auth(conn net.Conn, user string, pass string, timeout time.Duration) (bool, error) {
	reader := bufio.NewReader(conn)

	// 设置较长的超时时间以适应一些较慢的服务器
	conn.SetDeadline(time.Now().Add(timeout))

	// 读取欢迎信息
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("读取欢迎消息失败: %v", err)
	}

	// 检查是否有错误信息
	if strings.Contains(strings.ToLower(response), "error") ||
		strings.Contains(strings.ToLower(response), "too many") {
		return false, fmt.Errorf("服务器拒绝连接: %s", strings.TrimSpace(response))
	}

	// 发送用户名前等待一小段时间
	time.Sleep(300 * time.Millisecond)

	// 发送用户名
	conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte(fmt.Sprintf("USER %s\r\n", user)))
	if err != nil {
		return false, fmt.Errorf("发送用户名失败: %v", err)
	}

	// 读取用户名响应
	conn.SetDeadline(time.Now().Add(timeout))
	response, err = reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("读取用户名响应失败: %v", err)
	}
	if !strings.Contains(response, "+OK") {
		return false, fmt.Errorf("用户名无效: %s", strings.TrimSpace(response))
	}

	// 发送密码前等待一小段时间
	time.Sleep(300 * time.Millisecond)

	// 发送密码
	conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte(fmt.Sprintf("PASS %s\r\n", pass)))
	if err != nil {
		return false, fmt.Errorf("发送密码失败: %v", err)
	}

	// 读取密码响应
	conn.SetDeadline(time.Now().Add(timeout))
	response, err = reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("读取密码响应失败: %v", err)
	}

	if strings.Contains(response, "+OK") {
		return true, nil
	}

	return false, fmt.Errorf("认证失败: %s", strings.TrimSpace(response))
}

// savePOP3Result 保存POP3扫描结果
func savePOP3Result(info *Common.HostInfo, target string, result *POP3ScanResult) {
	tlsStatus := ""
	if result.IsTLS {
		tlsStatus = " (TLS)"
	}

	successMsg := fmt.Sprintf("POP3服务 %s 用户名: %v 密码: %v%s",
		target, result.Credential.Username, result.Credential.Password, tlsStatus)
	Common.LogSuccess(successMsg)

	// 保存结果
	vulnResult := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.VULN,
		Target: info.Host,
		Status: "vulnerable",
		Details: map[string]interface{}{
			"port":     info.Ports,
			"service":  "pop3",
			"username": result.Credential.Username,
			"password": result.Credential.Password,
			"type":     "weak-password",
			"tls":      result.IsTLS,
		},
	}
	Common.SaveResult(vulnResult)
}
