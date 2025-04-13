package Plugins

import (
	"context"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"sync"
	"time"
)

// ActiveMQCredential 表示一个ActiveMQ凭据
type ActiveMQCredential struct {
	Username string
	Password string
}

// ActiveMQScanResult 表示扫描结果
type ActiveMQScanResult struct {
	Success    bool
	Error      error
	Credential ActiveMQCredential
}

func ActiveMQScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 先尝试默认账户
	Common.LogDebug("尝试默认账户 admin:admin")

	defaultCredential := ActiveMQCredential{Username: "admin", Password: "admin"}
	defaultResult := tryActiveCredential(ctx, info, defaultCredential, Common.Timeout, Common.MaxRetries)

	if defaultResult.Success {
		saveActiveMQSuccess(info, target, defaultResult.Credential)
		return nil
	}

	// 生成所有凭据组合
	credentials := generateActiveMQCredentials(Common.Userdict["activemq"], Common.Passwords)
	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["activemq"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	result := concurrentActiveMQScan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 记录成功结果
		saveActiveMQSuccess(info, target, result.Credential)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("ActiveMQ扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)+1)) // +1 是因为还尝试了默认凭据
		return nil
	}
}

// generateActiveMQCredentials 生成ActiveMQ的用户名密码组合
func generateActiveMQCredentials(users, passwords []string) []ActiveMQCredential {
	var credentials []ActiveMQCredential
	for _, user := range users {
		for _, pass := range passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, ActiveMQCredential{
				Username: user,
				Password: actualPass,
			})
		}
	}
	return credentials
}

// concurrentActiveMQScan 并发扫描ActiveMQ服务
func concurrentActiveMQScan(ctx context.Context, info *Common.HostInfo, credentials []ActiveMQCredential, timeoutSeconds int64, maxRetries int) *ActiveMQScanResult {
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
	resultChan := make(chan *ActiveMQScanResult, 1)
	workChan := make(chan ActiveMQCredential, maxConcurrent)
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
					result := tryActiveCredential(scanCtx, info, credential, timeoutSeconds, maxRetries)
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
		Common.LogDebug("ActiveMQ并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryActiveCredential 尝试单个ActiveMQ凭据
func tryActiveCredential(ctx context.Context, info *Common.HostInfo, credential ActiveMQCredential, timeoutSeconds int64, maxRetries int) *ActiveMQScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &ActiveMQScanResult{
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
			success, err := ActiveMQConn(connCtx, info, credential.Username, credential.Password)
			cancel()

			if success {
				return &ActiveMQScanResult{
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

	return &ActiveMQScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// ActiveMQConn 尝试ActiveMQ连接
func ActiveMQConn(ctx context.Context, info *Common.HostInfo, user string, pass string) (bool, error) {
	addr := fmt.Sprintf("%s:%v", info.Host, info.Ports)

	// 使用上下文创建带超时的连接
	dialer := &net.Dialer{Timeout: time.Duration(Common.Timeout) * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// 创建结果通道
	resultChan := make(chan struct {
		success bool
		err     error
	}, 1)

	// 在协程中处理认证
	go func() {
		// STOMP协议的CONNECT命令
		stompConnect := fmt.Sprintf("CONNECT\naccept-version:1.0,1.1,1.2\nhost:/\nlogin:%s\npasscode:%s\n\n\x00", user, pass)

		// 发送认证请求
		conn.SetWriteDeadline(time.Now().Add(time.Duration(Common.Timeout) * time.Second))
		if _, err := conn.Write([]byte(stompConnect)); err != nil {
			select {
			case <-ctx.Done():
			case resultChan <- struct {
				success bool
				err     error
			}{false, err}:
			}
			return
		}

		// 读取响应
		conn.SetReadDeadline(time.Now().Add(time.Duration(Common.Timeout) * time.Second))
		respBuf := make([]byte, 1024)
		n, err := conn.Read(respBuf)
		if err != nil {
			select {
			case <-ctx.Done():
			case resultChan <- struct {
				success bool
				err     error
			}{false, err}:
			}
			return
		}

		// 检查认证结果
		response := string(respBuf[:n])

		var success bool
		var resultErr error

		if strings.Contains(response, "CONNECTED") {
			success = true
			resultErr = nil
		} else if strings.Contains(response, "Authentication failed") || strings.Contains(response, "ERROR") {
			success = false
			resultErr = fmt.Errorf("认证失败")
		} else {
			success = false
			resultErr = fmt.Errorf("未知响应: %s", response)
		}

		select {
		case <-ctx.Done():
		case resultChan <- struct {
			success bool
			err     error
		}{success, resultErr}:
		}
	}()

	// 等待认证结果或上下文取消
	select {
	case result := <-resultChan:
		return result.success, result.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// saveActiveMQSuccess 记录并保存ActiveMQ成功结果
func saveActiveMQSuccess(info *Common.HostInfo, target string, credential ActiveMQCredential) {
	successMsg := fmt.Sprintf("ActiveMQ服务 %s 成功爆破 用户名: %v 密码: %v",
		target, credential.Username, credential.Password)
	Common.LogSuccess(successMsg)

	// 保存结果
	result := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.VULN,
		Target: info.Host,
		Status: "vulnerable",
		Details: map[string]interface{}{
			"port":     info.Ports,
			"service":  "activemq",
			"username": credential.Username,
			"password": credential.Password,
			"type":     "weak-password",
		},
	}
	Common.SaveResult(result)
}
