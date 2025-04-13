package Plugins

import (
	"context"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

// SmtpCredential 表示一个SMTP凭据
type SmtpCredential struct {
	Username string
	Password string
}

// SmtpScanResult 表示SMTP扫描结果
type SmtpScanResult struct {
	Success     bool
	Error       error
	Credential  SmtpCredential
	IsAnonymous bool
}

// SmtpScan 执行 SMTP 服务扫描
func SmtpScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 先测试匿名访问
	Common.LogDebug("尝试匿名访问...")
	anonymousResult := trySmtpCredential(ctx, info, SmtpCredential{"", ""}, Common.Timeout, Common.MaxRetries)

	if anonymousResult.Success {
		// 匿名访问成功
		saveSmtpResult(info, target, anonymousResult)
		return nil
	}

	// 构建凭据列表
	var credentials []SmtpCredential
	for _, user := range Common.Userdict["smtp"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, SmtpCredential{
				Username: user,
				Password: actualPass,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["smtp"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	result := concurrentSmtpScan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 记录成功结果
		saveSmtpResult(info, target, result)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("SMTP扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)+1)) // +1 是因为还尝试了匿名访问
		return nil
	}
}

// concurrentSmtpScan 并发扫描SMTP服务
func concurrentSmtpScan(ctx context.Context, info *Common.HostInfo, credentials []SmtpCredential, timeoutSeconds int64, maxRetries int) *SmtpScanResult {
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
	resultChan := make(chan *SmtpScanResult, 1)
	workChan := make(chan SmtpCredential, maxConcurrent)
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
					result := trySmtpCredential(scanCtx, info, credential, timeoutSeconds, maxRetries)
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
		Common.LogDebug("SMTP并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// trySmtpCredential 尝试单个SMTP凭据
func trySmtpCredential(ctx context.Context, info *Common.HostInfo, credential SmtpCredential, timeoutSeconds int64, maxRetries int) *SmtpScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &SmtpScanResult{
				Success:    false,
				Error:      fmt.Errorf("全局超时"),
				Credential: credential,
			}
		default:
			if retry > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retry+1, credential.Username, credential.Password))
				time.Sleep(500 * time.Millisecond) // 重试前等待
			}

			// 创建连接超时上下文
			connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)

			// 在协程中尝试连接
			resultChan := make(chan struct {
				success bool
				err     error
			}, 1)

			go func() {
				success, err := SmtpConn(info, credential.Username, credential.Password, timeoutSeconds)
				select {
				case <-connCtx.Done():
				case resultChan <- struct {
					success bool
					err     error
				}{success, err}:
				}
			}()

			// 等待结果或超时
			var success bool
			var err error

			select {
			case result := <-resultChan:
				success = result.success
				err = result.err
			case <-connCtx.Done():
				cancel()
				if ctx.Err() != nil {
					// 全局超时
					return &SmtpScanResult{
						Success:    false,
						Error:      ctx.Err(),
						Credential: credential,
					}
				}
				// 单个连接超时
				err = fmt.Errorf("连接超时")
			}

			cancel() // 释放连接上下文

			if success {
				isAnonymous := credential.Username == "" && credential.Password == ""
				return &SmtpScanResult{
					Success:     true,
					Credential:  credential,
					IsAnonymous: isAnonymous,
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

	return &SmtpScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// SmtpConn 尝试 SMTP 连接
func SmtpConn(info *Common.HostInfo, user string, pass string, timeoutSeconds int64) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(timeoutSeconds) * time.Second
	addr := fmt.Sprintf("%s:%s", host, port)

	// 设置连接超时
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// 设置读写超时
	conn.SetDeadline(time.Now().Add(timeout))

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return false, err
	}
	defer client.Close()

	// 尝试认证
	if user != "" {
		auth := smtp.PlainAuth("", user, pass, host)
		err = client.Auth(auth)
		if err != nil {
			return false, err
		}
	}

	// 尝试发送邮件（测试权限）
	err = client.Mail("test@test.com")
	if err != nil {
		return false, err
	}

	return true, nil
}

// saveSmtpResult 保存SMTP扫描结果
func saveSmtpResult(info *Common.HostInfo, target string, result *SmtpScanResult) {
	var successMsg string
	var details map[string]interface{}

	if result.IsAnonymous {
		successMsg = fmt.Sprintf("SMTP服务 %s 允许匿名访问", target)
		details = map[string]interface{}{
			"port":      info.Ports,
			"service":   "smtp",
			"type":      "anonymous-access",
			"anonymous": true,
		}
	} else {
		successMsg = fmt.Sprintf("SMTP服务 %s 爆破成功 用户名: %v 密码: %v",
			target, result.Credential.Username, result.Credential.Password)
		details = map[string]interface{}{
			"port":     info.Ports,
			"service":  "smtp",
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
