package Plugins

import (
	"context"
	"fmt"
	"github.com/mitchellh/go-vnc"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"sync"
	"time"
)

// VncCredential 表示VNC凭据
type VncCredential struct {
	Password string
}

// VncScanResult 表示VNC扫描结果
type VncScanResult struct {
	Success    bool
	Error      error
	Credential VncCredential
}

func VncScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 构建密码列表
	var credentials []VncCredential
	for _, pass := range Common.Passwords {
		credentials = append(credentials, VncCredential{Password: pass})
	}

	Common.LogDebug(fmt.Sprintf("开始尝试密码组合 (总密码数: %d)", len(credentials)))

	// 使用工作池并发扫描
	result := concurrentVncScan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 记录成功结果
		saveVncResult(info, target, result.Credential)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("VNC扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个密码", len(credentials)))
		return nil
	}
}

// concurrentVncScan 并发扫描VNC服务
func concurrentVncScan(ctx context.Context, info *Common.HostInfo, credentials []VncCredential, timeoutSeconds int64, maxRetries int) *VncScanResult {
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
	resultChan := make(chan *VncScanResult, 1)
	workChan := make(chan VncCredential, maxConcurrent)
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
					result := tryVncCredential(scanCtx, info, credential, timeoutSeconds, maxRetries)
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
		Common.LogDebug("VNC并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryVncCredential 尝试单个VNC凭据
func tryVncCredential(ctx context.Context, info *Common.HostInfo, credential VncCredential, timeoutSeconds int64, maxRetries int) *VncScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &VncScanResult{
				Success:    false,
				Error:      fmt.Errorf("全局超时"),
				Credential: credential,
			}
		default:
			if retry > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试密码: %s", retry+1, credential.Password))
				time.Sleep(500 * time.Millisecond) // 重试前等待
			}

			// 创建连接超时上下文
			connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
			success, err := VncConn(connCtx, info, credential.Password)
			cancel()

			if success {
				return &VncScanResult{
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

	return &VncScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// VncConn 尝试建立VNC连接
func VncConn(ctx context.Context, info *Common.HostInfo, pass string) (bool, error) {
	Host, Port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// 使用带上下文的TCP连接
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%s", Host, Port))
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// 设置读写超时
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false, err
	}

	// 创建完成通道
	doneChan := make(chan struct {
		success bool
		err     error
	}, 1)

	// 在协程中处理VNC认证
	go func() {
		// 配置VNC客户端
		config := &vnc.ClientConfig{
			Auth: []vnc.ClientAuth{
				&vnc.PasswordAuth{
					Password: pass,
				},
			},
		}

		// 尝试VNC认证
		client, err := vnc.Client(conn, config)
		if err != nil {
			select {
			case <-ctx.Done():
			case doneChan <- struct {
				success bool
				err     error
			}{false, err}:
			}
			return
		}

		// 认证成功
		defer client.Close()
		select {
		case <-ctx.Done():
		case doneChan <- struct {
			success bool
			err     error
		}{true, nil}:
		}
	}()

	// 等待认证结果或上下文取消
	select {
	case result := <-doneChan:
		return result.success, result.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// saveVncResult 保存VNC扫描结果
func saveVncResult(info *Common.HostInfo, target string, credential VncCredential) {
	successLog := fmt.Sprintf("vnc://%s 密码: %v", target, credential.Password)
	Common.LogSuccess(successLog)

	// 保存结果
	vulnResult := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.VULN,
		Target: info.Host,
		Status: "vulnerable",
		Details: map[string]interface{}{
			"port":     info.Ports,
			"service":  "vnc",
			"password": credential.Password,
			"type":     "weak-password",
		},
	}
	Common.SaveResult(vulnResult)
}
