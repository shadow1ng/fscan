package Plugins

import (
	"context"
	"fmt"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"sync"
	"time"
)

// RabbitMQCredential 表示一个RabbitMQ凭据
type RabbitMQCredential struct {
	Username string
	Password string
}

// RabbitMQScanResult 表示扫描结果
type RabbitMQScanResult struct {
	Success    bool
	Error      error
	Credential RabbitMQCredential
	ErrorMsg   string // 保存详细的错误信息
}

// RabbitMQScan 执行 RabbitMQ 服务扫描
func RabbitMQScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 先测试默认账号 guest/guest
	Common.LogDebug("尝试默认账号 guest/guest")
	defaultCredential := RabbitMQCredential{Username: "guest", Password: "guest"}
	defaultResult := tryRabbitMQCredential(ctx, info, defaultCredential, Common.Timeout, Common.MaxRetries)

	if defaultResult.Success {
		saveRabbitMQResult(info, target, defaultResult.Credential)
		return nil
	} else if defaultResult.Error != nil {
		// 打印默认账号的详细错误信息
		Common.LogDebug(fmt.Sprintf("默认账号 guest/guest 失败，详细错误: %s", defaultResult.ErrorMsg))
	}

	// 构建其他凭据列表
	var credentials []RabbitMQCredential
	for _, user := range Common.Userdict["rabbitmq"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, RabbitMQCredential{
				Username: user,
				Password: actualPass,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["rabbitmq"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	result := concurrentRabbitMQScan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 记录成功结果
		saveRabbitMQResult(info, target, result.Credential)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("RabbitMQ扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)+1)) // +1 是因为还尝试了默认账号
		return nil
	}
}

// concurrentRabbitMQScan 并发扫描RabbitMQ服务
func concurrentRabbitMQScan(ctx context.Context, info *Common.HostInfo, credentials []RabbitMQCredential, timeoutSeconds int64, maxRetries int) *RabbitMQScanResult {
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
	resultChan := make(chan *RabbitMQScanResult, 1)
	workChan := make(chan RabbitMQCredential, maxConcurrent)
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
					result := tryRabbitMQCredential(scanCtx, info, credential, timeoutSeconds, maxRetries)
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
		Common.LogDebug("RabbitMQ并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryRabbitMQCredential 尝试单个RabbitMQ凭据
func tryRabbitMQCredential(ctx context.Context, info *Common.HostInfo, credential RabbitMQCredential, timeoutSeconds int64, maxRetries int) *RabbitMQScanResult {
	var lastErr error
	var errorMsg string

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &RabbitMQScanResult{
				Success:    false,
				Error:      fmt.Errorf("全局超时"),
				Credential: credential,
				ErrorMsg:   "全局超时",
			}
		default:
			if retry > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retry+1, credential.Username, credential.Password))
				time.Sleep(500 * time.Millisecond) // 重试前等待
			}

			// 创建连接超时上下文
			connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
			success, err, detailErr := RabbitMQConn(connCtx, info, credential.Username, credential.Password)
			cancel()

			if success {
				return &RabbitMQScanResult{
					Success:    true,
					Credential: credential,
				}
			}

			lastErr = err
			errorMsg = detailErr

			// 打印详细的错误信息，包括所有原始错误信息
			Common.LogDebug(fmt.Sprintf("凭据 %s:%s 失败，错误详情: %s",
				credential.Username, credential.Password, errorMsg))

			if err != nil {
				// 可以根据错误信息类型来决定是否需要重试
				// 例如，如果错误是认证错误，则无需重试
				if strings.Contains(errorMsg, "ACCESS_REFUSED") {
					Common.LogDebug("认证错误，无需重试")
					break
				}

				// 检查是否需要重试
				if retryErr := Common.CheckErrs(err); retryErr == nil {
					break // 不需要重试的错误
				}
			}
		}
	}

	return &RabbitMQScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
		ErrorMsg:   errorMsg,
	}
}

// RabbitMQConn 尝试 RabbitMQ 连接
func RabbitMQConn(ctx context.Context, info *Common.HostInfo, user string, pass string) (bool, error, string) {
	host, port := info.Host, info.Ports

	// 构造 AMQP URL
	amqpURL := fmt.Sprintf("amqp://%s:%s@%s:%s/", user, pass, host, port)

	// 创建结果通道
	resultChan := make(chan struct {
		success   bool
		err       error
		detailErr string
	}, 1)

	// 在协程中尝试连接
	go func() {
		// 配置连接
		config := amqp.Config{
			Dial: func(network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: time.Duration(Common.Timeout) * time.Second}
				return dialer.DialContext(ctx, network, addr)
			},
		}

		// 尝试连接
		conn, err := amqp.DialConfig(amqpURL, config)

		if err != nil {
			detailErr := err.Error()
			select {
			case <-ctx.Done():
			case resultChan <- struct {
				success   bool
				err       error
				detailErr string
			}{false, err, detailErr}:
			}
			return
		}
		defer conn.Close()

		select {
		case <-ctx.Done():
		case resultChan <- struct {
			success   bool
			err       error
			detailErr string
		}{true, nil, ""}:
		}
	}()

	// 等待结果或上下文取消
	select {
	case result := <-resultChan:
		return result.success, result.err, result.detailErr
	case <-ctx.Done():
		return false, ctx.Err(), ctx.Err().Error()
	}
}

// saveRabbitMQResult 保存RabbitMQ扫描结果
func saveRabbitMQResult(info *Common.HostInfo, target string, credential RabbitMQCredential) {
	successMsg := fmt.Sprintf("RabbitMQ服务 %s 连接成功 用户名: %v 密码: %v",
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
			"service":  "rabbitmq",
			"username": credential.Username,
			"password": credential.Password,
			"type":     "weak-password",
		},
	}
	Common.SaveResult(vulnResult)
}
