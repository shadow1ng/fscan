package Plugins

import (
	"context"
	"fmt"
	"github.com/IBM/sarama"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"sync"
	"time"
)

// KafkaCredential 表示Kafka凭据
type KafkaCredential struct {
	Username string
	Password string
}

// KafkaScanResult 表示扫描结果
type KafkaScanResult struct {
	Success    bool
	IsUnauth   bool
	Error      error
	Credential KafkaCredential
}

func KafkaScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 先尝试无认证访问
	Common.LogDebug("尝试无认证访问...")
	unauthResult := tryKafkaCredential(ctx, info, KafkaCredential{"", ""}, Common.Timeout, Common.MaxRetries)

	if unauthResult.Success {
		// 无认证访问成功
		Common.LogSuccess(fmt.Sprintf("Kafka服务 %s 无需认证即可访问", target))

		// 保存无认证访问结果
		result := &Common.ScanResult{
			Time:   time.Now(),
			Type:   Common.VULN,
			Target: info.Host,
			Status: "vulnerable",
			Details: map[string]interface{}{
				"port":    info.Ports,
				"service": "kafka",
				"type":    "unauthorized-access",
			},
		}
		Common.SaveResult(result)
		return nil
	}

	// 构建凭据列表
	var credentials []KafkaCredential
	for _, user := range Common.Userdict["kafka"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, KafkaCredential{
				Username: user,
				Password: actualPass,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["kafka"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	result := concurrentKafkaScan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 保存爆破成功结果
		vulnResult := &Common.ScanResult{
			Time:   time.Now(),
			Type:   Common.VULN,
			Target: info.Host,
			Status: "vulnerable",
			Details: map[string]interface{}{
				"port":     info.Ports,
				"service":  "kafka",
				"type":     "weak-password",
				"username": result.Credential.Username,
				"password": result.Credential.Password,
			},
		}
		Common.SaveResult(vulnResult)
		Common.LogSuccess(fmt.Sprintf("Kafka服务 %s 爆破成功 用户名: %s 密码: %s",
			target, result.Credential.Username, result.Credential.Password))
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("Kafka扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)+1)) // +1 是因为还尝试了无认证
		return nil
	}
}

// concurrentKafkaScan 并发扫描Kafka服务
func concurrentKafkaScan(ctx context.Context, info *Common.HostInfo, credentials []KafkaCredential, timeoutSeconds int64, maxRetries int) *KafkaScanResult {
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
	resultChan := make(chan *KafkaScanResult, 1)
	workChan := make(chan KafkaCredential, maxConcurrent)
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
					result := tryKafkaCredential(scanCtx, info, credential, timeoutSeconds, maxRetries)
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
		Common.LogDebug("Kafka并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryKafkaCredential 尝试单个Kafka凭据
func tryKafkaCredential(ctx context.Context, info *Common.HostInfo, credential KafkaCredential, timeoutSeconds int64, maxRetries int) *KafkaScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &KafkaScanResult{
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

			// 在协程中执行Kafka连接
			resultChan := make(chan struct {
				success bool
				err     error
			}, 1)

			go func() {
				success, err := KafkaConn(info, credential.Username, credential.Password)
				select {
				case <-connCtx.Done():
					// 连接超时或被取消
				case resultChan <- struct {
					success bool
					err     error
				}{success, err}:
					// 发送结果
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
				if ctx.Err() != nil {
					// 全局超时
					cancel()
					return &KafkaScanResult{
						Success:    false,
						Error:      ctx.Err(),
						Credential: credential,
					}
				}
				// 单个连接超时
				err = fmt.Errorf("连接超时")
			}

			cancel() // 清理单个连接上下文

			if success {
				isUnauth := credential.Username == "" && credential.Password == ""
				return &KafkaScanResult{
					Success:    true,
					IsUnauth:   isUnauth,
					Credential: credential,
				}
			}

			lastErr = err
			if err != nil {
				// 记录错误
				Common.LogError(fmt.Sprintf("Kafka尝试失败 用户名: %s 密码: %s 错误: %v",
					credential.Username, credential.Password, err))

				// 检查是否需要重试
				if retryErr := Common.CheckErrs(err); retryErr == nil {
					break // 不需要重试的错误
				}
			}
		}
	}

	return &KafkaScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// KafkaConn 尝试 Kafka 连接
func KafkaConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	config := sarama.NewConfig()
	config.Net.DialTimeout = timeout
	config.Net.ReadTimeout = timeout
	config.Net.WriteTimeout = timeout
	config.Net.TLS.Enable = false
	config.Version = sarama.V2_0_0_0

	// 设置 SASL 配置
	if user != "" || pass != "" {
		config.Net.SASL.Enable = true
		config.Net.SASL.Mechanism = sarama.SASLTypePlaintext
		config.Net.SASL.User = user
		config.Net.SASL.Password = pass
		config.Net.SASL.Handshake = true
	}

	brokers := []string{fmt.Sprintf("%s:%s", host, port)}

	// 尝试作为消费者连接测试
	consumer, err := sarama.NewConsumer(brokers, config)
	if err == nil {
		defer consumer.Close()
		return true, nil
	}

	// 如果消费者连接失败，尝试作为客户端连接
	client, err := sarama.NewClient(brokers, config)
	if err == nil {
		defer client.Close()
		return true, nil
	}

	// 检查错误类型
	if strings.Contains(err.Error(), "SASL") ||
		strings.Contains(err.Error(), "authentication") ||
		strings.Contains(err.Error(), "credentials") {
		return false, fmt.Errorf("认证失败")
	}

	return false, err
}
