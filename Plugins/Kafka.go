package Plugins

import (
	"fmt"
	"github.com/IBM/sarama"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"time"
)

func KafkaScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries

	// 首先测试无认证访问
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		flag, err := KafkaConn(info, "", "")
		if flag && err == nil {
			return nil
		}
		if err != nil && Common.CheckErrs(err) != nil {
			if retryCount < maxRetries-1 {
				continue
			}
			return err
		}
		break
	}

	starttime := time.Now().Unix()

	// 遍历所有用户名密码组合
	for _, user := range Common.Userdict["kafka"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)

			// 检查是否超时
			if time.Now().Unix()-starttime > int64(Common.Timeout) {
				return fmt.Errorf("扫描超时")
			}

			// 重试循环
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				// 执行Kafka连接
				done := make(chan struct {
					success bool
					err     error
				})

				go func(user, pass string) {
					success, err := KafkaConn(info, user, pass)
					done <- struct {
						success bool
						err     error
					}{success, err}
				}(user, pass)

				// 等待结果或超时
				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success && err == nil {
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("连接超时")
				}

				// 处理错误情况
				if err != nil {
					errlog := fmt.Sprintf("Kafka服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
						info.Host, info.Ports, user, pass, err)
					Common.LogError(errlog)

					// 检查是否需要重试
					if retryErr := Common.CheckErrs(err); retryErr != nil {
						if retryCount == maxRetries-1 {
							return err
						}
						continue // 继续重试
					}
				}

				break // 如果不需要重试，跳出重试循环
			}
		}
	}

	return tmperr
}

// KafkaConn 尝试 Kafka 连接
func KafkaConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	config := sarama.NewConfig()
	config.Net.DialTimeout = timeout
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
		result := fmt.Sprintf("Kafka服务 %v:%v ", host, port)
		if user != "" {
			result += fmt.Sprintf("爆破成功 用户名: %v 密码: %v", user, pass)
		} else {
			result += "无需认证即可访问"
		}
		Common.LogSuccess(result)
		return true, nil
	}

	// 如果消费者连接失败，尝试作为客户端连接
	client, err := sarama.NewClient(brokers, config)
	if err == nil {
		defer client.Close()
		result := fmt.Sprintf("Kafka服务 %v:%v ", host, port)
		if user != "" {
			result += fmt.Sprintf("爆破成功 用户名: %v 密码: %v", user, pass)
		} else {
			result += "无需认证即可访问"
		}
		Common.LogSuccess(result)
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
