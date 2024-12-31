package Plugins

import (
	"fmt"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"time"
)

// RabbitMQScan 执行 RabbitMQ 服务扫描
func RabbitMQScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	starttime := time.Now().Unix()

	// 先测试默认账号 guest/guest
	user, pass := "guest", "guest"
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		// 检查是否超时
		if time.Now().Unix()-starttime > int64(Common.Timeout) {
			return fmt.Errorf("扫描超时")
		}

		// 执行RabbitMQ连接
		done := make(chan struct {
			success bool
			err     error
		})

		go func() {
			success, err := RabbitMQConn(info, user, pass)
			done <- struct {
				success bool
				err     error
			}{success, err}
		}()

		// 等待结果或超时
		var err error
		select {
		case result := <-done:
			err = result.err
			if result.success && err == nil {
				result := fmt.Sprintf("RabbitMQ服务 %v:%v 连接成功 用户名: %v 密码: %v",
					info.Host, info.Ports, user, pass)
				Common.LogSuccess(result)
				return nil
			}
		case <-time.After(time.Duration(Common.Timeout) * time.Second):
			err = fmt.Errorf("连接超时")
		}

		if err != nil {
			errlog := fmt.Sprintf("RabbitMQ服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
				info.Host, info.Ports, user, pass, err)
			Common.LogError(errlog)

			if retryErr := Common.CheckErrs(err); retryErr != nil {
				if retryCount == maxRetries-1 {
					return err
				}
				continue
			}
		}
		break
	}

	// 遍历其他用户名密码组合
	for _, user := range Common.Userdict["rabbitmq"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)

			// 检查是否超时
			if time.Now().Unix()-starttime > int64(Common.Timeout) {
				return fmt.Errorf("扫描超时")
			}

			// 重试循环
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				// 执行RabbitMQ连接
				done := make(chan struct {
					success bool
					err     error
				})

				go func(user, pass string) {
					success, err := RabbitMQConn(info, user, pass)
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
						result := fmt.Sprintf("RabbitMQ服务 %v:%v 连接成功 用户名: %v 密码: %v",
							info.Host, info.Ports, user, pass)
						Common.LogSuccess(result)
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("连接超时")
				}

				if err != nil {
					errlog := fmt.Sprintf("RabbitMQ服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
						info.Host, info.Ports, user, pass, err)
					Common.LogError(errlog)

					if retryErr := Common.CheckErrs(err); retryErr != nil {
						if retryCount == maxRetries-1 {
							return err
						}
						continue
					}
				}
				break
			}
		}
	}

	return tmperr
}

// RabbitMQConn 尝试 RabbitMQ 连接
func RabbitMQConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造 AMQP URL
	amqpURL := fmt.Sprintf("amqp://%s:%s@%s:%s/", user, pass, host, port)

	// 配置连接
	config := amqp.Config{
		Dial: func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, timeout)
		},
	}

	// 尝试连接
	conn, err := amqp.DialConfig(amqpURL, config)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// 如果成功连接
	if conn != nil {
		result := fmt.Sprintf("RabbitMQ服务 %v:%v 爆破成功 用户名: %v 密码: %v", host, port, user, pass)
		Common.LogSuccess(result)
		return true, nil
	}

	return false, fmt.Errorf("认证失败")
}
