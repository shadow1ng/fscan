package Plugins

import (
	"fmt"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"sync"
	"time"
)

// RabbitMQScan 执行 RabbitMQ 服务扫描
func RabbitMQScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	threads := Common.BruteThreads

	// 创建任务通道
	taskChan := make(chan struct {
		user string
		pass string
	}, len(Common.Userdict["rabbitmq"])*len(Common.Passwords)+1) // +1 是为了加入guest账号

	resultChan := make(chan error, threads)

	// 先加入默认账号guest/guest
	taskChan <- struct {
		user string
		pass string
	}{"guest", "guest"}

	// 生成其他用户名密码组合任务
	for _, user := range Common.Userdict["rabbitmq"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			taskChan <- struct {
				user string
				pass string
			}{user, pass}
		}
	}
	close(taskChan)

	// 启动工作线程
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			starttime := time.Now().Unix()

			for task := range taskChan {
				// 重试循环
				for retryCount := 0; retryCount < maxRetries; retryCount++ {
					// 检查是否超时
					if time.Now().Unix()-starttime > int64(Common.Timeout) {
						resultChan <- fmt.Errorf("扫描超时")
						return
					}

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
					}(task.user, task.pass)

					// 等待结果或超时
					var err error
					select {
					case result := <-done:
						err = result.err
						if result.success && err == nil {
							result := fmt.Sprintf("RabbitMQ服务 %v:%v 连接成功 用户名: %v 密码: %v",
								info.Host, info.Ports, task.user, task.pass)
							Common.LogSuccess(result)
							resultChan <- nil
							return
						}
					case <-time.After(time.Duration(Common.Timeout) * time.Second):
						err = fmt.Errorf("连接超时")
					}

					// 处理错误情况
					if err != nil {
						errlog := fmt.Sprintf("RabbitMQ服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
							info.Host, info.Ports, task.user, task.pass, err)
						Common.LogError(errlog)

						// 检查是否需要重试
						if retryErr := Common.CheckErrs(err); retryErr != nil {
							if retryCount == maxRetries-1 {
								resultChan <- err
								return
							}
							continue // 继续重试
						}
					}

					break // 如果不需要重试，跳出重试循环
				}
			}
			resultChan <- nil
		}()
	}

	// 等待所有线程完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 检查结果
	for err := range resultChan {
		if err != nil {
			tmperr = err
			if retryErr := Common.CheckErrs(err); retryErr != nil {
				return err
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
