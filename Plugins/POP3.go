package Plugins

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"sync"
	"time"
)

func POP3Scan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	threads := Common.BruteThreads

	// 创建任务通道
	taskChan := make(chan struct {
		user string
		pass string
	}, len(Common.Userdict["pop3"])*len(Common.Passwords))

	resultChan := make(chan error, threads)

	// 生成所有用户名密码组合任务
	for _, user := range Common.Userdict["pop3"] {
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

					// 执行POP3连接
					done := make(chan struct {
						success bool
						err     error
					})

					go func(user, pass string) {
						success, err := POP3Conn(info, user, pass)
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
							// 连接成功
							successLog := fmt.Sprintf("[+] POP3服务 %v:%v 用户名: %v 密码: %v",
								info.Host, info.Ports, task.user, task.pass)
							Common.LogSuccess(successLog)
							resultChan <- nil
							return
						}
					case <-time.After(time.Duration(Common.Timeout) * time.Second):
						err = fmt.Errorf("连接超时")
					}

					// 处理错误情况
					if err != nil {
						errlog := fmt.Sprintf("[-] POP3服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
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

func POP3Conn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second
	addr := fmt.Sprintf("%s:%s", host, port)

	// 首先尝试普通连接
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		if flag, err := tryPOP3Auth(conn, host, port, user, pass, timeout, false); err == nil {
			return flag, nil
		}
		conn.Close()
	}

	// 如果普通连接失败，尝试TLS连接
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, tlsConfig)
	if err != nil {
		return false, fmt.Errorf("连接失败: %v", err)
	}
	defer conn.Close()

	return tryPOP3Auth(conn, host, port, user, pass, timeout, true)
}

func tryPOP3Auth(conn net.Conn, host string, port string, user string, pass string, timeout time.Duration, isTLS bool) (bool, error) {
	reader := bufio.NewReader(conn)
	conn.SetDeadline(time.Now().Add(timeout))

	// 读取欢迎信息
	_, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("读取欢迎消息失败: %v", err)
	}

	// 发送用户名
	conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte(fmt.Sprintf("USER %s\r\n", user)))
	if err != nil {
		return false, fmt.Errorf("发送用户名失败: %v", err)
	}

	// 读取用户名响应
	conn.SetDeadline(time.Now().Add(timeout))
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("读取用户名响应失败: %v", err)
	}
	if !strings.Contains(response, "+OK") {
		return false, fmt.Errorf("用户名无效")
	}

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
		result := fmt.Sprintf("[+] POP3服务 %v:%v 爆破成功 用户名: %v 密码: %v", host, port, user, pass)
		if isTLS {
			result += " (TLS)"
		}
		Common.LogSuccess(result)
		return true, nil
	}

	return false, fmt.Errorf("认证失败")
}
