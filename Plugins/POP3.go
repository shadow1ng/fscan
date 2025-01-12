package Plugins

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"time"
)

func POP3Scan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries

	Common.LogDebug(fmt.Sprintf("开始扫描 %v:%v", info.Host, info.Ports))
	totalUsers := len(Common.Userdict["pop3"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// 遍历所有用户名密码组合
	for _, user := range Common.Userdict["pop3"] {
		for _, pass := range Common.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			Common.LogDebug(fmt.Sprintf("[%d/%d] 尝试: %s:%s", tried, total, user, pass))

			// 重试循环
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retryCount+1, user, pass))
				}

				// 执行POP3连接
				done := make(chan struct {
					success bool
					err     error
				}, 1)

				go func(user, pass string) {
					success, err := POP3Conn(info, user, pass)
					select {
					case done <- struct {
						success bool
						err     error
					}{success, err}:
					default:
					}
				}(user, pass)

				// 等待结果或超时
				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success && err == nil {
						successLog := fmt.Sprintf("POP3服务 %v:%v 用户名: %v 密码: %v",
							info.Host, info.Ports, user, pass)
						Common.LogSuccess(successLog)
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("连接超时")
				}

				// 处理错误情况
				if err != nil {
					errlog := fmt.Sprintf("POP3服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
						info.Host, info.Ports, user, pass, err)
					Common.LogError(errlog)

					// 检查是否需要重试
					if retryErr := Common.CheckErrs(err); retryErr != nil {
						if retryCount == maxRetries-1 {
							continue
						}
						continue // 继续重试
					}
				}
				break // 如果不需要重试，跳出重试循环
			}
		}
	}

	Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", tried))
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
		result := fmt.Sprintf("POP3服务 %v:%v 爆破成功 用户名: %v 密码: %v", host, port, user, pass)
		if isTLS {
			result += " (TLS)"
		}
		Common.LogSuccess(result)
		return true, nil
	}

	return false, fmt.Errorf("认证失败")
}
