package Plugins

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"io"
	"net"
	"strings"
	"time"
)

func IMAPScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	starttime := time.Now().Unix()

	// 遍历所有用户名密码组合
	for _, user := range Common.Userdict["imap"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)

			// 检查是否超时
			if time.Now().Unix()-starttime > int64(Common.Timeout) {
				return fmt.Errorf("扫描超时")
			}

			// 重试循环
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				// 执行IMAP连接
				done := make(chan struct {
					success bool
					err     error
				})

				go func(user, pass string) {
					success, err := IMAPConn(info, user, pass)
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
					errlog := fmt.Sprintf("IMAP服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
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

func IMAPConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second
	addr := fmt.Sprintf("%s:%s", host, port)

	// 首先尝试普通连接
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		if flag, err := tryIMAPAuth(conn, host, port, user, pass, timeout); err == nil {
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

	return tryIMAPAuth(conn, host, port, user, pass, timeout)
}

// tryIMAPAuth 尝试IMAP认证
func tryIMAPAuth(conn net.Conn, host string, port string, user string, pass string, timeout time.Duration) (bool, error) {
	conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	_, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("读取欢迎消息失败: %v", err)
	}

	loginCmd := fmt.Sprintf("a001 LOGIN \"%s\" \"%s\"\r\n", user, pass)
	_, err = conn.Write([]byte(loginCmd))
	if err != nil {
		return false, fmt.Errorf("发送登录命令失败: %v", err)
	}

	for {
		conn.SetDeadline(time.Now().Add(timeout))
		response, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return false, fmt.Errorf("认证失败")
			}
			return false, fmt.Errorf("读取响应失败: %v", err)
		}

		if strings.Contains(response, "a001 OK") {
			result := fmt.Sprintf("IMAP服务 %v:%v 爆破成功 用户名: %v 密码: %v",
				host, port, user, pass)
			Common.LogSuccess(result)
			return true, nil
		}

		if strings.Contains(response, "a001 NO") || strings.Contains(response, "a001 BAD") {
			return false, fmt.Errorf("认证失败")
		}
	}
}
