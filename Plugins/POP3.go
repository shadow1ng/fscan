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
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))
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

				done := make(chan struct {
					success bool
					err     error
					isTLS   bool
				}, 1)

				go func(user, pass string) {
					success, isTLS, err := POP3Conn(info, user, pass)
					select {
					case done <- struct {
						success bool
						err     error
						isTLS   bool
					}{success, err, isTLS}:
					default:
					}
				}(user, pass)

				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success && err == nil {
						successMsg := fmt.Sprintf("POP3服务 %s 用户名: %v 密码: %v", target, user, pass)
						if result.isTLS {
							successMsg += " (TLS)"
						}
						Common.LogSuccess(successMsg)

						// 保存结果
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":     info.Ports,
								"service":  "pop3",
								"username": user,
								"password": pass,
								"type":     "weak-password",
								"tls":      result.isTLS,
							},
						}
						Common.SaveResult(vulnResult)
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("连接超时")
				}

				if err != nil {
					errMsg := fmt.Sprintf("POP3服务 %s 尝试失败 用户名: %v 密码: %v 错误: %v",
						target, user, pass, err)
					Common.LogError(errMsg)

					if retryErr := Common.CheckErrs(err); retryErr != nil {
						if retryCount == maxRetries-1 {
							continue
						}
						continue
					}
				}
				break
			}
		}
	}

	Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", tried))
	return tmperr
}

func POP3Conn(info *Common.HostInfo, user string, pass string) (success bool, isTLS bool, err error) {
	timeout := time.Duration(Common.Timeout) * time.Second
	addr := fmt.Sprintf("%s:%s", info.Host, info.Ports)

	// 首先尝试普通连接
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		if flag, err := tryPOP3Auth(conn, user, pass, timeout); err == nil {
			return flag, false, nil
		}
		conn.Close()
	}

	// 如果普通连接失败，尝试TLS连接
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, tlsConfig)
	if err != nil {
		return false, false, fmt.Errorf("连接失败: %v", err)
	}
	defer conn.Close()

	success, err = tryPOP3Auth(conn, user, pass, timeout)
	return success, true, err
}

func tryPOP3Auth(conn net.Conn, user string, pass string, timeout time.Duration) (bool, error) {
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
		return true, nil
	}

	return false, fmt.Errorf("认证失败")
}
