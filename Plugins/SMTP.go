package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// SmtpScan 执行 SMTP 服务扫描
func SmtpScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries

	Common.LogDebug(fmt.Sprintf("开始扫描 %v:%v", info.Host, info.Ports))
	Common.LogDebug("尝试匿名访问...")

	// 先测试匿名访问
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		flag, err := SmtpConn(info, "", "")
		if flag && err == nil {
			Common.LogSuccess("匿名访问成功!")
			return err
		}
		if err != nil {
			errlog := fmt.Sprintf("smtp %v:%v anonymous %v", info.Host, info.Ports, err)
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

	totalUsers := len(Common.Userdict["smtp"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// 遍历所有用户名密码组合
	for _, user := range Common.Userdict["smtp"] {
		for _, pass := range Common.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			Common.LogDebug(fmt.Sprintf("[%d/%d] 尝试: %s:%s", tried, total, user, pass))

			// 重试循环
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retryCount+1, user, pass))
				}

				// 执行SMTP连接
				done := make(chan struct {
					success bool
					err     error
				}, 1)

				go func(user, pass string) {
					flag, err := SmtpConn(info, user, pass)
					select {
					case done <- struct {
						success bool
						err     error
					}{flag, err}:
					default:
					}
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
					errlog := fmt.Sprintf("SMTP服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
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

// SmtpConn 尝试 SMTP 连接
func SmtpConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造地址
	addr := fmt.Sprintf("%s:%s", host, port)

	// 创建带超时的连接
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// 创建SMTP客户端
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return false, err
	}
	defer client.Close()

	// 如果提供了认证信息
	if user != "" {
		auth := smtp.PlainAuth("", user, pass, host)
		err = client.Auth(auth)
		if err != nil {
			return false, err
		}
	}

	// 验证是否可以发送邮件
	err = client.Mail("test@test.com")
	if err != nil {
		return false, err
	}

	// 如果成功
	result := fmt.Sprintf("SMTP服务 %v:%v ", host, port)
	if user != "" {
		result += fmt.Sprintf("爆破成功 用户名: %v 密码: %v", user, pass)
	} else {
		result += "允许匿名访问"
	}
	Common.LogSuccess(result)

	return true, nil
}
