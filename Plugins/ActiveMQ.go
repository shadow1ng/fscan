package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"time"
)

// ActiveMQScan 执行 ActiveMQ 服务扫描
func ActiveMQScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries

	// 首先测试默认账户
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		flag, err := ActiveMQConn(info, "admin", "admin")
		if flag {
			return nil
		}
		if err != nil {
			if retryErr := Common.CheckErrs(err); retryErr != nil {
				if retryCount == maxRetries-1 {
					return err
				}
				continue
			}
		}
		break
	}

	starttime := time.Now().Unix()

	// 遍历所有用户名密码组合
	for _, user := range Common.Userdict["activemq"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)

			// 检查是否超时
			if time.Now().Unix()-starttime > int64(Common.Timeout) {
				return fmt.Errorf("扫描超时")
			}

			// 重试循环
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				// 执行连接测试
				done := make(chan struct {
					success bool
					err     error
				})

				go func(user, pass string) {
					flag, err := ActiveMQConn(info, user, pass)
					done <- struct {
						success bool
						err     error
					}{flag, err}
				}(user, pass)

				// 等待结果或超时
				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success {
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
