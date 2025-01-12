package Plugins

import (
	"fmt"
	"github.com/mitchellh/go-vnc"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"time"
)

func VncScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	modename := "vnc"

	Common.LogDebug(fmt.Sprintf("开始扫描 %v:%v", info.Host, info.Ports))
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("开始尝试密码组合 (总密码数: %d)", totalPass))

	tried := 0

	// 遍历所有密码
	for _, pass := range Common.Passwords {
		tried++
		Common.LogDebug(fmt.Sprintf("[%d/%d] 尝试密码: %s", tried, totalPass, pass))

		// 重试循环
		for retryCount := 0; retryCount < maxRetries; retryCount++ {
			if retryCount > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试密码: %s", retryCount+1, pass))
			}

			// 执行VNC连接
			done := make(chan struct {
				success bool
				err     error
			}, 1)

			go func(pass string) {
				success, err := VncConn(info, pass)
				select {
				case done <- struct {
					success bool
					err     error
				}{success, err}:
				default:
				}
			}(pass)

			// 等待结果或超时
			var err error
			select {
			case result := <-done:
				err = result.err
				if result.success && err == nil {
					// 连接成功
					successLog := fmt.Sprintf("%s://%v:%v 密码: %v",
						modename, info.Host, info.Ports, pass)
					Common.LogSuccess(successLog)
					return nil
				}
			case <-time.After(time.Duration(Common.Timeout) * time.Second):
				err = fmt.Errorf("连接超时")
			}

			// 处理错误情况
			if err != nil {
				errlog := fmt.Sprintf("%s://%v:%v 尝试密码: %v 错误: %v",
					modename, info.Host, info.Ports, pass, err)
				Common.LogError(errlog)

				// 检查是否是需要重试的错误
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

	Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个密码", tried))
	return tmperr
}

// VncConn 尝试建立VNC连接
func VncConn(info *Common.HostInfo, pass string) (flag bool, err error) {
	flag = false
	Host, Port := info.Host, info.Ports

	// 建立TCP连接
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", Host, Port),
		time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	// 配置VNC客户端
	config := &vnc.ClientConfig{
		Auth: []vnc.ClientAuth{
			&vnc.PasswordAuth{
				Password: pass,
			},
		},
	}

	// 尝试VNC认证
	client, err := vnc.Client(conn, config)
	if err == nil {
		defer client.Close()
		flag = true
	}

	return
}
