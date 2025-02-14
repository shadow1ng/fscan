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
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))
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

			var err error
			select {
			case result := <-done:
				err = result.err
				if result.success && err == nil {
					// 连接成功
					successLog := fmt.Sprintf("%s://%s 密码: %v", modename, target, pass)
					Common.LogSuccess(successLog)

					// 保存结果
					vulnResult := &Common.ScanResult{
						Time:   time.Now(),
						Type:   Common.VULN,
						Target: info.Host,
						Status: "vulnerable",
						Details: map[string]interface{}{
							"port":     info.Ports,
							"service":  "vnc",
							"password": pass,
							"type":     "weak-password",
						},
					}
					Common.SaveResult(vulnResult)
					return nil
				}
			case <-time.After(time.Duration(Common.Timeout) * time.Second):
				err = fmt.Errorf("连接超时")
			}

			if err != nil {
				errlog := fmt.Sprintf("%s://%s 尝试密码: %v 错误: %v",
					modename, target, pass, err)
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
