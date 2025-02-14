package Plugins

import (
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"time"
)

func FtpScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))
	Common.LogDebug("尝试匿名登录...")

	// 尝试匿名登录
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		success, dirs, err := FtpConn(info, "anonymous", "")
		if success && err == nil {
			Common.LogSuccess("匿名登录成功!")

			// 保存匿名登录结果
			result := &Common.ScanResult{
				Time:   time.Now(),
				Type:   Common.VULN,
				Target: info.Host,
				Status: "vulnerable",
				Details: map[string]interface{}{
					"port":        info.Ports,
					"service":     "ftp",
					"username":    "anonymous",
					"password":    "",
					"type":        "anonymous-login",
					"directories": dirs,
				},
			}
			Common.SaveResult(result)
			return nil
		}
		errlog := fmt.Sprintf("ftp %s %v", target, err)
		Common.LogError(errlog)
		break
	}

	totalUsers := len(Common.Userdict["ftp"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// 遍历用户名密码组合
	for _, user := range Common.Userdict["ftp"] {
		for _, pass := range Common.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			Common.LogDebug(fmt.Sprintf("[%d/%d] 尝试: %s:%s", tried, total, user, pass))

			var lastErr error

			// 重试循环
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retryCount+1, user, pass))
				}

				done := make(chan struct {
					success bool
					dirs    []string
					err     error
				}, 1)

				go func(user, pass string) {
					success, dirs, err := FtpConn(info, user, pass)
					select {
					case done <- struct {
						success bool
						dirs    []string
						err     error
					}{success, dirs, err}:
					default:
					}
				}(user, pass)

				select {
				case result := <-done:
					if result.success && result.err == nil {
						successLog := fmt.Sprintf("FTP服务 %s 成功爆破 用户名: %v 密码: %v", target, user, pass)
						Common.LogSuccess(successLog)

						// 保存爆破成功结果
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":        info.Ports,
								"service":     "ftp",
								"username":    user,
								"password":    pass,
								"type":        "weak-password",
								"directories": result.dirs,
							},
						}
						Common.SaveResult(vulnResult)
						return nil
					}
					lastErr = result.err
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					lastErr = fmt.Errorf("连接超时")
				}

				// 错误处理
				if lastErr != nil {
					errlog := fmt.Sprintf("FTP服务 %s 尝试失败 用户名: %v 密码: %v 错误: %v",
						target, user, pass, lastErr)
					Common.LogError(errlog)

					if strings.Contains(lastErr.Error(), "Login incorrect") {
						break
					}

					if strings.Contains(lastErr.Error(), "too many connections") {
						Common.LogDebug("连接数过多，等待5秒...")
						time.Sleep(5 * time.Second)
						if retryCount < maxRetries-1 {
							continue
						}
					}
				}
			}
		}
	}

	Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", tried))
	return tmperr
}

// FtpConn 建立FTP连接并尝试登录
func FtpConn(info *Common.HostInfo, user string, pass string) (success bool, directories []string, err error) {
	Host, Port := info.Host, info.Ports

	// 建立FTP连接
	conn, err := ftp.DialTimeout(fmt.Sprintf("%v:%v", Host, Port), time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		if conn != nil {
			conn.Quit()
		}
	}()

	// 尝试登录
	if err = conn.Login(user, pass); err != nil {
		return false, nil, err
	}

	// 获取目录信息
	dirs, err := conn.List("")
	if err == nil && len(dirs) > 0 {
		directories = make([]string, 0, min(6, len(dirs)))
		for i := 0; i < len(dirs) && i < 6; i++ {
			name := dirs[i].Name
			if len(name) > 50 {
				name = name[:50]
			}
			directories = append(directories, name)
		}
	}

	return true, directories, nil
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
