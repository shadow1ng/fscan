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

	Common.LogDebug(fmt.Sprintf("开始扫描 %v:%v", info.Host, info.Ports))
	Common.LogDebug("尝试匿名登录...")

	// 先尝试匿名登录
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		flag, err := FtpConn(info, "anonymous", "")
		if flag && err == nil {
			Common.LogSuccess("匿名登录成功!")
			return nil
		}
		errlog := fmt.Sprintf("ftp %v:%v %v %v", info.Host, info.Ports, "anonymous", err)
		Common.LogError(errlog)
		break
	}

	totalUsers := len(Common.Userdict["ftp"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// 遍历所有用户名密码组合
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

				// 执行FTP连接
				done := make(chan struct {
					success bool
					err     error
				}, 1)

				go func(user, pass string) {
					success, err := FtpConn(info, user, pass)
					select {
					case done <- struct {
						success bool
						err     error
					}{success, err}:
					default:
					}
				}(user, pass)

				// 等待结果或超时
				select {
				case result := <-done:
					if result.success && result.err == nil {
						successLog := fmt.Sprintf("FTP %v:%v %v %v",
							info.Host, info.Ports, user, pass)
						Common.LogSuccess(successLog)
						return nil
					}
					lastErr = result.err
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					lastErr = fmt.Errorf("连接超时")
				}

				// 处理错误情况
				if lastErr != nil {
					errlog := fmt.Sprintf("ftp %v:%v %v %v %v",
						info.Host, info.Ports, user, pass, lastErr)
					Common.LogError(errlog)

					// 如果是密码错误，直接尝试下一个组合
					if strings.Contains(lastErr.Error(), "Login incorrect") {
						break
					}

					// 如果是连接数限制，等待后重试
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
func FtpConn(info *Common.HostInfo, user string, pass string) (flag bool, err error) {
	Host, Port, Username, Password := info.Host, info.Ports, user, pass

	// 建立FTP连接
	conn, err := ftp.DialTimeout(fmt.Sprintf("%v:%v", Host, Port), time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		return false, err
	}
	// 确保连接被关闭
	defer func() {
		if conn != nil {
			conn.Quit() // 发送QUIT命令关闭连接
		}
	}()

	// 尝试登录
	if err = conn.Login(Username, Password); err != nil {
		return false, err
	}

	// 登录成功,获取目录信息
	result := fmt.Sprintf("ftp %v:%v:%v %v", Host, Port, Username, Password)
	dirs, err := conn.List("")
	if err == nil && len(dirs) > 0 {
		// 最多显示前6个目录
		for i := 0; i < len(dirs) && i < 6; i++ {
			name := dirs[i].Name
			if len(name) > 50 {
				name = name[:50]
			}
			result += "\n   [->]" + name
		}
	}

	return true, nil
}
