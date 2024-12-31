package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/stacktitan/smb/smb"
	"strings"
	"sync"
	"time"
)

func SmbScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return nil
	}

	threads := Common.BruteThreads
	var wg sync.WaitGroup
	successChan := make(chan struct{}, 1)

	// 按用户分组处理
	for _, user := range Common.Userdict["smb"] {
		taskChan := make(chan string, len(Common.Passwords))

		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			taskChan <- pass
		}
		close(taskChan)

		for i := 0; i < threads; i++ {
			wg.Add(1)
			go func(username string) {
				defer wg.Done()
				for pass := range taskChan {
					select {
					case <-successChan:
						return
					default:
					}

					success, err := doWithTimeOut(info, username, pass)
					if success {
						if Common.Domain != "" {
							Common.LogSuccess(fmt.Sprintf("SMB认证成功 %s:%s %s\\%s:%s",
								info.Host, info.Ports, Common.Domain, username, pass))
						} else {
							Common.LogSuccess(fmt.Sprintf("SMB认证成功 %s:%s %s:%s",
								info.Host, info.Ports, username, pass))
						}
						successChan <- struct{}{}

						// 成功后等待确保日志打印完成
						time.Sleep(500 * time.Millisecond)
						return
					}

					if err != nil {
						Common.LogError(fmt.Sprintf("SMB认证失败 %s:%s %s:%s %v",
							info.Host, info.Ports, username, pass, err))

						// 等待失败日志打印完成
						time.Sleep(100 * time.Millisecond)

						if strings.Contains(err.Error(), "账号锁定") {
							for range taskChan {
								// 清空通道
							}
							time.Sleep(200 * time.Millisecond) // 确保锁定日志打印完成
							return
						}
					}
				}
			}(user)
		}

		wg.Wait()

		select {
		case <-successChan:
			// 等待日志打印完成
			time.Sleep(500 * time.Millisecond)
			Common.LogWG.Wait()
			return nil
		default:
		}
	}

	// 主函数结束前多等待一会
	time.Sleep(500 * time.Millisecond)
	Common.LogWG.Wait()
	// 最后再等待一下，确保所有日志都打印完成
	time.Sleep(500 * time.Millisecond)
	return nil
}

func SmblConn(info *Common.HostInfo, user string, pass string, signal chan struct{}) (flag bool, err error) {
	options := smb.Options{
		Host:        info.Host,
		Port:        445,
		User:        user,
		Password:    pass,
		Domain:      Common.Domain,
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err == nil {
		defer session.Close()
		if session.IsAuthenticated {
			return true, nil
		}
		return false, fmt.Errorf("认证失败")
	}

	// 清理错误信息中的换行符和多余空格
	errMsg := strings.TrimSpace(strings.ReplaceAll(err.Error(), "\n", " "))
	if strings.Contains(errMsg, "NT Status Error") {
		switch {
		case strings.Contains(errMsg, "STATUS_LOGON_FAILURE"):
			err = fmt.Errorf("密码错误")
		case strings.Contains(errMsg, "STATUS_ACCOUNT_LOCKED_OUT"):
			err = fmt.Errorf("账号锁定")
		case strings.Contains(errMsg, "STATUS_ACCESS_DENIED"):
			err = fmt.Errorf("拒绝访问")
		case strings.Contains(errMsg, "STATUS_ACCOUNT_DISABLED"):
			err = fmt.Errorf("账号禁用")
		case strings.Contains(errMsg, "STATUS_PASSWORD_EXPIRED"):
			err = fmt.Errorf("密码过期")
		case strings.Contains(errMsg, "STATUS_USER_SESSION_DELETED"):
			return false, fmt.Errorf("会话断开")
		default:
			err = fmt.Errorf("认证失败")
		}
	}

	signal <- struct{}{}
	return false, err
}

func doWithTimeOut(info *Common.HostInfo, user string, pass string) (flag bool, err error) {
	signal := make(chan struct{}, 1)
	result := make(chan struct {
		success bool
		err     error
	}, 1)

	go func() {
		success, err := SmblConn(info, user, pass, signal)
		select {
		case result <- struct {
			success bool
			err     error
		}{success, err}:
		default:
		}
	}()

	select {
	case r := <-result:
		return r.success, r.err
	case <-time.After(time.Duration(Common.Timeout) * time.Second):
		select {
		case r := <-result:
			return r.success, r.err
		default:
			return false, fmt.Errorf("连接超时")
		}
	}
}
