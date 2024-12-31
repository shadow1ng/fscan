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
	totalTasks := len(Common.Userdict["smb"]) * len(Common.Passwords)

	taskChan := make(chan struct {
		user string
		pass string
	}, totalTasks)

	// 生成任务
	for _, user := range Common.Userdict["smb"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			taskChan <- struct {
				user string
				pass string
			}{user, pass}
		}
	}
	close(taskChan)

	var wg sync.WaitGroup
	successChan := make(chan struct{}, 1)

	// 启动工作线程
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskChan {
				select {
				case <-successChan:
					return
				default:
				}

				success, err := doWithTimeOut(info, task.user, task.pass)
				if success {
					if Common.Domain != "" {
						Common.LogSuccess(fmt.Sprintf("[+] SMB认证成功 %v:%v Domain:%v\\%v Pass:%v",
							info.Host, info.Ports, Common.Domain, task.user, task.pass))
					} else {
						Common.LogSuccess(fmt.Sprintf("[+] SMB认证成功 %v:%v User:%v Pass:%v",
							info.Host, info.Ports, task.user, task.pass))
					}
					successChan <- struct{}{}
					return
				}
				if err != nil {
					Common.LogError(fmt.Sprintf("[-] SMB认证失败 %v:%v User:%v Pass:%v Err:%v",
						info.Host, info.Ports, task.user, task.pass, err))
				}
			}
		}()
	}

	wg.Wait()
	return nil
}

func SmblConn(info *Common.HostInfo, user string, pass string, signal chan struct{}) (flag bool, err error) {
	flag = false

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
			flag = true
			return flag, nil
		}
		return flag, fmt.Errorf("认证失败")
	}

	// 清理错误信息中的换行符和多余空格
	errMsg := strings.TrimSpace(strings.ReplaceAll(err.Error(), "\n", " "))
	if strings.Contains(errMsg, "NT Status Error") {
		switch {
		case strings.Contains(errMsg, "STATUS_LOGON_FAILURE"):
			err = fmt.Errorf("用户名或密码错误")
		case strings.Contains(errMsg, "STATUS_ACCOUNT_LOCKED_OUT"):
			err = fmt.Errorf("账号已锁定")
		case strings.Contains(errMsg, "STATUS_ACCESS_DENIED"):
			err = fmt.Errorf("访问被拒绝")
		case strings.Contains(errMsg, "STATUS_ACCOUNT_DISABLED"):
			err = fmt.Errorf("账号已禁用")
		case strings.Contains(errMsg, "STATUS_PASSWORD_EXPIRED"):
			err = fmt.Errorf("密码已过期")
		case strings.Contains(errMsg, "STATUS_USER_SESSION_DELETED"):
			return flag, fmt.Errorf("会话已断开")
		default:
			err = fmt.Errorf("认证失败") // 简化错误信息
		}
	}

	signal <- struct{}{}
	return flag, err
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
		// 尝试从result通道读取，避免协程泄露
		select {
		case r := <-result:
			return r.success, r.err
		default:
			return false, fmt.Errorf("连接超时")
		}
	}
}
