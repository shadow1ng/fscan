package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/stacktitan/smb/smb"
	"strings"
	"time"
)

func SmbScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%s:%s", info.Host, info.Ports)

	// 遍历所有用户
	for _, user := range Common.Userdict["smb"] {
		// 遍历该用户的所有密码
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)

			success, err := doWithTimeOut(info, user, pass)
			if success {
				// 构建结果消息
				var successMsg string
				details := map[string]interface{}{
					"port":     info.Ports,
					"service":  "smb",
					"username": user,
					"password": pass,
					"type":     "weak-password",
				}

				if Common.Domain != "" {
					successMsg = fmt.Sprintf("SMB认证成功 %s %s\\%s:%s", target, Common.Domain, user, pass)
					details["domain"] = Common.Domain
				} else {
					successMsg = fmt.Sprintf("SMB认证成功 %s %s:%s", target, user, pass)
				}

				// 记录成功日志
				Common.LogSuccess(successMsg)

				// 保存结果
				result := &Common.ScanResult{
					Time:    time.Now(),
					Type:    Common.VULN,
					Target:  info.Host,
					Status:  "vulnerable",
					Details: details,
				}
				Common.SaveResult(result)
				return nil
			}

			if err != nil {
				errMsg := fmt.Sprintf("SMB认证失败 %s %s:%s %v", target, user, pass, err)
				Common.LogError(errMsg)

				// 等待失败日志打印完成
				time.Sleep(100 * time.Millisecond)

				if strings.Contains(err.Error(), "账号锁定") {
					// 账号锁定时跳过当前用户的剩余密码
					break // 跳出密码循环，继续下一个用户
				}
			}
		}
	}

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
