package Plugins

import (
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/stacktitan/smb/smb"
	"strings"
	"time"
)

// SmbScan 执行SMB服务的认证扫描
func SmbScan(info *Common.HostInfo) (tmperr error) {
	// 如果未启用暴力破解则直接返回
	if Common.DisableBrute {
		return nil
	}

	startTime := time.Now().Unix()

	// 遍历用户名和密码字典进行认证尝试
	for _, user := range Common.Userdict["smb"] {
		for _, pass := range Common.Passwords {
			// 替换密码中的用户名占位符
			pass = strings.Replace(pass, "{user}", user, -1)

			// 执行带超时的认证
			success, err := doWithTimeOut(info, user, pass)

			if success && err == nil {
				// 认证成功,记录结果
				var result string
				if Common.Domain != "" {
					result = fmt.Sprintf("[✓] SMB认证成功 %v:%v Domain:%v\\%v Pass:%v",
						info.Host, info.Ports, Common.Domain, user, pass)
				} else {
					result = fmt.Sprintf("[✓] SMB认证成功 %v:%v User:%v Pass:%v",
						info.Host, info.Ports, user, pass)
				}
				Common.LogSuccess(result)
				return err
			} else {
				// 认证失败,记录错误
				errorMsg := fmt.Sprintf("[x] SMB认证失败 %v:%v User:%v Pass:%v Err:%v",
					info.Host, info.Ports, user, pass,
					strings.ReplaceAll(err.Error(), "\n", ""))
				Common.LogError(errorMsg)
				tmperr = err

				// 检查是否需要中断扫描
				if Common.CheckErrs(err) {
					return err
				}

				// 检查是否超时
				timeoutLimit := int64(len(Common.Userdict["smb"])*len(Common.Passwords)) * Common.Timeout
				if time.Now().Unix()-startTime > timeoutLimit {
					return err
				}
			}
		}
	}
	return tmperr
}

// SmblConn 尝试建立SMB连接并进行认证
func SmblConn(info *Common.HostInfo, user string, pass string, signal chan struct{}) (flag bool, err error) {
	flag = false

	// 配置SMB连接选项
	options := smb.Options{
		Host:        info.Host,
		Port:        445,
		User:        user,
		Password:    pass,
		Domain:      Common.Domain,
		Workstation: "",
	}

	// 尝试建立SMB会话
	session, err := smb.NewSession(options, false)
	if err == nil {
		defer session.Close()
		if session.IsAuthenticated {
			flag = true
		}
	}

	// 发送完成信号
	signal <- struct{}{}
	return flag, err
}

// doWithTimeOut 执行带超时的SMB连接认证
func doWithTimeOut(info *Common.HostInfo, user string, pass string) (flag bool, err error) {
	signal := make(chan struct{})

	// 在goroutine中执行SMB连接
	go func() {
		flag, err = SmblConn(info, user, pass, signal)
	}()

	// 等待连接结果或超时
	select {
	case <-signal:
		return flag, err
	case <-time.After(time.Duration(Common.Timeout) * time.Second):
		return false, errors.New("[!] SMB连接超时")
	}
}
