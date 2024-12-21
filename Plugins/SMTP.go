package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// SmtpScan 执行 SMTP 服务扫描
func SmtpScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	starttime := time.Now().Unix()

	// 首先测试匿名访问
	flag, err := SmtpConn(info, "", "")
	if flag && err == nil {
		return err
	}

	// 尝试用户名密码组合
	for _, user := range Common.Userdict["smtp"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)

			flag, err := SmtpConn(info, user, pass)
			if flag && err == nil {
				return err
			}

			errlog := fmt.Sprintf("[-] SMTP服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
				info.Host, info.Ports, user, pass, err)
			Common.LogError(errlog)
			tmperr = err

			if Common.CheckErrs(err) {
				return err
			}

			// 超时检查
			if time.Now().Unix()-starttime > (int64(len(Common.Userdict["smtp"])*len(Common.Passwords)) * Common.Timeout) {
				return err
			}
		}
	}
	return tmperr
}

// SmtpConn 尝试 SMTP 连接
func SmtpConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造地址
	addr := fmt.Sprintf("%s:%s", host, port)

	// 创建带超时的连接
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// 创建SMTP客户端
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return false, err
	}
	defer client.Close()

	// 如果提供了认证信息
	if user != "" {
		auth := smtp.PlainAuth("", user, pass, host)
		err = client.Auth(auth)
		if err != nil {
			return false, err
		}
	}

	// 验证是否可以发送邮件
	err = client.Mail("test@test.com")
	if err != nil {
		return false, err
	}

	// 如果成功
	result := fmt.Sprintf("[+] SMTP服务 %v:%v ", host, port)
	if user != "" {
		result += fmt.Sprintf("爆破成功 用户名: %v 密码: %v", user, pass)
	} else {
		result += "允许匿名访问"
	}
	Common.LogSuccess(result)

	return true, nil
}
