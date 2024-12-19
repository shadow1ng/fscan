package Plugins

import (
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Config"
	"strings"
	"time"
)

// FtpScan 执行FTP服务扫描
func FtpScan(info *Config.HostInfo) (tmperr error) {
	// 如果已开启暴力破解则直接返回
	if Common.IsBrute {
		return
	}
	fmt.Println("[+] FTP扫描模块开始...")

	starttime := time.Now().Unix()

	// 尝试匿名登录
	flag, err := FtpConn(info, "anonymous", "")
	if flag && err == nil {
		return err
	}
	errlog := fmt.Sprintf("[-] ftp %v:%v %v %v", info.Host, info.Ports, "anonymous", err)
	Common.LogError(errlog)
	tmperr = err
	if Common.CheckErrs(err) {
		return err
	}

	// 尝试用户名密码组合
	for _, user := range Common.Userdict["ftp"] {
		for _, pass := range Common.Passwords {
			// 替换密码中的用户名占位符
			pass = strings.Replace(pass, "{user}", user, -1)

			flag, err := FtpConn(info, user, pass)
			if flag && err == nil {
				return err
			}

			// 记录错误信息
			errlog := fmt.Sprintf("[-] ftp %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
			Common.LogError(errlog)
			tmperr = err

			if Common.CheckErrs(err) {
				return err
			}

			// 超时检查
			if time.Now().Unix()-starttime > (int64(len(Common.Userdict["ftp"])*len(Common.Passwords)) * Common.Timeout) {
				return err
			}
		}
	}
	fmt.Println("[+] FTP扫描模块结束...") // 添加结束打印
	return tmperr
}

// FtpConn 建立FTP连接并尝试登录
func FtpConn(info *Config.HostInfo, user string, pass string) (flag bool, err error) {
	Host, Port, Username, Password := info.Host, info.Ports, user, pass

	// 建立FTP连接
	conn, err := ftp.DialTimeout(fmt.Sprintf("%v:%v", Host, Port), time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		return false, err
	}

	// 尝试登录
	if err = conn.Login(Username, Password); err != nil {
		return false, err
	}

	// 登录成功,获取目录信息
	result := fmt.Sprintf("[+] ftp %v:%v:%v %v", Host, Port, Username, Password)
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

	Common.LogSuccess(result)
	return true, nil
}
