package Plugins

import (
	"fmt"
	"github.com/mitchellh/go-vnc"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"time"
)

// VncScan 执行VNC服务扫描及密码尝试
func VncScan(info *Common.HostInfo) (tmperr error) {
	// 如果已开启暴力破解则直接返回
	if Common.IsBrute {
		return
	}

	modename := "vnc"
	starttime := time.Now().Unix()

	// 遍历密码字典尝试连接
	for _, pass := range Common.Passwords {
		flag, err := VncConn(info, pass)

		if flag && err == nil {
			// 连接成功，记录结果
			result := fmt.Sprintf("[+] %s://%v:%v 密码: %v", modename, info.Host, info.Ports, pass)
			Common.LogSuccess(result)
			return err
		}

		// 连接失败，记录错误信息
		errlog := fmt.Sprintf("[-] %s://%v:%v 尝试密码: %v 错误: %v",
			modename, info.Host, info.Ports, pass, err)
		Common.LogError(errlog)
		tmperr = err

		// 检查是否需要中断扫描
		if Common.CheckErrs(err) {
			return err
		}

		// 检查是否超时
		if time.Now().Unix()-starttime > (int64(len(Common.Passwords)) * Common.Timeout) {
			return fmt.Errorf("扫描超时")
		}
	}
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
