package Plugins

import (
	"fmt"
	"strings"
	"time"

	"github.com/jlaffaye/ftp"
	"github.com/shadow1ng/fscan/common"
)

func FtpScan(info common.HostInfo, flags common.Flags) (tmperr error) {
	if flags.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	flag, err := FtpConn(info, "anonymous", "", flags.Timeout)
	if flag && err == nil {
		return err
	} else {
		errlog := fmt.Sprintf("[-] ftp://%v:%v %v %v", info.Host, info.Ports, "anonymous", err)
		common.LogError(errlog)
		tmperr = err
		if common.CheckErrs(err) {
			return err
		}
	}

	for _, user := range common.Userdict["ftp"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := FtpConn(info, user, pass, flags.Timeout)
			if flag && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] ftp://%v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				common.LogError(errlog)
				tmperr = err
				if common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(common.Userdict["ftp"])*len(common.Passwords)) * flags.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func FtpConn(info common.HostInfo, user string, pass string, timeout int64) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	conn, err := ftp.Dial(fmt.Sprintf("%v:%v", Host, Port), ftp.DialWithTimeout(time.Duration(timeout)*time.Second))
	if err == nil {
		err = conn.Login(Username, Password)
		if err == nil {
			flag = true
			result := fmt.Sprintf("[+] ftp://%v:%v:%v %v", Host, Port, Username, Password)
			dirs, err := conn.List("")
			//defer conn.Logout()
			if err == nil {
				if len(dirs) > 0 {
					for i := 0; i < len(dirs); i++ {
						if len(dirs[i].Name) > 50 {
							result += "\n   [->]" + dirs[i].Name[:50]
						} else {
							result += "\n   [->]" + dirs[i].Name
						}
						if i == 5 {
							break
						}
					}
				}
			}
			common.LogSuccess(result)
		}
	}
	return flag, err
}
