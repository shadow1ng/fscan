package Plugins

import (
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/shadow1ng/fscan/common"
	"time"
)

type FtpConn struct{}

func FtpScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return
	}
	// 这里把单独的未授权访问测试:anonymous 添加到字典内来测试。
	ftpConn := &FtpConn{}
	bt := common.InitBruteThread("ftp", info, common.Timeout, ftpConn)
	return bt.Run()
}

func (f *FtpConn) Attack(info *common.HostInfo, user string, pass string, timeout int64) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	conn, err := ftp.DialTimeout(fmt.Sprintf("%v:%v", Host, Port), time.Duration(timeout)*time.Second)
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
