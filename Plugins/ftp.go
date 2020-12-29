package Plugins

import (
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/shadow1ng/fscan/common"
	"strings"
	"time"
)

func FtpScan(info *common.HostInfo) (tmperr error) {
	for _, user := range common.Userdict["ftp"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := FtpConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				tmperr = err
			}
		}
	}
	return tmperr
}

func FtpConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, common.PORTList["ftp"], user, pass
	conn, err := ftp.DialTimeout(fmt.Sprintf("%v:%v", Host, Port), time.Duration(info.Timeout)*time.Second)
	if err == nil {
		err = conn.Login(Username, Password)
		if err == nil {
			defer conn.Logout()
			result := fmt.Sprintf("FTP:%v:%v:%v %v", Host, Port, Username, Password)
			common.LogSuccess(result)
			flag = true
		}
	}
	return flag, err
}
