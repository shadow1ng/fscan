package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"github.com/stacktitan/smb/smb"
	"strings"
	"time"
)

func SmbScan(info *common.HostInfo) (tmperr error) {
	for _, user := range common.Userdict["smb"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := doWithTimeOut(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				tmperr = err
			}
		}
	}
	return tmperr
}

func SmblConn(info *common.HostInfo, user string, pass string, Domain string, signal chan struct{}) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, common.PORTList["smb"], user, pass
	options := smb.Options{
		Host:        Host,
		Port:        445,
		User:        Username,
		Password:    Password,
		Domain:      Domain,
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err == nil {
		session.Close()
		if session.IsAuthenticated {
			var result string
			if Domain != "" {
				result = fmt.Sprintf("SMB:%v:%v:%v\\%v %v", Host, Port, Domain, Username, Password)
			} else {
				result = fmt.Sprintf("SMB:%v:%v:%v %v", Host, Port, Username, Password)
			}
			common.LogSuccess(result)
			flag = true
		}
	}
	signal <- struct{}{}
	return flag, err
}

func doWithTimeOut(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	signal := make(chan struct{})
	go func() {
		flag, err = SmblConn(info, user, pass, info.Domain, signal)
	}()
	select {
	case <-signal:
		return flag, err
	case <-time.After(time.Duration(info.Timeout) * time.Second):
		return false, err
	}

}
