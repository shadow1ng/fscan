package Plugins

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/stacktitan/smb/smb"
)

func SmbScan(info common.HostInfo, flags common.Flags) (tmperr error) {
	if flags.IsBrute {
		return nil
	}
	starttime := time.Now().Unix()
	for _, user := range common.Userdict["smb"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := doWithTimeOut(info, flags, user, pass)
			if flag && err == nil {
				var result string
				if flags.Domain != "" {
					result = fmt.Sprintf("[+] SMB:%v:%v:%v\\%v %v", info.Host, info.Ports, flags.Domain, user, pass)
				} else {
					result = fmt.Sprintf("[+] SMB:%v:%v:%v %v", info.Host, info.Ports, user, pass)
				}
				common.LogSuccess(result)
				return err
			} else {
				errlog := fmt.Sprintf("[-] smb %v:%v %v %v %v", info.Host, 445, user, pass, err)
				errlog = strings.Replace(errlog, "\n", "", -1)
				common.LogError(errlog)
				tmperr = err
				if common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(common.Userdict["smb"])*len(common.Passwords)) * flags.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func SmblConn(info common.HostInfo, flags common.Flags, user string, pass string, signal chan struct{}) (flag bool, err error) {
	flag = false
	Host, Username, Password := info.Host, user, pass
	options := smb.Options{
		Host:        Host,
		Port:        445,
		User:        Username,
		Password:    Password,
		Domain:      flags.Domain,
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err == nil {
		session.Close()
		if session.IsAuthenticated {
			flag = true
		}
	}
	signal <- struct{}{}
	return flag, err
}

func doWithTimeOut(info common.HostInfo, flags common.Flags, user string, pass string) (flag bool, err error) {
	signal := make(chan struct{})
	go func() {
		flag, err = SmblConn(info, flags, user, pass, signal)
	}()
	select {
	case <-signal:
		return flag, err
	case <-time.After(time.Duration(flags.Timeout) * time.Second):
		return false, errors.New("time out")
	}
}
