package Plugins

import (
	"errors"
	"github.com/shadow1ng/fscan/common"
	"github.com/stacktitan/smb/smb"
	"time"
)

type SmbConn struct {
}

func SmbScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return nil
	}
	smbConn := &SmbConn{}
	bt := common.InitBruteThread("smb", info, common.Timeout, smbConn)
	return bt.Run()
}

func SmblConn(info *common.HostInfo, user string, pass string, signal chan struct{}) (flag bool, err error) {
	flag = false
	Host, Username, Password := info.Host, user, pass
	options := smb.Options{
		Host:        Host,
		Port:        445,
		User:        Username,
		Password:    Password,
		Domain:      common.Domain,
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

func (s *SmbConn) Attack(info *common.HostInfo, user string, pass string, timeout int64) (flag bool, err error) {
	signal := make(chan struct{})
	go func() {
		flag, err = SmblConn(info, user, pass, signal)
	}()
	select {
	case <-signal:
		return flag, err
	case <-time.After(time.Duration(timeout) * time.Second):
		return false, errors.New("time out")
	}
}
