package Plugins

import (
	"context"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"github.com/stacktitan/smb/smb"
	"strings"
	"sync"
	"time"
)

func SmbScan(info *common.HostInfo, ch chan int, wg *sync.WaitGroup) {

Loop:
	for _, user := range common.Userdict["smb"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", string(user), -1)
			flag, err := doWithTimeOut(info, user, pass)
			if flag == true && err == nil {
				break Loop
			}
		}
	}
	wg.Done()
	<-ch

}

func SmblConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, common.PORTList["smb"], user, pass
	options := smb.Options{
		Host:        Host,
		Port:        445,
		User:        Username,
		Password:    Password,
		Domain:      "",
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err == nil {
		defer session.Close()
		if session.IsAuthenticated {
			result := fmt.Sprintf("SMB:%v:%v:%v %v", Host, Port, Username, Password)
			common.LogSuccess(result)
			flag = true
		}
	}
	return flag, err
}

func doWithTimeOut(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(info.Timeout)*time.Second)
	defer cancel()
	signal := make(chan int, 1)
	go func() {
		flag, err = SmblConn(info, user, pass)
		signal <- 1
	}()

	select {
	case <-signal:
		return flag, err
	case <-ctx.Done():
		return false, err
	}
}
