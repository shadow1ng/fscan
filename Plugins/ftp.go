package Plugins

import (
	"../common"
	"github.com/jlaffaye/ftp"
	"fmt"
	"strings"
	"sync"
	"time"
)

func FtpScan(info *common.HostInfo,ch chan int,wg *sync.WaitGroup) {
	Loop:
	for _,user:=range common.Userdict["ftp"]{
		for _,pass:=range common.Passwords{
			pass = strings.Replace(pass, "{user}", string(user), -1)
			flag,err := FtpConn(info,user,pass)
			if flag==true && err==nil {
				break Loop
			}
		}
	}
	wg.Done()
	<- ch
}

func FtpConn(info *common.HostInfo,user string,pass string)(flag bool,err error){
	flag = false
	Host,Port,Username,Password := info.Host, common.PORTList["ftp"],user, pass
	conn, err := ftp.DialTimeout(fmt.Sprintf("%v:%v",Host,Port), time.Duration(info.Timeout)*time.Second)
	if err == nil {
		err = conn.Login(Username,Password)
		if err == nil {
			defer conn.Logout()
			result := fmt.Sprintf("FTP:%v:%v:%v %v",Host,Port,Username,Password)
			common.LogSuccess(result)
			flag = true
		}
	}
	return flag,err
}