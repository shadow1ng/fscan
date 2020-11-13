package Plugins

import (
	"../common"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"strings"
	"sync"
	"time"
)
func SshScan(info *common.HostInfo,ch chan int,wg *sync.WaitGroup) {
	//SshConn(info,"oracle","oracle",ch,wg)
Loop:
	for _,user:=range common.Userdict["ssh"]{
		for _,pass:=range common.Passwords{
			pass = strings.Replace(pass, "{user}", string(user), -1)
			//wg.Add(1)
			//var good bool
			//go SshConn(info,user,pass,ch,wg)
			//if good == true{
			//	break Loop
			//}
			flag,err := SshConn(info,user,pass,ch,wg)
			if flag==true && err==nil {
				break Loop
			}
		}
	}
	wg.Done()
	<- ch
}

func SshConn(info *common.HostInfo,user string,pass string,ch chan int,wg *sync.WaitGroup)(flag bool,err error){
	flag = false
	Host,Port,Username,Password := info.Host, common.PORTList["ssh"],user, pass
	//fmt.Println(Host,Port,Username,Password)
	config := &ssh.ClientConfig{
		User: Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(Password),
		},
		Timeout: time.Duration(info.Timeout)*time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", Host, Port), config)
	if err == nil {
		defer client.Close()
		session, err := client.NewSession()
		if err == nil  { //if err == nil && errRet == nil {
			defer session.Close()
			flag = true
			if info.Command != ""{
				combo,_ := session.CombinedOutput(info.Command)
				result := fmt.Sprintf("SSH:%v:%v:%v %v \n %v",Host,Port,Username,Password,string(combo))
				common.LogSuccess(result)
			}else {
				result := fmt.Sprintf("SSH:%v:%v:%v %v",Host,Port,Username,Password)
				common.LogSuccess(result)
			}
		}
	}
	return flag,err

}
