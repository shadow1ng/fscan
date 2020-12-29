package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"golang.org/x/crypto/ssh"
	"net"
	"strings"
	"time"
)

func SshScan(info *common.HostInfo) (tmperr error) {
	for _, user := range common.Userdict["ssh"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := SshConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				tmperr = err
			}
		}
	}
	return tmperr
}

func SshConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, common.PORTList["ssh"], user, pass
	config := &ssh.ClientConfig{
		User: Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(Password),
		},
		Timeout: time.Duration(info.Timeout) * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", Host, Port), config)
	if err == nil {
		defer client.Close()
		session, err := client.NewSession()
		if err == nil {
			defer session.Close()
			flag = true
			if info.Command != "" {
				combo, _ := session.CombinedOutput(info.Command)
				result := fmt.Sprintf("SSH:%v:%v:%v %v \n %v", Host, Port, Username, Password, string(combo))
				common.LogSuccess(result)
			} else {
				result := fmt.Sprintf("[+] SSH:%v:%v:%v %v", Host, Port, Username, Password)
				common.LogSuccess(result)
			}
		}
	}
	return flag, err

}
