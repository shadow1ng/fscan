package Plugins

import (
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"time"
)

type SshConn struct {
}

func SshScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return
	}
	sshConn := &SshConn{}
	bt := common.InitBruteThread("ssh", info, common.Timeout, sshConn)
	return bt.Run()
}

func (*SshConn) Attack(info *common.HostInfo, user string, pass string, timeout int64) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	Auth := []ssh.AuthMethod{}
	if common.SshKey != "" {
		pemBytes, err := ioutil.ReadFile(common.SshKey)
		if err != nil {
			return false, errors.New("read key failed" + err.Error())
		}
		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return false, errors.New("parse key failed" + err.Error())
		}
		Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		Auth = []ssh.AuthMethod{ssh.Password(Password)}
	}

	config := &ssh.ClientConfig{
		User:    Username,
		Auth:    Auth,
		Timeout: time.Duration(timeout) * time.Second,
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
			var result string
			if common.Command != "" {
				combo, _ := session.CombinedOutput(common.Command)
				result = fmt.Sprintf("[+] SSH:%v:%v:%v %v \n %v", Host, Port, Username, Password, string(combo))
				if common.SshKey != "" {
					result = fmt.Sprintf("[+] SSH:%v:%v sshkey correct \n %v", Host, Port, string(combo))
				}
				common.LogSuccess(result)
			} else {
				result = fmt.Sprintf("[+] SSH:%v:%v:%v %v", Host, Port, Username, Password)
				if common.SshKey != "" {
					result = fmt.Sprintf("[+] SSH:%v:%v sshkey correct", Host, Port)
				}
				common.LogSuccess(result)
			}
		}
	}
	return flag, err

}
