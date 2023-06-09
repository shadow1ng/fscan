package Plugins

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"golang.org/x/crypto/ssh"
)

func SshScan(info common.HostInfo, flags common.Flags) (tmperr error) {
	if flags.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	for _, user := range common.Userdict["ssh"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := SshConn(info, flags, user, pass)
			if flag && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] ssh %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				common.LogError(errlog)
				tmperr = err
				if common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(common.Userdict["ssh"])*len(common.Passwords)) * flags.Timeout) {
					return err
				}
			}
			if flags.SshKey != "" {
				return err
			}
		}
	}
	return tmperr
}

func SshConn(info common.HostInfo, flags common.Flags, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	var Auth []ssh.AuthMethod
	if flags.SshKey != "" {
		pemBytes, err := os.ReadFile(flags.SshKey)
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
		Timeout: time.Duration(flags.Timeout) * time.Second,
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
			if flags.Command != "" {
				combo, _ := session.CombinedOutput(flags.Command)
				result = fmt.Sprintf("[+] SSH:%v:%v:%v %v \n %v", Host, Port, Username, Password, string(combo))
				if flags.SshKey != "" {
					result = fmt.Sprintf("[+] SSH:%v:%v sshkey correct \n %v", Host, Port, string(combo))
				}
				common.LogSuccess(result)
			} else {
				result = fmt.Sprintf("[+] SSH:%v:%v:%v %v", Host, Port, Username, Password)
				if flags.SshKey != "" {
					result = fmt.Sprintf("[+] SSH:%v:%v sshkey correct", Host, Port)
				}
				common.LogSuccess(result)
			}
		}
	}
	return flag, err

}
