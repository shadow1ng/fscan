package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

func SshScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	for _, user := range Common.Userdict["ssh"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			success, err := SshConn(info, user, pass)

			if err != nil {
				errlog := fmt.Sprintf("[-] SSH认证失败 %v:%v User:%v Pass:%v Err:%v",
					info.Host, info.Ports, user, pass, err)
				Common.LogError(errlog)
				tmperr = err

				if Common.CheckErrs(err) {
					return err
				}
			}

			if success {
				return nil
			}

			if Common.SshKeyPath != "" {
				return err
			}
		}
	}
	return tmperr
}

func SshConn(info *Common.HostInfo, user string, pass string) (flag bool, err error) {
	var auth []ssh.AuthMethod
	if Common.SshKeyPath != "" {
		pemBytes, err := ioutil.ReadFile(Common.SshKeyPath)
		if err != nil {
			return false, fmt.Errorf("[-] 读取密钥失败: %v", err)
		}

		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return false, fmt.Errorf("[-] 解析密钥失败: %v", err)
		}
		auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		auth = []ssh.AuthMethod{ssh.Password(pass)}
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: auth,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: time.Duration(Common.Timeout),
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", info.Host, info.Ports), config)
	if err != nil {
		return false, err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return false, err
	}
	defer session.Close()

	flag = true

	if Common.Command != "" {
		output, err := session.CombinedOutput(Common.Command)
		if err != nil {
			return true, err
		}
		if Common.SshKeyPath != "" {
			Common.LogSuccess(fmt.Sprintf("[+] SSH密钥认证成功 %v:%v\n命令输出:\n%v",
				info.Host, info.Ports, string(output)))
		} else {
			Common.LogSuccess(fmt.Sprintf("[+] SSH认证成功 %v:%v User:%v Pass:%v\n命令输出:\n%v",
				info.Host, info.Ports, user, pass, string(output)))
		}
	} else {
		if Common.SshKeyPath != "" {
			Common.LogSuccess(fmt.Sprintf("[+] SSH密钥认证成功 %v:%v",
				info.Host, info.Ports))
		} else {
			Common.LogSuccess(fmt.Sprintf("[+] SSH认证成功 %v:%v User:%v Pass:%v",
				info.Host, info.Ports, user, pass))
		}
	}

	return flag, nil
}
