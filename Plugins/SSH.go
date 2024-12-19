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

// SshScan 执行SSH服务的认证扫描
func SshScan(info *Common.HostInfo) (tmperr error) {
	if Common.IsBrute {
		return
	}
	fmt.Println("[+] SSH扫描模块开始...")

	startTime := time.Now().Unix()

	// 遍历用户名和密码字典进行认证尝试
	for _, user := range Common.Userdict["ssh"] {
		for _, pass := range Common.Passwords {
			// 替换密码中的用户名占位符
			pass = strings.Replace(pass, "{user}", user, -1)

			success, err := SshConn(info, user, pass)
			if success && err == nil {
				return err
			}

			// 记录失败信息
			errlog := fmt.Sprintf("[x] SSH认证失败 %v:%v User:%v Pass:%v Err:%v",
				info.Host, info.Ports, user, pass, err)
			Common.LogError(errlog)
			tmperr = err

			// 检查是否需要中断扫描
			if Common.CheckErrs(err) {
				return err
			}

			// 检查是否超时
			timeoutLimit := int64(len(Common.Userdict["ssh"])*len(Common.Passwords)) * Common.Timeout
			if time.Now().Unix()-startTime > timeoutLimit {
				return err
			}

			// 如果指定了SSH密钥，则不进行密码尝试
			if Common.SshKey != "" {
				return err
			}
		}
	}
	fmt.Println("[+] SSH扫描模块结束...")
	return tmperr
}

// SshConn 尝试建立SSH连接并进行认证
func SshConn(info *Common.HostInfo, user string, pass string) (flag bool, err error) {
	// 准备认证方法
	var auth []ssh.AuthMethod
	if Common.SshKey != "" {
		// 使用SSH密钥认证
		pemBytes, err := ioutil.ReadFile(Common.SshKey)
		if err != nil {
			return false, fmt.Errorf("读取密钥失败: %v", err)
		}

		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return false, fmt.Errorf("解析密钥失败: %v", err)
		}
		auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		// 使用密码认证
		auth = []ssh.AuthMethod{ssh.Password(pass)}
	}

	// 配置SSH客户端
	config := &ssh.ClientConfig{
		User:    user,
		Auth:    auth,
		Timeout: time.Duration(Common.Timeout) * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	// 建立SSH连接
	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", info.Host, info.Ports), config)
	if err == nil {
		defer client.Close()
		session, err := client.NewSession()
		if err == nil {
			defer session.Close()
			flag = true

			// 处理认证成功的情况
			if Common.Command != "" {
				// 执行指定命令
				output, _ := session.CombinedOutput(Common.Command)
				if Common.SshKey != "" {
					Common.LogSuccess(fmt.Sprintf("[✓] SSH密钥认证成功 %v:%v\n命令输出:\n%v",
						info.Host, info.Ports, string(output)))
				} else {
					Common.LogSuccess(fmt.Sprintf("[✓] SSH认证成功 %v:%v User:%v Pass:%v\n命令输出:\n%v",
						info.Host, info.Ports, user, pass, string(output)))
				}
			} else {
				// 仅记录认证成功
				if Common.SshKey != "" {
					Common.LogSuccess(fmt.Sprintf("[✓] SSH密钥认证成功 %v:%v",
						info.Host, info.Ports))
				} else {
					Common.LogSuccess(fmt.Sprintf("[✓] SSH认证成功 %v:%v User:%v Pass:%v",
						info.Host, info.Ports, user, pass))
				}
			}
		}
	}
	return flag, err
}
