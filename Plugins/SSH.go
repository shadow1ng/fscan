package Plugins

import (
	"context"
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

	maxRetries := Common.MaxRetries

	// 遍历所有用户名密码组合
	for _, user := range Common.Userdict["ssh"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)

			// 重试循环
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.Timeout)*time.Second)
				done := make(chan struct {
					success bool
					err     error
				}, 1)

				go func(user, pass string) {
					success, err := SshConn(info, user, pass)
					select {
					case <-ctx.Done():
					case done <- struct {
						success bool
						err     error
					}{success, err}:
					}
				}(user, pass)

				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success {
						successLog := fmt.Sprintf("SSH认证成功 %v:%v User:%v Pass:%v",
							info.Host, info.Ports, user, pass)
						Common.LogSuccess(successLog)
						time.Sleep(100 * time.Millisecond)
						cancel()
						return nil
					}
				case <-ctx.Done():
					err = fmt.Errorf("连接超时")
				}

				cancel()

				if err != nil {
					errlog := fmt.Sprintf("SSH认证失败 %v:%v User:%v Pass:%v Err:%v",
						info.Host, info.Ports, user, pass, err)
					Common.LogError(errlog)

					if retryErr := Common.CheckErrs(err); retryErr != nil {
						if retryCount == maxRetries-1 {
							return err
						}
						continue
					}
				}

				if Common.SshKeyPath != "" {
					return err
				}

				break
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
			return false, fmt.Errorf("读取密钥失败: %v", err)
		}

		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return false, fmt.Errorf("解析密钥失败: %v", err)
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
		Timeout: time.Duration(Common.Timeout) * time.Millisecond,
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

	// 如果需要执行命令
	if Common.Command != "" {
		_, err := session.CombinedOutput(Common.Command)
		if err != nil {
			return true, err
		}
	}

	return true, nil
}
