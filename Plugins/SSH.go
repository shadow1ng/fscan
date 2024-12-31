package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"
)

func SshScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	threads := Common.BruteThreads
	taskChan := make(chan struct {
		user string
		pass string
	}, len(Common.Userdict["ssh"])*len(Common.Passwords))

	resultChan := make(chan error, threads)

	// 生成所有任务
	for _, user := range Common.Userdict["ssh"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			taskChan <- struct {
				user string
				pass string
			}{user, pass}
		}
	}
	close(taskChan)

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskChan {
				// 重试循环
				for retryCount := 0; retryCount < maxRetries; retryCount++ {
					done := make(chan struct {
						success bool
						err     error
					})

					go func(user, pass string) {
						success, err := SshConn(info, user, pass)
						done <- struct {
							success bool
							err     error
						}{success, err}
					}(task.user, task.pass)

					var err error
					select {
					case result := <-done:
						err = result.err
						if result.success {
							resultChan <- nil
							return
						}
					case <-time.After(time.Duration(Common.Timeout) * time.Second):
						err = fmt.Errorf("连接超时")
					}

					if err != nil {
						errlog := fmt.Sprintf("[-] SSH认证失败 %v:%v User:%v Pass:%v Err:%v",
							info.Host, info.Ports, task.user, task.pass, err)
						Common.LogError(errlog)

						// 检查是否是已知错误，如果是则等待3秒后重试
						if retryErr := Common.CheckErrs(err); retryErr != nil {
							if retryCount == maxRetries-1 {
								resultChan <- err
								return
							}
							continue // 继续重试
						}
					}

					if Common.SshKeyPath != "" {
						resultChan <- err
						return
					}

					break // 如果不需要重试，跳出重试循环
				}
			}
			resultChan <- nil
		}()
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 检查结果
	for err := range resultChan {
		if err != nil {
			tmperr = err
			if retryErr := Common.CheckErrs(err); retryErr != nil {
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
