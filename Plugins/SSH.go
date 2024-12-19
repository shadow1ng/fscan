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

	// 增加全局扫描超时
	scanCtx, scanCancel := context.WithTimeout(context.Background(), time.Duration(Common.Timeout*2)*time.Second)
	defer scanCancel()

	for _, user := range Common.Userdict["ssh"] {
		for _, pass := range Common.Passwords {
			// 使用全局 context 创建子 context
			ctx, cancel := context.WithTimeout(scanCtx, time.Duration(Common.Timeout)*time.Second)

			// 替换密码中的用户名占位符
			pass = strings.Replace(pass, "{user}", user, -1)
			currentUser := user
			currentPass := pass

			// 创建结果通道
			done := make(chan struct {
				success bool
				err     error
			}, 1)

			// 在 goroutine 中执行单次连接尝试
			go func() {
				success, err := SshConn(ctx, info, currentUser, currentPass)
				select {
				case done <- struct {
					success bool
					err     error
				}{success, err}:
				case <-ctx.Done():
				}
			}()

			// 等待连接结果或超时
			var err error
			select {
			case result := <-done:
				err = result.err
				if result.success {
					cancel()
					return err
				}
			case <-ctx.Done():
				err = fmt.Errorf("[-] 连接超时: %v", ctx.Err())
			}

			cancel()

			// 记录失败信息
			if err != nil {
				errlog := fmt.Sprintf("[-] SSH认证失败 %v:%v User:%v Pass:%v Err:%v",
					info.Host, info.Ports, currentUser, currentPass, err)
				Common.LogError(errlog)
				tmperr = err
			}

			// 检查是否需要中断扫描
			if Common.CheckErrs(err) {
				return err
			}

			// 检查全局超时
			if scanCtx.Err() != nil {
				return fmt.Errorf("扫描总时间超时: %v", scanCtx.Err())
			}

			// 如果指定了SSH密钥，则不进行密码尝试
			if Common.SshKeyPath != "" {
				return err
			}
		}
	}

	return tmperr
}

func SshConn(ctx context.Context, info *Common.HostInfo, user string, pass string) (flag bool, err error) {
	// 准备认证方法
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
		Timeout: time.Duration(Common.Timeout) * time.Second,
	}

	// 使用带超时的 Dial
	conn, err := (&net.Dialer{Timeout: time.Duration(Common.Timeout) * time.Second}).DialContext(ctx, "tcp", fmt.Sprintf("%v:%v", info.Host, info.Ports))
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// 设置连接超时
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	// 创建一个新的 context 用于 SSH 握手
	sshCtx, sshCancel := context.WithTimeout(ctx, time.Duration(Common.Timeout)*time.Second)
	defer sshCancel()

	// 使用 channel 来控制 SSH 握手的超时
	sshDone := make(chan struct {
		client *ssh.Client
		err    error
	}, 1)

	go func() {
		sshConn, chans, reqs, err := ssh.NewClientConn(conn, fmt.Sprintf("%v:%v", info.Host, info.Ports), config)
		if err != nil {
			sshDone <- struct {
				client *ssh.Client
				err    error
			}{nil, err}
			return
		}
		client := ssh.NewClient(sshConn, chans, reqs)
		sshDone <- struct {
			client *ssh.Client
			err    error
		}{client, nil}
	}()

	// 等待 SSH 握手完成或超时
	var client *ssh.Client
	select {
	case result := <-sshDone:
		if result.err != nil {
			return false, result.err
		}
		client = result.client
	case <-sshCtx.Done():
		return false, fmt.Errorf("SSH握手超时: %v", sshCtx.Err())
	}
	defer client.Close()

	// 创建会话
	session, err := client.NewSession()
	if err != nil {
		return false, err
	}
	defer session.Close()

	flag = true

	if Common.Command != "" {
		// 执行命令的通道
		cmdDone := make(chan struct {
			output []byte
			err    error
		}, 1)

		go func() {
			output, err := session.CombinedOutput(Common.Command)
			select {
			case cmdDone <- struct {
				output []byte
				err    error
			}{output, err}:
			case <-ctx.Done():
			}
		}()

		select {
		case <-ctx.Done():
			return true, fmt.Errorf("命令执行超时: %v", ctx.Err())
		case result := <-cmdDone:
			if result.err != nil {
				return true, result.err
			}
			if Common.SshKeyPath != "" {
				Common.LogSuccess(fmt.Sprintf("[+] SSH密钥认证成功 %v:%v\n命令输出:\n%v",
					info.Host, info.Ports, string(result.output)))
			} else {
				Common.LogSuccess(fmt.Sprintf("[+] SSH认证成功 %v:%v User:%v Pass:%v\n命令输出:\n%v",
					info.Host, info.Ports, user, pass, string(result.output)))
			}
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
