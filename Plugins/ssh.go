package Plugins

import (
	"context"
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"
)

type SshScanInfo struct {
	Host, User, Password, Port string
}

func SshScan(info *common.HostInfo) error {
	var (
		wg              sync.WaitGroup
		sshScanInfoChan chan SshScanInfo
	)
	if common.IsBrute {
		return nil
	}
	sshScanInfoChan = make(chan SshScanInfo, 50)
	defer close(sshScanInfoChan)
	for i := 0; i < 50; i++ {
		SshConn(&wg, sshScanInfoChan)
	}
	for _, user := range common.Userdict["ssh"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			wg.Add(1)
			sshScanInfoChan <- SshScanInfo{
				Host:     info.Host,
				Port:     info.Ports,
				User:     user,
				Password: pass,
			}
		}
	}
	wg.Wait()
	return nil
}

func SshConn(wg *sync.WaitGroup, sshScanInfoChan chan SshScanInfo) {
	go func() {
		var (
			Auth   []ssh.AuthMethod
			ctx    context.Context
			cancel context.CancelFunc
		)
		for info := range sshScanInfoChan {
			func() {
				defer wg.Done()
				ch := make(chan struct{})
				ctx, cancel = context.WithTimeout(context.Background(), time.Second*5)
				if common.SshKey != "" {
					pemBytes, err := ioutil.ReadFile(common.SshKey)
					if err != nil {
						common.LogError(errors.New("read key failed" + err.Error()))
						return
					}
					signer, err := ssh.ParsePrivateKey(pemBytes)
					if err != nil {
						common.LogError(errors.New("parse key failed" + err.Error()))
						return
					}
					Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
				} else {
					Auth = []ssh.AuthMethod{ssh.Password(info.Password)}
				}
				config := &ssh.ClientConfig{
					User:    info.User,
					Auth:    Auth,
					Timeout: time.Duration(common.Timeout) * time.Second,
					HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
						return nil
					},
				}
				select {
				case <-ctx.Done(): //如果5秒未返回结果(有概率出现连接假死不释放)，强行结束此协程,避免主协程无法接收wg.done,一直阻塞
					common.LogError(fmt.Errorf("host %v port %v connect hang", info.Host, info.Port))
					cancel()
					return
				case <-startScan(info, config, ch):
				}
			}()
		}
	}()
}

func startScan(info SshScanInfo, config *ssh.ClientConfig, ch chan struct{}) <-chan struct{} {
	go func() {
		client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", info.Host, info.Port), config)
		if err == nil {
			defer func() {
				_ = client.Close()
			}()
			session, err := client.NewSession()
			if err == nil {
				defer func() {
					_ = session.Close()
				}()
				var result string
				if common.Command != "" {
					combo, _ := session.CombinedOutput(common.Command)
					result = fmt.Sprintf("[+] SSH:%v:%v:%v %v \n %v", info.Host, info.Port, info.User, info.Password, string(combo))
					if common.SshKey != "" {
						result = fmt.Sprintf("[+] SSH:%v:%v sshkey correct \n %v", info.Host, info.Port, string(combo))
					}
					common.LogSuccess(result)
				} else {
					result = fmt.Sprintf("[+] SSH:%v:%v:%v %v", info.Host, info.Port, info.User, info.Password)
					if common.SshKey != "" {
						result = fmt.Sprintf("[+] SSH:%v:%v sshkey correct", info.Host, info.Port)
					}
					common.LogSuccess(result)
				}
			}
			ch <- struct{}{}
		}
	}()
	return ch
}
