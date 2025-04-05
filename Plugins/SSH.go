package Plugins

import (
	"context"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"
)

// SshCredential 表示一个SSH凭据
type SshCredential struct {
	Username string
	Password string
}

// SshScanResult 表示SSH扫描结果
type SshScanResult struct {
	Success    bool
	Error      error
	Credential SshCredential
}

// SshScan 扫描SSH服务弱密码
func SshScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 生成凭据列表
	credentials := generateCredentials(Common.Userdict["ssh"], Common.Passwords)
	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["ssh"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	result := concurrentSshScan(info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 记录成功结果
		logAndSaveSuccess(info, target, result)
		return nil
	}

	Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)))
	return nil
}

// generateCredentials 生成所有用户名密码组合
func generateCredentials(users, passwords []string) []SshCredential {
	var credentials []SshCredential
	for _, user := range users {
		for _, pass := range passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, SshCredential{
				Username: user,
				Password: actualPass,
			})
		}
	}
	return credentials
}

// concurrentSshScan 并发扫描SSH服务
func concurrentSshScan(info *Common.HostInfo, credentials []SshCredential, timeout int64, maxRetries int) *SshScanResult {
	// 限制并发数
	maxConcurrent := 10
	if maxConcurrent > len(credentials) {
		maxConcurrent = len(credentials)
	}

	// 创建工作池
	var wg sync.WaitGroup
	resultChan := make(chan *SshScanResult, 1)
	workChan := make(chan SshCredential, maxConcurrent)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动工作协程
	for i := 0; i < maxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for credential := range workChan {
				select {
				case <-ctx.Done():
					return
				default:
					result := trySshCredential(info, credential, timeout, maxRetries)
					if result.Success {
						select {
						case resultChan <- result:
							cancel() // 找到有效凭据，取消其他工作
						default:
						}
						return
					}
				}
			}
		}()
	}

	// 发送工作
	go func() {
		for i, cred := range credentials {
			select {
			case <-ctx.Done():
				break
			default:
				Common.LogDebug(fmt.Sprintf("[%d/%d] 尝试: %s:%s", i+1, len(credentials), cred.Username, cred.Password))
				workChan <- cred
			}
		}
		close(workChan)
	}()

	// 等待结果或完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 获取结果
	result, ok := <-resultChan
	if ok {
		return result
	}
	return nil
}

// trySshCredential 尝试单个SSH凭据
func trySshCredential(info *Common.HostInfo, credential SshCredential, timeout int64, maxRetries int) *SshScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		if retry > 0 {
			Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retry+1, credential.Username, credential.Password))
			time.Sleep(500 * time.Millisecond) // 重试前等待
		}

		success, err := attemptSshConnection(info, credential.Username, credential.Password, timeout)
		if success {
			return &SshScanResult{
				Success:    true,
				Credential: credential,
			}
		}

		lastErr = err
		if err != nil {
			// 检查是否需要重试
			if retryErr := Common.CheckErrs(err); retryErr == nil {
				break // 不需要重试的错误
			}
		}
	}

	return &SshScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// attemptSshConnection 尝试SSH连接
func attemptSshConnection(info *Common.HostInfo, username, password string, timeoutSeconds int64) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	connChan := make(chan struct {
		success bool
		err     error
	}, 1)

	go func() {
		success, err := sshConnect(info, username, password)
		select {
		case <-ctx.Done():
		case connChan <- struct {
			success bool
			err     error
		}{success, err}:
		}
	}()

	select {
	case result := <-connChan:
		return result.success, result.err
	case <-ctx.Done():
		return false, fmt.Errorf("连接超时")
	}
}

// sshConnect 建立SSH连接并验证
func sshConnect(info *Common.HostInfo, username, password string) (bool, error) {
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
		auth = []ssh.AuthMethod{ssh.Password(password)}
	}

	config := &ssh.ClientConfig{
		User: username,
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
			return true, fmt.Errorf("命令执行失败: %v", err)
		}
	}

	return true, nil
}

// logAndSaveSuccess 记录并保存成功结果
func logAndSaveSuccess(info *Common.HostInfo, target string, result *SshScanResult) {
	successMsg := fmt.Sprintf("SSH认证成功 %s User:%v Pass:%v",
		target, result.Credential.Username, result.Credential.Password)
	Common.LogSuccess(successMsg)

	details := map[string]interface{}{
		"port":     info.Ports,
		"service":  "ssh",
		"username": result.Credential.Username,
		"password": result.Credential.Password,
		"type":     "weak-password",
	}

	// 如果使用了密钥认证，添加密钥信息
	if Common.SshKeyPath != "" {
		details["auth_type"] = "key"
		details["key_path"] = Common.SshKeyPath
		details["password"] = nil
	}

	// 如果执行了命令，添加命令信息
	if Common.Command != "" {
		details["command"] = Common.Command
	}

	vulnResult := &Common.ScanResult{
		Time:    time.Now(),
		Type:    Common.VULN,
		Target:  info.Host,
		Status:  "vulnerable",
		Details: details,
	}
	Common.SaveResult(vulnResult)
}
