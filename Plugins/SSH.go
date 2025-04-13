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

	// 创建全局超时上下文
	globalCtx, globalCancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer globalCancel()

	// 创建结果通道
	resultChan := make(chan *SshScanResult, 1)

	// 启动一个协程进行扫描
	go func() {
		// 如果指定了SSH密钥，使用密钥认证而非密码爆破
		if Common.SshKeyPath != "" {
			Common.LogDebug(fmt.Sprintf("使用SSH密钥认证: %s", Common.SshKeyPath))

			// 尝试使用密钥连接各个用户
			for _, user := range Common.Userdict["ssh"] {
				select {
				case <-globalCtx.Done():
					Common.LogDebug("全局超时，中止密钥认证")
					return
				default:
					Common.LogDebug(fmt.Sprintf("尝试使用密钥认证用户: %s", user))

					success, err := attemptKeyAuth(info, user, Common.SshKeyPath, Common.Timeout)
					if success {
						credential := SshCredential{
							Username: user,
							Password: "", // 使用密钥，无密码
						}

						resultChan <- &SshScanResult{
							Success:    true,
							Credential: credential,
						}
						return
					} else {
						Common.LogDebug(fmt.Sprintf("密钥认证失败: %s, 错误: %v", user, err))
					}
				}
			}

			Common.LogDebug("所有用户密钥认证均失败")
			resultChan <- nil
			return
		}

		// 否则使用密码爆破
		credentials := generateCredentials(Common.Userdict["ssh"], Common.Passwords)
		Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
			len(Common.Userdict["ssh"]), len(Common.Passwords), len(credentials)))

		// 使用工作池并发扫描
		result := concurrentSshScan(globalCtx, info, credentials, Common.Timeout, Common.MaxRetries, Common.ModuleThreadNum)
		resultChan <- result
	}()

	// 等待结果或全局超时
	select {
	case result := <-resultChan:
		if result != nil {
			// 记录成功结果
			logAndSaveSuccess(info, target, result)
			return nil
		}
	case <-globalCtx.Done():
		Common.LogDebug(fmt.Sprintf("扫描 %s 全局超时", target))
		return fmt.Errorf("全局超时，扫描未完成")
	}

	Common.LogDebug(fmt.Sprintf("扫描完成，未发现有效凭据"))
	return nil
}

// attemptKeyAuth 尝试使用SSH密钥认证
func attemptKeyAuth(info *Common.HostInfo, username, keyPath string, timeoutSeconds int64) (bool, error) {
	pemBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return false, fmt.Errorf("读取密钥失败: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return false, fmt.Errorf("解析密钥失败: %v", err)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: time.Duration(timeoutSeconds) * time.Second,
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

	return true, nil
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
func concurrentSshScan(ctx context.Context, info *Common.HostInfo, credentials []SshCredential, timeout int64, maxRetries, maxThreads int) *SshScanResult {
	// 限制并发数
	if maxThreads <= 0 {
		maxThreads = 10 // 默认值
	}

	if maxThreads > len(credentials) {
		maxThreads = len(credentials)
	}

	// 创建工作池
	var wg sync.WaitGroup
	resultChan := make(chan *SshScanResult, 1)
	workChan := make(chan SshCredential, maxThreads)
	scanCtx, scanCancel := context.WithCancel(ctx)
	defer scanCancel()

	// 启动工作协程
	for i := 0; i < maxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for credential := range workChan {
				select {
				case <-scanCtx.Done():
					return
				default:
					result := trySshCredential(info, credential, timeout, maxRetries)
					if result.Success {
						select {
						case resultChan <- result:
							scanCancel() // 找到有效凭据，取消其他工作
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
			case <-scanCtx.Done():
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
	select {
	case result, ok := <-resultChan:
		if ok {
			return result
		}
	case <-ctx.Done():
		Common.LogDebug("父上下文取消，中止所有扫描")
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
		success, err := sshConnect(info, username, password, timeoutSeconds)
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
func sshConnect(info *Common.HostInfo, username, password string, timeoutSeconds int64) (bool, error) {
	auth := []ssh.AuthMethod{ssh.Password(password)}

	config := &ssh.ClientConfig{
		User: username,
		Auth: auth,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: time.Duration(timeoutSeconds) * time.Second,
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

	return true, nil
}

// logAndSaveSuccess 记录并保存成功结果
func logAndSaveSuccess(info *Common.HostInfo, target string, result *SshScanResult) {
	var successMsg string
	details := map[string]interface{}{
		"port":     info.Ports,
		"service":  "ssh",
		"username": result.Credential.Username,
		"type":     "weak-password",
	}

	// 区分密钥认证和密码认证
	if Common.SshKeyPath != "" {
		successMsg = fmt.Sprintf("SSH密钥认证成功 %s User:%v KeyPath:%v",
			target, result.Credential.Username, Common.SshKeyPath)
		details["auth_type"] = "key"
		details["key_path"] = Common.SshKeyPath
	} else {
		successMsg = fmt.Sprintf("SSH密码认证成功 %s User:%v Pass:%v",
			target, result.Credential.Username, result.Credential.Password)
		details["auth_type"] = "password"
		details["password"] = result.Credential.Password
	}

	Common.LogSuccess(successMsg)

	vulnResult := &Common.ScanResult{
		Time:    time.Now(),
		Type:    Common.VULN,
		Target:  info.Host,
		Status:  "vulnerable",
		Details: details,
	}
	Common.SaveResult(vulnResult)
}
