package Plugins

import (
	"context"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/stacktitan/smb/smb"
	"strings"
	"sync"
	"time"
)

// SmbCredential 表示一个SMB凭据
type SmbCredential struct {
	Username string
	Password string
}

// SmbScanResult 表示SMB扫描结果
type SmbScanResult struct {
	Success    bool
	Error      error
	Credential SmbCredential
}

func SmbScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%s:%s", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 构建凭据列表
	var credentials []SmbCredential
	for _, user := range Common.Userdict["smb"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, SmbCredential{
				Username: user,
				Password: actualPass,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["smb"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	result := concurrentSmbScan(ctx, info, credentials, Common.Timeout)
	if result != nil {
		// 记录成功结果
		saveSmbResult(info, target, result.Credential)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("SMB扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)))
		return nil
	}
}

// concurrentSmbScan 并发扫描SMB服务
func concurrentSmbScan(ctx context.Context, info *Common.HostInfo, credentials []SmbCredential, timeoutSeconds int64) *SmbScanResult {
	// 使用ModuleThreadNum控制并发数
	maxConcurrent := Common.ModuleThreadNum
	if maxConcurrent <= 0 {
		maxConcurrent = 10 // 默认值
	}
	if maxConcurrent > len(credentials) {
		maxConcurrent = len(credentials)
	}

	// 创建工作池
	var wg sync.WaitGroup
	resultChan := make(chan *SmbScanResult, 1)
	workChan := make(chan SmbCredential, maxConcurrent)
	scanCtx, scanCancel := context.WithCancel(ctx)
	defer scanCancel()

	// 记录用户锁定状态，避免继续尝试已锁定的用户
	lockedUsers := make(map[string]bool)
	var lockedMutex sync.Mutex

	// 启动工作协程
	for i := 0; i < maxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for credential := range workChan {
				select {
				case <-scanCtx.Done():
					return
				default:
					// 检查用户是否已锁定
					lockedMutex.Lock()
					locked := lockedUsers[credential.Username]
					lockedMutex.Unlock()
					if locked {
						Common.LogDebug(fmt.Sprintf("跳过已锁定用户: %s", credential.Username))
						continue
					}

					result := trySmbCredential(scanCtx, info, credential, timeoutSeconds)
					if result.Success {
						select {
						case resultChan <- result:
							scanCancel() // 找到有效凭据，取消其他工作
						default:
						}
						return
					}

					// 检查账号锁定错误
					if result.Error != nil && strings.Contains(result.Error.Error(), "账号锁定") {
						lockedMutex.Lock()
						lockedUsers[credential.Username] = true
						lockedMutex.Unlock()
						Common.LogError(fmt.Sprintf("用户 %s 已被锁定", credential.Username))
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
				// 检查用户是否已锁定
				lockedMutex.Lock()
				locked := lockedUsers[cred.Username]
				lockedMutex.Unlock()
				if locked {
					continue // 跳过已锁定用户
				}

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

	// 获取结果，考虑全局超时
	select {
	case result, ok := <-resultChan:
		if ok && result != nil && result.Success {
			return result
		}
		return nil
	case <-ctx.Done():
		Common.LogDebug("SMB并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// trySmbCredential 尝试单个SMB凭据
func trySmbCredential(ctx context.Context, info *Common.HostInfo, credential SmbCredential, timeoutSeconds int64) *SmbScanResult {
	// 创建单个连接超时上下文的结果通道
	resultChan := make(chan struct {
		success bool
		err     error
	}, 1)

	// 在协程中尝试连接
	go func() {
		signal := make(chan struct{}, 1)
		success, err := SmblConn(info, credential.Username, credential.Password, signal)

		select {
		case <-ctx.Done():
		case resultChan <- struct {
			success bool
			err     error
		}{success, err}:
		}
	}()

	// 等待结果或超时
	select {
	case result := <-resultChan:
		return &SmbScanResult{
			Success:    result.success,
			Error:      result.err,
			Credential: credential,
		}
	case <-ctx.Done():
		return &SmbScanResult{
			Success:    false,
			Error:      ctx.Err(),
			Credential: credential,
		}
	case <-time.After(time.Duration(timeoutSeconds) * time.Second):
		return &SmbScanResult{
			Success:    false,
			Error:      fmt.Errorf("连接超时"),
			Credential: credential,
		}
	}
}

// saveSmbResult 保存SMB扫描结果
func saveSmbResult(info *Common.HostInfo, target string, credential SmbCredential) {
	// 构建结果消息
	var successMsg string
	details := map[string]interface{}{
		"port":     info.Ports,
		"service":  "smb",
		"username": credential.Username,
		"password": credential.Password,
		"type":     "weak-password",
	}

	if Common.Domain != "" {
		successMsg = fmt.Sprintf("SMB认证成功 %s %s\\%s:%s", target, Common.Domain, credential.Username, credential.Password)
		details["domain"] = Common.Domain
	} else {
		successMsg = fmt.Sprintf("SMB认证成功 %s %s:%s", target, credential.Username, credential.Password)
	}

	// 记录成功日志
	Common.LogSuccess(successMsg)

	// 保存结果
	result := &Common.ScanResult{
		Time:    time.Now(),
		Type:    Common.VULN,
		Target:  info.Host,
		Status:  "vulnerable",
		Details: details,
	}
	Common.SaveResult(result)
}

// SmblConn 尝试建立SMB连接并认证
func SmblConn(info *Common.HostInfo, user string, pass string, signal chan struct{}) (flag bool, err error) {
	options := smb.Options{
		Host:        info.Host,
		Port:        445,
		User:        user,
		Password:    pass,
		Domain:      Common.Domain,
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err == nil {
		defer session.Close()
		if session.IsAuthenticated {
			return true, nil
		}
		return false, fmt.Errorf("认证失败")
	}

	// 清理错误信息中的换行符和多余空格
	errMsg := strings.TrimSpace(strings.ReplaceAll(err.Error(), "\n", " "))
	if strings.Contains(errMsg, "NT Status Error") {
		switch {
		case strings.Contains(errMsg, "STATUS_LOGON_FAILURE"):
			err = fmt.Errorf("密码错误")
		case strings.Contains(errMsg, "STATUS_ACCOUNT_LOCKED_OUT"):
			err = fmt.Errorf("账号锁定")
		case strings.Contains(errMsg, "STATUS_ACCESS_DENIED"):
			err = fmt.Errorf("拒绝访问")
		case strings.Contains(errMsg, "STATUS_ACCOUNT_DISABLED"):
			err = fmt.Errorf("账号禁用")
		case strings.Contains(errMsg, "STATUS_PASSWORD_EXPIRED"):
			err = fmt.Errorf("密码过期")
		case strings.Contains(errMsg, "STATUS_USER_SESSION_DELETED"):
			return false, fmt.Errorf("会话断开")
		default:
			err = fmt.Errorf("认证失败")
		}
	}

	signal <- struct{}{}
	return false, err
}
