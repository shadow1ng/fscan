package Plugins

import (
	"context"
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"sync"
	"time"
)

// FtpCredential 表示一个FTP凭据
type FtpCredential struct {
	Username string
	Password string
}

// FtpScanResult 表示FTP扫描结果
type FtpScanResult struct {
	Success     bool
	Error       error
	Credential  FtpCredential
	Directories []string
	IsAnonymous bool
}

func FtpScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 首先尝试匿名登录
	Common.LogDebug("尝试匿名登录...")
	anonymousResult := tryFtpCredential(ctx, info, FtpCredential{"anonymous", ""}, Common.Timeout, Common.MaxRetries)

	if anonymousResult.Success {
		// 匿名登录成功
		saveFtpResult(info, target, anonymousResult)
		return nil
	}

	// 构建凭据列表
	var credentials []FtpCredential
	for _, user := range Common.Userdict["ftp"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, FtpCredential{
				Username: user,
				Password: actualPass,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["ftp"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	result := concurrentFtpScan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 保存成功结果
		saveFtpResult(info, target, result)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("FTP扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)+1)) // +1 是因为还尝试了匿名登录
		return nil
	}
}

// concurrentFtpScan 并发扫描FTP服务
func concurrentFtpScan(ctx context.Context, info *Common.HostInfo, credentials []FtpCredential, timeoutSeconds int64, maxRetries int) *FtpScanResult {
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
	resultChan := make(chan *FtpScanResult, 1)
	workChan := make(chan FtpCredential, maxConcurrent)
	scanCtx, scanCancel := context.WithCancel(ctx)
	defer scanCancel()

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
					result := tryFtpCredential(scanCtx, info, credential, timeoutSeconds, maxRetries)
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

	// 获取结果，考虑全局超时
	select {
	case result, ok := <-resultChan:
		if ok && result != nil && result.Success {
			return result
		}
		return nil
	case <-ctx.Done():
		Common.LogDebug("FTP并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryFtpCredential 尝试单个FTP凭据
func tryFtpCredential(ctx context.Context, info *Common.HostInfo, credential FtpCredential, timeoutSeconds int64, maxRetries int) *FtpScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &FtpScanResult{
				Success:    false,
				Error:      fmt.Errorf("全局超时"),
				Credential: credential,
			}
		default:
			if retry > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retry+1, credential.Username, credential.Password))
				time.Sleep(500 * time.Millisecond) // 重试前等待
			}

			// 创建结果通道
			resultChan := make(chan struct {
				success     bool
				directories []string
				err         error
			}, 1)

			// 在协程中尝试连接
			connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
			go func() {
				defer cancel()
				success, dirs, err := FtpConn(info, credential.Username, credential.Password)
				select {
				case <-connCtx.Done():
				case resultChan <- struct {
					success     bool
					directories []string
					err         error
				}{success, dirs, err}:
				}
			}()

			// 等待结果或超时
			var success bool
			var dirs []string
			var err error

			select {
			case result := <-resultChan:
				success = result.success
				dirs = result.directories
				err = result.err
			case <-connCtx.Done():
				if ctx.Err() != nil {
					// 全局超时
					return &FtpScanResult{
						Success:    false,
						Error:      ctx.Err(),
						Credential: credential,
					}
				}
				// 单个连接超时
				err = fmt.Errorf("连接超时")
			}

			if success {
				isAnonymous := credential.Username == "anonymous" && credential.Password == ""
				return &FtpScanResult{
					Success:     true,
					Credential:  credential,
					Directories: dirs,
					IsAnonymous: isAnonymous,
				}
			}

			lastErr = err
			if err != nil {
				// 登录错误不需要重试
				if strings.Contains(err.Error(), "Login incorrect") {
					break
				}

				// 连接数过多需要等待
				if strings.Contains(err.Error(), "too many connections") {
					Common.LogDebug("连接数过多，等待5秒...")
					time.Sleep(5 * time.Second)
					continue
				}

				// 检查是否需要重试
				if retryErr := Common.CheckErrs(err); retryErr == nil {
					break
				}
			}
		}
	}

	return &FtpScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// FtpConn 建立FTP连接并尝试登录
func FtpConn(info *Common.HostInfo, user string, pass string) (success bool, directories []string, err error) {
	Host, Port := info.Host, info.Ports

	// 建立FTP连接
	conn, err := ftp.DialTimeout(fmt.Sprintf("%v:%v", Host, Port), time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		if conn != nil {
			conn.Quit()
		}
	}()

	// 尝试登录
	if err = conn.Login(user, pass); err != nil {
		return false, nil, err
	}

	// 获取目录信息
	dirs, err := conn.List("")
	if err == nil && len(dirs) > 0 {
		directories = make([]string, 0, min(6, len(dirs)))
		for i := 0; i < len(dirs) && i < 6; i++ {
			name := dirs[i].Name
			if len(name) > 50 {
				name = name[:50]
			}
			directories = append(directories, name)
		}
	}

	return true, directories, nil
}

// saveFtpResult 保存FTP扫描结果
func saveFtpResult(info *Common.HostInfo, target string, result *FtpScanResult) {
	var successMsg string
	var details map[string]interface{}

	if result.IsAnonymous {
		successMsg = fmt.Sprintf("FTP服务 %s 匿名登录成功!", target)
		details = map[string]interface{}{
			"port":        info.Ports,
			"service":     "ftp",
			"username":    "anonymous",
			"password":    "",
			"type":        "anonymous-login",
			"directories": result.Directories,
		}
	} else {
		successMsg = fmt.Sprintf("FTP服务 %s 成功爆破 用户名: %v 密码: %v",
			target, result.Credential.Username, result.Credential.Password)
		details = map[string]interface{}{
			"port":        info.Ports,
			"service":     "ftp",
			"username":    result.Credential.Username,
			"password":    result.Credential.Password,
			"type":        "weak-password",
			"directories": result.Directories,
		}
	}

	Common.LogSuccess(successMsg)

	// 保存结果
	vulnResult := &Common.ScanResult{
		Time:    time.Now(),
		Type:    Common.VULN,
		Target:  info.Host,
		Status:  "vulnerable",
		Details: details,
	}
	Common.SaveResult(vulnResult)
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
