package Plugins

import (
	"context"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"sync"
	"time"
)

// RsyncCredential 表示一个Rsync凭据
type RsyncCredential struct {
	Username string
	Password string
}

// RsyncScanResult 表示Rsync扫描结果
type RsyncScanResult struct {
	Success     bool
	Error       error
	Credential  RsyncCredential
	IsAnonymous bool
	ModuleName  string
}

func RsyncScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 首先尝试匿名访问
	Common.LogDebug("尝试匿名访问...")
	anonymousResult := tryRsyncCredential(ctx, info, RsyncCredential{"", ""}, Common.Timeout, Common.MaxRetries)

	if anonymousResult.Success {
		// 匿名访问成功
		saveRsyncResult(info, target, anonymousResult)
		return nil
	}

	// 构建凭据列表
	var credentials []RsyncCredential
	for _, user := range Common.Userdict["rsync"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, RsyncCredential{
				Username: user,
				Password: actualPass,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["rsync"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	result := concurrentRsyncScan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 保存成功结果
		saveRsyncResult(info, target, result)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("Rsync扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)+1)) // +1 是因为还尝试了匿名访问
		return nil
	}
}

// concurrentRsyncScan 并发扫描Rsync服务
func concurrentRsyncScan(ctx context.Context, info *Common.HostInfo, credentials []RsyncCredential, timeoutSeconds int64, maxRetries int) *RsyncScanResult {
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
	resultChan := make(chan *RsyncScanResult, 1)
	workChan := make(chan RsyncCredential, maxConcurrent)
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
					result := tryRsyncCredential(scanCtx, info, credential, timeoutSeconds, maxRetries)
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
		Common.LogDebug("Rsync并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryRsyncCredential 尝试单个Rsync凭据
func tryRsyncCredential(ctx context.Context, info *Common.HostInfo, credential RsyncCredential, timeoutSeconds int64, maxRetries int) *RsyncScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &RsyncScanResult{
				Success:    false,
				Error:      fmt.Errorf("全局超时"),
				Credential: credential,
			}
		default:
			if retry > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retry+1, credential.Username, credential.Password))
				time.Sleep(500 * time.Millisecond) // 重试前等待
			}

			// 创建连接超时上下文
			connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
			success, moduleName, err := RsyncConn(connCtx, info, credential.Username, credential.Password)
			cancel()

			if success {
				isAnonymous := credential.Username == "" && credential.Password == ""
				return &RsyncScanResult{
					Success:     true,
					Credential:  credential,
					IsAnonymous: isAnonymous,
					ModuleName:  moduleName,
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
	}

	return &RsyncScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// RsyncConn 尝试Rsync连接
func RsyncConn(ctx context.Context, info *Common.HostInfo, user string, pass string) (bool, string, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// 设置带有上下文的拨号器
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	// 建立连接
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		return false, "", err
	}
	defer conn.Close()

	// 创建结果通道用于超时控制
	resultChan := make(chan struct {
		success    bool
		moduleName string
		err        error
	}, 1)

	// 在协程中处理连接，以支持上下文取消
	go func() {
		buffer := make([]byte, 1024)

		// 1. 读取服务器初始greeting
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buffer)
		if err != nil {
			select {
			case <-ctx.Done():
			case resultChan <- struct {
				success    bool
				moduleName string
				err        error
			}{false, "", err}:
			}
			return
		}

		greeting := string(buffer[:n])
		if !strings.HasPrefix(greeting, "@RSYNCD:") {
			select {
			case <-ctx.Done():
			case resultChan <- struct {
				success    bool
				moduleName string
				err        error
			}{false, "", fmt.Errorf("不是Rsync服务")}:
			}
			return
		}

		// 获取服务器版本号
		version := strings.TrimSpace(strings.TrimPrefix(greeting, "@RSYNCD:"))

		// 2. 回应相同的版本号
		conn.SetWriteDeadline(time.Now().Add(timeout))
		_, err = conn.Write([]byte(fmt.Sprintf("@RSYNCD: %s\n", version)))
		if err != nil {
			select {
			case <-ctx.Done():
			case resultChan <- struct {
				success    bool
				moduleName string
				err        error
			}{false, "", err}:
			}
			return
		}

		// 3. 选择模块 - 先列出可用模块
		conn.SetWriteDeadline(time.Now().Add(timeout))
		_, err = conn.Write([]byte("#list\n"))
		if err != nil {
			select {
			case <-ctx.Done():
			case resultChan <- struct {
				success    bool
				moduleName string
				err        error
			}{false, "", err}:
			}
			return
		}

		// 4. 读取模块列表
		var moduleList strings.Builder
		for {
			// 检查上下文是否取消
			select {
			case <-ctx.Done():
				return
			default:
			}

			conn.SetReadDeadline(time.Now().Add(timeout))
			n, err = conn.Read(buffer)
			if err != nil {
				break
			}
			chunk := string(buffer[:n])
			moduleList.WriteString(chunk)
			if strings.Contains(chunk, "@RSYNCD: EXIT") {
				break
			}
		}

		modules := strings.Split(moduleList.String(), "\n")
		for _, module := range modules {
			if strings.HasPrefix(module, "@RSYNCD") || module == "" {
				continue
			}

			// 获取模块名
			moduleName := strings.Fields(module)[0]

			// 检查上下文是否取消
			select {
			case <-ctx.Done():
				return
			default:
			}

			// 5. 为每个模块创建新连接尝试认证
			authConn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%s", host, port))
			if err != nil {
				continue
			}
			defer authConn.Close()

			// 重复初始握手
			authConn.SetReadDeadline(time.Now().Add(timeout))
			_, err = authConn.Read(buffer)
			if err != nil {
				authConn.Close()
				continue
			}

			authConn.SetWriteDeadline(time.Now().Add(timeout))
			_, err = authConn.Write([]byte(fmt.Sprintf("@RSYNCD: %s\n", version)))
			if err != nil {
				authConn.Close()
				continue
			}

			// 6. 选择模块
			authConn.SetWriteDeadline(time.Now().Add(timeout))
			_, err = authConn.Write([]byte(moduleName + "\n"))
			if err != nil {
				authConn.Close()
				continue
			}

			// 7. 等待认证挑战
			authConn.SetReadDeadline(time.Now().Add(timeout))
			n, err = authConn.Read(buffer)
			if err != nil {
				authConn.Close()
				continue
			}

			authResponse := string(buffer[:n])
			if strings.Contains(authResponse, "@RSYNCD: OK") {
				// 模块不需要认证
				if user == "" && pass == "" {
					authConn.Close()
					select {
					case <-ctx.Done():
					case resultChan <- struct {
						success    bool
						moduleName string
						err        error
					}{true, moduleName, nil}:
					}
					return
				}
			} else if strings.Contains(authResponse, "@RSYNCD: AUTHREQD") {
				if user != "" && pass != "" {
					// 8. 发送认证信息
					authString := fmt.Sprintf("%s %s\n", user, pass)
					authConn.SetWriteDeadline(time.Now().Add(timeout))
					_, err = authConn.Write([]byte(authString))
					if err != nil {
						authConn.Close()
						continue
					}

					// 9. 读取认证结果
					authConn.SetReadDeadline(time.Now().Add(timeout))
					n, err = authConn.Read(buffer)
					if err != nil {
						authConn.Close()
						continue
					}

					if !strings.Contains(string(buffer[:n]), "@ERROR") {
						authConn.Close()
						select {
						case <-ctx.Done():
						case resultChan <- struct {
							success    bool
							moduleName string
							err        error
						}{true, moduleName, nil}:
						}
						return
					}
				}
			}
			authConn.Close()
		}

		// 如果执行到这里，没有找到成功的认证
		select {
		case <-ctx.Done():
		case resultChan <- struct {
			success    bool
			moduleName string
			err        error
		}{false, "", fmt.Errorf("认证失败或无可用模块")}:
		}
	}()

	// 等待结果或上下文取消
	select {
	case result := <-resultChan:
		return result.success, result.moduleName, result.err
	case <-ctx.Done():
		return false, "", ctx.Err()
	}
}

// saveRsyncResult 保存Rsync扫描结果
func saveRsyncResult(info *Common.HostInfo, target string, result *RsyncScanResult) {
	var successMsg string
	var details map[string]interface{}

	if result.IsAnonymous {
		successMsg = fmt.Sprintf("Rsync服务 %s 匿名访问成功 模块: %s", target, result.ModuleName)
		details = map[string]interface{}{
			"port":    info.Ports,
			"service": "rsync",
			"type":    "anonymous-access",
			"module":  result.ModuleName,
		}
	} else {
		successMsg = fmt.Sprintf("Rsync服务 %s 爆破成功 用户名: %v 密码: %v 模块: %s",
			target, result.Credential.Username, result.Credential.Password, result.ModuleName)
		details = map[string]interface{}{
			"port":     info.Ports,
			"service":  "rsync",
			"type":     "weak-password",
			"username": result.Credential.Username,
			"password": result.Credential.Password,
			"module":   result.ModuleName,
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
