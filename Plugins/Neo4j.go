package Plugins

import (
	"context"
	"fmt"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"sync"
	"time"
)

// Neo4jCredential 表示一个Neo4j凭据
type Neo4jCredential struct {
	Username string
	Password string
}

// Neo4jScanResult 表示Neo4j扫描结果
type Neo4jScanResult struct {
	Success        bool
	Error          error
	Credential     Neo4jCredential
	IsUnauth       bool
	IsDefaultCreds bool
}

func Neo4jScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 初始检查列表 - 无认证和默认凭证
	initialCredentials := []Neo4jCredential{
		{"", ""},           // 无认证
		{"neo4j", "neo4j"}, // 默认凭证
	}

	// 先检查无认证和默认凭证
	Common.LogDebug("尝试默认凭证...")
	for _, credential := range initialCredentials {
		Common.LogDebug(fmt.Sprintf("尝试: %s:%s", credential.Username, credential.Password))

		result := tryNeo4jCredential(ctx, info, credential, Common.Timeout, 1)
		if result.Success {
			// 标记结果类型
			if credential.Username == "" && credential.Password == "" {
				result.IsUnauth = true
			} else {
				result.IsDefaultCreds = true
			}

			// 保存结果
			saveNeo4jResult(info, target, result)
			return nil
		}
	}

	// 构建凭据列表
	var credentials []Neo4jCredential
	for _, user := range Common.Userdict["neo4j"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, Neo4jCredential{
				Username: user,
				Password: actualPass,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["neo4j"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	result := concurrentNeo4jScan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 记录成功结果
		saveNeo4jResult(info, target, result)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("Neo4j扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)+len(initialCredentials)))
		return nil
	}
}

// concurrentNeo4jScan 并发扫描Neo4j服务
func concurrentNeo4jScan(ctx context.Context, info *Common.HostInfo, credentials []Neo4jCredential, timeoutSeconds int64, maxRetries int) *Neo4jScanResult {
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
	resultChan := make(chan *Neo4jScanResult, 1)
	workChan := make(chan Neo4jCredential, maxConcurrent)
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
					result := tryNeo4jCredential(scanCtx, info, credential, timeoutSeconds, maxRetries)
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
		Common.LogDebug("Neo4j并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryNeo4jCredential 尝试单个Neo4j凭据
func tryNeo4jCredential(ctx context.Context, info *Common.HostInfo, credential Neo4jCredential, timeoutSeconds int64, maxRetries int) *Neo4jScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &Neo4jScanResult{
				Success:    false,
				Error:      fmt.Errorf("全局超时"),
				Credential: credential,
			}
		default:
			if retry > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retry+1, credential.Username, credential.Password))
				time.Sleep(500 * time.Millisecond) // 重试前等待
			}

			// 创建连接结果通道
			resultChan := make(chan struct {
				success bool
				err     error
			}, 1)

			// 在协程中尝试连接
			connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
			go func() {
				defer cancel()
				success, err := Neo4jConn(info, credential.Username, credential.Password)
				select {
				case <-connCtx.Done():
				case resultChan <- struct {
					success bool
					err     error
				}{success, err}:
				}
			}()

			// 等待结果或超时
			var success bool
			var err error

			select {
			case result := <-resultChan:
				success = result.success
				err = result.err
			case <-connCtx.Done():
				if ctx.Err() != nil {
					// 全局超时
					return &Neo4jScanResult{
						Success:    false,
						Error:      ctx.Err(),
						Credential: credential,
					}
				}
				// 单个连接超时
				err = fmt.Errorf("连接超时")
			}

			if success {
				return &Neo4jScanResult{
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
	}

	return &Neo4jScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// Neo4jConn 尝试Neo4j连接
func Neo4jConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造Neo4j URL
	uri := fmt.Sprintf("bolt://%s:%s", host, port)

	// 配置驱动选项
	config := func(c *neo4j.Config) {
		c.SocketConnectTimeout = timeout
		c.ConnectionAcquisitionTimeout = timeout
	}

	var driver neo4j.Driver
	var err error

	// 尝试建立连接
	if user != "" || pass != "" {
		// 有认证信息时使用认证
		driver, err = neo4j.NewDriver(uri, neo4j.BasicAuth(user, pass, ""), config)
	} else {
		// 无认证时使用NoAuth
		driver, err = neo4j.NewDriver(uri, neo4j.NoAuth(), config)
	}

	if err != nil {
		return false, err
	}
	defer driver.Close()

	// 测试连接有效性
	err = driver.VerifyConnectivity()
	if err != nil {
		return false, err
	}

	// 尝试执行简单查询以确认权限
	session := driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	_, err = session.Run("MATCH (n) RETURN count(n) LIMIT 1", nil)
	if err != nil {
		return false, err
	}

	return true, nil
}

// saveNeo4jResult 保存Neo4j扫描结果
func saveNeo4jResult(info *Common.HostInfo, target string, result *Neo4jScanResult) {
	var successMsg string
	var details map[string]interface{}

	if result.IsUnauth {
		// 无认证访问
		successMsg = fmt.Sprintf("Neo4j服务 %s 无需认证即可访问", target)
		details = map[string]interface{}{
			"port":    info.Ports,
			"service": "neo4j",
			"type":    "unauthorized-access",
		}
	} else if result.IsDefaultCreds {
		// 默认凭证
		successMsg = fmt.Sprintf("Neo4j服务 %s 默认凭证可用 用户名: %s 密码: %s",
			target, result.Credential.Username, result.Credential.Password)
		details = map[string]interface{}{
			"port":     info.Ports,
			"service":  "neo4j",
			"type":     "default-credentials",
			"username": result.Credential.Username,
			"password": result.Credential.Password,
		}
	} else {
		// 弱密码
		successMsg = fmt.Sprintf("Neo4j服务 %s 爆破成功 用户名: %s 密码: %s",
			target, result.Credential.Username, result.Credential.Password)
		details = map[string]interface{}{
			"port":     info.Ports,
			"service":  "neo4j",
			"type":     "weak-password",
			"username": result.Credential.Username,
			"password": result.Credential.Password,
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
