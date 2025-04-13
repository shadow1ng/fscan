package Plugins

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	_ "github.com/sijms/go-ora/v2"
	"strings"
	"sync"
	"time"
)

// OracleCredential 表示一个Oracle凭据
type OracleCredential struct {
	Username string
	Password string
}

// OracleScanResult 表示Oracle扫描结果
type OracleScanResult struct {
	Success     bool
	Error       error
	Credential  OracleCredential
	ServiceName string
}

// 常见Oracle服务名列表
var commonServiceNames = []string{"XE", "ORCL", "ORCLPDB1", "XEPDB1", "PDBORCL"}

func OracleScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 构建常见高危凭据列表（优先测试）
	highRiskCredentials := []OracleCredential{
		{Username: "SYS", Password: "123456"},
		{Username: "SYSTEM", Password: "123456"},
		{Username: "SYS", Password: "oracle"},
		{Username: "SYSTEM", Password: "oracle"},
		{Username: "SYS", Password: "password"},
		{Username: "SYSTEM", Password: "password"},
		{Username: "SYS", Password: "sys123"},
		{Username: "SYS", Password: "change_on_install"},
		{Username: "SYSTEM", Password: "manager"},
	}

	// 先尝试常见高危凭据
	Common.LogDebug("尝试常见高危凭据...")
	for _, cred := range highRiskCredentials {
		result := tryAllServiceNames(ctx, info, cred, Common.Timeout, 1)
		if result != nil && result.Success {
			saveOracleResult(info, target, result.Credential, result.ServiceName)
			return nil
		}
	}

	// 构建完整凭据列表
	var credentials []OracleCredential
	for _, user := range Common.Userdict["oracle"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			// 转换用户名为大写，提高匹配率
			credentials = append(credentials, OracleCredential{
				Username: strings.ToUpper(user),
				Password: actualPass,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["oracle"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	result := concurrentOracleScan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 记录成功结果
		saveOracleResult(info, target, result.Credential, result.ServiceName)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("Oracle扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)+len(highRiskCredentials)))
		return nil
	}
}

// tryAllServiceNames 尝试所有常见服务名
func tryAllServiceNames(ctx context.Context, info *Common.HostInfo, credential OracleCredential, timeoutSeconds int64, maxRetries int) *OracleScanResult {
	for _, serviceName := range commonServiceNames {
		result := tryOracleCredential(ctx, info, credential, serviceName, timeoutSeconds, maxRetries)
		if result.Success {
			result.ServiceName = serviceName
			return result
		}

		// 对SYS用户尝试SYSDBA模式
		if strings.ToUpper(credential.Username) == "SYS" {
			result = tryOracleSysCredential(ctx, info, credential, serviceName, timeoutSeconds, maxRetries)
			if result.Success {
				result.ServiceName = serviceName
				return result
			}
		}
	}
	return nil
}

// concurrentOracleScan 并发扫描Oracle服务
func concurrentOracleScan(ctx context.Context, info *Common.HostInfo, credentials []OracleCredential, timeoutSeconds int64, maxRetries int) *OracleScanResult {
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
	resultChan := make(chan *OracleScanResult, 1)
	workChan := make(chan OracleCredential, maxConcurrent)
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
					// 尝试所有常见服务名
					result := tryAllServiceNames(scanCtx, info, credential, timeoutSeconds, maxRetries)
					if result != nil && result.Success {
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
		Common.LogDebug("Oracle并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryOracleCredential 尝试单个Oracle凭据
func tryOracleCredential(ctx context.Context, info *Common.HostInfo, credential OracleCredential, serviceName string, timeoutSeconds int64, maxRetries int) *OracleScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &OracleScanResult{
				Success:    false,
				Error:      fmt.Errorf("全局超时"),
				Credential: credential,
			}
		default:
			if retry > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s@%s", retry+1, credential.Username, credential.Password, serviceName))
				time.Sleep(500 * time.Millisecond) // 重试前等待
			}

			// 创建连接超时上下文
			connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)

			// 在协程中执行数据库连接
			resultChan := make(chan struct {
				success bool
				err     error
			}, 1)

			go func() {
				success, err := OracleConn(connCtx, info, credential.Username, credential.Password, serviceName, false)
				select {
				case <-connCtx.Done():
					// 已超时或取消，不发送结果
				case resultChan <- struct {
					success bool
					err     error
				}{success, err}:
				}
			}()

			// 等待结果或连接超时
			var success bool
			var err error

			select {
			case result := <-resultChan:
				success = result.success
				err = result.err
			case <-connCtx.Done():
				err = connCtx.Err()
			}

			// 取消连接超时上下文
			cancel()

			if success {
				return &OracleScanResult{
					Success:     true,
					Credential:  credential,
					ServiceName: serviceName,
				}
			}

			lastErr = err
			if err != nil {
				// 如果是认证错误，不需要重试
				if strings.Contains(err.Error(), "ORA-01017") {
					break // 认证失败
				}

				// 检查是否需要重试
				if retryErr := Common.CheckErrs(err); retryErr == nil {
					break // 不需要重试的错误
				}
			}
		}
	}

	return &OracleScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// tryOracleSysCredential 尝试SYS用户SYSDBA模式连接
func tryOracleSysCredential(ctx context.Context, info *Common.HostInfo, credential OracleCredential, serviceName string, timeoutSeconds int64, maxRetries int) *OracleScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &OracleScanResult{
				Success:    false,
				Error:      fmt.Errorf("全局超时"),
				Credential: credential,
			}
		default:
			if retry > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试SYS用户SYSDBA模式: %s:%s@%s", retry+1, credential.Username, credential.Password, serviceName))
				time.Sleep(500 * time.Millisecond) // 重试前等待
			}

			// 创建连接超时上下文
			connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)

			// 在协程中执行数据库连接
			resultChan := make(chan struct {
				success bool
				err     error
			}, 1)

			go func() {
				success, err := OracleConn(connCtx, info, credential.Username, credential.Password, serviceName, true)
				select {
				case <-connCtx.Done():
					// 已超时或取消，不发送结果
				case resultChan <- struct {
					success bool
					err     error
				}{success, err}:
				}
			}()

			// 等待结果或连接超时
			var success bool
			var err error

			select {
			case result := <-resultChan:
				success = result.success
				err = result.err
			case <-connCtx.Done():
				err = connCtx.Err()
			}

			// 取消连接超时上下文
			cancel()

			if success {
				return &OracleScanResult{
					Success:     true,
					Credential:  credential,
					ServiceName: serviceName,
				}
			}

			lastErr = err
			if err != nil {
				// 如果是认证错误，不需要重试
				if strings.Contains(err.Error(), "ORA-01017") {
					break // 认证失败
				}

				// 检查是否需要重试
				if retryErr := Common.CheckErrs(err); retryErr == nil {
					break // 不需要重试的错误
				}
			}
		}
	}

	return &OracleScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// OracleConn 尝试Oracle连接
func OracleConn(ctx context.Context, info *Common.HostInfo, user string, pass string, serviceName string, asSysdba bool) (bool, error) {
	host, port := info.Host, info.Ports

	// 构造连接字符串，添加更多参数
	connStr := fmt.Sprintf("oracle://%s:%s@%s:%s/%s?connect_timeout=%d",
		user, pass, host, port, serviceName, Common.Timeout)

	// 对SYS用户使用SYSDBA权限
	if asSysdba {
		connStr += "&sysdba=1"
	}

	// 建立数据库连接
	db, err := sql.Open("oracle", connStr)
	if err != nil {
		return false, err
	}
	defer db.Close()

	// 设置连接参数
	db.SetConnMaxLifetime(time.Duration(Common.Timeout) * time.Second)
	db.SetConnMaxIdleTime(time.Duration(Common.Timeout) * time.Second)
	db.SetMaxIdleConns(0)
	db.SetMaxOpenConns(1)

	// 使用上下文测试连接
	pingCtx, cancel := context.WithTimeout(ctx, time.Duration(Common.Timeout)*time.Second)
	defer cancel()

	// 测试连接
	err = db.PingContext(pingCtx)
	if err != nil {
		return false, err
	}

	// 不需要额外的查询验证，连接成功即可
	return true, nil
}

// saveOracleResult 保存Oracle扫描结果
func saveOracleResult(info *Common.HostInfo, target string, credential OracleCredential, serviceName string) {
	var successMsg string
	if strings.ToUpper(credential.Username) == "SYS" {
		successMsg = fmt.Sprintf("Oracle %s 成功爆破 用户名: %v 密码: %v 服务名: %s (可能需要SYSDBA权限)",
			target, credential.Username, credential.Password, serviceName)
	} else {
		successMsg = fmt.Sprintf("Oracle %s 成功爆破 用户名: %v 密码: %v 服务名: %s",
			target, credential.Username, credential.Password, serviceName)
	}
	Common.LogSuccess(successMsg)

	// 保存结果
	vulnResult := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.VULN,
		Target: info.Host,
		Status: "vulnerable",
		Details: map[string]interface{}{
			"port":         info.Ports,
			"service":      "oracle",
			"username":     credential.Username,
			"password":     credential.Password,
			"service_name": serviceName,
			"type":         "weak-password",
		},
	}
	Common.SaveResult(vulnResult)
}
