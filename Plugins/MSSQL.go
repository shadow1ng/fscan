package Plugins

import (
	"context"
	"database/sql"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"sync"
	"time"
)

// MssqlCredential 表示一个MSSQL凭据
type MssqlCredential struct {
	Username string
	Password string
}

// MssqlScanResult 表示MSSQL扫描结果
type MssqlScanResult struct {
	Success    bool
	Error      error
	Credential MssqlCredential
}

// MssqlScan 执行MSSQL服务扫描
func MssqlScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 构建凭据列表
	var credentials []MssqlCredential
	for _, user := range Common.Userdict["mssql"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, MssqlCredential{
				Username: user,
				Password: actualPass,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["mssql"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	result := concurrentMssqlScan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 记录成功结果
		saveMssqlResult(info, target, result.Credential)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("MSSQL扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)))
		return nil
	}
}

// concurrentMssqlScan 并发扫描MSSQL服务
func concurrentMssqlScan(ctx context.Context, info *Common.HostInfo, credentials []MssqlCredential, timeoutSeconds int64, maxRetries int) *MssqlScanResult {
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
	resultChan := make(chan *MssqlScanResult, 1)
	workChan := make(chan MssqlCredential, maxConcurrent)
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
					result := tryMssqlCredential(scanCtx, info, credential, timeoutSeconds, maxRetries)
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
		Common.LogDebug("MSSQL并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryMssqlCredential 尝试单个MSSQL凭据
func tryMssqlCredential(ctx context.Context, info *Common.HostInfo, credential MssqlCredential, timeoutSeconds int64, maxRetries int) *MssqlScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &MssqlScanResult{
				Success:    false,
				Error:      fmt.Errorf("全局超时"),
				Credential: credential,
			}
		default:
			if retry > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retry+1, credential.Username, credential.Password))
				time.Sleep(500 * time.Millisecond) // 重试前等待
			}

			// 创建连接超时的上下文
			connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
			success, err := MssqlConn(connCtx, info, credential.Username, credential.Password)
			cancel()

			if success {
				return &MssqlScanResult{
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

	return &MssqlScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// MssqlConn 尝试MSSQL连接
func MssqlConn(ctx context.Context, info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port, username, password := info.Host, info.Ports, user, pass
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造连接字符串
	connStr := fmt.Sprintf(
		"server=%s;user id=%s;password=%s;port=%v;encrypt=disable;",
		host, username, password, port,
	)

	// 建立数据库连接
	db, err := sql.Open("mssql", connStr)
	if err != nil {
		return false, err
	}
	defer db.Close()

	// 设置连接参数
	db.SetConnMaxLifetime(timeout)
	db.SetConnMaxIdleTime(timeout)
	db.SetMaxIdleConns(0)
	db.SetMaxOpenConns(1)

	// 通过上下文执行ping操作，以支持超时控制
	pingCtx, pingCancel := context.WithTimeout(ctx, timeout)
	defer pingCancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- db.PingContext(pingCtx)
	}()

	// 等待ping结果或者超时
	select {
	case err := <-errChan:
		if err != nil {
			return false, err
		}
		return true, nil
	case <-ctx.Done():
		// 全局超时或取消
		return false, ctx.Err()
	case <-pingCtx.Done():
		if pingCtx.Err() == context.DeadlineExceeded {
			// 单个连接超时
			return false, fmt.Errorf("连接超时")
		}
		return false, pingCtx.Err()
	}
}

// saveMssqlResult 保存MSSQL扫描结果
func saveMssqlResult(info *Common.HostInfo, target string, credential MssqlCredential) {
	successMsg := fmt.Sprintf("MSSQL %s %v %v", target, credential.Username, credential.Password)
	Common.LogSuccess(successMsg)

	// 保存结果
	vulnResult := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.VULN,
		Target: info.Host,
		Status: "vulnerable",
		Details: map[string]interface{}{
			"port":     info.Ports,
			"service":  "mssql",
			"username": credential.Username,
			"password": credential.Password,
			"type":     "weak-password",
		},
	}
	Common.SaveResult(vulnResult)
}
