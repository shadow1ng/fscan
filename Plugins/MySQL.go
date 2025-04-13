package Plugins

import (
	"context"
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"sync"
	"time"
)

// MySQLCredential 表示一个MySQL凭据
type MySQLCredential struct {
	Username string
	Password string
}

// MySQLScanResult 表示MySQL扫描结果
type MySQLScanResult struct {
	Success    bool
	Error      error
	Credential MySQLCredential
}

// MysqlScan 执行MySQL服务扫描
func MysqlScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 构建凭据列表
	var credentials []MySQLCredential
	for _, user := range Common.Userdict["mysql"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, MySQLCredential{
				Username: user,
				Password: actualPass,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["mysql"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	result := concurrentMySQLScan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 记录成功结果
		saveMySQLResult(info, target, result.Credential)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("MySQL扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)))
		return nil
	}
}

// concurrentMySQLScan 并发扫描MySQL服务
func concurrentMySQLScan(ctx context.Context, info *Common.HostInfo, credentials []MySQLCredential, timeoutSeconds int64, maxRetries int) *MySQLScanResult {
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
	resultChan := make(chan *MySQLScanResult, 1)
	workChan := make(chan MySQLCredential, maxConcurrent)
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
					result := tryMySQLCredential(scanCtx, info, credential, timeoutSeconds, maxRetries)
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
		Common.LogDebug("MySQL并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryMySQLCredential 尝试单个MySQL凭据
func tryMySQLCredential(ctx context.Context, info *Common.HostInfo, credential MySQLCredential, timeoutSeconds int64, maxRetries int) *MySQLScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &MySQLScanResult{
				Success:    false,
				Error:      fmt.Errorf("全局超时"),
				Credential: credential,
			}
		default:
			if retry > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retry+1, credential.Username, credential.Password))
				time.Sleep(500 * time.Millisecond) // 重试前等待
			}

			// 创建独立的超时上下文
			connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
			success, err := MysqlConn(connCtx, info, credential.Username, credential.Password)
			cancel()

			if success {
				return &MySQLScanResult{
					Success:    true,
					Credential: credential,
				}
			}

			lastErr = err
			if err != nil {
				// Access denied 表示用户名或密码错误，无需重试
				if strings.Contains(err.Error(), "Access denied") {
					break
				}

				// 检查是否需要重试
				if retryErr := Common.CheckErrs(err); retryErr == nil {
					break // 不需要重试的错误
				}
			}
		}
	}

	return &MySQLScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// MysqlConn 尝试MySQL连接
func MysqlConn(ctx context.Context, info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port, username, password := info.Host, info.Ports, user, pass
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造连接字符串，包含超时设置
	connStr := fmt.Sprintf(
		"%v:%v@tcp(%v:%v)/mysql?charset=utf8&timeout=%v",
		username, password, host, port, timeout,
	)

	// 创建结果通道
	resultChan := make(chan struct {
		success bool
		err     error
	}, 1)

	// 在协程中尝试连接
	go func() {
		// 建立数据库连接
		db, err := sql.Open("mysql", connStr)
		if err != nil {
			select {
			case <-ctx.Done():
			case resultChan <- struct {
				success bool
				err     error
			}{false, err}:
			}
			return
		}
		defer db.Close()

		// 设置连接参数
		db.SetConnMaxLifetime(timeout)
		db.SetConnMaxIdleTime(timeout)
		db.SetMaxIdleConns(0)

		// 添加上下文支持
		conn, err := db.Conn(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
			case resultChan <- struct {
				success bool
				err     error
			}{false, err}:
			}
			return
		}
		defer conn.Close()

		// 测试连接
		err = conn.PingContext(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
			case resultChan <- struct {
				success bool
				err     error
			}{false, err}:
			}
			return
		}

		// 连接成功
		select {
		case <-ctx.Done():
		case resultChan <- struct {
			success bool
			err     error
		}{true, nil}:
		}
	}()

	// 等待结果或上下文取消
	select {
	case result := <-resultChan:
		return result.success, result.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// saveMySQLResult 保存MySQL扫描结果
func saveMySQLResult(info *Common.HostInfo, target string, credential MySQLCredential) {
	successMsg := fmt.Sprintf("MySQL %s %v %v", target, credential.Username, credential.Password)
	Common.LogSuccess(successMsg)

	// 保存结果
	vulnResult := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.VULN,
		Target: info.Host,
		Status: "vulnerable",
		Details: map[string]interface{}{
			"port":     info.Ports,
			"service":  "mysql",
			"username": credential.Username,
			"password": credential.Password,
			"type":     "weak-password",
		},
	}
	Common.SaveResult(vulnResult)
}
