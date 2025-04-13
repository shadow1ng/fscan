package Plugins

import (
	"context"
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"sync"
	"time"
)

// PostgresCredential 表示一个PostgreSQL凭据
type PostgresCredential struct {
	Username string
	Password string
}

// PostgresScanResult 表示PostgreSQL扫描结果
type PostgresScanResult struct {
	Success    bool
	Error      error
	Credential PostgresCredential
}

// PostgresScan 执行PostgreSQL服务扫描
func PostgresScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 构建凭据列表
	var credentials []PostgresCredential
	for _, user := range Common.Userdict["postgresql"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, PostgresCredential{
				Username: user,
				Password: actualPass,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["postgresql"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	result := concurrentPostgresScan(ctx, info, credentials, Common.Timeout+10, Common.MaxRetries)
	if result != nil {
		// 记录成功结果
		savePostgresResult(info, target, result.Credential)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("PostgreSQL扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)))
		return nil
	}
}

// concurrentPostgresScan 并发扫描PostgreSQL服务
func concurrentPostgresScan(ctx context.Context, info *Common.HostInfo, credentials []PostgresCredential, timeoutSeconds int64, maxRetries int) *PostgresScanResult {
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
	resultChan := make(chan *PostgresScanResult, 1)
	workChan := make(chan PostgresCredential, maxConcurrent)
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
					result := tryPostgresCredential(scanCtx, info, credential, timeoutSeconds, maxRetries)
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
		Common.LogDebug("PostgreSQL并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryPostgresCredential 尝试单个PostgreSQL凭据
func tryPostgresCredential(ctx context.Context, info *Common.HostInfo, credential PostgresCredential, timeoutSeconds int64, maxRetries int) *PostgresScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &PostgresScanResult{
				Success:    false,
				Error:      fmt.Errorf("全局超时"),
				Credential: credential,
			}
		default:
			if retry > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retry+1, credential.Username, credential.Password))
				time.Sleep(500 * time.Millisecond) // 重试前等待
			}

			// 创建单个连接超时的上下文
			connCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
			success, err := PostgresConn(connCtx, info, credential.Username, credential.Password)
			cancel()

			if success {
				return &PostgresScanResult{
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

	return &PostgresScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// PostgresConn 尝试PostgreSQL连接
func PostgresConn(ctx context.Context, info *Common.HostInfo, user string, pass string) (bool, error) {
	// 构造连接字符串
	connStr := fmt.Sprintf(
		"postgres://%v:%v@%v:%v/postgres?sslmode=disable&connect_timeout=%d",
		user, pass, info.Host, info.Ports, Common.Timeout/1000, // 转换为秒
	)

	// 建立数据库连接
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return false, err
	}
	defer db.Close()

	// 设置连接参数
	db.SetConnMaxLifetime(time.Duration(Common.Timeout) * time.Millisecond)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	// 使用上下文测试连接
	err = db.PingContext(ctx)
	if err != nil {
		return false, err
	}

	// 简单查询测试权限
	var version string
	err = db.QueryRowContext(ctx, "SELECT version()").Scan(&version)
	if err != nil {
		return false, err
	}

	return true, nil
}

// savePostgresResult 保存PostgreSQL扫描结果
func savePostgresResult(info *Common.HostInfo, target string, credential PostgresCredential) {
	successMsg := fmt.Sprintf("PostgreSQL服务 %s 成功爆破 用户名: %v 密码: %v",
		target, credential.Username, credential.Password)
	Common.LogSuccess(successMsg)

	// 保存结果
	vulnResult := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.VULN,
		Target: info.Host,
		Status: "vulnerable",
		Details: map[string]interface{}{
			"port":     info.Ports,
			"service":  "postgresql",
			"username": credential.Username,
			"password": credential.Password,
			"type":     "weak-password",
		},
	}
	Common.SaveResult(vulnResult)
}
