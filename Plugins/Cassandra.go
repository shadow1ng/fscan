package Plugins

import (
	"context"
	"fmt"
	"github.com/gocql/gocql"
	"github.com/shadow1ng/fscan/Common"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CassandraCredential 表示一个Cassandra凭据
type CassandraCredential struct {
	Username string
	Password string
}

// CassandraScanResult 表示扫描结果
type CassandraScanResult struct {
	Success     bool
	IsAnonymous bool
	Error       error
	Credential  CassandraCredential
}

func CassandraScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 先尝试无认证访问
	Common.LogDebug("尝试无认证访问...")

	anonymousCredential := CassandraCredential{Username: "", Password: ""}
	anonymousResult := tryCassandraCredential(ctx, info, anonymousCredential, Common.Timeout, Common.MaxRetries)

	if anonymousResult.Success {
		saveCassandraSuccess(info, target, anonymousResult.Credential, true)
		return nil
	}

	// 生成所有凭据组合
	credentials := generateCassandraCredentials(Common.Userdict["cassandra"], Common.Passwords)
	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["cassandra"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	result := concurrentCassandraScan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 记录成功结果
		saveCassandraSuccess(info, target, result.Credential, false)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("Cassandra扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)+1)) // +1 是因为还尝试了匿名访问
		return nil
	}
}

// generateCassandraCredentials 生成Cassandra的用户名密码组合
func generateCassandraCredentials(users, passwords []string) []CassandraCredential {
	var credentials []CassandraCredential
	for _, user := range users {
		for _, pass := range passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, CassandraCredential{
				Username: user,
				Password: actualPass,
			})
		}
	}
	return credentials
}

// concurrentCassandraScan 并发扫描Cassandra服务
func concurrentCassandraScan(ctx context.Context, info *Common.HostInfo, credentials []CassandraCredential, timeoutSeconds int64, maxRetries int) *CassandraScanResult {
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
	resultChan := make(chan *CassandraScanResult, 1)
	workChan := make(chan CassandraCredential, maxConcurrent)
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
					result := tryCassandraCredential(scanCtx, info, credential, timeoutSeconds, maxRetries)
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
		Common.LogDebug("Cassandra并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryCassandraCredential 尝试单个Cassandra凭据
func tryCassandraCredential(ctx context.Context, info *Common.HostInfo, credential CassandraCredential, timeoutSeconds int64, maxRetries int) *CassandraScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &CassandraScanResult{
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
			success, err := CassandraConn(connCtx, info, credential.Username, credential.Password)
			cancel()

			if success {
				return &CassandraScanResult{
					Success:     true,
					IsAnonymous: credential.Username == "" && credential.Password == "",
					Credential:  credential,
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

	return &CassandraScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// CassandraConn 尝试Cassandra连接，支持上下文超时
func CassandraConn(ctx context.Context, info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	cluster := gocql.NewCluster(host)
	cluster.Port, _ = strconv.Atoi(port)
	cluster.Timeout = timeout
	cluster.ConnectTimeout = timeout
	cluster.ProtoVersion = 4
	cluster.Consistency = gocql.One

	if user != "" || pass != "" {
		cluster.Authenticator = gocql.PasswordAuthenticator{
			Username: user,
			Password: pass,
		}
	}

	cluster.RetryPolicy = &gocql.SimpleRetryPolicy{NumRetries: 3}

	// 创建会话通道
	sessionChan := make(chan struct {
		session *gocql.Session
		err     error
	}, 1)

	// 在后台创建会话，以便可以通过上下文取消
	go func() {
		session, err := cluster.CreateSession()
		select {
		case <-ctx.Done():
			if session != nil {
				session.Close()
			}
		case sessionChan <- struct {
			session *gocql.Session
			err     error
		}{session, err}:
		}
	}()

	// 等待会话创建或上下文取消
	var session *gocql.Session
	var err error
	select {
	case result := <-sessionChan:
		session, err = result.session, result.err
		if err != nil {
			return false, err
		}
	case <-ctx.Done():
		return false, ctx.Err()
	}

	defer session.Close()

	// 尝试执行查询，测试连接是否成功
	resultChan := make(chan struct {
		success bool
		err     error
	}, 1)

	go func() {
		var version string
		var err error

		// 尝试两种查询，确保至少一种成功
		err = session.Query("SELECT peer FROM system.peers").WithContext(ctx).Scan(&version)
		if err != nil {
			err = session.Query("SELECT now() FROM system.local").WithContext(ctx).Scan(&version)
		}

		select {
		case <-ctx.Done():
		case resultChan <- struct {
			success bool
			err     error
		}{err == nil, err}:
		}
	}()

	// 等待查询结果或上下文取消
	select {
	case result := <-resultChan:
		return result.success, result.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// saveCassandraSuccess 记录并保存Cassandra成功结果
func saveCassandraSuccess(info *Common.HostInfo, target string, credential CassandraCredential, isAnonymous bool) {
	var successMsg string
	var details map[string]interface{}

	if isAnonymous {
		successMsg = fmt.Sprintf("Cassandra服务 %s 无认证访问成功", target)
		details = map[string]interface{}{
			"port":        info.Ports,
			"service":     "cassandra",
			"auth_type":   "anonymous",
			"type":        "unauthorized-access",
			"description": "数据库允许无认证访问",
		}
	} else {
		successMsg = fmt.Sprintf("Cassandra服务 %s 爆破成功 用户名: %v 密码: %v",
			target, credential.Username, credential.Password)
		details = map[string]interface{}{
			"port":     info.Ports,
			"service":  "cassandra",
			"username": credential.Username,
			"password": credential.Password,
			"type":     "weak-password",
		}
	}

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
