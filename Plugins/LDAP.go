package Plugins

import (
	"context"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"sync"
	"time"
)

// LDAPCredential 表示一个LDAP凭据
type LDAPCredential struct {
	Username string
	Password string
}

// LDAPScanResult 表示LDAP扫描结果
type LDAPScanResult struct {
	Success     bool
	Error       error
	Credential  LDAPCredential
	IsAnonymous bool
}

func LDAPScan(info *Common.HostInfo) error {
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
	anonymousResult := tryLDAPCredential(ctx, info, LDAPCredential{"", ""}, Common.Timeout, 1)

	if anonymousResult.Success {
		// 匿名访问成功
		saveLDAPResult(info, target, anonymousResult)
		return nil
	}

	// 构建凭据列表
	var credentials []LDAPCredential
	for _, user := range Common.Userdict["ldap"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, LDAPCredential{
				Username: user,
				Password: actualPass,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["ldap"]), len(Common.Passwords), len(credentials)))

	// 使用工作池并发扫描
	result := concurrentLDAPScan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 记录成功结果
		saveLDAPResult(info, target, result)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("LDAP扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)+1)) // +1 是因为还尝试了匿名访问
		return nil
	}
}

// concurrentLDAPScan 并发扫描LDAP服务
func concurrentLDAPScan(ctx context.Context, info *Common.HostInfo, credentials []LDAPCredential, timeoutSeconds int64, maxRetries int) *LDAPScanResult {
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
	resultChan := make(chan *LDAPScanResult, 1)
	workChan := make(chan LDAPCredential, maxConcurrent)
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
					result := tryLDAPCredential(scanCtx, info, credential, timeoutSeconds, maxRetries)
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
		Common.LogDebug("LDAP并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryLDAPCredential 尝试单个LDAP凭据
func tryLDAPCredential(ctx context.Context, info *Common.HostInfo, credential LDAPCredential, timeoutSeconds int64, maxRetries int) *LDAPScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &LDAPScanResult{
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
			success, err := LDAPConn(connCtx, info, credential.Username, credential.Password)
			cancel()

			if success {
				isAnonymous := credential.Username == "" && credential.Password == ""
				return &LDAPScanResult{
					Success:     true,
					Credential:  credential,
					IsAnonymous: isAnonymous,
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

	return &LDAPScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// LDAPConn 尝试LDAP连接
func LDAPConn(ctx context.Context, info *Common.HostInfo, user string, pass string) (bool, error) {
	address := fmt.Sprintf("%s:%s", info.Host, info.Ports)

	// 创建拨号器并设置超时
	dialer := &net.Dialer{
		Timeout: time.Duration(Common.Timeout) * time.Second,
	}

	// 使用上下文控制的拨号过程
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false, err
	}

	// 使用已连接的TCP连接创建LDAP连接
	l := ldap.NewConn(conn, false)
	defer l.Close()

	// 在单独的协程中启动LDAP连接
	go l.Start()

	// 创建一个完成通道
	done := make(chan error, 1)

	// 在协程中进行绑定和搜索操作，确保可以被上下文取消
	go func() {
		// 尝试绑定
		var err error
		if user != "" {
			// 使用更通用的绑定DN模式
			bindDN := fmt.Sprintf("cn=%s,dc=example,dc=com", user)
			err = l.Bind(bindDN, pass)
		} else {
			// 匿名绑定
			err = l.UnauthenticatedBind("")
		}

		if err != nil {
			done <- err
			return
		}

		// 尝试简单搜索以验证权限
		searchRequest := ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"dn"},
			nil,
		)

		_, err = l.Search(searchRequest)
		done <- err
	}()

	// 等待操作完成或上下文取消
	select {
	case err := <-done:
		if err != nil {
			return false, err
		}
		return true, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// saveLDAPResult 保存LDAP扫描结果
func saveLDAPResult(info *Common.HostInfo, target string, result *LDAPScanResult) {
	var successMsg string
	var details map[string]interface{}

	if result.IsAnonymous {
		successMsg = fmt.Sprintf("LDAP服务 %s 匿名访问成功", target)
		details = map[string]interface{}{
			"port":    info.Ports,
			"service": "ldap",
			"type":    "anonymous-access",
		}
	} else {
		successMsg = fmt.Sprintf("LDAP服务 %s 爆破成功 用户名: %v 密码: %v",
			target, result.Credential.Username, result.Credential.Password)
		details = map[string]interface{}{
			"port":     info.Ports,
			"service":  "ldap",
			"username": result.Credential.Username,
			"password": result.Credential.Password,
			"type":     "weak-password",
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
