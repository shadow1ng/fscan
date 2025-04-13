package Plugins

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ElasticCredential 表示Elasticsearch的凭据
type ElasticCredential struct {
	Username string
	Password string
}

// ElasticScanResult 表示扫描结果
type ElasticScanResult struct {
	Success    bool
	IsUnauth   bool
	Error      error
	Credential ElasticCredential
}

func ElasticScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("开始扫描 %s", target))

	// 设置全局超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.GlobalTimeout)*time.Second)
	defer cancel()

	// 首先测试无认证访问
	Common.LogDebug("尝试无认证访问...")
	unauthResult := tryElasticCredential(ctx, info, ElasticCredential{"", ""}, Common.Timeout, Common.MaxRetries)

	if unauthResult.Success {
		// 无需认证情况
		saveElasticResult(info, target, unauthResult.Credential, true)
		return nil
	}

	// 构建凭据列表
	var credentials []ElasticCredential
	for _, user := range Common.Userdict["elastic"] {
		for _, pass := range Common.Passwords {
			actualPass := strings.Replace(pass, "{user}", user, -1)
			credentials = append(credentials, ElasticCredential{
				Username: user,
				Password: actualPass,
			})
		}
	}

	Common.LogDebug(fmt.Sprintf("开始尝试用户名密码组合 (总用户数: %d, 总密码数: %d, 总组合数: %d)",
		len(Common.Userdict["elastic"]), len(Common.Passwords), len(credentials)))

	// 并发扫描
	result := concurrentElasticScan(ctx, info, credentials, Common.Timeout, Common.MaxRetries)
	if result != nil {
		// 记录成功结果
		saveElasticResult(info, target, result.Credential, false)
		return nil
	}

	// 检查是否因为全局超时而退出
	select {
	case <-ctx.Done():
		Common.LogDebug("Elasticsearch扫描全局超时")
		return fmt.Errorf("全局超时")
	default:
		Common.LogDebug(fmt.Sprintf("扫描完成，共尝试 %d 个组合", len(credentials)+1)) // +1是因为尝试了无认证
		return nil
	}
}

// concurrentElasticScan 并发扫描Elasticsearch服务
func concurrentElasticScan(ctx context.Context, info *Common.HostInfo, credentials []ElasticCredential, timeoutSeconds int64, maxRetries int) *ElasticScanResult {
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
	resultChan := make(chan *ElasticScanResult, 1)
	workChan := make(chan ElasticCredential, maxConcurrent)
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
					result := tryElasticCredential(scanCtx, info, credential, timeoutSeconds, maxRetries)
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
		Common.LogDebug("Elasticsearch并发扫描全局超时")
		scanCancel() // 确保取消所有未完成工作
		return nil
	}
}

// tryElasticCredential 尝试单个Elasticsearch凭据
func tryElasticCredential(ctx context.Context, info *Common.HostInfo, credential ElasticCredential, timeoutSeconds int64, maxRetries int) *ElasticScanResult {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return &ElasticScanResult{
				Success:    false,
				Error:      fmt.Errorf("全局超时"),
				Credential: credential,
			}
		default:
			if retry > 0 {
				Common.LogDebug(fmt.Sprintf("第%d次重试: %s:%s", retry+1, credential.Username, credential.Password))
				time.Sleep(500 * time.Millisecond) // 重试前等待
			}

			success, err := ElasticConn(ctx, info, credential.Username, credential.Password, timeoutSeconds)
			if success {
				isUnauth := credential.Username == "" && credential.Password == ""
				return &ElasticScanResult{
					Success:    true,
					IsUnauth:   isUnauth,
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

	return &ElasticScanResult{
		Success:    false,
		Error:      lastErr,
		Credential: credential,
	}
}

// ElasticConn 尝试Elasticsearch连接
func ElasticConn(ctx context.Context, info *Common.HostInfo, user string, pass string, timeoutSeconds int64) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(timeoutSeconds) * time.Second

	// 创建带有超时的HTTP客户端
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	baseURL := fmt.Sprintf("http://%s:%s", host, port)

	// 使用上下文创建请求
	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/_cat/indices", nil)
	if err != nil {
		return false, err
	}

	if user != "" || pass != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Add("Authorization", "Basic "+auth)
	}

	// 创建结果通道
	resultChan := make(chan struct {
		success bool
		err     error
	}, 1)

	// 在协程中执行HTTP请求
	go func() {
		resp, err := client.Do(req)
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
		defer resp.Body.Close()

		select {
		case <-ctx.Done():
		case resultChan <- struct {
			success bool
			err     error
		}{resp.StatusCode == 200, nil}:
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

// saveElasticResult 保存Elasticsearch扫描结果
func saveElasticResult(info *Common.HostInfo, target string, credential ElasticCredential, isUnauth bool) {
	var successMsg string
	var details map[string]interface{}

	if isUnauth {
		successMsg = fmt.Sprintf("Elasticsearch服务 %s 无需认证", target)
		details = map[string]interface{}{
			"port":    info.Ports,
			"service": "elasticsearch",
			"type":    "unauthorized-access",
		}
	} else {
		successMsg = fmt.Sprintf("Elasticsearch服务 %s 爆破成功 用户名: %v 密码: %v",
			target, credential.Username, credential.Password)
		details = map[string]interface{}{
			"port":     info.Ports,
			"service":  "elasticsearch",
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
