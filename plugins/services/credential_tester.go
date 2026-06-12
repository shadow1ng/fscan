package services

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

/*
credential_tester.go - 统一凭据测试框架

解决的问题：
1. goroutine 泄漏：context 取消时正确清理资源
2. 效率问题：找到成功凭据后通知其他 worker 停止
3. 代码重复：20+ 插件共享同一套并发测试逻辑

设计原则：
- 简洁：只提供必要的抽象
- 安全：正确处理 context 取消和资源清理
- 通用：适用于所有凭据测试场景
*/

// =============================================================================
// 错误类型定义
// =============================================================================

// ErrorType 错误分类
type ErrorType int

const (
	ErrorTypeAuth    ErrorType = iota // 认证错误 - 密码错误，不重试
	ErrorTypeNetwork                  // 网络错误 - 连接问题，可重试
	ErrorTypeUnknown                  // 未知错误
)

// =============================================================================
// 核心类型定义
// =============================================================================

// AuthResult 认证结果
type AuthResult struct {
	Success   bool
	Conn      io.Closer // 成功时的连接，需要调用者关闭
	ErrorType ErrorType
	Error     error
}

// AuthFunc 认证函数类型
// 执行实际的连接和认证操作
// 返回的 Conn 在成功时由调用者负责关闭
type AuthFunc func(ctx context.Context, cred Credential) *AuthResult

// ErrorClassifier 错误分类函数
type ErrorClassifier func(err error) ErrorType

var authCleanupWaitNanos int64 = int64(2 * time.Second)

func authCleanupWait() time.Duration {
	return time.Duration(atomic.LoadInt64(&authCleanupWaitNanos))
}

// =============================================================================
// 单凭据测试（解决 goroutine 泄漏）
// =============================================================================

// TestSingleCredential 安全地测试单个凭据
// 正确处理 context 取消时的资源清理
func TestSingleCredential(ctx context.Context, cred Credential, authFn AuthFunc) *AuthResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if authFn == nil {
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeUnknown,
			Error:     fmt.Errorf("auth function is nil"),
		}
	}
	if err := ctx.Err(); err != nil {
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeNetwork,
			Error:     err,
		}
	}

	resultChan := make(chan *AuthResult, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				resultChan <- &AuthResult{
					Success:   false,
					ErrorType: ErrorTypeUnknown,
					Error:     fmt.Errorf("auth function panic: %v", r),
				}
			}
		}()
		result := authFn(ctx, cred)
		resultChan <- result
	}()

	select {
	case result := <-resultChan:
		return result
	case <-ctx.Done():
		// context 被取消后只做有界等待，避免 authFn 卡死时清理 goroutine 也永久泄漏。
		go func() {
			timer := time.NewTimer(authCleanupWait())
			defer timer.Stop()

			select {
			case result := <-resultChan:
				if result != nil && result.Conn != nil {
					_ = result.Conn.Close()
				}
			case <-timer.C:
			}
		}()
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeNetwork,
			Error:     ctx.Err(),
		}
	}
}

// =============================================================================
// 并发凭据测试（解决效率问题）
// =============================================================================

// ConcurrentTestConfig 并发测试配置
type ConcurrentTestConfig struct {
	Concurrency             int           // 并发数，默认 10
	MaxRetries              int           // 最大重试次数，默认 3
	RetryDelay              time.Duration // 重试延迟，默认 1s
	MaxConsecutiveNetErrors int           // 连续网络错误阈值，超过则认为目标不可达，默认 5
	TargetAddr              string        // 目标地址 host:port，用于 TCP 预检（可选）
	UseProxy                bool          // 代理模式下跳过直连 TCP 预检
}

func normalizeConcurrentTestConfig(testConfig ConcurrentTestConfig) ConcurrentTestConfig {
	if testConfig.Concurrency <= 0 {
		testConfig.Concurrency = 10
	}
	if testConfig.MaxRetries <= 0 {
		testConfig.MaxRetries = 3
	}
	if testConfig.RetryDelay <= 0 {
		testConfig.RetryDelay = time.Second
	}
	if testConfig.MaxConsecutiveNetErrors <= 0 {
		testConfig.MaxConsecutiveNetErrors = 5
	}
	return testConfig
}

// DefaultConcurrentTestConfig 默认配置
func DefaultConcurrentTestConfig(config *common.Config) ConcurrentTestConfig {
	concurrency := config.ModuleThreadNum
	if concurrency <= 0 {
		concurrency = 10
	}
	maxRetries := config.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}
	return ConcurrentTestConfig{
		Concurrency:             concurrency,
		MaxRetries:              maxRetries,
		RetryDelay:              time.Second,
		MaxConsecutiveNetErrors: 5,
		UseProxy:                config.Network.Socks5Proxy != "" || config.Network.HTTPProxy != "",
	}
}

// DefaultConcurrentTestConfigWithTarget 带目标预检的默认配置
func DefaultConcurrentTestConfigWithTarget(config *common.Config, info *common.HostInfo) ConcurrentTestConfig {
	cfg := DefaultConcurrentTestConfig(config)
	cfg.TargetAddr = info.Target()
	return cfg
}

// TestCredentialsConcurrently 并发测试多个凭据
// 找到成功凭据后立即通知其他 worker 停止
func TestCredentialsConcurrently(
	ctx context.Context,
	credentials []Credential,
	authFn AuthFunc,
	serviceName string,
	testConfig ConcurrentTestConfig,
) *ScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: serviceName,
			Error:   fmt.Errorf("%s", i18n.GetText("service_no_test_creds")),
		}
	}
	testConfig = normalizeConcurrentTestConfig(testConfig)

	// TCP 预检：快速验证目标可达，避免对不可达目标浪费全部凭据尝试
	// 代理模式下跳过：net.DialTimeout 直连无法到达代理后的内网目标
	if testConfig.TargetAddr != "" && !testConfig.UseProxy {
		dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
		defer dialCancel()

		var dialer net.Dialer
		preConn, err := dialer.DialContext(dialCtx, "tcp", testConfig.TargetAddr)
		if err != nil {
			return &ScanResult{
				Success: false,
				Service: serviceName,
				Error:   fmt.Errorf(i18n.Tr("service_target_unreachable", "%w"), err),
			}
		}
		_ = preConn.Close()
	}

	// 调整并发数
	concurrency := testConfig.Concurrency
	if concurrency > len(credentials) {
		concurrency = len(credentials)
	}

	// 创建可取消的 context - 找到成功后取消其他 worker
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 通道（buffer 设为 concurrency+1 避免 worker 阻塞在发送上）
	credChan := make(chan Credential, len(credentials))
	resultChan := make(chan *ScanResult, concurrency+1)

	// 发送所有凭据
	for _, cred := range credentials {
		credChan <- cred
	}
	close(credChan)

	// 启动 workers
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			workerTestCredentials(cancelCtx, credChan, resultChan, authFn, serviceName, testConfig)
		}()
	}

	// 等待所有 worker 完成后关闭结果通道
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 收集结果
	for result := range resultChan {
		if result != nil && result.Success {
			cancel() // 通知其他 worker 停止
			return result
		}
	}

	// 检查父 context 是否被取消
	if ctx.Err() != nil {
		return &ScanResult{
			Success: false,
			Service: serviceName,
			Error:   ctx.Err(),
		}
	}

	return &ScanResult{
		Type:    plugins.ResultTypeCredential, // 标记这是凭据测试结果
		Success: false,
		Service: serviceName,
		Error:   fmt.Errorf("%s", i18n.GetText("service_no_weak_pass")),
	}
}

// workerTestCredentials worker 协程
func workerTestCredentials(
	ctx context.Context,
	credChan <-chan Credential,
	resultChan chan<- *ScanResult,
	authFn AuthFunc,
	serviceName string,
	testConfig ConcurrentTestConfig,
) {
	consecutiveNetErrors := 0

	for cred := range credChan {
		// 检查是否应该停止
		select {
		case <-ctx.Done():
			return
		default:
		}

		// 连续网络错误达到阈值，目标可能不可达，提前退出
		if consecutiveNetErrors >= testConfig.MaxConsecutiveNetErrors {
			return
		}

		// 带重试的凭据测试
		result, errType := testCredentialWithRetry(ctx, cred, authFn, serviceName, testConfig)
		if result != nil && result.Success {
			resultChan <- result
			return
		}

		// 跟踪连续网络错误
		if errType == ErrorTypeNetwork {
			consecutiveNetErrors++
		} else {
			consecutiveNetErrors = 0
		}
	}
}

// testCredentialWithRetry 带重试的凭据测试
func testCredentialWithRetry(
	ctx context.Context,
	cred Credential,
	authFn AuthFunc,
	serviceName string,
	testConfig ConcurrentTestConfig,
) (*ScanResult, ErrorType) {
	for attempt := 0; attempt < testConfig.MaxRetries; attempt++ {
		// 检查是否应该停止
		select {
		case <-ctx.Done():
			return nil, ErrorTypeUnknown
		default:
		}

		// 测试凭据
		result := TestSingleCredential(ctx, cred, authFn)
		if result == nil {
			result = &AuthResult{
				Success:   false,
				ErrorType: ErrorTypeUnknown,
				Error:     fmt.Errorf("auth function returned nil result"),
			}
		}

		if result.Success {
			if result.Conn != nil {
				_ = result.Conn.Close()
			}
			return &ScanResult{
				Type:     plugins.ResultTypeCredential,
				Success:  true,
				Service:  serviceName,
				Username: cred.Username,
				Password: cred.Password,
			}, ErrorTypeUnknown
		}

		// 根据错误类型决定是否重试
		switch result.ErrorType {
		case ErrorTypeAuth:
			// 认证错误（密码错误），不重试
			return nil, result.ErrorType
		case ErrorTypeNetwork, ErrorTypeUnknown:
			// 网络错误或未知错误，可以重试（可能是服务端限流等临时问题）
			if attempt < testConfig.MaxRetries-1 {
				timer := time.NewTimer(testConfig.RetryDelay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil, result.ErrorType
				case <-timer.C:
				}
			}
		}
	}
	return nil, ErrorTypeNetwork
}

// =============================================================================
// 通用错误分类
// =============================================================================

// CommonNetworkErrors 常见的网络错误关键词
var CommonNetworkErrors = []string{
	"connection reset by peer",
	"connection refused",
	"timeout",
	"network unreachable",
	"broken pipe",
	"no route to host",
	"connection timed out",
	"i/o timeout",
	"connection aborted",
	"host is down",
}

// CommonAuthErrors 常见的认证错误关键词
var CommonAuthErrors = []string{
	"unable to authenticate",
	"authentication failed",
	"permission denied",
	"access denied",
	"invalid credentials",
	"bad password",
	"login incorrect",
}

// ClassifyError 通用错误分类函数
func ClassifyError(err error, authKeywords, networkKeywords []string) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	errStr := err.Error()

	// 先检查认证错误
	for _, keyword := range authKeywords {
		if containsIgnoreCase(errStr, keyword) {
			return ErrorTypeAuth
		}
	}

	// 再检查网络错误
	for _, keyword := range networkKeywords {
		if containsIgnoreCase(errStr, keyword) {
			return ErrorTypeNetwork
		}
	}

	return ErrorTypeUnknown
}

// containsIgnoreCase 忽略大小写的字符串包含检查
func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(substr) == 0 ||
			findIgnoreCase(s, substr) >= 0)
}

// findIgnoreCase 忽略大小写查找子串
func findIgnoreCase(s, substr string) int {
	if len(substr) == 0 {
		return 0
	}
	if len(substr) > len(s) {
		return -1
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if matchIgnoreCase(s[i:i+len(substr)], substr) {
			return i
		}
	}
	return -1
}

// matchIgnoreCase 忽略大小写比较
func matchIgnoreCase(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// =============================================================================
// 通用数据库连接包装
// =============================================================================

// SQLDBWrapper 包装 sql.DB 以实现 io.Closer
// 用于 MySQL、PostgreSQL、MSSQL、Oracle 等数据库插件的连接返回
type SQLDBWrapper struct {
	*sql.DB
}

func (w *SQLDBWrapper) Close() error {
	return w.DB.Close()
}
