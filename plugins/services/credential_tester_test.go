package services

import (
	"context"
	"errors"
	"io"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shadow1ng/fscan/common"
)

/*
credential_tester_test.go - 凭据测试框架高价值测试

测试重点：
1. 错误分类准确性 - 认证错误 vs 网络错误，影响重试策略
2. 字符串函数边界情况 - 空串、大小写、部分匹配
3. 并发安全性 - 早期退出、资源清理
4. context 取消处理 - 不泄漏 goroutine

不测试：
- 具体的服务连接（那是各插件的职责）
- 配置解析
*/

// =============================================================================
// 错误分类测试
// =============================================================================

// TestClassifyError_AuthErrors 测试认证错误识别
func TestClassifyError_AuthErrors(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected ErrorType
	}{
		{"认证失败", errors.New("authentication failed"), ErrorTypeAuth},
		{"权限拒绝", errors.New("permission denied"), ErrorTypeAuth},
		{"访问拒绝", errors.New("Access Denied"), ErrorTypeAuth},
		{"密码错误", errors.New("Bad Password"), ErrorTypeAuth},
		{"登录错误", errors.New("LOGIN INCORRECT"), ErrorTypeAuth},
		{"凭据无效", errors.New("Invalid Credentials"), ErrorTypeAuth},
		{"无法认证", errors.New("unable to authenticate"), ErrorTypeAuth},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ClassifyError(tc.err, CommonAuthErrors, CommonNetworkErrors)
			if result != tc.expected {
				t.Errorf("期望 ErrorTypeAuth, 实际 %v", result)
			}
		})
	}
}

// TestClassifyError_NetworkErrors 测试网络错误识别
func TestClassifyError_NetworkErrors(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected ErrorType
	}{
		{"连接重置", errors.New("connection reset by peer"), ErrorTypeNetwork},
		{"连接拒绝", errors.New("connection refused"), ErrorTypeNetwork},
		{"超时", errors.New("timeout"), ErrorTypeNetwork},
		{"网络不可达", errors.New("network unreachable"), ErrorTypeNetwork},
		{"管道破裂", errors.New("broken pipe"), ErrorTypeNetwork},
		{"无路由", errors.New("no route to host"), ErrorTypeNetwork},
		{"IO超时", errors.New("i/o timeout"), ErrorTypeNetwork},
		{"主机宕机", errors.New("host is down"), ErrorTypeNetwork},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ClassifyError(tc.err, CommonAuthErrors, CommonNetworkErrors)
			if result != tc.expected {
				t.Errorf("期望 ErrorTypeNetwork, 实际 %v", result)
			}
		})
	}
}

// TestClassifyError_Priority 测试错误分类优先级
//
// 如果错误同时包含认证和网络关键词，认证应该优先
func TestClassifyError_Priority(t *testing.T) {
	// 错误信息同时包含 "authentication failed" 和 "timeout"
	mixedErr := errors.New("authentication failed due to timeout")
	result := ClassifyError(mixedErr, CommonAuthErrors, CommonNetworkErrors)

	// 认证错误应该优先
	if result != ErrorTypeAuth {
		t.Errorf("期望 ErrorTypeAuth（认证优先），实际 %v", result)
	}
}

// TestClassifyError_EdgeCases 边界情况
func TestClassifyError_EdgeCases(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		result := ClassifyError(nil, CommonAuthErrors, CommonNetworkErrors)
		if result != ErrorTypeUnknown {
			t.Errorf("nil error 应该返回 Unknown, 实际 %v", result)
		}
	})

	t.Run("未知错误", func(t *testing.T) {
		result := ClassifyError(errors.New("something weird happened"), CommonAuthErrors, CommonNetworkErrors)
		if result != ErrorTypeUnknown {
			t.Errorf("未知错误应该返回 Unknown, 实际 %v", result)
		}
	})

	t.Run("空关键词列表", func(t *testing.T) {
		result := ClassifyError(errors.New("authentication failed"), nil, nil)
		if result != ErrorTypeUnknown {
			t.Errorf("空关键词列表应该返回 Unknown, 实际 %v", result)
		}
	})
}

// =============================================================================
// 字符串函数测试
// =============================================================================

// TestContainsIgnoreCase 忽略大小写包含检查
func TestContainsIgnoreCase(t *testing.T) {
	testCases := []struct {
		s        string
		substr   string
		expected bool
	}{
		// 正常情况
		{"hello world", "world", true},
		{"HELLO WORLD", "world", true},
		{"hello world", "WORLD", true},
		{"Hello World", "LLO", true},

		// 不包含
		{"hello world", "xyz", false},
		{"hello", "hello world", false},

		// 边界情况
		{"", "", true},
		{"hello", "", true},
		{"", "a", false},
		{"a", "a", true},
	}

	for _, tc := range testCases {
		t.Run(tc.s+"_"+tc.substr, func(t *testing.T) {
			result := containsIgnoreCase(tc.s, tc.substr)
			if result != tc.expected {
				t.Errorf("containsIgnoreCase(%q, %q) = %v, 期望 %v",
					tc.s, tc.substr, result, tc.expected)
			}
		})
	}
}

// TestMatchIgnoreCase 忽略大小写精确匹配
func TestMatchIgnoreCase(t *testing.T) {
	testCases := []struct {
		a, b     string
		expected bool
	}{
		{"hello", "hello", true},
		{"HELLO", "hello", true},
		{"Hello", "hElLo", true},
		{"hello", "world", false},
		{"hello", "hell", false},
		{"", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.a+"_"+tc.b, func(t *testing.T) {
			result := matchIgnoreCase(tc.a, tc.b)
			if result != tc.expected {
				t.Errorf("matchIgnoreCase(%q, %q) = %v, 期望 %v",
					tc.a, tc.b, result, tc.expected)
			}
		})
	}
}

// =============================================================================
// 并发测试
// =============================================================================

func setAuthCleanupWaitForTest(wait time.Duration) func() {
	oldWait := atomic.LoadInt64(&authCleanupWaitNanos)
	atomic.StoreInt64(&authCleanupWaitNanos, int64(wait))
	return func() { atomic.StoreInt64(&authCleanupWaitNanos, oldWait) }
}

func TestDefaultConcurrentTestConfigUsesConfigRetries(t *testing.T) {
	cfg := DefaultConcurrentTestConfig(&common.Config{
		ModuleThreadNum: 7,
		MaxRetries:      5,
	})

	if cfg.Concurrency != 7 {
		t.Fatalf("Concurrency = %d, want 7", cfg.Concurrency)
	}
	if cfg.MaxRetries != 5 {
		t.Fatalf("MaxRetries = %d, want config MaxRetries 5", cfg.MaxRetries)
	}
}

func TestDefaultConcurrentTestConfigRetriesFallback(t *testing.T) {
	cfg := DefaultConcurrentTestConfig(&common.Config{
		ModuleThreadNum: 0,
		MaxRetries:      0,
	})

	if cfg.Concurrency != 10 {
		t.Fatalf("Concurrency = %d, want fallback 10", cfg.Concurrency)
	}
	if cfg.MaxRetries != 3 {
		t.Fatalf("MaxRetries = %d, want fallback 3", cfg.MaxRetries)
	}
}

func TestTestCredentialsConcurrently_ZeroValueConfigStillRuns(t *testing.T) {
	var calls atomic.Int32
	authFn := func(ctx context.Context, cred Credential) *AuthResult {
		calls.Add(1)
		return &AuthResult{Success: true}
	}

	result := TestCredentialsConcurrently(context.Background(), []Credential{{Username: "u", Password: "p"}}, authFn, "test", ConcurrentTestConfig{})
	if !result.Success {
		t.Fatalf("zero-value config should still test credentials: %v", result.Error)
	}
	if calls.Load() != 1 {
		t.Fatalf("authFn calls = %d, want 1", calls.Load())
	}
}

func TestTestCredentialsConcurrently_PrecheckHonorsCanceledContext(t *testing.T) {
	var calls atomic.Int32
	authFn := func(ctx context.Context, cred Credential) *AuthResult {
		calls.Add(1)
		return &AuthResult{Success: false}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	result := TestCredentialsConcurrently(ctx, []Credential{{Username: "u", Password: "p"}}, authFn, "test", ConcurrentTestConfig{
		Concurrency: 1,
		MaxRetries:  1,
		TargetAddr:  "203.0.113.1:65000",
	})

	if result.Success {
		t.Fatal("canceled context should not return success")
	}
	if calls.Load() != 0 {
		t.Fatalf("authFn calls = %d, want 0 when precheck context is canceled", calls.Load())
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("precheck ignored canceled context, elapsed=%v", elapsed)
	}
}

// mockConn 模拟连接
type mockConn struct {
	closed atomic.Bool
}

func (c *mockConn) Close() error {
	c.closed.Store(true)
	return nil
}

// TestTestCredentialsConcurrently_EarlyExit 测试找到成功凭据后早期退出
func TestTestCredentialsConcurrently_EarlyExit(t *testing.T) {
	// 准备100个凭据，第5个会成功
	credentials := make([]Credential, 100)
	for i := range credentials {
		credentials[i] = Credential{Username: "user", Password: "pass" + string(rune('0'+i%10))}
	}

	var testedCount atomic.Int32
	successPassword := "pass5"

	// 模拟认证函数
	authFn := func(ctx context.Context, cred Credential) *AuthResult {
		testedCount.Add(1)
		time.Sleep(10 * time.Millisecond) // 模拟网络延迟

		if cred.Password == successPassword {
			return &AuthResult{
				Success: true,
				Conn:    &mockConn{},
			}
		}
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeAuth,
		}
	}

	config := ConcurrentTestConfig{
		Concurrency: 5,
		MaxRetries:  1,
		RetryDelay:  time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "test", config)

	if !result.Success {
		t.Fatal("应该找到成功的凭据")
	}

	// 验证早期退出：不应该测试所有100个凭据
	tested := testedCount.Load()
	if tested >= 100 {
		t.Errorf("早期退出失败：测试了 %d 个凭据（应该远少于100）", tested)
	}
	t.Logf("测试了 %d 个凭据后找到成功凭据", tested)
}

// TestTestCredentialsConcurrently_EmptyCredentials 空凭据测试
func TestTestCredentialsConcurrently_EmptyCredentials(t *testing.T) {
	authFn := func(ctx context.Context, cred Credential) *AuthResult {
		return &AuthResult{Success: false}
	}

	config := ConcurrentTestConfig{
		Concurrency: 5,
		MaxRetries:  1,
	}

	result := TestCredentialsConcurrently(context.Background(), nil, authFn, "test", config)

	if result.Success {
		t.Error("空凭据不应该返回成功")
	}
	if result.Error == nil {
		t.Error("空凭据应该返回错误")
	}
}

func TestTestCredentialsConcurrently_ProxySkipsDirectPrecheck(t *testing.T) {
	var calls atomic.Int32
	authFn := func(ctx context.Context, cred Credential) *AuthResult {
		calls.Add(1)
		return &AuthResult{
			Success: true,
			Conn:    &mockConn{},
		}
	}

	config := ConcurrentTestConfig{
		Concurrency: 1,
		MaxRetries:  1,
		RetryDelay:  time.Millisecond,
		TargetAddr:  "127.0.0.1:1",
		UseProxy:    true,
	}

	result := TestCredentialsConcurrently(context.Background(), []Credential{{Username: "u", Password: "p"}}, authFn, "test", config)
	if !result.Success {
		t.Fatalf("proxy mode should skip direct precheck: %v", result.Error)
	}
	if calls.Load() == 0 {
		t.Fatal("auth function was not called")
	}
}

// TestTestCredentialsConcurrently_ContextCancel 测试context取消
func TestTestCredentialsConcurrently_ContextCancel(t *testing.T) {
	credentials := make([]Credential, 100)
	for i := range credentials {
		credentials[i] = Credential{Username: "user", Password: "pass"}
	}

	authFn := func(ctx context.Context, cred Credential) *AuthResult {
		// 模拟慢速认证
		select {
		case <-ctx.Done():
			return &AuthResult{
				Success:   false,
				ErrorType: ErrorTypeNetwork,
				Error:     ctx.Err(),
			}
		case <-time.After(100 * time.Millisecond):
			return &AuthResult{
				Success:   false,
				ErrorType: ErrorTypeAuth,
			}
		}
	}

	config := ConcurrentTestConfig{
		Concurrency: 5,
		MaxRetries:  1,
	}

	// 50ms后取消
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	result := TestCredentialsConcurrently(ctx, credentials, authFn, "test", config)

	if result.Success {
		t.Error("context取消后不应该返回成功")
	}
}

func TestTestCredentialsConcurrently_CancelWithStuckAuthReturnsPromptly(t *testing.T) {
	defer setAuthCleanupWaitForTest(20 * time.Millisecond)()

	credentials := make([]Credential, 10)
	for i := range credentials {
		credentials[i] = Credential{Username: "user", Password: "pass"}
	}

	authStarted := make(chan struct{}, len(credentials))
	releaseAuth := make(chan struct{})
	authFn := func(ctx context.Context, cred Credential) *AuthResult {
		authStarted <- struct{}{}
		<-releaseAuth
		return &AuthResult{Success: false, ErrorType: ErrorTypeNetwork}
	}

	config := ConcurrentTestConfig{
		Concurrency: 3,
		MaxRetries:  1,
		RetryDelay:  time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *ScanResult, 1)
	go func() {
		done <- TestCredentialsConcurrently(ctx, credentials, authFn, "test", config)
	}()

	for i := 0; i < config.Concurrency; i++ {
		select {
		case <-authStarted:
		case <-time.After(time.Second):
			close(releaseAuth)
			t.Fatalf("authFn started %d workers, want %d", i, config.Concurrency)
		}
	}

	start := time.Now()
	cancel()
	select {
	case result := <-done:
		close(releaseAuth)
		if result.Success {
			t.Fatal("context取消后不应该返回成功")
		}
		if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
			t.Fatalf("取消后返回过慢: %v", elapsed)
		}
	case <-time.After(time.Second):
		close(releaseAuth)
		t.Fatal("authFn 卡住时并发测试没有及时返回")
	}
}

// =============================================================================
// 单凭据测试
// =============================================================================

// TestTestSingleCredential_Success 测试成功情况
func TestTestSingleCredential_Success(t *testing.T) {
	conn := &mockConn{}
	authFn := func(ctx context.Context, cred Credential) *AuthResult {
		return &AuthResult{
			Success: true,
			Conn:    conn,
		}
	}

	cred := Credential{Username: "admin", Password: "admin"}
	result := TestSingleCredential(context.Background(), cred, authFn)

	if !result.Success {
		t.Error("应该返回成功")
	}
	if result.Conn == nil {
		t.Error("成功时应该返回连接")
	}
}

func TestTestSingleCredential_CanceledContextSkipsAuth(t *testing.T) {
	var calls atomic.Int32
	authFn := func(ctx context.Context, cred Credential) *AuthResult {
		calls.Add(1)
		return &AuthResult{Success: true}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := TestSingleCredential(ctx, Credential{Username: "admin", Password: "admin"}, authFn)
	if result.Success {
		t.Fatal("canceled context should not return success")
	}
	if calls.Load() != 0 {
		t.Fatalf("authFn calls = %d, want 0", calls.Load())
	}
}

func TestTestSingleCredential_NilAuthFunc(t *testing.T) {
	result := TestSingleCredential(context.Background(), Credential{Username: "admin", Password: "admin"}, nil)
	if result.Success {
		t.Fatal("nil authFn should not return success")
	}
	if result.Error == nil {
		t.Fatal("nil authFn should return an error")
	}
}

func TestTestSingleCredential_RecoverAuthPanic(t *testing.T) {
	authFn := func(ctx context.Context, cred Credential) *AuthResult {
		panic("boom")
	}

	result := TestSingleCredential(context.Background(), Credential{Username: "admin", Password: "admin"}, authFn)
	if result.Success {
		t.Fatal("panic authFn should not return success")
	}
	if result.Error == nil {
		t.Fatal("panic authFn should return an error")
	}
}

// TestTestSingleCredential_ContextCancel 测试context取消时的资源清理
func TestTestSingleCredential_ContextCancel(t *testing.T) {
	conn := &mockConn{}
	authStarted := make(chan struct{})

	authFn := func(ctx context.Context, cred Credential) *AuthResult {
		close(authStarted)
		// 模拟慢速认证
		time.Sleep(200 * time.Millisecond)
		return &AuthResult{
			Success: true,
			Conn:    conn,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	// 启动认证后立即取消
	go func() {
		<-authStarted
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	cred := Credential{Username: "admin", Password: "admin"}
	result := TestSingleCredential(ctx, cred, authFn)

	// 应该返回失败（context被取消）
	if result.Success {
		t.Error("context取消后不应该返回成功")
	}

	// 等待清理协程运行
	time.Sleep(300 * time.Millisecond)

	// 连接应该被清理协程关闭
	if !conn.closed.Load() {
		t.Error("连接应该被清理协程关闭")
	}
}

func TestTestSingleCredential_ContextCancelCleanupIsBounded(t *testing.T) {
	defer setAuthCleanupWaitForTest(20 * time.Millisecond)()

	authStarted := make(chan struct{})
	releaseAuth := make(chan struct{})
	authFn := func(ctx context.Context, cred Credential) *AuthResult {
		close(authStarted)
		<-releaseAuth
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-authStarted
		cancel()
	}()

	before := runtime.NumGoroutine()
	result := TestSingleCredential(ctx, Credential{Username: "admin", Password: "admin"}, authFn)
	if result.Success {
		t.Error("context取消后不应该返回成功")
	}

	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()
	close(releaseAuth)

	if after > before+1 {
		t.Fatalf("清理 goroutine 疑似泄漏: before=%d after=%d", before, after)
	}
}

// =============================================================================
// 重试逻辑测试
// =============================================================================

// TestRetryLogic_NetworkErrorRetries 网络错误应该重试
func TestRetryLogic_NetworkErrorRetries(t *testing.T) {
	var attempts atomic.Int32

	authFn := func(ctx context.Context, cred Credential) *AuthResult {
		count := attempts.Add(1)
		if count < 3 {
			return &AuthResult{
				Success:   false,
				ErrorType: ErrorTypeNetwork,
				Error:     errors.New("connection timeout"),
			}
		}
		// 第3次成功
		return &AuthResult{
			Success: true,
			Conn:    &mockConn{},
		}
	}

	cred := Credential{Username: "admin", Password: "admin"}
	config := ConcurrentTestConfig{
		Concurrency: 1,
		MaxRetries:  3,
		RetryDelay:  time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := TestCredentialsConcurrently(ctx, []Credential{cred}, authFn, "test", config)

	if !result.Success {
		t.Error("网络错误重试后应该成功")
	}
	if attempts.Load() != 3 {
		t.Errorf("应该尝试3次，实际 %d 次", attempts.Load())
	}
}

func TestRetryLogic_SuccessWithoutConn(t *testing.T) {
	var attempts atomic.Int32
	authFn := func(ctx context.Context, cred Credential) *AuthResult {
		attempts.Add(1)
		return &AuthResult{Success: true}
	}

	result := TestCredentialsConcurrently(context.Background(), []Credential{{Username: "admin", Password: "admin"}}, authFn, "test", ConcurrentTestConfig{
		Concurrency: 1,
		MaxRetries:  3,
	})
	if !result.Success {
		t.Fatalf("success result without Conn should be accepted: %v", result.Error)
	}
	if attempts.Load() != 1 {
		t.Fatalf("attempts = %d, want 1", attempts.Load())
	}
}

func TestRetryLogic_NilAuthResultDoesNotPanic(t *testing.T) {
	var attempts atomic.Int32
	authFn := func(ctx context.Context, cred Credential) *AuthResult {
		attempts.Add(1)
		return nil
	}

	result := TestCredentialsConcurrently(context.Background(), []Credential{{Username: "admin", Password: "admin"}}, authFn, "test", ConcurrentTestConfig{
		Concurrency: 1,
		MaxRetries:  2,
		RetryDelay:  time.Millisecond,
	})
	if result.Success {
		t.Fatal("nil auth result should not return success")
	}
	if attempts.Load() != 2 {
		t.Fatalf("attempts = %d, want 2", attempts.Load())
	}
}

// TestRetryLogic_AuthErrorNoRetry 认证错误不应该重试
func TestRetryLogic_AuthErrorNoRetry(t *testing.T) {
	var attempts atomic.Int32

	authFn := func(ctx context.Context, cred Credential) *AuthResult {
		attempts.Add(1)
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeAuth,
			Error:     errors.New("authentication failed"),
		}
	}

	cred := Credential{Username: "admin", Password: "wrong"}
	config := ConcurrentTestConfig{
		Concurrency: 1,
		MaxRetries:  3,
		RetryDelay:  time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = TestCredentialsConcurrently(ctx, []Credential{cred}, authFn, "test", config)

	// 认证错误只应该尝试1次
	if attempts.Load() != 1 {
		t.Errorf("认证错误不应该重试，实际尝试了 %d 次", attempts.Load())
	}
}

// 确保 mockConn 实现 io.Closer 接口
var _ io.Closer = (*mockConn)(nil)
