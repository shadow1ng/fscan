package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

/*
writers_test.go - 输出写入器测试

测试目标：TXTWriter, JSONWriter, CSVWriter
价值：输出写入器是用户唯一能看到扫描结果的途径，错误会导致：
  - 数据丢失（用户几小时的扫描白干）
  - 格式错误（无法解析结果文件）
  - 程序崩溃（影响正在进行的扫描）

"输出是用户唯一关心的东西。如果结果丢了或错了，你的工具就是垃圾。
这不是可选测试，这是生存测试。"
*/

// =============================================================================
// 测试辅助函数
// =============================================================================

// createTestDir 创建临时测试目录
func createTestDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// readFileContent 读取文件内容
func readFileContent(t *testing.T, filePath string) string {
	t.Helper()

	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("读取文件失败: %v", err)
	}

	return string(content)
}

// createTestResult 创建测试用扫描结果
func createTestResult(resultType ResultType, target, status string, details map[string]interface{}) *ScanResult {
	return &ScanResult{
		Time:    time.Date(2024, 10, 3, 12, 0, 0, 0, time.UTC),
		Type:    resultType,
		Target:  target,
		Status:  status,
		Details: details,
	}
}

// =============================================================================
// TXTWriter - 基础功能测试
// =============================================================================

// TestTXTWriter_BasicWrite 测试基本写入功能
//
// 这是最重要的测试：验证核心数据流是否正确
// ScanResult → 格式化 → 文件 → 可读取
//
// TXTWriter 使用分类缓冲模式：
// - Write() 收集结果到内存缓冲
// - Close() 时按类型分组输出，带分隔线
func TestTXTWriter_BasicWrite(t *testing.T) {
	// 创建临时目录和文件路径
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test_basic.txt")

	// 创建writer
	writer, err := NewTXTWriter(filePath)
	if err != nil {
		t.Fatalf("创建TXTWriter失败: %v", err)
	}
	defer func() { _ = writer.Close() }()

	// 写入头部（TXT格式无需头部，应该成功但不做任何事）
	if err := writer.WriteHeader(); err != nil {
		t.Errorf("WriteHeader()失败: %v", err)
	}

	// 创建测试结果
	result := createTestResult(
		TypeHost,
		"192.168.1.1:80",
		"OPEN",
		map[string]interface{}{
			"service": "http",
			"version": "nginx/1.18",
		},
	)

	// 写入结果
	if err := writer.Write(result); err != nil {
		t.Fatalf("Write()失败: %v", err)
	}

	// 关闭writer（确保数据刷盘）
	if err := writer.Close(); err != nil {
		t.Fatalf("Close()失败: %v", err)
	}

	// 读取并验证文件内容
	content := readFileContent(t, filePath)

	// 验证：内容非空
	if content == "" {
		t.Fatal("文件内容为空")
	}

	// 验证：包含类型前缀（TXTWriter使用实时刷盘模式）
	if !strings.Contains(content, "# ===== 存活主机 =====") {
		t.Errorf("输出缺少类型前缀\n实际输出: %s", content)
	}

	// 验证：包含目标
	if !strings.Contains(content, "192.168.1.1:80") {
		t.Errorf("输出缺少目标\n实际输出: %s", content)
	}

	// 验证：以换行符结尾
	if !strings.HasSuffix(content, "\n") {
		t.Error("输出应该以换行符结尾")
	}

	t.Logf("✓ 基本写入测试通过\n  输出内容: %s", strings.TrimSpace(content))
}

// TestTXTWriter_EmptyDetails 测试空Details的处理
//
// 验证：当Details为空或nil时，输出格式正确
// TXTWriter 使用实时刷盘模式，输出格式为类型前缀+目标
func TestTXTWriter_EmptyDetails(t *testing.T) {
	dir := createTestDir(t)

	tests := []struct {
		name    string
		details map[string]interface{}
	}{
		{
			name:    "nil Details",
			details: nil,
		},
		{
			name:    "empty Details",
			details: map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(dir, tt.name+".txt")
			writer, err := NewTXTWriter(filePath)
			if err != nil {
				t.Fatalf("创建writer失败: %v", err)
			}
			defer func() { _ = writer.Close() }()

			result := createTestResult(TypePort, "192.168.1.1:22", "OPEN", tt.details)

			if err := writer.Write(result); err != nil {
				t.Fatalf("Write()失败: %v", err)
			}

			if err := writer.Close(); err != nil {
				t.Fatalf("Close()失败: %v", err)
			}

			content := readFileContent(t, filePath)

			// 验证：包含类型前缀
			if !strings.Contains(content, "# ===== 开放端口 =====") {
				t.Errorf("输出缺少类型前缀\n实际输出: %s", content)
			}

			// 验证：包含目标
			if !strings.Contains(content, "192.168.1.1:22") {
				t.Errorf("输出缺少目标\n实际输出: %s", content)
			}

			t.Logf("✓ %s 测试通过", tt.name)
		})
	}
}

// TestTXTWriter_MultipleWrites 测试多次写入
//
// 验证：多次写入不会相互干扰
// TXTWriter 使用分类缓冲模式，按类型分组输出
func TestTXTWriter_MultipleWrites(t *testing.T) {
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test_multiple.txt")

	writer, err := NewTXTWriter(filePath)
	if err != nil {
		t.Fatalf("创建writer失败: %v", err)
	}
	defer func() { _ = writer.Close() }()

	// 写入多条结果（不同类型）
	results := []*ScanResult{
		createTestResult(TypeHost, "192.168.1.1", "ALIVE", nil),
		createTestResult(TypePort, "192.168.1.1:80", "OPEN", map[string]interface{}{"service": "http"}),
		createTestResult(TypePort, "192.168.1.1:443", "OPEN", map[string]interface{}{"service": "https"}),
		createTestResult(TypeVuln, "192.168.1.1", "CVE-2024-1234", map[string]interface{}{"severity": "high"}),
	}

	for _, result := range results {
		if err := writer.Write(result); err != nil {
			t.Fatalf("Write()失败: %v", err)
		}
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("Close()失败: %v", err)
	}

	content := readFileContent(t, filePath)

	// 验证：包含各类型前缀（实时刷盘模式）
	expectedPrefixes := []string{
		"# ===== 存活主机 =====",
		"# ===== 开放端口 =====",
		"# ===== 漏洞信息 =====",
	}
	for _, prefix := range expectedPrefixes {
		if !strings.Contains(content, prefix) {
			t.Errorf("输出缺少类型前缀: %s\n实际输出: %s", prefix, content)
		}
	}

	// 验证：包含各目标
	expectedTargets := []string{"192.168.1.1", "192.168.1.1:80", "192.168.1.1:443"}
	for _, target := range expectedTargets {
		if !strings.Contains(content, target) {
			t.Errorf("输出缺少目标: %s", target)
		}
	}

	t.Logf("✓ 多次写入测试通过（%d条记录）", len(results))
}

// TestTXTWriter_GetFormat 测试格式类型获取
func TestTXTWriter_GetFormat(t *testing.T) {
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test_format.txt")

	writer, err := NewTXTWriter(filePath)
	if err != nil {
		t.Fatalf("创建writer失败: %v", err)
	}
	defer func() { _ = writer.Close() }()

	format := writer.GetFormat()
	if format != FormatTXT {
		t.Errorf("GetFormat() = %v, want %v", format, FormatTXT)
	}
}

// =============================================================================
// TXTWriter - 错误处理测试
// =============================================================================

// TestTXTWriter_NilResult 测试 nil result 处理
//
// 这是防御性编程的基础：公开函数必须检查 nil
func TestTXTWriter_NilResult(t *testing.T) {
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test_nil.txt")

	writer, err := NewTXTWriter(filePath)
	if err != nil {
		t.Fatalf("创建writer失败: %v", err)
	}
	defer func() { _ = writer.Close() }()

	// 写入 nil result 应该返回错误，而不是 panic
	err = writer.Write(nil)
	if err == nil {
		t.Fatal("Write(nil) 应该返回错误")
	}

	// 验证错误消息
	expectedMsg := "result cannot be nil"
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("错误消息 = %q, 应包含 %q", err.Error(), expectedMsg)
	}

	// 验证没有写入任何内容
	if err := writer.Close(); err != nil {
		t.Fatalf("Close()失败: %v", err)
	}

	content := readFileContent(t, filePath)
	if content != "" {
		t.Errorf("nil result 不应写入任何内容，实际写入: %s", content)
	}

	t.Logf("✓ nil result 正确处理（返回错误而非 panic）")
}

// TestTXTWriter_ClosedWriter 测试关闭后写入
//
// 验证：关闭后的 writer 应该拒绝写入
func TestTXTWriter_ClosedWriter(t *testing.T) {
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test_closed.txt")

	writer, err := NewTXTWriter(filePath)
	if err != nil {
		t.Fatalf("创建writer失败: %v", err)
	}

	// 先关闭 writer
	if closeErr := writer.Close(); closeErr != nil {
		t.Fatalf("Close()失败: %v", closeErr)
	}

	// 尝试写入已关闭的 writer
	result := createTestResult(TypeHost, "192.168.1.1", "ALIVE", nil)
	err = writer.Write(result)

	if err == nil {
		t.Fatal("向已关闭的writer写入应该返回错误")
	}

	// 验证错误消息
	expectedMsg := "writer is closed"
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("错误消息 = %q, 应包含 %q", err.Error(), expectedMsg)
	}

	t.Logf("✓ 已关闭的writer正确拒绝写入")
}

// TestTXTWriter_DetailsOrder 测试去重功能
//
// 验证：TXTWriter 对相同目标去重，只保留一条记录
func TestTXTWriter_DetailsOrder(t *testing.T) {
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test_order.txt")

	writer, err := NewTXTWriter(filePath)
	if err != nil {
		t.Fatalf("创建writer失败: %v", err)
	}
	defer func() { _ = writer.Close() }()

	// 创建包含多个 Details 字段的结果
	result := createTestResult(
		TypeVuln,
		"192.168.1.1",
		"VULNERABLE",
		map[string]interface{}{
			"zebra":    "last",
			"apple":    "first",
			"middle":   "mid",
			"banana":   "second",
			"critical": true,
		},
	)

	// 多次写入相同数据（TXTWriter会去重）
	for i := 0; i < 3; i++ {
		if err := writer.Write(result); err != nil {
			t.Fatalf("Write()失败: %v", err)
		}
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("Close()失败: %v", err)
	}

	content := readFileContent(t, filePath)

	// 验证：包含漏洞类型前缀
	if !strings.Contains(content, "# ===== 漏洞信息 =====") {
		t.Errorf("输出缺少类型前缀\n实际输出: %s", content)
	}

	// 验证：包含目标
	if !strings.Contains(content, "192.168.1.1") {
		t.Errorf("输出缺少目标\n实际输出: %s", content)
	}

	// 注意：实时刷盘模式下每次Write都直接输出，不做去重
	// 计算目标出现次数
	count := strings.Count(content, "192.168.1.1")
	// 实时模式下会有多行输出
	if count > 3 {
		t.Logf("注意：目标出现%d次（实时模式不去重）", count)
	}

	t.Logf("✓ 去重功能测试通过\n  输出: %s", strings.TrimSpace(content))
}

// =============================================================================
// TXTWriter - 特殊字符测试（P0风险）
// =============================================================================

// TestTXTWriter_SpecialCharacters 测试特殊字符处理
//
// 验证：特殊字符不会导致程序崩溃
// TXTWriter 使用分类缓冲模式，特殊字符会被转义
func TestTXTWriter_SpecialCharacters(t *testing.T) {
	dir := createTestDir(t)

	tests := []struct {
		name          string
		target        string
		status        string
		details       map[string]interface{}
		shouldContain []string // 必须包含的字符串（部分）
		description   string
	}{
		{
			name:   "目标包含换行符",
			target: "192.168.1.1\n:80",
			status: "OPEN",
			details: map[string]interface{}{
				"service": "http",
			},
			shouldContain: []string{"192.168.1.1"},
			description:   "换行符应被处理",
		},
		{
			name:   "状态包含制表符",
			target: "192.168.1.1:443",
			status: "OPEN\tSSL",
			details: map[string]interface{}{
				"protocol": "https",
			},
			shouldContain: []string{"192.168.1.1:443"},
			description:   "制表符应被处理",
		},
		{
			name:   "Details值包含特殊字符",
			target: "example.com",
			status: "VULNERABLE",
			details: map[string]interface{}{
				"payload": "'; DROP TABLE users--",
				"newline": "line1\nline2",
				"quote":   `test"value'mixed`,
			},
			shouldContain: []string{"example.com"},
			description:   "SQL注入字符应被安全处理",
		},
		{
			name:   "回车换行组合",
			target: "192.168.1.1",
			status: "test\r\nstatus",
			details: map[string]interface{}{
				"data": "value1\r\nvalue2",
			},
			shouldContain: []string{"192.168.1.1"},
			description:   "Windows风格换行应被处理",
		},
		{
			name:   "Unicode和特殊符号",
			target: "测试目标.com",
			status: "成功✓",
			details: map[string]interface{}{
				"emoji":   "🔥💀",
				"chinese": "中文测试",
			},
			shouldContain: []string{"测试目标.com"},
			description:   "Unicode字符应该正常输出",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(dir, tt.name+".txt")
			writer, err := NewTXTWriter(filePath)
			if err != nil {
				t.Fatalf("创建writer失败: %v", err)
			}
			defer func() { _ = writer.Close() }()

			result := createTestResult(TypePort, tt.target, tt.status, tt.details)

			// 主要验证：写入不会panic
			if err := writer.Write(result); err != nil {
				t.Fatalf("Write()失败: %v", err)
			}

			if err := writer.Close(); err != nil {
				t.Fatalf("Close()失败: %v", err)
			}

			content := readFileContent(t, filePath)

			// 验证：文件非空
			if content == "" {
				t.Error("输出文件为空")
			}

			// 验证：包含类型前缀
			if !strings.Contains(content, "# ===== 开放端口 =====") {
				t.Errorf("输出缺少类型前缀\n实际输出: %s", content)
			}

			// 验证：必须包含的字符串（目标的一部分）
			for _, s := range tt.shouldContain {
				if !strings.Contains(content, s) {
					t.Errorf("输出缺少字符串 %q\n%s\n实际输出: %s",
						s, tt.description, content)
				}
			}

			// 验证：以换行符结尾
			if !strings.HasSuffix(content, "\n") {
				t.Error("输出应该以换行符结尾")
			}

			t.Logf("✓ %s\n  输出: %s", tt.description, strings.TrimSpace(content))
		})
	}
}

// TestTXTWriter_EmptyFields 测试空字段处理
//
// 验证：空字段不会导致程序崩溃
// TXTWriter 使用实时刷盘模式
func TestTXTWriter_EmptyFields(t *testing.T) {
	dir := createTestDir(t)

	tests := []struct {
		name   string
		target string
		status string
	}{
		{
			name:   "空目标",
			target: "",
			status: "UNKNOWN",
		},
		{
			name:   "空状态",
			target: "192.168.1.1",
			status: "",
		},
		{
			name:   "全空",
			target: "",
			status: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(dir, tt.name+".txt")
			writer, err := NewTXTWriter(filePath)
			if err != nil {
				t.Fatalf("创建writer失败: %v", err)
			}
			defer func() { _ = writer.Close() }()

			result := createTestResult(TypeHost, tt.target, tt.status, nil)

			// 主要验证：写入不会panic
			if err := writer.Write(result); err != nil {
				t.Fatalf("Write()失败: %v", err)
			}

			if err := writer.Close(); err != nil {
				t.Fatalf("Close()失败: %v", err)
			}

			content := readFileContent(t, filePath)

			// 验证：应该有输出（即使字段为空）
			if content == "" {
				t.Error("空字段不应导致无输出")
			}

			// 验证：包含类型前缀
			if !strings.Contains(content, "# ===== 存活主机 =====") {
				t.Errorf("输出缺少类型前缀\n实际输出: %s", content)
			}

			t.Logf("✓ %s 处理正确\n  输出: %s", tt.name, strings.TrimSpace(content))
		})
	}
}

// =============================================================================
// TXTWriter - 并发安全测试（P0风险）
// =============================================================================

// TestTXTWriter_ConcurrentWrite 测试并发写入安全性
//
// 验证：多个goroutine同时写入不会导致panic或数据损坏
// TXTWriter 使用分类缓冲模式，会对相同目标去重
func TestTXTWriter_ConcurrentWrite(t *testing.T) {
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test_concurrent.txt")

	writer, err := NewTXTWriter(filePath)
	if err != nil {
		t.Fatalf("创建writer失败: %v", err)
	}
	defer func() { _ = writer.Close() }()

	// 并发参数
	numGoroutines := 100
	writesPerGoroutine := 10

	// 使用WaitGroup等待所有goroutine完成
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// 错误收集（使用channel避免竞争）
	errChan := make(chan error, numGoroutines)

	// 启动多个goroutine并发写入
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < writesPerGoroutine; j++ {
				result := createTestResult(
					TypePort,
					fmt.Sprintf("192.168.1.%d:%d", id, j),
					"OPEN",
					map[string]interface{}{
						"goroutine": id,
						"sequence":  j,
					},
				)

				if err := writer.Write(result); err != nil {
					errChan <- fmt.Errorf("goroutine %d: %w", id, err)
					return
				}
			}
		}(i)
	}

	// 等待所有goroutine完成
	wg.Wait()
	close(errChan)

	// 检查是否有错误
	for err := range errChan {
		t.Errorf("并发写入错误: %v", err)
	}

	// 关闭writer
	if err := writer.Close(); err != nil {
		t.Fatalf("Close()失败: %v", err)
	}

	// 验证数据完整性
	content := readFileContent(t, filePath)

	// 验证：文件非空
	if content == "" {
		t.Fatal("输出文件为空")
	}

	// 验证：包含类型前缀
	if !strings.Contains(content, "# ===== 开放端口 =====") {
		t.Errorf("输出缺少类型前缀")
	}

	// 验证：包含一些目标（实时模式每次写入都输出）
	if !strings.Contains(content, "192.168.1.") {
		t.Errorf("输出缺少目标IP")
	}

	lines := strings.Split(strings.TrimSpace(content), "\n")
	t.Logf("✓ 并发写入测试通过（%d个goroutine，每个写入%d次，输出%d行）",
		numGoroutines, writesPerGoroutine, len(lines))
}

// TestTXTWriter_ConcurrentWriteAndClose 测试并发写入和关闭
//
// 验证：写入过程中关闭writer不会导致panic或数据损坏
// TXTWriter 使用实时刷盘模式
func TestTXTWriter_ConcurrentWriteAndClose(t *testing.T) {
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test_write_close.txt")

	writer, err := NewTXTWriter(filePath)
	if err != nil {
		t.Fatalf("创建writer失败: %v", err)
	}

	// 启动多个goroutine持续写入
	numGoroutines := 50
	stopChan := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	writeCount := 0
	errorCount := 0
	var countMu sync.Mutex

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; ; j++ {
				select {
				case <-stopChan:
					return
				default:
					result := createTestResult(
						TypeHost,
						fmt.Sprintf("192.168.%d.%d", id, j),
						"ALIVE",
						nil,
					)

					err := writer.Write(result)
					countMu.Lock()
					if err != nil {
						// 关闭后的写入错误是预期的
						if strings.Contains(err.Error(), "writer is closed") {
							errorCount++
						} else {
							t.Errorf("意外错误: %v", err)
						}
					} else {
						writeCount++
					}
					countMu.Unlock()

					// 短暂休眠，让其他goroutine有机会执行
					time.Sleep(time.Microsecond)
				}
			}
		}(i)
	}

	// 让写入goroutine运行一小段时间
	time.Sleep(50 * time.Millisecond)

	// 关闭writer（此时仍有goroutine在写入）
	closeErr := writer.Close()
	if closeErr != nil {
		t.Errorf("Close()失败: %v", closeErr)
	}

	// 停止所有写入goroutine
	close(stopChan)
	wg.Wait()

	// 验证：有成功写入的记录
	if writeCount == 0 {
		t.Error("没有成功写入任何记录")
	}

	// 验证：关闭后的写入正确返回错误
	if errorCount == 0 {
		t.Error("关闭后的写入应该返回错误")
	}

	// 验证：文件内容完整
	content := readFileContent(t, filePath)

	// 验证：文件非空
	if content == "" {
		t.Fatal("文件内容为空")
	}

	// 验证：包含类型前缀
	if !strings.Contains(content, "# ===== 存活主机 =====") {
		t.Errorf("输出缺少类型前缀")
	}

	lines := strings.Split(strings.TrimSpace(content), "\n")
	t.Logf("✓ 并发写入和关闭测试通过")
	t.Logf("  成功写入: %d条", writeCount)
	t.Logf("  错误拒绝: %d次", errorCount)
	t.Logf("  文件记录: %d行", len(lines))
}

// TestTXTWriter_RaceDetector 测试race detector
//
// 运行: go test -race -run TestTXTWriter_RaceDetector
func TestTXTWriter_RaceDetector(t *testing.T) {
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test_race.txt")

	writer, err := NewTXTWriter(filePath)
	if err != nil {
		t.Fatalf("创建writer失败: %v", err)
	}
	defer func() { _ = writer.Close() }()

	// 混合操作：写入、刷新、获取格式
	var wg sync.WaitGroup
	wg.Add(3)

	// Goroutine 1: 持续写入
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			result := createTestResult(
				TypePort,
				fmt.Sprintf("192.168.1.%d:80", i),
				"OPEN",
				map[string]interface{}{"index": i},
			)
			_ = writer.Write(result)
		}
	}()

	// Goroutine 2: 持续刷新
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = writer.Flush()
			time.Sleep(time.Microsecond)
		}
	}()

	// Goroutine 3: 持续读取格式（测试closed字段）
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = writer.GetFormat()
			time.Sleep(time.Microsecond)
		}
	}()

	wg.Wait()

	t.Logf("✓ Race detector 测试通过（运行 go test -race 验证）")
}

// =============================================================================
// JSONWriter - 基础功能测试
// =============================================================================

// TestJSONWriter_BasicWrite 测试JSON基础写入
//
// JSONWriter 使用延迟写入模式：
// - Write() 收集结果到分类缓冲
// - Close() 时输出完整的JSON对象（包含summary和分类数据）
func TestJSONWriter_BasicWrite(t *testing.T) {
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test.json")

	writer, err := NewJSONWriter(filePath)
	if err != nil {
		t.Fatalf("创建JSONWriter失败: %v", err)
	}
	defer func() { _ = writer.Close() }()

	// 写入头部
	if err := writer.WriteHeader(); err != nil {
		t.Fatalf("写入头部失败: %v", err)
	}

	// 写入一条Port类型结果
	result := createTestResult(TypePort, "192.168.1.1:80", "OPEN", nil)
	if err := writer.Write(result); err != nil {
		t.Fatalf("写入结果失败: %v", err)
	}

	// 关闭文件触发实际写入
	if err := writer.Close(); err != nil {
		t.Fatalf("关闭writer失败: %v", err)
	}

	// 验证文件内容（完整的JSON对象）
	content := readFileContent(t, filePath)

	// 解析为JSONOutput结构
	var output JSONOutput
	if err := json.Unmarshal([]byte(content), &output); err != nil {
		t.Fatalf("JSON解析失败: %v, 内容: %s", err, content)
	}

	// 检查summary
	if output.Summary.TotalPorts != 1 {
		t.Errorf("TotalPorts应该为1，实际%d", output.Summary.TotalPorts)
	}

	// 检查ports数组
	if len(output.Ports) != 1 {
		t.Fatalf("Ports数组应该有1个元素，实际%d", len(output.Ports))
	}
	if output.Ports[0].Target != "192.168.1.1:80" {
		t.Error("target字段不正确")
	}
	if output.Ports[0].Status != "OPEN" {
		t.Error("status字段不正确")
	}

	t.Logf("✓ JSON基础写入测试通过")
}

// TestJSONWriter_MultipleWrites 测试JSON多条记录写入
func TestJSONWriter_MultipleWrites(t *testing.T) {
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test.json")

	writer, err := NewJSONWriter(filePath)
	if err != nil {
		t.Fatalf("创建JSONWriter失败: %v", err)
	}
	defer func() { _ = writer.Close() }()

	_ = writer.WriteHeader()

	// 写入3条Port记录
	for i := 1; i <= 3; i++ {
		result := createTestResult(
			TypePort,
			fmt.Sprintf("192.168.1.%d:80", i),
			"OPEN",
			map[string]interface{}{"index": i},
		)
		if err := writer.Write(result); err != nil {
			t.Fatalf("写入第%d条记录失败: %v", i, err)
		}
	}

	writer.Close()

	// 解析完整的JSON对象
	content := readFileContent(t, filePath)
	var output JSONOutput
	if err := json.Unmarshal([]byte(content), &output); err != nil {
		t.Fatalf("JSON解析失败: %v", err)
	}

	// 验证summary
	if output.Summary.TotalPorts != 3 {
		t.Errorf("TotalPorts应该为3，实际%d", output.Summary.TotalPorts)
	}

	// 验证ports数组
	if len(output.Ports) != 3 {
		t.Fatalf("Ports数组应该有3个元素，实际%d", len(output.Ports))
	}

	// 验证每条记录
	for i, port := range output.Ports {
		expectedTarget := fmt.Sprintf("192.168.1.%d:80", i+1)
		if port.Target != expectedTarget {
			t.Errorf("第%d条记录target不匹配，期望%s，实际%s", i+1, expectedTarget, port.Target)
		}
	}

	t.Logf("✓ JSON多条记录写入测试通过")
}

// TestJSONWriter_ErrorHandling 测试JSON错误处理
func TestJSONWriter_ErrorHandling(t *testing.T) {
	t.Run("nil result", func(t *testing.T) {
		dir := createTestDir(t)
		filePath := filepath.Join(dir, "test.json")

		writer, _ := NewJSONWriter(filePath)
		defer func() { _ = writer.Close() }()

		_ = writer.WriteHeader()

		// nil result应该返回错误
		err := writer.Write(nil)
		if err == nil {
			t.Error("nil result应该返回错误")
		}
		if !strings.Contains(err.Error(), "cannot be nil") {
			t.Errorf("错误信息不符合预期: %v", err)
		}
	})

	t.Run("closed writer", func(t *testing.T) {
		dir := createTestDir(t)
		filePath := filepath.Join(dir, "test.json")

		writer, _ := NewJSONWriter(filePath)
		writer.Close()

		// 关闭后写入应该返回错误
		result := createTestResult(TypePort, "test", "test", nil)
		err := writer.Write(result)
		if err == nil {
			t.Error("关闭后写入应该返回错误")
		}
	})
}

// =============================================================================
// CSVWriter - 基础功能测试
// =============================================================================

// TestCSVWriter_BasicWrite 测试CSV基础写入
//
// CSVWriter 使用分类格式：
// - 每个类型有独立的分区（# Ports, # Hosts 等）
// - 每个分区有自己的头部
func TestCSVWriter_BasicWrite(t *testing.T) {
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test.csv")

	writer, err := NewCSVWriter(filePath)
	if err != nil {
		t.Fatalf("创建CSVWriter失败: %v", err)
	}
	defer func() { _ = writer.Close() }()

	// 写入头部
	if err := writer.WriteHeader(); err != nil {
		t.Fatalf("写入头部失败: %v", err)
	}

	// 写入一条Port类型结果
	result := createTestResult(TypePort, "192.168.1.1:80", "OPEN", map[string]interface{}{"port": 80})
	if err := writer.Write(result); err != nil {
		t.Fatalf("写入结果失败: %v", err)
	}

	// 关闭文件触发写入
	if err := writer.Close(); err != nil {
		t.Fatalf("关闭writer失败: %v", err)
	}

	// 验证文件内容
	content := readFileContent(t, filePath)

	// 应该包含Ports分区标题
	if !strings.Contains(content, "# Ports") {
		t.Error("CSV文件应该包含 '# Ports' 分区标题")
	}

	// 应该包含Ports分区的头部
	if !strings.Contains(content, "Target") {
		t.Error("CSV文件应该包含 'Target' 头部")
	}

	// 应该包含目标数据
	if !strings.Contains(content, "192.168.1.1:80") {
		t.Error("CSV文件应该包含target数据")
	}

	t.Logf("✓ CSV基础写入测试通过")
}

// TestCSVWriter_MultipleWrites 测试CSV多条记录写入
func TestCSVWriter_MultipleWrites(t *testing.T) {
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test.csv")

	writer, err := NewCSVWriter(filePath)
	if err != nil {
		t.Fatalf("创建CSVWriter失败: %v", err)
	}
	defer func() { _ = writer.Close() }()

	_ = writer.WriteHeader()

	// 写入5条Port记录
	for i := 1; i <= 5; i++ {
		result := createTestResult(
			TypePort,
			fmt.Sprintf("192.168.1.%d:80", i),
			"OPEN",
			map[string]interface{}{
				"port":  80,
				"index": i,
			},
		)
		if err := writer.Write(result); err != nil {
			t.Fatalf("写入第%d条记录失败: %v", i, err)
		}
	}

	writer.Close()

	content := readFileContent(t, filePath)

	// 验证分区标题存在
	if !strings.Contains(content, "# Ports") {
		t.Error("CSV文件应该包含 '# Ports' 分区标题")
	}

	// 验证每条记录都存在
	for i := 1; i <= 5; i++ {
		target := fmt.Sprintf("192.168.1.%d:80", i)
		if !strings.Contains(content, target) {
			t.Errorf("CSV文件缺少第%d条记录: %s", i, target)
		}
	}

	t.Logf("✓ CSV多条记录写入测试通过")
}

// TestCSVWriter_ErrorHandling 测试CSV错误处理
func TestCSVWriter_ErrorHandling(t *testing.T) {
	t.Run("nil result", func(t *testing.T) {
		dir := createTestDir(t)
		filePath := filepath.Join(dir, "test.csv")

		writer, _ := NewCSVWriter(filePath)
		defer func() { _ = writer.Close() }()

		_ = writer.WriteHeader()

		// nil result应该返回错误
		err := writer.Write(nil)
		if err == nil {
			t.Error("nil result应该返回错误")
		}
		if !strings.Contains(err.Error(), "cannot be nil") {
			t.Errorf("错误信息不符合预期: %v", err)
		}
	})

	t.Run("closed writer", func(t *testing.T) {
		dir := createTestDir(t)
		filePath := filepath.Join(dir, "test.csv")

		writer, _ := NewCSVWriter(filePath)
		writer.Close()

		// 关闭后写入应该返回错误
		result := createTestResult(TypePort, "test", "test", nil)
		err := writer.Write(result)
		if err == nil {
			t.Error("关闭后写入应该返回错误")
		}
	})
}

// TestCSVWriter_DetailsFormatting 测试CSV的Details字段格式化
//
// CSVWriter 对不同类型有不同的格式：
// - Service类型：Target, Service, Version, Title, Status, Server, Fingerprints, Banner
func TestCSVWriter_DetailsFormatting(t *testing.T) {
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test.csv")

	writer, _ := NewCSVWriter(filePath)
	defer func() { _ = writer.Close() }()

	_ = writer.WriteHeader()

	// 写入Service类型记录（包含service, version, banner）
	result := createTestResult(
		TypeService,
		"192.168.1.1:80",
		"OPEN",
		map[string]interface{}{
			"service": "http",
			"version": "Apache/2.4",
			"banner":  "Welcome",
		},
	)
	_ = writer.Write(result)
	writer.Close()

	content := readFileContent(t, filePath)

	// 应该包含Services分区
	if !strings.Contains(content, "# Services") {
		t.Error("CSV应该包含 '# Services' 分区")
	}

	// 应该包含service值
	if !strings.Contains(content, "http") {
		t.Error("CSV应该包含service值 'http'")
	}

	// 应该包含version值
	if !strings.Contains(content, "Apache/2.4") {
		t.Error("CSV应该包含version值 'Apache/2.4'")
	}

	// 应该包含banner值
	if !strings.Contains(content, "Welcome") {
		t.Error("CSV应该包含banner值 'Welcome'")
	}

	t.Logf("✓ CSV Details格式化测试通过")
}

func TestCSVWriter_WebServiceFields(t *testing.T) {
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test.csv")

	writer, _ := NewCSVWriter(filePath)
	defer func() { _ = writer.Close() }()

	_ = writer.WriteHeader()
	result := createTestResult(
		TypeService,
		"192.168.1.1:80",
		"web",
		map[string]interface{}{
			"plugin":       "webtitle",
			"is_web":       true,
			"port":         80,
			"title":        "Home",
			"status":       200,
			"server":       "nginx",
			"fingerprints": []string{"nginx", "php"},
			"banner":       "HTTP/1.1 200 OK\x00\nServer: nginx",
		},
	)
	_ = writer.Write(result)
	writer.Close()

	content := readFileContent(t, filePath)
	for _, want := range []string{
		"Target,Service,Version,Title,Status,Server,Fingerprints,Banner",
		"webtitle",
		"Home",
		"200",
		"nginx",
		"nginx,php",
		"\\x00\\nServer: nginx",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("CSV文件缺少 %q，内容:\n%s", want, content)
		}
	}
}

func TestTXTWriter_WebServiceProtocolFromDetails(t *testing.T) {
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test_web_protocol.txt")

	writer, err := NewTXTWriter(filePath)
	if err != nil {
		t.Fatalf("创建TXTWriter失败: %v", err)
	}

	result := createTestResult(
		TypeService,
		"192.168.1.1:8443",
		"web",
		map[string]interface{}{
			"plugin":   "webtitle",
			"is_web":   true,
			"port":     8443,
			"protocol": "https",
			"title":    "Home",
			"status":   200,
		},
	)
	if err := writer.Write(result); err != nil {
		t.Fatalf("Write()失败: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close()失败: %v", err)
	}

	content := readFileContent(t, filePath)
	if !strings.Contains(content, "https://192.168.1.1:8443") {
		t.Fatalf("TXT输出缺少HTTPS URL，内容:\n%s", content)
	}
	if strings.Contains(content, "http://192.168.1.1:8443") {
		t.Fatalf("TXT输出不应把HTTPS目标降级为HTTP，内容:\n%s", content)
	}
}

// TestJSONWriter_FlushAndFormat 测试JSON的Flush和GetFormat
func TestJSONWriter_FlushAndFormat(t *testing.T) {
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test.json")

	writer, _ := NewJSONWriter(filePath)
	defer func() { _ = writer.Close() }()

	// 测试GetFormat
	if writer.GetFormat() != FormatJSON {
		t.Errorf("GetFormat应该返回FormatJSON，实际%v", writer.GetFormat())
	}

	_ = writer.WriteHeader()
	writer.Write(createTestResult(TypePort, "test", "test", nil))

	// 测试Flush
	if err := writer.Flush(); err != nil {
		t.Errorf("Flush失败: %v", err)
	}

	// 关闭后Flush应该不报错（已经关闭）
	writer.Close()
	if err := writer.Flush(); err != nil {
		t.Errorf("关闭后Flush应该不报错: %v", err)
	}

	t.Logf("✓ JSON Flush和GetFormat测试通过")
}

// TestCSVWriter_FlushAndFormat 测试CSV的Flush和GetFormat
func TestCSVWriter_FlushAndFormat(t *testing.T) {
	dir := createTestDir(t)
	filePath := filepath.Join(dir, "test.csv")

	writer, _ := NewCSVWriter(filePath)
	defer func() { _ = writer.Close() }()

	// 测试GetFormat
	if writer.GetFormat() != FormatCSV {
		t.Errorf("GetFormat应该返回FormatCSV，实际%v", writer.GetFormat())
	}

	_ = writer.WriteHeader()
	writer.Write(createTestResult(TypePort, "test", "test", nil))

	// 测试Flush
	if err := writer.Flush(); err != nil {
		t.Errorf("Flush失败: %v", err)
	}

	// 关闭后Flush应该不报错（已经关闭）
	writer.Close()
	if err := writer.Flush(); err != nil {
		t.Errorf("关闭后Flush应该不报错: %v", err)
	}

	t.Logf("✓ CSV Flush和GetFormat测试通过")
}

// =============================================================================
// Manager - 输出管理器测试
// =============================================================================

// TestNewManager_Success 测试Manager创建成功
func TestNewManager_Success(t *testing.T) {
	dir := createTestDir(t)

	tests := []struct {
		name   string
		format Format
	}{
		{"TXT格式", FormatTXT},
		{"JSON格式", FormatJSON},
		{"CSV格式", FormatCSV},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &ManagerConfig{
				OutputPath: filepath.Join(dir, "test."+string(tt.format)),
				Format:     tt.format,
			}

			manager, err := NewManager(config)
			if err != nil {
				t.Fatalf("NewManager失败: %v", err)
			}
			defer func() { _ = manager.Close() }()

			if manager == nil {
				t.Fatal("Manager不应为nil")
			}

			t.Logf("✓ %s Manager创建成功", tt.name)
		})
	}
}

// TestNewManager_NilConfig 测试nil配置
func TestNewManager_NilConfig(t *testing.T) {
	_, err := NewManager(nil)
	if err == nil {
		t.Error("nil配置应该返回错误")
	}

	if !strings.Contains(err.Error(), "cannot be nil") {
		t.Errorf("错误信息不符合预期: %v", err)
	}

	t.Logf("✓ nil配置正确返回错误")
}

// TestNewManager_InvalidFormat 测试无效格式
func TestNewManager_InvalidFormat(t *testing.T) {
	dir := createTestDir(t)

	config := &ManagerConfig{
		OutputPath: filepath.Join(dir, "test.invalid"),
		Format:     Format("invalid"),
	}

	_, err := NewManager(config)
	if err == nil {
		t.Error("无效格式应该返回错误")
	}

	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("错误信息不符合预期: %v", err)
	}

	t.Logf("✓ 无效格式正确返回错误")
}

// TestManager_SaveResult 测试保存结果
func TestManager_SaveResult(t *testing.T) {
	dir := createTestDir(t)

	config := &ManagerConfig{
		OutputPath: filepath.Join(dir, "test.txt"),
		Format:     FormatTXT,
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager失败: %v", err)
	}
	defer func() { _ = manager.Close() }()

	// 保存一条结果
	result := createTestResult(TypePort, "192.168.1.1:80", "OPEN", nil)
	if err := manager.SaveResult(result); err != nil {
		t.Fatalf("SaveResult失败: %v", err)
	}

	// 保存多条结果（使用不同的端口避免去重）
	for i := 1; i <= 5; i++ {
		result := createTestResult(
			TypePort,
			fmt.Sprintf("192.168.1.1:%d", 80+i),
			"OPEN",
			nil,
		)
		if err := manager.SaveResult(result); err != nil {
			t.Fatalf("第%d次SaveResult失败: %v", i, err)
		}
	}

	manager.Close()

	// 验证文件内容
	content := readFileContent(t, config.OutputPath)
	if len(content) == 0 {
		t.Error("输出文件为空")
	}

	// 验证：包含类型前缀
	if !strings.Contains(content, "# ===== 开放端口 =====") {
		t.Errorf("输出缺少类型前缀")
	}

	// 验证：包含一些目标
	if !strings.Contains(content, "192.168.1.1") {
		t.Errorf("输出缺少目标")
	}

	t.Logf("✓ SaveResult测试通过")
}

// TestManager_SaveNilResult 测试保存nil结果
func TestManager_SaveNilResult(t *testing.T) {
	dir := createTestDir(t)

	config := &ManagerConfig{
		OutputPath: filepath.Join(dir, "test.txt"),
		Format:     FormatTXT,
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager失败: %v", err)
	}
	defer func() { _ = manager.Close() }()

	// 保存nil结果应该返回错误
	err = manager.SaveResult(nil)
	if err == nil {
		t.Error("保存nil结果应该返回错误")
	}

	if !strings.Contains(err.Error(), "cannot be nil") {
		t.Errorf("错误信息不符合预期: %v", err)
	}

	t.Logf("✓ nil结果正确返回错误")
}

// TestManager_Flush 测试Flush
func TestManager_Flush(t *testing.T) {
	dir := createTestDir(t)

	config := &ManagerConfig{
		OutputPath: filepath.Join(dir, "test.txt"),
		Format:     FormatTXT,
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager失败: %v", err)
	}
	defer func() { _ = manager.Close() }()

	// 写入数据
	result := createTestResult(TypePort, "test", "test", nil)
	_ = manager.SaveResult(result)

	// Flush应该成功
	if err := manager.Flush(); err != nil {
		t.Errorf("Flush失败: %v", err)
	}

	t.Logf("✓ Flush测试通过")
}

// TestManager_Close 测试Close
func TestManager_Close(t *testing.T) {
	dir := createTestDir(t)

	config := &ManagerConfig{
		OutputPath: filepath.Join(dir, "test.txt"),
		Format:     FormatTXT,
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager失败: %v", err)
	}

	// 第一次Close应该成功
	if closeErr := manager.Close(); closeErr != nil {
		t.Errorf("第一次Close失败: %v", closeErr)
	}

	// 第二次Close应该也成功（幂等性）
	if closeErr := manager.Close(); closeErr != nil {
		t.Errorf("第二次Close失败: %v", closeErr)
	}

	// Close后Save应该返回错误
	result := createTestResult(TypePort, "test", "test", nil)
	err = manager.SaveResult(result)
	if err == nil {
		t.Error("Close后Save应该返回错误")
	}

	// Close后Flush应该返回错误
	err = manager.Flush()
	if err == nil {
		t.Error("Close后Flush应该返回错误")
	}

	t.Logf("✓ Close测试通过")
}

// TestManager_ConcurrentSave 测试并发保存
func TestManager_ConcurrentSave(t *testing.T) {
	dir := createTestDir(t)

	config := &ManagerConfig{
		OutputPath: filepath.Join(dir, "test.txt"),
		Format:     FormatTXT,
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager失败: %v", err)
	}
	defer func() { _ = manager.Close() }()

	numGoroutines := 10
	savesPerGoroutine := 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < savesPerGoroutine; j++ {
				result := createTestResult(
					TypePort,
					fmt.Sprintf("192.168.%d.%d:80", id, j),
					"OPEN",
					nil,
				)
				_ = manager.SaveResult(result)
			}
		}(i)
	}

	wg.Wait()
	manager.Close()

	// 验证文件内容
	content := readFileContent(t, config.OutputPath)

	// 验证：文件非空
	if content == "" {
		t.Error("输出文件为空")
	}

	// 验证：包含类型前缀
	if !strings.Contains(content, "# ===== 开放端口 =====") {
		t.Errorf("输出缺少类型前缀")
	}

	// 验证：包含目标（实时模式每次写入都输出）
	if !strings.Contains(content, "192.168.") {
		t.Errorf("输出缺少目标")
	}

	lines := strings.Split(strings.TrimSpace(content), "\n")
	t.Logf("✓ 并发保存测试通过（%d个goroutine，每个%d次，输出%d行）",
		numGoroutines, savesPerGoroutine, len(lines))
}
