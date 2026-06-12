package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

/*
logger_test.go - 日志系统测试

测试目标：Logger核心功能
价值：日志是程序的眼睛，错误会导致：
  - 关键信息丢失（用户看不到错误）
  - 性能问题（并发日志混乱）
  - 调试困难（时间格式错误）

"日志不是可选功能。日志丢失或错误，等于程序在撒谎。
测试必须验证：过滤正确、格式正确、并发安全。"
*/

// =============================================================================
// 测试辅助函数
// =============================================================================

// captureOutput 捕获日志输出（不污染控制台）
type captureOutput struct {
	mu     sync.Mutex
	output []string
}

func (c *captureOutput) Write(msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.output = append(c.output, msg)
}

func (c *captureOutput) Get() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]string, len(c.output))
	copy(result, c.output)
	return result
}

func (c *captureOutput) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.output = nil
}

// createTestLogger 创建测试用Logger（捕获输出）
func createTestLogger(level LogLevel, enableColor bool) (*Logger, *captureOutput) {
	capture := &captureOutput{}
	config := &LoggerConfig{
		Level:        level,
		EnableColor:  enableColor,
		SlowOutput:   false, // 测试时禁用慢速输出
		ShowProgress: false,
		StartTime:    time.Now(),
		LevelColors:  GetDefaultLevelColors(),
	}
	logger := NewLogger(config)
	logger.SetCoordinatedOutput(capture.Write)
	return logger, capture
}

// =============================================================================
// Logger - 基础功能测试
// =============================================================================

// TestNewLogger_DefaultConfig 测试默认配置
func TestNewLogger_DefaultConfig(t *testing.T) {
	// nil配置应该使用默认值
	logger := NewLogger(nil)

	if logger == nil {
		t.Fatal("NewLogger(nil) 应该返回有效的logger")
	}

	if logger.config == nil {
		t.Error("config不应为nil（应使用默认配置）")
	}

	if logger.config.Level != DefaultLevel {
		t.Errorf("默认Level = %v, want %v", logger.config.Level, DefaultLevel)
	}

	if !logger.initialized {
		t.Error("logger应该已初始化")
	}

	t.Logf("✓ 默认配置测试通过")
}

// TestNewLogger_CustomConfig 测试自定义配置
func TestNewLogger_CustomConfig(t *testing.T) {
	config := &LoggerConfig{
		Level:        LevelError,
		EnableColor:  false,
		SlowOutput:   true,
		ShowProgress: false,
		StartTime:    time.Now(),
		LevelColors:  GetDefaultLevelColors(),
	}

	logger := NewLogger(config)

	if logger.config.Level != LevelError {
		t.Errorf("Level = %v, want %v", logger.config.Level, LevelError)
	}

	if logger.config.EnableColor {
		t.Error("EnableColor应该为false")
	}

	t.Logf("✓ 自定义配置测试通过")
}

// TestLogger_AllLevels 测试所有日志级别
//
// 验证：每个级别都能正确输出
func TestLogger_AllLevels(t *testing.T) {
	logger, capture := createTestLogger(LevelAll, false)

	tests := []struct {
		name    string
		logFunc func(string)
		message string
		wantMsg string
		wantPfx string
	}{
		{
			name:    "Debug级别",
			logFunc: logger.Debug,
			message: "debug message",
			wantMsg: "debug message",
			wantPfx: PrefixDebug,
		},
		{
			name:    "Base级别",
			logFunc: logger.Base,
			message: "base message",
			wantMsg: "base message",
			wantPfx: PrefixInfo, // Base 已废弃，默认使用 Info 前缀
		},
		{
			name:    "Info级别",
			logFunc: logger.Info,
			message: "info message",
			wantMsg: "info message",
			wantPfx: PrefixInfo,
		},
		{
			name:    "Success级别",
			logFunc: logger.Success,
			message: "success message",
			wantMsg: "success message",
			wantPfx: PrefixSuccess,
		},
		{
			name:    "Vuln级别",
			logFunc: logger.Vuln,
			message: "vuln message",
			wantMsg: "vuln message",
			wantPfx: PrefixVuln,
		},
		{
			name:    "Error级别",
			logFunc: logger.Error,
			message: "error message",
			wantMsg: "error message",
			wantPfx: PrefixError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capture.Clear()
			tt.logFunc(tt.message)

			output := capture.Get()
			if len(output) != 1 {
				t.Fatalf("期望1条输出，实际%d条", len(output))
			}

			msg := output[0]
			if !strings.Contains(msg, tt.wantMsg) {
				t.Errorf("输出缺少消息: %s\n实际: %s", tt.wantMsg, msg)
			}

			if !strings.Contains(msg, tt.wantPfx) {
				t.Errorf("输出缺少前缀: %s\n实际: %s", tt.wantPfx, msg)
			}

			// 验证输出格式：前缀 + 空格 + 消息
			if !strings.HasPrefix(msg, tt.wantPfx) {
				t.Errorf("输出应该以前缀开头: %s\n实际: %s", tt.wantPfx, msg)
			}

			t.Logf("✓ %s 输出正确: %s", tt.name, msg)
		})
	}
}

// =============================================================================
// Logger - 级别过滤测试
// =============================================================================

// TestLogger_LevelFiltering 测试日志级别过滤
//
// 验证：不同级别配置下，只输出对应级别的日志
func TestLogger_LevelFiltering(t *testing.T) {
	tests := []struct {
		name        string
		configLevel LogLevel
		logLevels   map[string]func(*Logger, string)
		wantOutput  map[string]bool // true表示应该输出
	}{
		{
			name:        "LevelAll - 显示所有",
			configLevel: LevelAll,
			logLevels: map[string]func(*Logger, string){
				"debug":   (*Logger).Debug,
				"base":    (*Logger).Base,
				"info":    (*Logger).Info,
				"success": (*Logger).Success,
				"error":   (*Logger).Error,
			},
			wantOutput: map[string]bool{
				"debug": true, "base": true, "info": true,
				"success": true, "error": true,
			},
		},
		{
			name:        "LevelError - 仅错误",
			configLevel: LevelError,
			logLevels: map[string]func(*Logger, string){
				"info":  (*Logger).Info,
				"error": (*Logger).Error,
			},
			wantOutput: map[string]bool{
				"info": false, "error": true,
			},
		},
		{
			name:        "LevelInfoSuccess - 信息和成功",
			configLevel: LevelInfoSuccess,
			logLevels: map[string]func(*Logger, string){
				"base":    (*Logger).Base,
				"info":    (*Logger).Info,
				"success": (*Logger).Success,
				"error":   (*Logger).Error,
			},
			wantOutput: map[string]bool{
				"base": false, "info": true,
				"success": true, "error": true, // Error 始终显示（层级设计）
			},
		},
		{
			name:        "LevelBaseInfoSuccess - 基础、信息和成功",
			configLevel: LevelBaseInfoSuccess,
			logLevels: map[string]func(*Logger, string){
				"debug":   (*Logger).Debug,
				"base":    (*Logger).Base,
				"info":    (*Logger).Info,
				"success": (*Logger).Success,
			},
			wantOutput: map[string]bool{
				"debug": false, "base": true,
				"info": true, "success": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, capture := createTestLogger(tt.configLevel, false)

			for levelName, logFunc := range tt.logLevels {
				capture.Clear()
				logFunc(logger, levelName+" message")

				output := capture.Get()
				shouldOutput := tt.wantOutput[levelName]

				if shouldOutput && len(output) == 0 {
					t.Errorf("%s: 应该输出但没有输出", levelName)
				}
				if !shouldOutput && len(output) > 0 {
					t.Errorf("%s: 不应该输出但输出了: %v", levelName, output)
				}
			}

			t.Logf("✓ %s 过滤测试通过", tt.name)
		})
	}
}

// =============================================================================
// Logger - 时间格式化测试
// =============================================================================

// TestLogger_TimeFormatting 测试时间格式化函数
//
// 验证：formatElapsedTime 对不同时长格式化正确（毫秒、秒、分钟、小时）
func TestLogger_TimeFormatting(t *testing.T) {
	tests := []struct {
		name    string
		elapsed time.Duration
		wantStr string
	}{
		{
			name:    "0毫秒",
			elapsed: 0,
			wantStr: "0ms",
		},
		{
			name:    "500毫秒",
			elapsed: 500 * time.Millisecond,
			wantStr: "500ms",
		},
		{
			name:    "999毫秒",
			elapsed: 999 * time.Millisecond,
			wantStr: "999ms",
		},
		{
			name:    "1秒",
			elapsed: 1 * time.Second,
			wantStr: "1.0s",
		},
		{
			name:    "30秒",
			elapsed: 30 * time.Second,
			wantStr: "30.0s",
		},
		{
			name:    "59秒",
			elapsed: 59 * time.Second,
			wantStr: "59.0s",
		},
		{
			name:    "1分钟",
			elapsed: 1 * time.Minute,
			wantStr: "1m0s",
		},
		{
			name:    "5分30秒",
			elapsed: 5*time.Minute + 30*time.Second,
			wantStr: "5m30s",
		},
		{
			name:    "59分59秒",
			elapsed: 59*time.Minute + 59*time.Second,
			wantStr: "59m59s",
		},
		{
			name:    "1小时",
			elapsed: 1 * time.Hour,
			wantStr: "1h0m0s",
		},
		{
			name:    "2小时30分45秒",
			elapsed: 2*time.Hour + 30*time.Minute + 45*time.Second,
			wantStr: "2h30m45s",
		},
	}

	// 直接测试 formatElapsedTime 函数
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(nil)
			result := logger.formatElapsedTime(tt.elapsed)

			if result != tt.wantStr {
				t.Errorf("时间格式错误\n期望: %s\n实际: %s", tt.wantStr, result)
			}

			t.Logf("✓ %s → %s", tt.name, result)
		})
	}
}

// =============================================================================
// Logger - 并发安全测试
// =============================================================================

// TestLogger_ConcurrentLogging 测试并发日志输出
//
// 验证：多个goroutine同时写日志不会panic或丢失
func TestLogger_ConcurrentLogging(t *testing.T) {
	logger, capture := createTestLogger(LevelAll, false)

	numGoroutines := 100
	logsPerGoroutine := 10
	totalLogs := numGoroutines * logsPerGoroutine

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// 并发写入不同级别的日志
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < logsPerGoroutine; j++ {
				msg := fmt.Sprintf("goroutine-%d-log-%d", id, j)

				// 随机使用不同级别
				switch j % 5 {
				case 0:
					logger.Debug(msg)
				case 1:
					logger.Info(msg)
				case 2:
					logger.Success(msg)
				case 3:
					logger.Error(msg)
				case 4:
					logger.Base(msg)
				}
			}
		}(i)
	}

	wg.Wait()

	// 验证输出数量
	output := capture.Get()
	if len(output) != totalLogs {
		t.Errorf("期望%d条日志，实际%d条（数据丢失或重复）",
			totalLogs, len(output))
	}

	// 验证每条日志格式正确（前缀可能是 "[" 或空格）
	for i, line := range output {
		if !strings.HasPrefix(line, "[") && !strings.HasPrefix(line, " ") {
			t.Errorf("第%d条日志格式错误: %s", i+1, line)
			break
		}
	}

	t.Logf("✓ 并发日志测试通过（%d个goroutine，共%d条日志）",
		numGoroutines, totalLogs)
}

// TestLogger_NoCoordinatedOutput 测试无协调输出的情况
//
// 验证：coordinatedOutput为nil时，使用fmt.Println（不会panic）
func TestLogger_NoCoordinatedOutput(t *testing.T) {
	config := &LoggerConfig{
		Level:       LevelAll,
		EnableColor: false,
		StartTime:   time.Now(),
	}
	logger := NewLogger(config)
	// 不设置 coordinatedOutput

	// 应该不会panic（会使用fmt.Println）
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("不应该panic: %v", r)
		}
	}()

	logger.Info("test message")

	t.Logf("✓ 无协调输出测试通过（使用fmt.Println）")
}

// =============================================================================
// Logger - 高级功能测试（提升覆盖率）
// =============================================================================

// TestLogger_SingleLevels 测试单独级别配置
//
// 验证：层级过滤 - 设置一个级别后，显示该级别及以上的日志，Error始终显示
func TestLogger_SingleLevels(t *testing.T) {
	tests := []struct {
		name        string
		configLevel LogLevel
		testLevels  map[string]func(*Logger, string)
		wantOutput  map[string]bool
	}{
		{
			name:        "LevelDebug - 显示所有",
			configLevel: LevelDebug,
			testLevels: map[string]func(*Logger, string){
				"debug":   (*Logger).Debug,
				"base":    (*Logger).Base,
				"info":    (*Logger).Info,
				"success": (*Logger).Success,
				"error":   (*Logger).Error,
			},
			wantOutput: map[string]bool{
				"debug": true, "base": true, "info": true,
				"success": true, "error": true, // 层级过滤：Debug(0)及以上全显示
			},
		},
		{
			name:        "LevelBase - 基础及以上",
			configLevel: LevelBase,
			testLevels: map[string]func(*Logger, string){
				"debug": (*Logger).Debug,
				"base":  (*Logger).Base,
				"info":  (*Logger).Info,
			},
			wantOutput: map[string]bool{
				"debug": false, "base": true, "info": true, // 层级过滤：Base(1)及以上
			},
		},
		{
			name:        "LevelInfo - 信息及以上",
			configLevel: LevelInfo,
			testLevels: map[string]func(*Logger, string){
				"base": (*Logger).Base,
				"info": (*Logger).Info,
			},
			wantOutput: map[string]bool{
				"base": false, "info": true, // 层级过滤：Info(2)及以上
			},
		},
		{
			name:        "LevelSuccess - 成功及以上",
			configLevel: LevelSuccess,
			testLevels: map[string]func(*Logger, string){
				"info":    (*Logger).Info,
				"success": (*Logger).Success,
			},
			wantOutput: map[string]bool{
				"info": false, "success": true, // 层级过滤：Success(3)及以上
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, capture := createTestLogger(tt.configLevel, false)

			for levelName, logFunc := range tt.testLevels {
				capture.Clear()
				logFunc(logger, levelName+" message")

				output := capture.Get()
				shouldOutput := tt.wantOutput[levelName]

				if shouldOutput && len(output) == 0 {
					t.Errorf("%s: 应该输出但没有输出", levelName)
				}
				if !shouldOutput && len(output) > 0 {
					t.Errorf("%s: 不应该输出但输出了: %v", levelName, output)
				}
			}

			t.Logf("✓ %s 测试通过", tt.name)
		})
	}
}

// TestLogger_ColorOutput 测试颜色输出
//
// 验证：EnableColor开关正确控制颜色输出
func TestLogger_ColorOutput(t *testing.T) {
	t.Run("禁用颜色", func(t *testing.T) {
		logger, capture := createTestLogger(LevelAll, false)
		logger.Info("test")

		output := capture.Get()
		if len(output) == 0 {
			t.Fatal("应该有输出")
		}

		// 无颜色时，输出就是纯文本
		if strings.Contains(output[0], "\033[") {
			t.Error("禁用颜色时不应该包含ANSI转义序列")
		}

		t.Logf("✓ 禁用颜色测试通过")
	})

	t.Run("启用颜色", func(t *testing.T) {
		logger, capture := createTestLogger(LevelAll, true)
		logger.Info("test")

		output := capture.Get()
		if len(output) == 0 {
			t.Fatal("应该有输出")
		}

		// 启用颜色时，输出可能包含颜色（取决于终端支持）
		// 但不会panic
		t.Logf("✓ 启用颜色测试通过: %s", output[0])
	})
}

// TestLogger_BackwardCompatibility 测试向后兼容性
//
// 验证：LevelAll 等同于 LevelDebug，显示所有级别
func TestLogger_BackwardCompatibility(t *testing.T) {
	config := &LoggerConfig{
		Level:        LevelAll, // LevelAll 是 LevelDebug 的别名
		EnableColor:  false,
		ShowProgress: false,
		StartTime:    time.Now(),
		LevelColors:  GetDefaultLevelColors(),
	}
	logger := NewLogger(config)
	capture := &captureOutput{}
	logger.SetCoordinatedOutput(capture.Write)

	// LevelAll 应该显示所有级别
	logger.Debug("debug msg")
	logger.Info("info msg")
	logger.Error("error msg")

	output := capture.Get()
	if len(output) != 3 {
		t.Errorf("LevelAll应该显示所有级别，期望3条，实际%d条", len(output))
	}

	t.Logf("✓ 向后兼容测试通过（LevelAll显示所有级别）")
}

// TestLogger_Initialize 测试初始化标记
//
// 验证：Initialize方法正确设置initialized标志
func TestLogger_Initialize(t *testing.T) {
	config := &LoggerConfig{
		Level:        LevelAll,
		EnableColor:  false,
		ShowProgress: false,
		StartTime:    time.Now(),
		LevelColors:  GetDefaultLevelColors(),
	}

	// 手动创建logger，跳过NewLogger中的自动初始化
	logger := &Logger{
		config:      config,
		initialized: false, // 明确设置为false
	}

	// 验证初始状态
	if logger.initialized {
		t.Error("新创建的logger不应该已初始化")
	}

	// 调用Initialize
	logger.Initialize()

	// 验证已初始化
	if !logger.initialized {
		t.Error("调用Initialize后应该已初始化")
	}

	t.Logf("✓ Initialize测试通过")
}

func TestLogger_CloseClosesDebugFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "debug.log")
	logger := NewLogger(&LoggerConfig{
		Level:        LevelAll,
		EnableColor:  false,
		ShowProgress: false,
		StartTime:    time.Now(),
		LevelColors:  GetDefaultLevelColors(),
		DebugLogFile: path,
	})
	if logger.debugFile == nil {
		t.Fatal("debug file should be opened")
	}

	logger.Info("debug file line")
	logger.Close()
	if logger.debugFile != nil {
		t.Fatal("debug file should be nil after Close")
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read debug file: %v", err)
	}
	if !strings.Contains(string(content), "debug file line") {
		t.Fatalf("debug file content = %q", string(content))
	}

	logger.Close()
}
