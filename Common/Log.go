package Common

import (
	"fmt"
	"io"
	"log"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// 全局变量定义
var (
	// 扫描状态管理器，记录最近一次成功和错误的时间
	status = &ScanStatus{lastSuccess: time.Now(), lastError: time.Now()}

	// Num 表示待处理的总任务数量
	Num int64
	// End 表示已经完成的任务数量
	End int64
)

// ScanStatus 用于记录和管理扫描状态的结构体
type ScanStatus struct {
	mu          sync.RWMutex // 读写互斥锁，用于保护并发访问
	total       int64        // 总任务数
	completed   int64        // 已完成任务数
	lastSuccess time.Time    // 最近一次成功的时间
	lastError   time.Time    // 最近一次错误的时间
}

// LogEntry 定义单条日志的结构
type LogEntry struct {
	Level   string    // 日志级别: ERROR/INFO/SUCCESS/DEBUG
	Time    time.Time // 日志时间
	Content string    // 日志内容
}

// 定义系统支持的日志级别常量
const (
	LogLevelAll     = "ALL"     // 显示所有级别日志
	LogLevelError   = "ERROR"   // 仅显示错误日志
	LogLevelBase    = "BASE"    // 仅显示信息日志
	LogLevelInfo    = "INFO"    // 仅显示信息日志
	LogLevelSuccess = "SUCCESS" // 仅显示成功日志
	LogLevelDebug   = "DEBUG"   // 仅显示调试日志
)

// 日志级别对应的显示颜色映射
var logColors = map[string]color.Attribute{
	LogLevelError:   color.FgBlue,   // 错误日志显示蓝色
	LogLevelBase:    color.FgYellow, // 信息日志显示黄色
	LogLevelInfo:    color.FgGreen,  // 信息日志显示绿色
	LogLevelSuccess: color.FgRed,    // 成功日志显示红色
	LogLevelDebug:   color.FgWhite,  // 调试日志显示白色
}

// InitLogger 初始化日志系统
func InitLogger() {
	// 禁用标准日志输出
	log.SetOutput(io.Discard)
}

var StartTime = time.Now()

// formatLogMessage 格式化日志消息为标准格式
// 返回格式：[时间] [级别] 内容
func formatLogMessage(entry *LogEntry) string {
	elapsed := time.Since(StartTime)
	var timeStr string

	// 根据时间长短选择合适的单位
	switch {
	case elapsed < time.Second:
		// 毫秒显示，不需要小数
		timeStr = fmt.Sprintf("%dms", elapsed.Milliseconds())
	case elapsed < time.Minute:
		// 秒显示，保留一位小数
		timeStr = fmt.Sprintf("%.1fs", elapsed.Seconds())
	case elapsed < time.Hour:
		// 分钟和秒显示
		minutes := int(elapsed.Minutes())
		seconds := int(elapsed.Seconds()) % 60
		timeStr = fmt.Sprintf("%dm%ds", minutes, seconds)
	default:
		// 小时、分钟和秒显示
		hours := int(elapsed.Hours())
		minutes := int(elapsed.Minutes()) % 60
		seconds := int(elapsed.Seconds()) % 60
		timeStr = fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	}
	str := "   "
	switch entry.Level {
	case LogLevelSuccess:
		str = "[+]"
	case LogLevelInfo:
		str = "[*]"
	case LogLevelError:
		str = "[-]"
	}

	return fmt.Sprintf("[%s] %s %s", timeStr, str, entry.Content)
}

// printLog 根据日志级别打印日志
func printLog(entry *LogEntry) {
	if LogLevel != "debug" && (entry.Level == LogLevelDebug || entry.Level == LogLevelError) {
		return
	}

	OutputMutex.Lock()
	defer OutputMutex.Unlock()

	// 处理进度条
	clearAndWaitProgress()

	// 打印日志消息
	logMsg := formatLogMessage(entry)
	if !NoColor {
		// 使用彩色输出
		if colorAttr, ok := logColors[entry.Level]; ok {
			color.New(colorAttr).Println(logMsg)
		} else {
			fmt.Println(logMsg)
		}
	} else {
		// 普通输出
		fmt.Println(logMsg)
	}

	// 根据慢速输出设置决定是否添加延迟
	if SlowLogOutput {
		time.Sleep(50 * time.Millisecond)
	}

	// 重新显示进度条
	if ProgressBar != nil {
		ProgressBar.RenderBlank()
	}
}

// clearAndWaitProgress 清除进度条并等待
func clearAndWaitProgress() {
	if ProgressBar != nil {
		ProgressBar.Clear()
		time.Sleep(10 * time.Millisecond)
	}
}

// handleLog 统一处理日志的输出
func handleLog(entry *LogEntry) {
	if ProgressBar != nil {
		ProgressBar.Clear()
	}

	printLog(entry)

	if ProgressBar != nil {
		ProgressBar.RenderBlank()
	}
}

// LogDebug 记录调试日志
func LogDebug(msg string) {
	handleLog(&LogEntry{
		Level:   LogLevelDebug,
		Time:    time.Now(),
		Content: msg,
	})
}

// LogBase 记录进度信息
func LogBase(msg string) {
	handleLog(&LogEntry{
		Level:   LogLevelBase,
		Time:    time.Now(),
		Content: msg,
	})
}

// LogInfo 记录信息日志
// [*]
func LogInfo(msg string) {
	handleLog(&LogEntry{
		Level:   LogLevelInfo,
		Time:    time.Now(),
		Content: msg,
	})
}

// LogSuccess 记录成功日志，并更新最后成功时间
// [+]
func LogSuccess(result string) {
	entry := &LogEntry{
		Level:   LogLevelSuccess,
		Time:    time.Now(),
		Content: result,
	}

	handleLog(entry)

	// 更新最后成功时间
	status.mu.Lock()
	status.lastSuccess = time.Now()
	status.mu.Unlock()
}

// LogError 记录错误日志，自动包含文件名和行号信息
func LogError(errMsg string) {
	// 获取调用者的文件名和行号
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		file = "unknown"
		line = 0
	}
	file = filepath.Base(file)

	errorMsg := fmt.Sprintf("%s:%d - %s", file, line, errMsg)

	entry := &LogEntry{
		Level:   LogLevelError,
		Time:    time.Now(),
		Content: errorMsg,
	}

	handleLog(entry)
}

// CheckErrs 检查是否为需要重试的错误
func CheckErrs(err error) error {
	if err == nil {
		return nil
	}

	// 已知需要重试的错误列表
	errs := []string{
		"closed by the remote host", "too many connections",
		"EOF", "A connection attempt failed",
		"established connection failed", "connection attempt failed",
		"Unable to read", "is not allowed to connect to this",
		"no pg_hba.conf entry",
		"No connection could be made",
		"invalid packet size",
		"bad connection",
	}

	// 检查错误是否匹配
	errLower := strings.ToLower(err.Error())
	for _, key := range errs {
		if strings.Contains(errLower, strings.ToLower(key)) {
			time.Sleep(1 * time.Second)
			return err
		}
	}

	return nil
}
