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
	status = &ScanStatus{lastSuccess: time.Now(), lastError: time.Now()} // 扫描状态管理器
	Num    int64                                                         // 待处理的总任务数量
	End    int64                                                         // 已完成的任务数量
)

// ScanStatus 用于记录和管理扫描状态的结构体
type ScanStatus struct {
	mu          sync.RWMutex // 读写互斥锁
	total       int64        // 总任务数
	completed   int64        // 已完成任务数
	lastSuccess time.Time    // 最近一次成功的时间
	lastError   time.Time    // 最近一次错误的时间
}

// 日志级别常量
const (
	LogLevelAll     = "ALL"     // 显示所有级别
	LogLevelError   = "ERROR"   // 错误级别
	LogLevelInfo    = "INFO"    // 信息级别
	LogLevelSuccess = "SUCCESS" // 成功级别
	LogLevelDebug   = "DEBUG"   // 调试级别
)

// 日志级别对应的颜色映射
var logColors = map[string]color.Attribute{
	LogLevelError:   color.FgRed,
	LogLevelInfo:    color.FgYellow,
	LogLevelSuccess: color.FgGreen,
	LogLevelDebug:   color.FgBlue,
}

// InitLogger 初始化日志系统
func InitLogger() {
	log.SetOutput(io.Discard) // 禁用标准日志输出
}

// Log 统一日志处理核心函数，处理所有级别的日志
func Log(level, msg string) {
	now := time.Now()

	// 更新状态时间戳
	if level == LogLevelSuccess {
		status.mu.Lock()
		status.lastSuccess = now
		status.mu.Unlock()
	} else if level == LogLevelError {
		status.mu.Lock()
		status.lastError = now
		status.mu.Unlock()
	}

	// 根据日志级别判断是否应该显示
	shouldPrint := false
	switch LogLevel {
	case LogLevelAll, LogLevelDebug:
		shouldPrint = true // 显示所有日志
	case LogLevelError:
		shouldPrint = level != LogLevelDebug // 除DEBUG外都显示
	case LogLevelSuccess:
		shouldPrint = level == LogLevelSuccess || level == LogLevelInfo // 显示SUCCESS和INFO
	case LogLevelInfo:
		shouldPrint = level == LogLevelInfo // 只显示INFO
	default:
		shouldPrint = level == LogLevelInfo // 默认显示INFO
	}

	if !shouldPrint {
		return
	}

	OutputMutex.Lock()
	defer OutputMutex.Unlock()

	// 清除进度条以便输出日志
	if ProgressBar != nil {
		ProgressBar.Clear()
		time.Sleep(10 * time.Millisecond)
	}

	// 格式化日志消息
	logMsg := fmt.Sprintf("[%s] [%s] %s", now.Format("2006-01-02 15:04:05"), level, msg)

	// 根据设置选择彩色或普通输出
	if !NoColor {
		if attr, ok := logColors[level]; ok {
			color.New(attr).Println(logMsg)
		} else {
			fmt.Println(logMsg)
		}
	} else {
		fmt.Println(logMsg)
	}

	// 慢速输出模式下增加延迟
	if SlowLogOutput {
		time.Sleep(50 * time.Millisecond)
	}

	// 恢复进度条显示
	if ProgressBar != nil {
		ProgressBar.RenderBlank()
	}
}

// LogError 记录错误日志，自动包含文件名和行号
func LogError(errMsg string) {
	_, file, line, ok := runtime.Caller(1)
	if ok {
		errMsg = fmt.Sprintf("%s:%d - %s", filepath.Base(file), line, errMsg)
	}
	Log(LogLevelError, errMsg)
}

// LogInfo 记录信息日志
func LogInfo(msg string) {
	Log(LogLevelInfo, msg)
}

// LogSuccess 记录成功日志
func LogSuccess(msg string) {
	Log(LogLevelSuccess, msg)
}

// LogDebug 记录调试日志
func LogDebug(msg string) {
	Log(LogLevelDebug, msg)
}

// CheckErrs 检查是否为需要重试的错误
func CheckErrs(err error) error {
	if err == nil {
		return nil
	}

	// 需要重试的错误关键词列表
	retryErrors := []string{
		"closed by the remote host", "too many connections", "EOF",
		"A connection attempt failed", "established connection failed",
		"connection attempt failed", "Unable to read",
		"is not allowed to connect to this", "no pg_hba.conf entry",
		"No connection could be made", "invalid packet size", "bad connection",
	}

	// 检查错误是否匹配任一关键词
	errLower := strings.ToLower(err.Error())
	for _, key := range retryErrors {
		if strings.Contains(errLower, strings.ToLower(key)) {
			time.Sleep(1 * time.Second) // 遇到需要重试的错误，等待1秒
			return err
		}
	}

	return nil
}
