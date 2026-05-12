package logging

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// LogEntry 日志条目
type LogEntry struct {
	Level    LogLevel               `json:"level"`
	Time     time.Time              `json:"time"`
	Content  string                 `json:"content"`
	Source   string                 `json:"source"`
	Metadata map[string]interface{} `json:"metadata"`
}

// LoggerConfig 日志器配置
type LoggerConfig struct {
	Level        LogLevel                 `json:"level"`
	EnableColor  bool                     `json:"enable_color"`
	SlowOutput   bool                     `json:"slow_output"`
	ShowProgress bool                     `json:"show_progress"`
	Silent       bool                     `json:"silent"`
	StartTime    time.Time                `json:"start_time"`
	LevelColors  map[LogLevel]interface{} `json:"-"`
	DebugLogFile string                   `json:"debug_log_file"`
}

// DefaultLoggerConfig 默认日志器配置
func DefaultLoggerConfig() *LoggerConfig {
	return &LoggerConfig{
		Level:        DefaultLevel,
		EnableColor:  DefaultEnableColor,
		SlowOutput:   DefaultSlowOutput,
		ShowProgress: DefaultShowProgress,
		StartTime:    time.Now(),
		LevelColors:  GetDefaultLevelColors(),
	}
}

// Logger 简化的日志管理器
type Logger struct {
	mu                sync.RWMutex
	config            *LoggerConfig
	startTime         time.Time
	coordinatedOutput func(string)
	initialized       bool
	debugFile         *os.File
}

// NewLogger 创建新的日志管理器
func NewLogger(config *LoggerConfig) *Logger {
	if config == nil {
		config = DefaultLoggerConfig()
	}

	l := &Logger{
		config:      config,
		startTime:   config.StartTime,
		initialized: true,
	}

	if config.DebugLogFile != "" {
		f, err := os.OpenFile(config.DebugLogFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err == nil {
			l.debugFile = f
		}
	}

	return l
}

// Initialize 初始化日志器
func (l *Logger) Initialize() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.initialized = true
}

// SetCoordinatedOutput 设置协调输出函数
func (l *Logger) SetCoordinatedOutput(outputFunc func(string)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.coordinatedOutput = outputFunc
}

// Debug 输出调试信息
func (l *Logger) Debug(msg string) {
	l.log(LevelDebug, msg)
}

// Base 输出基础信息
func (l *Logger) Base(msg string) {
	l.log(LevelBase, msg)
}

// Info 输出信息
func (l *Logger) Info(msg string) {
	l.log(LevelInfo, msg)
}

// Success 输出成功信息
func (l *Logger) Success(msg string) {
	l.log(LevelSuccess, msg)
}

// Vuln 输出漏洞/重要发现信息
func (l *Logger) Vuln(msg string) {
	l.log(LevelVuln, msg)
}

// Error 输出错误信息
func (l *Logger) Error(msg string) {
	l.log(LevelError, msg)
}

// log 内部日志处理方法
func (l *Logger) log(level LogLevel, content string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.config.Silent {
		return
	}

	if !l.shouldLog(level) {
		return
	}

	// 格式化消息：保留前缀，去掉时间戳
	prefix := l.getLevelPrefix(level)

	// 处理多行内容：给每行加上前缀，然后作为一个整体输出
	if strings.Contains(content, "\n") {
		lines := strings.Split(content, "\n")
		var formattedLines []string
		for _, line := range lines {
			if line != "" {
				formattedLines = append(formattedLines, fmt.Sprintf("%s %s", prefix, line))
			}
		}
		logMsg := strings.Join(formattedLines, "\n")
		l.outputMessage(level, logMsg)
	} else {
		logMsg := fmt.Sprintf("%s %s", prefix, content)
		l.outputMessage(level, logMsg)
	}

	// 写入debug日志文件（纯文本，无颜色）
	if l.debugFile != nil {
		timestamp := time.Since(l.startTime).Truncate(time.Millisecond)
		if strings.Contains(content, "\n") {
			lines := strings.Split(content, "\n")
			for _, line := range lines {
				if line != "" {
					_, _ = fmt.Fprintf(l.debugFile, "[%s] %s %s\n", timestamp, prefix, line)
				}
			}
		} else {
			_, _ = fmt.Fprintf(l.debugFile, "[%s] %s %s\n", timestamp, prefix, content)
		}
	}

	// 根据慢速输出设置决定是否添加延迟
	if l.config.SlowOutput {
		time.Sleep(SlowOutputDelay)
	}
}

// Close 关闭日志器，释放文件资源
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.debugFile != nil {
		_ = l.debugFile.Close()
		l.debugFile = nil
	}
}

// shouldLog 检查是否应该记录该级别的日志
// 层级过滤：消息级别 >= 配置级别 时显示，Error 始终显示
func (l *Logger) shouldLog(level LogLevel) bool {
	// Error 级别始终显示
	if level == LevelError {
		return true
	}
	// 层级过滤：消息级别 >= 配置级别
	return level >= l.config.Level
}

// outputMessage 输出消息
func (l *Logger) outputMessage(level LogLevel, logMsg string) {
	if l.coordinatedOutput != nil {
		// 使用协调输出（与进度条配合）
		if l.config.EnableColor {
			if colorAttr, ok := l.config.LevelColors[level]; ok {
				if attr, ok := colorAttr.(color.Attribute); ok {
					coloredMsg := color.New(attr).Sprint(logMsg)
					l.coordinatedOutput(coloredMsg)
					return
				}
			}
		}
		l.coordinatedOutput(logMsg)
	} else {
		// 直接输出
		if l.config.EnableColor {
			if colorAttr, ok := l.config.LevelColors[level]; ok {
				if attr, ok := colorAttr.(color.Attribute); ok {
					_, _ = color.New(attr).Println(logMsg)
					return
				}
			}
		}
		fmt.Println(logMsg)
	}
}

// formatElapsedTime 格式化经过的时间
func (l *Logger) formatElapsedTime(elapsed time.Duration) string {
	switch {
	case elapsed < MaxMillisecondDisplay:
		return fmt.Sprintf("%dms", elapsed.Milliseconds())
	case elapsed < MaxSecondDisplay:
		return fmt.Sprintf("%.1fs", elapsed.Seconds())
	case elapsed < MaxMinuteDisplay:
		minutes := int(elapsed.Minutes())
		seconds := int(elapsed.Seconds()) % 60
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	default:
		hours := int(elapsed.Hours())
		minutes := int(elapsed.Minutes()) % 60
		seconds := int(elapsed.Seconds()) % 60
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	}
}

// getLevelPrefix 获取日志级别前缀
func (l *Logger) getLevelPrefix(level LogLevel) string {
	switch level {
	case LevelDebug:
		return PrefixDebug
	case LevelInfo:
		return PrefixInfo
	case LevelSuccess:
		return PrefixSuccess
	case LevelVuln:
		return PrefixVuln
	case LevelError:
		return PrefixError
	default:
		return PrefixInfo // 默认使用 Info 前缀
	}
}
